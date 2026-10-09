package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// BusinessProfile is the reviewed, data-free mapping used to generate one fixed
// query. Values supplied by a model or user are always query parameters.
type BusinessProfile struct {
	ID                string               `json:"id"`
	Version           int                  `json:"version"`
	Label             string               `json:"label"`
	Synonyms          []string             `json:"synonyms"`
	Capability        string               `json:"capability"`
	Relationship      *RelatedRelationship `json:"relationship,omitempty"`
	SearchStrategy    string               `json:"searchStrategy,omitempty"`
	Language          string               `json:"language,omitempty"`
	Schema            string               `json:"schema"`
	Relation          string               `json:"relation"`
	KeyColumn         string               `json:"keyColumn"`
	LabelColumn       string               `json:"labelColumn"`
	SearchColumns     []string             `json:"searchColumns"`
	ReturnColumns     []ProfileColumn      `json:"returnColumns"`
	SourceURLColumn   string               `json:"sourceURLColumn,omitempty"`
	Approval          string               `json:"approval"`
	SchemaFingerprint string               `json:"schemaFingerprint,omitempty"`
}

// RelatedRelationship is one DBA-reviewed foreign key from this child relation
// to a parent entity. Filter values are explicit business labels mapped to DB values.
type RelatedRelationship struct {
	ParentProfileID     string          `json:"parentProfileId"`
	ParentSchema        string          `json:"parentSchema"`
	ParentRelation      string          `json:"parentRelation"`
	ParentKeyColumn     string          `json:"parentKeyColumn"`
	ParentLabelColumn   string          `json:"parentLabelColumn"`
	ParentSearchColumns []string        `json:"parentSearchColumns"`
	ParentKeyType       string          `json:"parentKeyType"`
	ChildForeignKey     string          `json:"childForeignKey"`
	ChildForeignKeyType string          `json:"childForeignKeyType"`
	Filters             []ProfileFilter `json:"filters,omitempty"`
}

type ProfileFilter struct {
	Name     string               `json:"name"`
	Column   string               `json:"column"`
	Type     string               `json:"type"`
	Required bool                 `json:"required,omitempty"`
	Values   []ProfileFilterValue `json:"values"`
}

type ProfileFilterValue struct {
	Label string `json:"label"`
	Value string `json:"value"`
}

type ProfileColumn struct {
	Name string `json:"name"`
	Type string `json:"type"` // text, integer, number, boolean, date, timestamp
}

type BusinessRecord struct {
	ID          string         `json:"id"`
	Type        string         `json:"type"`
	DisplayName string         `json:"displayName"`
	Relevance   float64        `json:"relevance"`
	SourceURL   string         `json:"sourceURL,omitempty"`
	Attributes  map[string]any `json:"attributes"`
}

type ProfileClarification struct {
	Kind       string             `json:"kind"`
	Question   string             `json:"question"`
	Candidates []ProfileCandidate `json:"candidates"`
}
type ProfileCandidate struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
}

func ValidateBusinessProfile(p BusinessProfile) error {
	if !toolIDPattern.MatchString(p.ID) || p.Version < 1 || strings.TrimSpace(p.Label) == "" || len(p.Label) > 128 || len(p.Synonyms) > 16 || p.Capability != "related_list" && (len(p.SearchColumns) == 0 || len(p.SearchColumns) > 12) || len(p.ReturnColumns) == 0 || len(p.ReturnColumns) > 12 || strings.TrimSpace(p.Approval) == "" || len(p.Approval) > 256 {
		return errors.New("invalid PostgreSQL business profile")
	}
	for _, id := range []string{p.Schema, p.Relation, p.KeyColumn, p.LabelColumn} {
		if !validIdentifier(id) {
			return errors.New("invalid PostgreSQL profile identifier")
		}
	}
	if p.Capability != "entity_lookup" && p.Capability != "text_search" && p.Capability != "related_list" {
		return errors.New("unsupported PostgreSQL profile capability")
	}
	if (p.Capability == "related_list") != (p.Relationship != nil) {
		return errors.New("related-list profiles require one reviewed relationship")
	}
	if p.Capability == "related_list" && (p.SearchStrategy != "" || p.Language != "") {
		return errors.New("related-list profiles cannot set a text-search strategy")
	}
	if p.Capability == "entity_lookup" && (p.SearchStrategy != "" || p.Language != "") || p.Capability == "text_search" && p.SearchStrategy != "keyword" && p.SearchStrategy != "full_text" {
		return errors.New("invalid PostgreSQL profile search strategy")
	}
	if p.SearchStrategy == "full_text" && !validTextSearchLanguage(p.Language) || p.SearchStrategy != "full_text" && p.Language != "" {
		return errors.New("invalid PostgreSQL text-search language")
	}
	if p.SchemaFingerprint != "" {
		if len(p.SchemaFingerprint) != 64 {
			return errors.New("invalid profile schema fingerprint")
		}
		if _, err := hex.DecodeString(p.SchemaFingerprint); err != nil {
			return errors.New("invalid profile schema fingerprint")
		}
	}
	for _, s := range p.Synonyms {
		if strings.TrimSpace(s) == "" || len(s) > 128 {
			return errors.New("invalid profile synonym")
		}
	}
	for _, c := range p.SearchColumns {
		if !validIdentifier(c) {
			return errors.New("invalid PostgreSQL profile identifier")
		}
	}
	if hasDuplicate(p.SearchColumns) {
		return errors.New("duplicate PostgreSQL search column")
	}
	if r := p.Relationship; r != nil {
		if r.ParentKeyType != "" && !profileTypeMatches("key", r.ParentKeyType) {
			return errors.New("invalid PostgreSQL parent key type")
		}
		if r.ChildForeignKeyType != "" && !profileTypeMatches("key", r.ChildForeignKeyType) {
			return errors.New("invalid PostgreSQL relationship key type")
		}
		if !toolIDPattern.MatchString(r.ParentProfileID) {
			return errors.New("related-list parent must reference an approved entity profile")
		}
		for _, id := range []string{r.ParentSchema, r.ParentRelation, r.ParentKeyColumn, r.ParentLabelColumn, r.ChildForeignKey} {
			if !validIdentifier(id) {
				return errors.New("invalid PostgreSQL relationship identifier")
			}
		}
		if len(r.ParentSearchColumns) == 0 || len(r.ParentSearchColumns) > 12 || len(r.Filters) == 0 || len(r.Filters) > 6 {
			return errors.New("invalid PostgreSQL relationship configuration")
		}
		for _, name := range r.ParentSearchColumns {
			if !validIdentifier(name) {
				return errors.New("invalid PostgreSQL relationship identifier")
			}
		}
		if hasDuplicate(r.ParentSearchColumns) {
			return errors.New("duplicate PostgreSQL parent search column")
		}
		filterNames := make([]string, 0, len(r.Filters))
		for _, filter := range r.Filters {
			if !toolIDPattern.MatchString(filter.Name) || !validIdentifier(filter.Column) || !validProfileType(filter.Type) || len(filter.Values) == 0 || len(filter.Values) > 16 {
				return errors.New("invalid PostgreSQL related-list filter")
			}
			if !filter.Required && filter.Type != "text" {
				return errors.New("optional related-list filters must use text values")
			}
			filterNames = append(filterNames, filter.Name)
			labels, values := make([]string, 0, len(filter.Values)), make([]string, 0, len(filter.Values))
			for _, value := range filter.Values {
				if strings.TrimSpace(value.Label) == "" || len(value.Label) > 64 || len(value.Value) > 256 {
					return errors.New("invalid PostgreSQL related-list filter value")
				}
				if _, err := parseProfileAttribute(value.Value, filter.Type); err != nil {
					return errors.New("related-list filter value does not match its type")
				}
				labels, values = append(labels, strings.ToLower(value.Label)), append(values, value.Value)
			}
			if hasDuplicate(labels) || hasDuplicate(values) {
				return errors.New("duplicate PostgreSQL related-list filter value")
			}
		}
		if hasDuplicate(filterNames) {
			return errors.New("duplicate PostgreSQL related-list filter")
		}
	}
	returnNames := make([]string, 0, len(p.ReturnColumns))
	for _, c := range p.ReturnColumns {
		if !validIdentifier(c.Name) || !validProfileType(c.Type) {
			return errors.New("invalid PostgreSQL profile output column")
		}
		returnNames = append(returnNames, c.Name)
	}
	if p.SourceURLColumn != "" {
		if !validIdentifier(p.SourceURLColumn) {
			return errors.New("invalid PostgreSQL source URL column")
		}
		foundTextColumn := false
		for _, column := range p.ReturnColumns {
			if column.Name == p.SourceURLColumn && column.Type == "text" {
				foundTextColumn = true
				break
			}
		}
		if !foundTextColumn {
			return errors.New("source URL must use a selected text output column")
		}
	}
	if hasDuplicate(returnNames) {
		return errors.New("duplicate PostgreSQL output column")
	}
	childColumns := map[string]bool{p.KeyColumn: true, p.LabelColumn: true}
	for _, name := range p.SearchColumns {
		childColumns[name] = true
	}
	for _, column := range p.ReturnColumns {
		childColumns[column.Name] = true
	}
	if p.Relationship != nil {
		childColumns[p.Relationship.ChildForeignKey] = true
		for _, filter := range p.Relationship.Filters {
			childColumns[filter.Column] = true
		}
		parentColumns := map[string]bool{p.Relationship.ParentKeyColumn: true, p.Relationship.ParentLabelColumn: true}
		for _, name := range p.Relationship.ParentSearchColumns {
			parentColumns[name] = true
		}
		if len(childColumns)+len(parentColumns) > 16 {
			return errors.New("profile maps more than 16 columns")
		}
	} else if len(childColumns) > 16 {
		return errors.New("profile maps more than 16 columns")
	}
	return nil
}

// ValidateProfileReferences binds each related list to its saved entity profile.
func ValidateProfileReferences(tools []QueryTool) error {
	profiles := make(map[string]BusinessProfile)
	for _, tool := range tools {
		if len(tool.ProfileConfig) == 0 || string(tool.ProfileConfig) == "{}" {
			continue
		}
		var p BusinessProfile
		if json.Unmarshal(tool.ProfileConfig, &p) == nil && ValidateBusinessProfile(p) == nil {
			profiles[tool.ID] = p
		}
	}
	for _, tool := range tools {
		p, ok := profiles[tool.ID]
		if !ok || p.Capability != "related_list" {
			continue
		}
		parent, ok := profiles[p.Relationship.ParentProfileID]
		if !ok || parent.Capability != "entity_lookup" {
			return errors.New("related-list parent entity profile is missing")
		}
		r := p.Relationship
		if r.ParentSchema != parent.Schema || r.ParentRelation != parent.Relation || r.ParentKeyColumn != parent.KeyColumn || r.ParentLabelColumn != parent.LabelColumn || !equalStrings(r.ParentSearchColumns, parent.SearchColumns) {
			return errors.New("related-list parent mapping differs from its approved entity profile")
		}
	}
	return nil
}

func FilterProfileReferences(tools []QueryTool) []QueryTool {
	profiles := make(map[string]BusinessProfile)
	for _, tool := range tools {
		if len(tool.ProfileConfig) == 0 || string(tool.ProfileConfig) == "{}" {
			continue
		}
		var p BusinessProfile
		if json.Unmarshal(tool.ProfileConfig, &p) == nil && ValidateBusinessProfile(p) == nil {
			profiles[tool.ID] = p
		}
	}
	filtered := make([]QueryTool, 0, len(tools))
	for _, tool := range tools {
		var p BusinessProfile
		if len(tool.ProfileConfig) > 0 && string(tool.ProfileConfig) != "{}" && json.Unmarshal(tool.ProfileConfig, &p) == nil && p.Capability == "related_list" {
			if p.Relationship == nil {
				continue
			}
			parent, ok := profiles[p.Relationship.ParentProfileID]
			r := p.Relationship
			if !ok || parent.Capability != "entity_lookup" || r.ParentSchema != parent.Schema || r.ParentRelation != parent.Relation || r.ParentKeyColumn != parent.KeyColumn || r.ParentLabelColumn != parent.LabelColumn || !equalStrings(r.ParentSearchColumns, parent.SearchColumns) {
				continue
			}
		}
		filtered = append(filtered, tool)
	}
	return filtered
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func hasDuplicate(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, v := range values {
		if seen[v] {
			return true
		}
		seen[v] = true
	}
	return false
}

func CompileBusinessProfile(p BusinessProfile) (string, error) {
	if err := ValidateBusinessProfile(p); err != nil {
		return "", err
	}
	relation := (pgx.Identifier{p.Schema, p.Relation}).Sanitize()
	key := (pgx.Identifier{p.KeyColumn}).Sanitize()
	label := (pgx.Identifier{p.LabelColumn}).Sanitize()
	if p.Capability == "related_list" {
		fk := (pgx.Identifier{p.Relationship.ChildForeignKey}).Sanitize()
		outputs := []string{"left((" + key + ")::text,2049) AS id", "left((" + label + ")::text,256) AS \"displayName\"", "1.0::text AS relevance"}
		for i, c := range p.ReturnColumns {
			outputs = append(outputs, "left(("+(pgx.Identifier{c.Name}).Sanitize()+")::text,2048) AS "+(pgx.Identifier{fmt.Sprintf("field_%d", i+1)}).Sanitize())
		}
		keyType := p.Relationship.ParentKeyType
		if keyType == "" {
			keyType = p.Relationship.ChildForeignKeyType
		}
		if keyType == "" {
			keyType = "text" // Existing text-key profiles remain valid until re-saved.
		}
		predicates := []string{fk + "=$1::" + keyType}
		for i, filter := range p.Relationship.Filters {
			param := "$" + strconv.Itoa(i+2)
			predicate := (pgx.Identifier{filter.Column}).Sanitize() + "=" + param
			if !filter.Required {
				predicate = "(" + param + "::text IS NULL OR (" + (pgx.Identifier{filter.Column}).Sanitize() + ")::text=" + param + "::text)"
			}
			predicates = append(predicates, predicate)
		}
		return "SELECT " + strings.Join(outputs, ", ") + " FROM " + relation + " WHERE " + strings.Join(predicates, " AND ") + " ORDER BY " + key + " LIMIT $" + strconv.Itoa(len(p.Relationship.Filters)+2), nil
	}
	search := make([]string, 0, len(p.SearchColumns))
	ranks := make([]string, 0, len(p.SearchColumns))
	for _, c := range p.SearchColumns {
		column := "COALESCE(" + (pgx.Identifier{c}).Sanitize() + "::text,'')"
		if p.SearchStrategy == "full_text" {
			language := "'pg_catalog." + p.Language + "'::regconfig"
			vector := "to_tsvector(" + language + "," + column + ")"
			query := "websearch_to_tsquery(" + language + ",$1)"
			search = append(search, vector+" @@ "+query)
			ranks = append(ranks, "ts_rank_cd("+vector+","+query+")")
		} else {
			predicate := column + " ILIKE '%' || $1 || '%'"
			search = append(search, predicate)
			ranks = append(ranks, "CASE WHEN "+predicate+" THEN 1.0 ELSE 0.0 END")
		}
	}
	relevance := strings.Join(ranks, "+") + "/" + strconv.Itoa(len(ranks)) + ".0"
	if p.SearchStrategy == "full_text" {
		relevance = "LEAST(1.0,GREATEST(" + strings.Join(ranks, ",") + "))"
	}
	if p.Capability == "entity_lookup" {
		relevance = "CASE WHEN lower((" + key + ")::text)=lower($1) THEN 1.0 WHEN lower((" + label + ")::text)=lower($1) THEN 0.9 ELSE 0.5 END"
	}
	outputs := []string{"left((" + key + ")::text,2049) AS id", "left((" + label + ")::text,256) AS \"displayName\"", "(" + relevance + ")::text AS relevance"}
	for i, c := range p.ReturnColumns {
		outputs = append(outputs, "left(("+(pgx.Identifier{c.Name}).Sanitize()+")::text,2048) AS "+(pgx.Identifier{fmt.Sprintf("field_%d", i+1)}).Sanitize())
	}
	predicates := append([]string(nil), search...)
	if p.Capability == "entity_lookup" {
		predicates = append(predicates, "lower(("+key+")::text)=lower($1)", "lower(("+label+")::text)=lower($1)")
	}
	order := "(" + relevance + ") DESC, " + key
	return "SELECT " + strings.Join(outputs, ", ") + " FROM " + relation + " WHERE (" + strings.Join(predicates, " OR ") + ") ORDER BY " + order + " LIMIT $2", nil
}

func CompileRelatedParentLookup(p BusinessProfile) (string, error) {
	if err := ValidateBusinessProfile(p); err != nil || p.Capability != "related_list" {
		return "", errors.New("invalid related-list profile")
	}
	r := p.Relationship
	parent := (pgx.Identifier{r.ParentSchema, r.ParentRelation}).Sanitize()
	key := (pgx.Identifier{r.ParentKeyColumn}).Sanitize()
	label := (pgx.Identifier{r.ParentLabelColumn}).Sanitize()
	projection := "left((" + key + ")::text,2049) AS id,left((" + label + ")::text,256) AS \"displayName\""
	search := make([]string, 0, len(r.ParentSearchColumns))
	for _, column := range r.ParentSearchColumns {
		search = append(search, "COALESCE("+(pgx.Identifier{column}).Sanitize()+"::text,'') ILIKE '%' || $1 || '%'")
	}
	query := "WITH exact_key AS (SELECT " + projection + " FROM " + parent + " WHERE lower((" + key + ")::text)=lower($1) ORDER BY " + key + " LIMIT 2), exact_label AS (SELECT " + projection + " FROM " + parent + " WHERE lower((" + label + ")::text)=lower($1) ORDER BY " + key + " LIMIT 2), fallback AS (SELECT " + projection + " FROM " + parent + " WHERE (" + strings.Join(search, " OR ") + ") ORDER BY " + key + " LIMIT 2), matches AS (SELECT 0 AS rank,id,\"displayName\" FROM exact_key UNION ALL SELECT 1,id,\"displayName\" FROM exact_label WHERE NOT EXISTS(SELECT 1 FROM exact_key) UNION ALL SELECT 2,id,\"displayName\" FROM fallback WHERE NOT EXISTS(SELECT 1 FROM exact_key) AND NOT EXISTS(SELECT 1 FROM exact_label)) SELECT id,\"displayName\" FROM matches ORDER BY rank,id LIMIT 2"
	return query, nil
}

// ProfileParameters describes the saved fixed query's bound argument contract.
func ProfileParameters(p BusinessProfile) []QueryParameter {
	if p.Capability != "related_list" {
		return []QueryParameter{{Name: "term", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}}
	}
	params := []QueryParameter{{Name: "parent_key", Type: "text"}}
	for _, filter := range p.Relationship.Filters {
		params = append(params, QueryParameter{Name: "filter_" + filter.Name, Type: filter.Type})
	}
	return append(params, QueryParameter{Name: "limit", Type: "integer[1,5]"})
}

func ProfileOutputColumns(p BusinessProfile) []string {
	outputs := []string{"id:text", "displayName:text", "relevance:number"}
	for _, column := range p.ReturnColumns {
		if column.Name == p.SourceURLColumn {
			outputs = append(outputs, "sourceURL:https")
			continue
		}
		outputs = append(outputs, "attribute:"+column.Name+":"+column.Type)
	}
	return outputs
}

func validTextSearchLanguage(language string) bool {
	switch language {
	case "simple", "danish", "dutch", "english", "finnish", "french", "german", "hungarian", "italian", "norwegian", "portuguese", "romanian", "russian", "spanish", "swedish", "turkish":
		return true
	default:
		return false
	}
}

func profileCandidateLimit(capability string, requested int) int {
	if capability == "entity_lookup" && requested < 2 {
		return 2
	}
	return requested
}

func ProfileFingerprint(p BusinessProfile) (string, error) {
	if err := ValidateBusinessProfile(p); err != nil {
		return "", err
	}
	b, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func (c *Connector) ProfileSchemaFingerprint(ctx context.Context, databaseIdentity, password string, p BusinessProfile) (string, error) {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" {
		return "", errors.New("invalid PostgreSQL profile credentials")
	}
	if err := ValidateBusinessProfile(p); err != nil {
		return "", errors.New("invalid PostgreSQL business profile")
	}
	conn, tx, resolved, err := c.beginAuthorized(ctx, databaseIdentity, password)
	if err != nil {
		return "", errors.New("PostgreSQL profile metadata check failed")
	}
	defer closeConnection(conn)
	defer func() { _ = tx.Rollback(context.Background()) }()
	fingerprint, err := c.profileSchema(ctx, tx, resolved, p)
	if err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", errors.New("PostgreSQL profile metadata check failed")
	}
	return fingerprint, nil
}

func validateProfileSchema(ctx context.Context, tx pgx.Tx, p BusinessProfile) (string, error) {
	return validateProfileSchemaMode(ctx, tx, p, false)
}

func validateProfileSchemaMode(ctx context.Context, tx pgx.Tx, p BusinessProfile, application bool) (string, error) {
	if p.SearchStrategy == "full_text" {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_ts_config c JOIN pg_namespace n ON n.oid=c.cfgnamespace WHERE n.nspname='pg_catalog' AND c.cfgname=$1)`, p.Language).Scan(&exists); err != nil {
			return "", fmt.Errorf("PostgreSQL text-search language lookup failed: %w", err)
		}
		if !exists {
			return "", errors.New("PostgreSQL text-search language is unavailable")
		}
	}
	var relationKind string
	var owned, rls, forceRLS bool
	var relationOID string
	err := tx.QueryRow(ctx, `SELECT c.oid::text,c.relkind::text, pg_get_userbyid(c.relowner)=current_user, c.relrowsecurity, c.relforcerowsecurity
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
	WHERE n.nspname=$1 AND c.relname=$2`, p.Schema, p.Relation).Scan(&relationOID, &relationKind, &owned, &rls, &forceRLS)
	if err != nil || relationKind != "r" && relationKind != "p" && relationKind != "v" || !application && relationKind != "v" && owned && rls && !forceRLS {
		return "", errors.New("PostgreSQL profile relation is stale or has unsupported security semantics")
	}
	var relationMaterial []string
	if relationKind == "v" {
		relationMaterial, err = inspectInvokerView(ctx, tx, relationOID)
		if err != nil {
			return "", err
		}
	}
	var uniqueKey bool
	if relationKind == "v" {
		// ponytail: view keys lack catalog constraints, so prove the selected key
		// non-null and unique per read; use a DBA-provided indexed base table if
		// this bounded statement-timeout check is too expensive for the view.
		quotedRelation := (pgx.Identifier{p.Schema, p.Relation}).Sanitize()
		quotedKey := (pgx.Identifier{p.KeyColumn}).Sanitize()
		err = tx.QueryRow(ctx, "SELECT NOT EXISTS(SELECT 1 FROM "+quotedRelation+" GROUP BY "+quotedKey+" HAVING "+quotedKey+" IS NULL OR count(*)>1 LIMIT 1)").Scan(&uniqueKey)
	} else {
		err = tx.QueryRow(ctx, `SELECT EXISTS(
 SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=ANY(i.indkey)
	 WHERE n.nspname=$1 AND c.relname=$2 AND a.attname=$3 AND a.attnotnull AND i.indisunique AND i.indisvalid AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=1)`, p.Schema, p.Relation, p.KeyColumn).Scan(&uniqueKey)
	}
	if err != nil || !uniqueKey {
		return "", errors.New("PostgreSQL profile key is no longer unique")
	}
	columns := map[string]string{p.KeyColumn: "key", p.LabelColumn: "text"}
	if p.Relationship != nil {
		keyType := p.Relationship.ChildForeignKeyType
		if keyType == "" {
			keyType = "key"
		}
		columns[p.Relationship.ChildForeignKey] = keyType
	}
	for _, name := range p.SearchColumns {
		columns[name] = "text"
	}
	for _, col := range p.ReturnColumns {
		columns[col.Name] = col.Type
	}
	if p.Relationship != nil {
		for _, filter := range p.Relationship.Filters {
			columns[filter.Column] = filter.Type
		}
	}
	names := make([]string, 0, len(columns))
	for name := range columns {
		names = append(names, name)
	}
	sort.Strings(names)
	material := []string{"relation=" + relationOID, "key=" + p.KeyColumn, "unique=true"}
	material = append(material, relationMaterial...)
	rows, err := tx.Query(ctx, `SELECT c.column_name,c.data_type,format_type(a.atttypid,a.atttypmod),a.attnum,a.attnotnull FROM information_schema.columns c
JOIN pg_namespace n ON n.nspname=c.table_schema JOIN pg_class r ON r.relnamespace=n.oid AND r.relname=c.table_name
JOIN pg_attribute a ON a.attrelid=r.oid AND a.attname=c.column_name
	WHERE c.table_schema=$1 AND c.table_name=$2 AND c.column_name=ANY($3::text[]) AND has_column_privilege(current_user,quote_ident(c.table_schema)||'.'||quote_ident(c.table_name),c.column_name,'SELECT')`, p.Schema, p.Relation, names)
	if err != nil {
		return "", errors.New("PostgreSQL profile schema check failed")
	}
	seen := make(map[string]bool, len(names))
	for rows.Next() {
		var name, dataType, formatted string
		var ordinal int
		var notNull bool
		if err := rows.Scan(&name, &dataType, &formatted, &ordinal, &notNull); err != nil {
			rows.Close()
			return "", errors.New("PostgreSQL profile schema check failed")
		}
		expected, ok := columns[name]
		if !ok || !profileTypeMatches(expected, dataType) {
			rows.Close()
			return "", errors.New("PostgreSQL profile schema or column permission has changed")
		}
		seen[name] = true
		material = append(material, fmt.Sprintf("column=%s|%s|%d|%t", name, formatted, ordinal, notNull))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return "", errors.New("PostgreSQL profile schema check failed")
	}
	rows.Close()
	if len(seen) != len(names) {
		return "", errors.New("PostgreSQL profile schema or column permission has changed")
	}
	if p.Relationship != nil {
		parentMaterial, err := validateRelatedRelationshipMode(ctx, tx, p, application)
		if err != nil {
			return "", err
		}
		material = append(material, parentMaterial...)
	}
	return schemaMetadataFingerprint(material), nil
}

// inspectInvokerView rejects owner-rights or nested views and any direct
// non-built-in, volatile, or SECURITY DEFINER function/operator dependency.
// It fingerprints view definitions and their referenced relation identities.
func inspectInvokerView(ctx context.Context, tx pgx.Tx, oid string) ([]string, error) {
	var safe bool
	var fingerprint string
	err := tx.QueryRow(ctx, `WITH RECURSIVE view_tree(oid,path) AS (
 SELECT $1::oid, ARRAY[$1::oid]
 UNION ALL
 SELECT d.refobjid, v.path||d.refobjid
 FROM view_tree v
 JOIN pg_rewrite rw ON rw.ev_class=v.oid AND rw.rulename='_RETURN'
 JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=rw.oid AND d.refclassid='pg_class'::regclass
 JOIN pg_class child ON child.oid=d.refobjid AND child.relkind='v'
 WHERE NOT d.refobjid=ANY(v.path)
), relations AS (
 SELECT DISTINCT c.oid,c.relkind,c.reloptions,pg_get_userbyid(c.relowner)=current_user AS owned,c.relrowsecurity,c.relforcerowsecurity
 FROM view_tree v JOIN pg_class c ON c.oid=v.oid
 UNION
 SELECT DISTINCT c.oid,c.relkind,c.reloptions,pg_get_userbyid(c.relowner)=current_user AS owned,c.relrowsecurity,c.relforcerowsecurity
 FROM view_tree v
 JOIN pg_rewrite rw ON rw.ev_class=v.oid AND rw.rulename='_RETURN'
 JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=rw.oid AND d.refclassid='pg_class'::regclass
 JOIN pg_class c ON c.oid=d.refobjid
)
SELECT COALESCE(bool_and(CASE
 WHEN relkind='v' THEN COALESCE(reloptions @> ARRAY['security_invoker=true']::text[],false)
 WHEN relkind IN ('r','p') THEN NOT (owned AND relrowsecurity AND NOT relforcerowsecurity)
 ELSE false END),false),
 COALESCE(string_agg(relkind::text||':'||oid::text||':'||COALESCE(reloptions::text,'')||':'||CASE WHEN relkind='v' THEN pg_get_viewdef(oid,true) ELSE '' END,E'\n' ORDER BY oid),'')
FROM relations`, oid).Scan(&safe, &fingerprint)
	if err != nil || !safe {
		return nil, errors.New("PostgreSQL view must use invoker security and reference only safe base tables")
	}
	var unsafeFunctions, unsafeOperators bool
	if err := tx.QueryRow(ctx, `WITH RECURSIVE view_tree(oid,path) AS (
 SELECT $1::oid, ARRAY[$1::oid]
 UNION ALL
 SELECT d.refobjid, v.path||d.refobjid
 FROM view_tree v
 JOIN pg_rewrite rw ON rw.ev_class=v.oid AND rw.rulename='_RETURN'
 JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=rw.oid AND d.refclassid='pg_class'::regclass
 JOIN pg_class child ON child.oid=d.refobjid AND child.relkind='v'
 WHERE NOT d.refobjid=ANY(v.path)
)
SELECT EXISTS (
 SELECT 1 FROM view_tree v JOIN pg_rewrite rw ON rw.ev_class=v.oid AND rw.rulename='_RETURN'
 JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=rw.oid AND d.refclassid='pg_proc'::regclass
 JOIN pg_proc f ON f.oid=d.refobjid JOIN pg_namespace n ON n.oid=f.pronamespace
 WHERE n.nspname<>'pg_catalog' OR f.provolatile<>'i' OR f.prosecdef
), EXISTS (
 SELECT 1 FROM view_tree v JOIN pg_rewrite rw ON rw.ev_class=v.oid AND rw.rulename='_RETURN'
 JOIN pg_depend d ON d.classid='pg_rewrite'::regclass AND d.objid=rw.oid AND d.refclassid='pg_operator'::regclass
 JOIN pg_operator o ON o.oid=d.refobjid JOIN pg_namespace n ON n.oid=o.oprnamespace
 JOIN pg_proc f ON f.oid=o.oprcode JOIN pg_namespace fn ON fn.oid=f.pronamespace
 WHERE n.nspname<>'pg_catalog' OR fn.nspname<>'pg_catalog' OR f.provolatile<>'i' OR f.prosecdef)`, oid).Scan(&unsafeFunctions, &unsafeOperators); err != nil {
		return nil, errors.New("PostgreSQL view dependency check failed")
	}
	if unsafeFunctions || unsafeOperators {
		return nil, errors.New("PostgreSQL view references an unsupported function or operator")
	}
	return []string{"view_dependencies=" + fingerprint}, nil
}

func validateRelatedRelationship(ctx context.Context, tx pgx.Tx, p BusinessProfile) ([]string, error) {
	return validateRelatedRelationshipMode(ctx, tx, p, false)
}

func validateRelatedRelationshipMode(ctx context.Context, tx pgx.Tx, p BusinessProfile, application bool) ([]string, error) {
	r := p.Relationship
	var oid, kind string
	var owned, rls, forced bool
	err := tx.QueryRow(ctx, `SELECT c.oid::text,c.relkind::text,pg_get_userbyid(c.relowner)=current_user,c.relrowsecurity,c.relforcerowsecurity FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2`, r.ParentSchema, r.ParentRelation).Scan(&oid, &kind, &owned, &rls, &forced)
	if err != nil || kind != "r" && kind != "p" || !application && owned && rls && !forced {
		return nil, errors.New("PostgreSQL related parent is stale or has unsupported security semantics")
	}
	var uniqueKey, foreignKey bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_index i JOIN pg_class c ON c.oid=i.indrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=ANY(i.indkey) WHERE n.nspname=$1 AND c.relname=$2 AND a.attname=$3 AND i.indisunique AND i.indisvalid AND i.indpred IS NULL AND i.indexprs IS NULL AND i.indnatts=1)`, r.ParentSchema, r.ParentRelation, r.ParentKeyColumn).Scan(&uniqueKey); err != nil || !uniqueKey {
		return nil, errors.New("PostgreSQL related parent key is no longer unique")
	}
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_class p ON p.oid=con.confrelid JOIN pg_namespace pn ON pn.oid=p.relnamespace JOIN pg_attribute ca ON ca.attrelid=c.oid AND ca.attnum=con.conkey[1] JOIN pg_attribute pa ON pa.attrelid=p.oid AND pa.attnum=con.confkey[1] WHERE con.contype='f' AND con.convalidated AND array_length(con.conkey,1)=1 AND array_length(con.confkey,1)=1 AND n.nspname=$1 AND c.relname=$2 AND ca.attname=$3 AND pn.nspname=$4 AND p.relname=$5 AND pa.attname=$6)`, p.Schema, p.Relation, r.ChildForeignKey, r.ParentSchema, r.ParentRelation, r.ParentKeyColumn).Scan(&foreignKey); err != nil || !foreignKey {
		return nil, errors.New("PostgreSQL reviewed foreign key is missing")
	}
	parentKeyType := r.ParentKeyType
	if parentKeyType == "" {
		parentKeyType = "key"
	}
	columns := map[string]string{r.ParentKeyColumn: parentKeyType, r.ParentLabelColumn: "text"}
	for _, name := range r.ParentSearchColumns {
		columns[name] = "text"
	}
	names := make([]string, 0, len(columns))
	for name := range columns {
		names = append(names, name)
	}
	sort.Strings(names)
	rows, err := tx.Query(ctx, `SELECT c.column_name,c.data_type,format_type(a.atttypid,a.atttypmod),a.attnum,a.attnotnull FROM information_schema.columns c JOIN pg_namespace n ON n.nspname=c.table_schema JOIN pg_class rel ON rel.relnamespace=n.oid AND rel.relname=c.table_name JOIN pg_attribute a ON a.attrelid=rel.oid AND a.attname=c.column_name WHERE c.table_schema=$1 AND c.table_name=$2 AND c.column_name=ANY($3::text[]) AND has_column_privilege(current_user,quote_ident(c.table_schema)||'.'||quote_ident(c.table_name),c.column_name,'SELECT')`, r.ParentSchema, r.ParentRelation, names)
	if err != nil {
		return nil, errors.New("PostgreSQL related parent schema check failed")
	}
	seen := map[string]bool{}
	material := []string{"parent_relation=" + oid, "parent_key=" + r.ParentKeyColumn, "foreign_key=" + r.ChildForeignKey}
	for rows.Next() {
		var name, dataType, formatted string
		var ordinal int
		var notNull bool
		if err := rows.Scan(&name, &dataType, &formatted, &ordinal, &notNull); err != nil {
			rows.Close()
			return nil, errors.New("PostgreSQL related parent schema check failed")
		}
		expected := columns[name]
		if expected == "" || !profileTypeMatches(expected, dataType) {
			rows.Close()
			return nil, fmt.Errorf("PostgreSQL related parent column %q has unsupported type or is not readable", name)
		}
		seen[name] = true
		material = append(material, fmt.Sprintf("parent_column=%s|%s|%d|%t", name, formatted, ordinal, notNull))
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, errors.New("PostgreSQL related parent schema check failed")
	}
	rows.Close()
	if len(seen) != len(names) {
		return nil, errors.New("PostgreSQL related parent schema or permission changed")
	}
	return material, nil
}

func schemaMetadataFingerprint(material []string) string {
	ordered := append([]string(nil), material...)
	sort.Strings(ordered)
	sum := sha256.Sum256([]byte(strings.Join(ordered, "\n")))
	return hex.EncodeToString(sum[:])
}

func profileTypeMatches(expected, actual string) bool {
	switch expected {
	case "text":
		return actual == "text" || actual == "character varying" || actual == "character" || actual == "name" || actual == "uuid"
	case "key":
		return actual == "text" || actual == "character varying" || actual == "character" || actual == "name" || actual == "uuid" || actual == "smallint" || actual == "integer" || actual == "bigint"
	case "integer":
		return actual == "smallint" || actual == "integer" || actual == "bigint"
	case "number":
		return actual == "numeric" || actual == "real" || actual == "double precision"
	case "boolean":
		return actual == "boolean"
	case "date":
		return actual == "date"
	case "timestamp":
		return actual == "timestamp without time zone" || actual == "timestamp with time zone"
	default:
		return false
	}
}

// ProfileColumnType returns an allowlisted PostgreSQL type for a readable profile column.
func (c *Connector) ProfileColumnType(ctx context.Context, databaseIdentity, password, schema, relation, column string) (string, error) {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" || !validIdentifier(schema) || !validIdentifier(relation) || !validIdentifier(column) {
		return "", errors.New("invalid PostgreSQL profile column request")
	}
	conn, tx, resolved, err := c.beginAuthorized(ctx, databaseIdentity, password)
	if err != nil {
		return "", errors.New("PostgreSQL profile metadata check failed")
	}
	defer closeConnection(conn)
	defer func() { _ = tx.Rollback(context.Background()) }()
	if c.applicationRules() {
		if _, err = c.authorizeResource(ctx, resolved, schema, relation, []string{column}); err != nil {
			return "", err
		}
		if err = validateScalarResource(ctx, tx, schema, relation, []string{column}); err != nil {
			return "", err
		}
	}
	var typ string
	err = tx.QueryRow(ctx, `SELECT c.data_type FROM information_schema.columns c WHERE c.table_schema=$1 AND c.table_name=$2 AND c.column_name=$3 AND has_column_privilege(current_user,quote_ident(c.table_schema)||'.'||quote_ident(c.table_name),c.column_name,'SELECT')`, schema, relation, column).Scan(&typ)
	if err != nil || !profileTypeMatches("key", typ) {
		return "", errors.New("PostgreSQL relationship key is unavailable or unsupported")
	}
	if err := tx.Commit(ctx); err != nil {
		return "", errors.New("PostgreSQL profile metadata check failed")
	}
	return typ, nil
}

func parseProfileAttribute(value, kind string) (any, error) {
	switch kind {
	case "text":
		return value, nil
	case "integer":
		return strconv.ParseInt(value, 10, 64)
	case "number":
		return strconv.ParseFloat(value, 64)
	case "boolean":
		return strconv.ParseBool(value)
	case "date":
		return time.Parse("2006-01-02", value)
	case "timestamp":
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999-07:00", "2006-01-02 15:04:05.999999-07", "2006-01-02 15:04:05.999999", "2006-01-02 15:04:05-07:00", "2006-01-02 15:04:05-07"} {
			if parsed, err := time.Parse(layout, value); err == nil {
				return parsed, nil
			}
		}
		return nil, errors.New("timestamp output is invalid")
	default:
		return nil, errors.New("unsupported attribute type")
	}
}

func validIdentifier(s string) bool { return s != "" && len(s) <= 63 && !strings.ContainsRune(s, 0) }
func validProfileType(s string) bool {
	switch s {
	case "text", "integer", "number", "boolean", "date", "timestamp":
		return true
	}
	return false
}
