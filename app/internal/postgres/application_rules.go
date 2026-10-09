package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
	"iq-kbteams/internal/authorization"
)

func (c *Connector) applicationRules() bool {
	return c.adapter != nil && c.adapter.Mode == "application_rules"
}
func validateApplicationConfiguration(a AdapterConfig) error {
	if len(a.Claims) > 16 {
		return errors.New("too many identity attributes")
	}
	for claim, column := range a.Claims {
		if !ValidDatabaseIdentity(claim) || !validIdentifier(column) || SensitiveAuthorizationField(column) {
			return errors.New("invalid identity attribute mapping")
		}
	}
	if a.Mode != "application_rules" {
		if len(a.Rules) > 0 {
			return errors.New("application rules require their own adapter mode")
		}
		return nil
	}
	if len(a.RoleMappings) > 0 {
		return errors.New("application labels do not map to database roles in this mode")
	}
	if err := authorization.ValidateRules(a.Rules); err != nil {
		return err
	}
	for _, r := range a.Rules {
		if !validIdentifier(r.Schema) || !validIdentifier(r.Relation) || strings.HasPrefix(r.Schema, "pg_") || r.Schema == "information_schema" || (r.Schema == a.Schema && r.Relation == a.Relation) {
			return errors.New("invalid business resource")
		}
		for _, field := range r.Fields {
			if !validIdentifier(field) || SensitiveAuthorizationField(field) {
				return errors.New("invalid or sensitive field")
			}
		}
		if r.Scope.Kind != "all" && r.Scope.Kind != "pending" && (!validIdentifier(r.Scope.Column) || SensitiveAuthorizationField(r.Scope.Column)) {
			return errors.New("invalid scope column")
		}
		if r.Scope.Kind == "claim" && a.Claims[r.Scope.Claim] == "" {
			return errors.New("scope requires a mapped identity attribute")
		}
		if m := r.Scope.Membership; m != nil {
			for _, identifier := range []string{m.Schema, m.Relation, m.UserColumn, m.GroupColumn} {
				if !validIdentifier(identifier) {
					return errors.New("incomplete membership mapping")
				}
			}
			for _, column := range []string{m.UserColumn, m.GroupColumn, m.ActiveColumn, m.TenantColumn} {
				if column != "" && (!validIdentifier(column) || SensitiveAuthorizationField(column)) {
					return errors.New("invalid membership column")
				}
			}
			if strings.HasPrefix(m.Schema, "pg_") || m.Schema == "information_schema" {
				return errors.New("invalid membership source")
			}
		}
	}
	return nil
}

func profileFields(p BusinessProfile) []string {
	fields := []string{p.KeyColumn, p.LabelColumn}
	fields = append(fields, p.SearchColumns...)
	for _, col := range p.ReturnColumns {
		fields = append(fields, col.Name)
	}
	if p.Relationship != nil {
		fields = append(fields, p.Relationship.ChildForeignKey)
		for _, filter := range p.Relationship.Filters {
			fields = append(fields, filter.Column)
		}
	}
	seen := map[string]bool{}
	unique := []string{}
	for _, field := range fields {
		if !seen[field] {
			unique = append(unique, field)
			seen[field] = true
		}
	}
	return unique
}

func (c *Connector) authorizeResource(ctx context.Context, id ResolvedIdentity, schema, relation string, fields []string) (authorization.Decision, error) {
	provider := "database_policy"
	rules := []authorization.Rule(nil)
	identity := authorization.Identity{ID: id.UserID, Label: id.ApplicationRole, Revision: id.PermissionVersion, DatabasePolicyVerified: !c.applicationRules()}
	if c.subject != nil {
		identity.Email = c.subject.Email
		identity.TenantID = c.subject.TenantID
		identity.Claims = id.Claims
	}
	if c.applicationRules() {
		provider = "application_rules"
		rules = c.adapter.Rules
		if id.AutomaticPermissions {
			rules = id.Rules
		}
	}
	adapter, err := authorization.NewRegistry().Create(provider, rules)
	if err != nil {
		return authorization.Decision{}, err
	}
	decision, err := adapter.Authorize(ctx, identity, authorization.Resource{Namespace: schema, Name: relation, Fields: fields})
	if err != nil {
		return decision, &AuthorizationError{Code: "application_resource_permission_denied", Cause: err}
	}
	return decision, nil
}

// Resource projections and row predicates are server-generated from validated
// configuration. Arbitrary SQL, views, expressions and custom data types are
// excluded in application-rules mode, including with privileged URI credentials.
func validateScalarResource(ctx context.Context, tx pgx.Tx, schema, relation string, fields []string) error {
	var kind string
	if err := tx.QueryRow(ctx, `SELECT c.relkind::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2`, schema, relation).Scan(&kind); err != nil || kind != "r" && kind != "p" {
		return &AuthorizationError{Code: "application_rules_base_table_required"}
	}
	unique := make([]string, 0, len(fields))
	seen := map[string]bool{}
	for _, field := range fields {
		if !seen[field] {
			seen[field] = true
			unique = append(unique, field)
		}
	}
	var safe bool
	err := tx.QueryRow(ctx, `SELECT count(*)=cardinality($3::text[]) AND COALESCE(bool_and(tn.nspname='pg_catalog' AND t.typname IN ('text','varchar','bpchar','name','uuid','int2','int4','int8','numeric','float4','float8','bool','date','timestamp','timestamptz') AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT')),false) FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace WHERE n.nspname=$1 AND c.relname=$2 AND a.attname=ANY($3::text[]) AND a.attnum>0 AND NOT a.attisdropped`, schema, relation, unique).Scan(&safe)
	if err != nil || !safe {
		return &AuthorizationError{Code: "application_rules_scalar_field_required", Cause: err}
	}
	return nil
}

func scopedRelation(ctx context.Context, tx pgx.Tx, schema, relation string, d authorization.Decision) (string, error) {
	columns := append([]string(nil), d.Fields...)
	if d.Scope.Column != "" {
		columns = append(columns, d.Scope.Column)
	}
	if err := validateScalarResource(ctx, tx, schema, relation, columns); err != nil {
		return "", err
	}
	quote := func(column string) string { return pgx.Identifier{column}.Sanitize() }
	field := "b." + quote(d.Scope.Column)
	predicate := "true"
	switch d.Scope.Kind {
	case "all":
	case "user":
		predicate = field + "::text = NULLIF(current_setting('iqkb.user_id',true),'')"
	case "email":
		predicate = "lower(btrim(" + field + "::text)) = NULLIF(current_setting('iqkb.email',true),'')"
	case "claim":
		predicate = field + "::text = NULLIF(current_setting('iqkb.claims',true)::jsonb ->> '" + d.Scope.Claim + "','')"
	case "membership":
		m := d.Scope.Membership
		if m == nil {
			return "", authorization.ErrDenied
		}
		fields := []string{m.UserColumn, m.GroupColumn}
		if m.ActiveColumn != "" {
			fields = append(fields, m.ActiveColumn)
		}
		if m.TenantColumn != "" {
			fields = append(fields, m.TenantColumn)
		}
		if err := validateScalarResource(ctx, tx, m.Schema, m.Relation, fields); err != nil {
			return "", err
		}
		if m.ActiveColumn != "" {
			var boolean bool
			err := tx.QueryRow(ctx, `SELECT a.atttypid='pg_catalog.bool'::regtype FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname=$1 AND c.relname=$2 AND a.attname=$3 AND NOT a.attisdropped`, m.Schema, m.Relation, m.ActiveColumn).Scan(&boolean)
			if err != nil || !boolean {
				return "", &AuthorizationError{Code: "membership_active_boolean_required", Cause: err}
			}
		}
		predicate = "EXISTS (SELECT 1 FROM " + pgx.Identifier{m.Schema, m.Relation}.Sanitize() + " m WHERE m." + quote(m.UserColumn) + "::text = NULLIF(current_setting('iqkb.user_id',true),'') AND m." + quote(m.GroupColumn) + "::text = " + field + "::text"
		if m.ActiveColumn != "" {
			predicate += " AND m." + quote(m.ActiveColumn) + "::text = 'true'"
		}
		if m.TenantColumn != "" {
			predicate += " AND m." + quote(m.TenantColumn) + "::text = NULLIF(current_setting('iqkb.tenant_id',true),'')"
		}
		predicate += ")"
	default:
		return "", authorization.ErrDenied
	}
	projection := []string{}
	for _, column := range d.Fields {
		projection = append(projection, "b."+quote(column))
	}
	return "(SELECT " + strings.Join(projection, ",") + " FROM " + pgx.Identifier{schema, relation}.Sanitize() + " b WHERE " + predicate + ") AS iqkb_scoped", nil
}

func (c *Connector) scopeProfileSQL(ctx context.Context, tx pgx.Tx, id ResolvedIdentity, p BusinessProfile, query string, parent bool) (string, error) {
	if !c.applicationRules() {
		_, err := c.authorizeResource(ctx, id, p.Schema, p.Relation, profileFields(p))
		return query, err
	}
	schema, relation, fields := p.Schema, p.Relation, profileFields(p)
	if parent {
		if p.Relationship == nil {
			return "", authorization.ErrDenied
		}
		r := p.Relationship
		schema, relation = r.ParentSchema, r.ParentRelation
		fields = append([]string{r.ParentKeyColumn, r.ParentLabelColumn}, r.ParentSearchColumns...)
	}
	d, err := c.authorizeResource(ctx, id, schema, relation, fields)
	if err != nil {
		return "", err
	}
	source, err := scopedRelation(ctx, tx, schema, relation, d)
	if err != nil {
		return "", err
	}
	needle := "FROM " + pgx.Identifier{schema, relation}.Sanitize() + " "
	if !strings.Contains(query, needle) {
		return "", errors.New("unsupported compiled profile")
	}
	return strings.ReplaceAll(query, needle, "FROM "+source+" "), nil
}

func (c *Connector) profileSchema(ctx context.Context, tx pgx.Tx, id ResolvedIdentity, p BusinessProfile) (string, error) {
	if c.applicationRules() {
		q, err := CompileBusinessProfile(p)
		if err != nil {
			return "", err
		}
		if _, err = c.scopeProfileSQL(ctx, tx, id, p, q, false); err != nil {
			return "", err
		}
		if p.Relationship != nil {
			q, err = CompileRelatedParentLookup(p)
			if err != nil {
				return "", err
			}
			if _, err = c.scopeProfileSQL(ctx, tx, id, p, q, true); err != nil {
				return "", err
			}
		}
	}
	return validateProfileSchemaMode(ctx, tx, p, c.applicationRules())
}

func (c *Connector) discoverApplicationResources(ctx context.Context, login, password, schemaAfter, nameAfter string) (DiscoveryPage, error) {
	page := DiscoveryPage{Relations: []DiscoveredRelation{}, Columns: []DiscoveredColumn{}, Keys: []DiscoveredKey{}, Relationships: []DiscoveredRelationship{}}
	conn, tx, id, err := c.beginAuthorized(ctx, login, password)
	if err != nil {
		return page, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	rules := append([]authorization.Rule(nil), c.adapter.Rules...)
	if id.AutomaticPermissions {
		rules = append([]authorization.Rule(nil), id.Rules...)
	}
	sort.Slice(rules, func(i, j int) bool {
		if rules[i].Schema != rules[j].Schema {
			return rules[i].Schema < rules[j].Schema
		}
		return rules[i].Relation < rules[j].Relation
	})
	allowed := map[string]map[string]bool{}
	for _, rule := range rules {
		if rule.Label == id.ApplicationRole && rule.Reviewed {
			fields := map[string]bool{}
			for _, field := range rule.Fields {
				fields[field] = true
			}
			allowed[rule.Schema+"\x00"+rule.Relation] = fields
		}
	}
	for _, r := range rules {
		if r.Label != id.ApplicationRole || !r.Reviewed {
			continue
		}
		if r.Schema < schemaAfter || r.Schema == schemaAfter && r.Relation <= nameAfter {
			continue
		}
		if len(page.Relations) == 25 {
			page.NextSchema, page.NextName = nextRelationCursor(page.Relations)
			break
		}
		d, err := c.authorizeResource(ctx, id, r.Schema, r.Relation, nil)
		if err != nil {
			continue
		}
		if _, err = scopedRelation(ctx, tx, r.Schema, r.Relation, d); err != nil {
			return page, err
		}
		page.Relations = append(page.Relations, DiscoveredRelation{Schema: r.Schema, Name: r.Relation, Kind: "BASE TABLE", Supported: true, Reason: "Reviewed application permissions; row restrictions apply before retrieval."})
		columns, err := tx.Query(ctx, `SELECT column_name,data_type,is_nullable FROM information_schema.columns WHERE table_schema=$1 AND table_name=$2 AND column_name=ANY($3::text[]) ORDER BY ordinal_position`, r.Schema, r.Relation, r.Fields)
		if err != nil {
			return page, err
		}
		for columns.Next() {
			col := DiscoveredColumn{Schema: r.Schema, Relation: r.Relation}
			var nullable string
			if err = columns.Scan(&col.Name, &col.DataType, &nullable); err != nil {
				columns.Close()
				return page, err
			}
			col.Nullable = nullable == "YES"
			page.Columns = append(page.Columns, col)
		}
		err = columns.Err()
		columns.Close()
		if err != nil {
			return page, err
		}
		keys, err := tx.Query(ctx, `SELECT con.contype::text,array_agg(a.attname ORDER BY k.ordinality) FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN unnest(con.conkey) WITH ORDINALITY k(attnum,ordinality) ON true JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum WHERE n.nspname=$1 AND c.relname=$2 AND con.contype IN ('p','u') GROUP BY con.oid,con.contype ORDER BY con.oid LIMIT $3`, r.Schema, r.Relation, maxDiscoveryKeys+1)
		if err != nil {
			return page, err
		}
		for keys.Next() {
			key := DiscoveredKey{Schema: r.Schema, Relation: r.Relation, Kind: "unique"}
			var kind string
			if err = keys.Scan(&kind, &key.Columns); err != nil {
				keys.Close()
				return page, err
			}
			if kind == "p" {
				key.Kind = "primary"
			}
			if containsFields(allowed[r.Schema+"\x00"+r.Relation], key.Columns) {
				page.Keys = append(page.Keys, key)
			}
			if len(page.Keys) > maxDiscoveryKeys {
				keys.Close()
				return DiscoveryPage{}, errors.New("application key metadata exceeds page limit")
			}
		}
		err = keys.Err()
		keys.Close()
		if err != nil {
			return page, err
		}
		links, err := tx.Query(ctx, `SELECT con.conname,array_agg(sa.attname ORDER BY sk.ordinality),tn.nspname,dst.relname,array_agg(da.attname ORDER BY sk.ordinality) FROM pg_constraint con JOIN pg_class src ON src.oid=con.conrelid JOIN pg_namespace sn ON sn.oid=src.relnamespace JOIN pg_class dst ON dst.oid=con.confrelid JOIN pg_namespace tn ON tn.oid=dst.relnamespace JOIN unnest(con.conkey) WITH ORDINALITY sk(attnum,ordinality) ON true JOIN unnest(con.confkey) WITH ORDINALITY tk(attnum,ordinality) ON tk.ordinality=sk.ordinality JOIN pg_attribute sa ON sa.attrelid=src.oid AND sa.attnum=sk.attnum JOIN pg_attribute da ON da.attrelid=dst.oid AND da.attnum=tk.attnum WHERE sn.nspname=$1 AND src.relname=$2 AND con.contype='f' AND con.convalidated GROUP BY con.oid,con.conname,tn.nspname,dst.relname ORDER BY con.oid LIMIT $3`, r.Schema, r.Relation, maxDiscoveryForeignKeys+1)
		if err != nil {
			return page, err
		}
		for links.Next() {
			link := DiscoveredRelationship{SourceSchema: r.Schema, SourceRelation: r.Relation}
			if err = links.Scan(&link.Name, &link.SourceColumns, &link.TargetSchema, &link.TargetRelation, &link.TargetColumns); err != nil {
				links.Close()
				return page, err
			}
			if containsFields(allowed[r.Schema+"\x00"+r.Relation], link.SourceColumns) && containsFields(allowed[link.TargetSchema+"\x00"+link.TargetRelation], link.TargetColumns) {
				page.Relationships = append(page.Relationships, link)
			}
			if len(page.Relationships) > maxDiscoveryForeignKeys {
				links.Close()
				return DiscoveryPage{}, errors.New("application relationship metadata exceeds page limit")
			}
		}
		err = links.Err()
		links.Close()
		if err != nil {
			return page, err
		}
	}
	sort.Slice(page.Relations, func(i, j int) bool {
		return page.Relations[i].Schema+"."+page.Relations[i].Name < page.Relations[j].Schema+"."+page.Relations[j].Name
	})
	encoded, _ := json.Marshal(page)
	if len(page.Columns) > maxDiscoveryColumns || len(encoded) > maxDiscoveryBytes {
		return DiscoveryPage{}, errors.New("application metadata exceeds page limit")
	}
	return page, nil
}

func containsFields(allowed map[string]bool, fields []string) bool {
	for _, field := range fields {
		if !allowed[field] {
			return false
		}
	}
	return len(fields) > 0
}
