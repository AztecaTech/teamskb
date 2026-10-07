package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"iq-kbteams/internal/graph"
)

const (
	maxResults       = 5
	maxQuestionRunes = 500
	maxResultBytes   = 1 << 20
	maxResultRows    = 500
	maxURLBytes      = 2048
)

type QueryParameter struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type QueryTool struct {
	ID             string           `json:"id"`
	Version        int              `json:"version"`
	Description    string           `json:"description"`
	SQL            string           `json:"sql"`
	Parameters     []QueryParameter `json:"parameters"`
	OutputColumns  []string         `json:"outputColumns"`
	ApprovalRecord string           `json:"approvalRecord"`
	ProfileConfig  json.RawMessage  `json:"profileConfig,omitempty"`
}

type Connector struct {
	template, service *pgx.ConnConfig
	adapter           *AdapterConfig
	subject           *Subject
	metadataOnly      bool
}

func Open(_ context.Context, connectionString string) (*Connector, error) {
	if strings.TrimSpace(connectionString) == "" || len(connectionString) > 4096 || strings.ContainsAny(connectionString, "\r\n\x00") {
		return nil, errors.New("invalid PostgreSQL connection template")
	}
	config, err := pgx.ParseConfig(connectionString)
	if err != nil {
		return nil, errors.New("invalid PostgreSQL connection template")
	}
	if config.TLSConfig == nil || config.TLSConfig.InsecureSkipVerify || config.TLSConfig.ServerName == "" {
		return nil, errors.New("PostgreSQL requires TLS with certificate and hostname verification (sslmode=verify-full)")
	}
	service := config.Copy()
	config.User, config.Password = "", ""
	return &Connector{template: config, service: service}, nil
}

func (c *Connector) Close() {}

func (c *Connector) CheckIdentity(ctx context.Context, databaseIdentity, password string) error {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" {
		return errors.New("PostgreSQL credentials are invalid")
	}
	_, err := c.ResolveIdentity(ctx, databaseIdentity, password)
	return err
}

func (c *Connector) Search(ctx context.Context, databaseIdentity, password, question string, limit int, tool QueryTool) ([]graph.Document, error) {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" || !validQuestion(question) || limit < 1 || limit > maxResults {
		return nil, errors.New("invalid PostgreSQL search request")
	}
	if err := ValidateQueryTool(tool); err != nil {
		return nil, errors.New("PostgreSQL query catalog entry is invalid")
	}
	conn, tx, _, err := c.beginAuthorized(ctx, databaseIdentity, password)
	if err != nil {
		return nil, errors.New("PostgreSQL search failed")
	}
	defer closeConnection(conn)
	defer func() { _ = tx.Rollback(context.Background()) }()
	if _, err := tx.Exec(ctx, `SET LOCAL DateStyle = 'ISO, YMD'`); err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	if _, err := tx.Exec(ctx, `SET LOCAL TIME ZONE 'UTC'`); err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	query := `SELECT left(iqkb_catalog.id,2049) AS id, left(iqkb_catalog.title,256) AS title, left(iqkb_catalog.content,1048577) AS content, left(iqkb_catalog.source_url,2049) AS source_url
FROM (` + tool.SQL + `) AS iqkb_catalog LIMIT 501`
	rows, err := tx.Query(ctx, query, question, limit)
	if err != nil {
		return nil, errors.New("PostgreSQL search failed")
	}
	defer rows.Close()
	if err := validateOutputSchema(rows.FieldDescriptions()); err != nil {
		return nil, err
	}
	documents := make([]graph.Document, 0, limit)
	resultBytes, rowCount := 0, 0
	for rows.Next() {
		rowCount++
		if rowCount > maxResultRows {
			return nil, errors.New("PostgreSQL result row limit exceeded")
		}
		var id, title, content, sourceURL string
		if err := rows.Scan(&id, &title, &content, &sourceURL); err != nil {
			return nil, errors.New("PostgreSQL search failed")
		}
		resultBytes += len(id) + len(title) + len(content) + len(sourceURL)
		if resultBytes > maxResultBytes {
			return nil, errors.New("PostgreSQL result size limit exceeded")
		}
		if len(id) == 0 || len(id) > 2048 || len(title) == 0 || len(title) > 255 || len(content) == 0 || len(content) > maxResultBytes || len(sourceURL) > maxURLBytes || !validSourceURL(sourceURL) {
			continue
		}
		documents = append(documents, graph.Document{ID: id, Name: title, WebURL: sourceURL, Content: []byte(content), PlainText: true})
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("PostgreSQL search failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("PostgreSQL search failed")
	}
	return documents, nil
}

// SearchProfile runs only SQL produced by CompileBusinessProfile and returns a
// typed business record shape instead of converting profile rows to documents.
func (c *Connector) SearchProfile(ctx context.Context, databaseIdentity, password, term string, limit int, profile BusinessProfile) ([]BusinessRecord, error) {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" || !validQuestion(term) || limit < 1 || limit > maxResults || profile.Capability == "related_list" {
		return nil, errors.New("invalid PostgreSQL profile search request")
	}
	query, err := CompileBusinessProfile(profile)
	if err != nil {
		return nil, errors.New("PostgreSQL profile is invalid")
	}
	conn, tx, _, err := c.beginAuthorized(ctx, databaseIdentity, password)
	if err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	defer closeConnection(conn)
	defer func() { _ = tx.Rollback(context.Background()) }()
	actualFingerprint, err := validateProfileSchema(ctx, tx, profile)
	if err != nil || profile.SchemaFingerprint == "" || actualFingerprint != profile.SchemaFingerprint {
		return nil, errors.New("PostgreSQL profile is stale, unsupported, or not readable by this login")
	}
	queryLimit := profileCandidateLimit(profile.Capability, limit)
	rows, err := tx.Query(ctx, query, term, queryLimit)
	if err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	if len(fields) != 3+len(profile.ReturnColumns) {
		return nil, errors.New("PostgreSQL profile returned an unapproved schema")
	}
	for _, f := range fields {
		if f.DataTypeOID != pgtype.TextOID && f.DataTypeOID != pgtype.VarcharOID && f.DataTypeOID != pgtype.NameOID {
			return nil, errors.New("PostgreSQL profile returned an unapproved schema")
		}
	}
	records := make([]BusinessRecord, 0, queryLimit)
	bytesRead := 0
	for rows.Next() {
		values := make([]any, len(fields))
		scan := make([]any, len(fields))
		for i := range values {
			scan[i] = &values[i]
		}
		if err := rows.Scan(scan...); err != nil {
			return nil, errors.New("PostgreSQL profile search failed")
		}
		parts := make([]string, len(values))
		nulls := make([]bool, len(values))
		for i, v := range values {
			switch x := v.(type) {
			case string:
				parts[i] = x
			case []byte:
				parts[i] = string(x)
			case nil:
				nulls[i] = true
				parts[i] = ""
			default:
				return nil, errors.New("PostgreSQL profile returned an unapproved value type")
			}
			bytesRead += len(parts[i])
		}
		if bytesRead > maxResultBytes {
			return nil, errors.New("PostgreSQL result size limit exceeded")
		}
		relevance, err := strconv.ParseFloat(parts[2], 64)
		if err != nil || math.IsNaN(relevance) || math.IsInf(relevance, 0) || relevance < 0 || relevance > 1 {
			return nil, errors.New("PostgreSQL profile returned invalid relevance")
		}
		record := BusinessRecord{ID: parts[0], Type: profile.Label, DisplayName: parts[1], Relevance: relevance, Attributes: map[string]any{}}
		if len(record.ID) == 0 || len(record.ID) > 2048 || len(record.DisplayName) == 0 || len(record.DisplayName) > 255 {
			return nil, errors.New("PostgreSQL profile returned an invalid identifier or display name")
		}
		for i, col := range profile.ReturnColumns {
			if nulls[i+3] {
				if col.Name == profile.SourceURLColumn {
					record.SourceURL = ""
					continue
				}
				record.Attributes[col.Name] = nil
				continue
			}
			if col.Name == profile.SourceURLColumn {
				if validSourceURL(parts[i+3]) {
					record.SourceURL = parts[i+3]
				}
				continue
			}
			value, parseErr := parseProfileAttribute(parts[i+3], col.Type)
			if parseErr != nil {
				return nil, errors.New("PostgreSQL profile returned an invalid typed value")
			}
			record.Attributes[col.Name] = value
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	return records, nil
}

// SearchRelatedProfile resolves one parent entity before querying its children.
// Multiple matching parents are returned as candidates and never broaden the child query.
func (c *Connector) SearchRelatedProfile(ctx context.Context, databaseIdentity, password, term string, limit int, filters map[string]string, profile BusinessProfile) ([]BusinessRecord, []ProfileCandidate, error) {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" || !validQuestion(term) || limit < 1 || limit > maxResults || profile.Capability != "related_list" || profile.Relationship == nil || len(filters) > len(profile.Relationship.Filters) {
		return nil, nil, errors.New("invalid PostgreSQL related-list request")
	}
	query, err := CompileBusinessProfile(profile)
	if err != nil {
		return nil, nil, errors.New("PostgreSQL profile is invalid")
	}
	conn, tx, _, err := c.beginAuthorized(ctx, databaseIdentity, password)
	if err != nil {
		return nil, nil, errors.New("PostgreSQL profile search failed")
	}
	defer closeConnection(conn)
	defer func() { _ = tx.Rollback(context.Background()) }()
	fingerprint, err := validateProfileSchema(ctx, tx, profile)
	if err != nil || profile.SchemaFingerprint == "" || fingerprint != profile.SchemaFingerprint {
		return nil, nil, errors.New("PostgreSQL profile is stale, unsupported, or not readable by this login")
	}
	r := profile.Relationship
	resolveSQL, err := CompileRelatedParentLookup(profile)
	if err != nil {
		return nil, nil, errors.New("PostgreSQL profile is invalid")
	}
	rows, err := tx.Query(ctx, resolveSQL, term)
	if err != nil {
		return nil, nil, errors.New("PostgreSQL parent lookup failed")
	}
	candidates := make([]ProfileCandidate, 0, 2)
	for rows.Next() {
		var c ProfileCandidate
		if err := rows.Scan(&c.ID, &c.DisplayName); err != nil {
			rows.Close()
			return nil, nil, errors.New("PostgreSQL parent lookup failed")
		}
		candidates = append(candidates, c)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, nil, errors.New("PostgreSQL parent lookup failed")
	}
	rows.Close()
	if len(candidates) > 1 {
		return nil, candidates, nil
	}
	if len(candidates) == 0 {
		if err := tx.Commit(ctx); err != nil {
			return nil, nil, errors.New("PostgreSQL profile search failed")
		}
		return []BusinessRecord{}, nil, nil
	}
	args := []any{candidates[0].ID}
	for _, filter := range r.Filters {
		raw, ok := filters[filter.Name]
		if !ok && filter.Required {
			return nil, nil, errors.New("required related-list filter is missing")
		}
		if !ok {
			args = append(args, nil)
			continue
		}
		if !filter.Required {
			args = append(args, raw)
			continue
		}
		value, err := parseProfileAttribute(raw, filter.Type)
		if err != nil {
			return nil, nil, errors.New("related-list filter value is invalid")
		}
		args = append(args, value)
	}
	for name := range filters {
		found := false
		for _, filter := range r.Filters {
			if filter.Name == name {
				found = true
				break
			}
		}
		if !found {
			return nil, nil, errors.New("related-list filter is not approved")
		}
	}
	args = append(args, limit)
	result, err := tx.Query(ctx, query, args...)
	if err != nil {
		return nil, nil, errors.New("PostgreSQL profile search failed")
	}
	records, err := readBusinessRecords(result, profile, limit)
	if err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, errors.New("PostgreSQL profile search failed")
	}
	return records, nil, nil
}

// ValidateRelatedProfile executes the child query with a NULL parent key so
// profile tests can verify SQL privileges and output shape without reading rows.
func (c *Connector) ValidateRelatedProfile(ctx context.Context, databaseIdentity, password string, profile BusinessProfile) error {
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" || profile.Capability != "related_list" || profile.Relationship == nil {
		return errors.New("invalid PostgreSQL related-list test")
	}
	query, err := CompileBusinessProfile(profile)
	if err != nil {
		return errors.New("PostgreSQL profile is invalid")
	}
	conn, tx, _, err := c.beginAuthorized(ctx, databaseIdentity, password)
	if err != nil {
		return errors.New("PostgreSQL profile test failed")
	}
	defer closeConnection(conn)
	defer func() { _ = tx.Rollback(context.Background()) }()
	fingerprint, err := validateProfileSchema(ctx, tx, profile)
	if err != nil || fingerprint != profile.SchemaFingerprint {
		return errors.New("PostgreSQL profile is stale or inaccessible")
	}
	args := []any{nil}
	for _, filter := range profile.Relationship.Filters {
		if len(filter.Values) == 0 {
			return errors.New("related-list filter has no approved values")
		}
		value, err := parseProfileAttribute(filter.Values[0].Value, filter.Type)
		if err != nil {
			return errors.New("related-list filter value is invalid")
		}
		args = append(args, value)
	}
	args = append(args, 1)
	rows, err := tx.Query(ctx, query, args...)
	if err != nil {
		return errors.New("PostgreSQL profile test failed")
	}
	if _, err := readBusinessRecords(rows, profile, 1); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("PostgreSQL profile test failed")
	}
	return nil
}

func readBusinessRecords(rows pgx.Rows, profile BusinessProfile, limit int) ([]BusinessRecord, error) {
	defer rows.Close()
	fields := rows.FieldDescriptions()
	if len(fields) != 3+len(profile.ReturnColumns) {
		return nil, errors.New("PostgreSQL profile returned an unapproved schema")
	}
	for _, f := range fields {
		if f.DataTypeOID != pgtype.TextOID && f.DataTypeOID != pgtype.VarcharOID && f.DataTypeOID != pgtype.NameOID {
			return nil, errors.New("PostgreSQL profile returned an unapproved schema")
		}
	}
	records := make([]BusinessRecord, 0, limit)
	bytesRead := 0
	for rows.Next() {
		values := make([]any, len(fields))
		scan := make([]any, len(fields))
		for i := range values {
			scan[i] = &values[i]
		}
		if err := rows.Scan(scan...); err != nil {
			return nil, errors.New("PostgreSQL profile search failed")
		}
		parts := make([]string, len(values))
		nulls := make([]bool, len(values))
		for i, v := range values {
			switch x := v.(type) {
			case string:
				parts[i] = x
			case []byte:
				parts[i] = string(x)
			case nil:
				nulls[i] = true
			default:
				return nil, errors.New("PostgreSQL profile returned an unapproved value type")
			}
			bytesRead += len(parts[i])
		}
		if bytesRead > maxResultBytes {
			return nil, errors.New("PostgreSQL result size limit exceeded")
		}
		relevance, err := strconv.ParseFloat(parts[2], 64)
		if err != nil || math.IsNaN(relevance) || math.IsInf(relevance, 0) || relevance < 0 || relevance > 1 {
			return nil, errors.New("PostgreSQL profile returned invalid relevance")
		}
		record := BusinessRecord{ID: parts[0], Type: profile.Label, DisplayName: parts[1], Relevance: relevance, Attributes: map[string]any{}}
		if len(record.ID) == 0 || len(record.ID) > 2048 || len(record.DisplayName) == 0 || len(record.DisplayName) > 255 {
			return nil, errors.New("PostgreSQL profile returned an invalid identifier or display name")
		}
		for i, col := range profile.ReturnColumns {
			if nulls[i+3] {
				if col.Name == profile.SourceURLColumn {
					record.SourceURL = ""
					continue
				}
				record.Attributes[col.Name] = nil
				continue
			}
			if col.Name == profile.SourceURLColumn {
				if validSourceURL(parts[i+3]) {
					record.SourceURL = parts[i+3]
				}
				continue
			}
			value, err := parseProfileAttribute(parts[i+3], col.Type)
			if err != nil {
				return nil, errors.New("PostgreSQL profile returned an invalid typed value")
			}
			record.Attributes[col.Name] = value
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("PostgreSQL profile search failed")
	}
	return records, nil
}

type identityQuerier interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}

var ErrUnsafeDatabaseRole = errors.New("database login is a superuser or bypasses row security")

func checkExecutionIdentity(ctx context.Context, query identityQuerier, expected string) error {
	var sessionUser, currentUser string
	var canLogin, superuser, bypassRLS bool
	err := query.QueryRow(ctx, `SELECT session_user::text, current_user::text, r.rolcanlogin, r.rolsuper, r.rolbypassrls
FROM pg_roles r WHERE r.rolname = session_user AND r.rolname = current_user`).
		Scan(&sessionUser, &currentUser, &canLogin, &superuser, &bypassRLS)
	if err != nil || !strings.EqualFold(sessionUser, expected) || !strings.EqualFold(currentUser, expected) || !canLogin {
		return errors.New("PostgreSQL authenticated identity does not match the reviewed identity")
	}
	if superuser || bypassRLS {
		return ErrUnsafeDatabaseRole
	}
	return nil
}

func (c *Connector) connect(ctx context.Context, databaseIdentity, password string) (*pgx.Conn, error) {
	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	config := c.template.Copy()
	config.User, config.Password = databaseIdentity, password
	if c.adapter != nil {
		config = c.service.Copy()
	}
	return pgx.ConnectConfig(connectCtx, config)
}

func closeConnection(conn *pgx.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = conn.Close(ctx)
}

func setLimits(ctx context.Context, tx pgx.Tx) error {
	if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '5s'`); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '1s'`)
	return err
}

func ValidDatabaseIdentity(identity string) bool {
	if len(identity) == 0 || len(identity) > 63 || !(identity[0] == '_' || identity[0] >= 'A' && identity[0] <= 'Z' || identity[0] >= 'a' && identity[0] <= 'z') {
		return false
	}
	for _, r := range identity[1:] {
		if !(r == '_' || r == '$' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func validQuestion(question string) bool {
	question = strings.TrimSpace(question)
	return question != "" && len([]rune(question)) <= maxQuestionRunes && strings.IndexFunc(question, unicode.IsControl) < 0
}

func validSourceURL(raw string) bool {
	u, err := url.ParseRequestURI(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Fragment == "" && len(raw) <= maxURLBytes
}

func validateOutputSchema(fields []pgconn.FieldDescription) error {
	want := []string{"id", "title", "content", "source_url"}
	if len(fields) != len(want) {
		return errors.New("PostgreSQL query returned an unapproved output schema")
	}
	for i, field := range fields {
		if !strings.EqualFold(string(field.Name), want[i]) || (field.DataTypeOID != pgtype.TextOID && field.DataTypeOID != pgtype.VarcharOID && field.DataTypeOID != pgtype.NameOID) {
			return errors.New("PostgreSQL query returned an unapproved output schema")
		}
	}
	return nil
}
