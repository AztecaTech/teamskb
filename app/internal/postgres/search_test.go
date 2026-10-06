package postgres

import (
	"encoding/json"
	"strings"
	"testing"
)

func validTool() QueryTool {
	return QueryTool{
		ID:             "policy_search",
		Version:        1,
		Description:    "Search the approved policy view.",
		SQL:            "SELECT id::text AS id, title::text AS title, content::text AS content, source_url::text AS source_url FROM organization.policy_view WHERE search_text @@ plainto_tsquery('simple', $1) ORDER BY id LIMIT $2",
		Parameters:     []QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}},
		OutputColumns:  []string{"id:text", "title:text", "content:text", "source_url:text"},
		ApprovalRecord: "change-123 reviewed by DBA",
	}
}

func TestOpenRequiresVerifiedTLSAndDoesNotPingDatabase(t *testing.T) {
	for _, dsn := range []string{"", "postgres://localhost/db?sslmode=disable", "postgres://localhost/db?sslmode=prefer"} {
		if connector, err := Open(t.Context(), dsn); err == nil {
			connector.Close()
			t.Errorf("unverified DSN %q was accepted", dsn)
		}
	}
	connector, err := Open(t.Context(), "postgres://localhost:1/db?sslmode=verify-full")
	if err != nil {
		t.Fatalf("connection template parsing attempted or failed a live connection: %v", err)
	}
	connector.Close()
}

func TestDatabaseIdentityValidation(t *testing.T) {
	for _, identity := range []string{"reader_one", "Finance2", "a"} {
		if !ValidDatabaseIdentity(identity) {
			t.Errorf("valid identity %q rejected", identity)
		}
	}
	for _, identity := range []string{"", "has space", `x"; SET ROLE admin`, strings.Repeat("a", 64), "équipe"} {
		if ValidDatabaseIdentity(identity) {
			t.Errorf("invalid identity %q accepted", identity)
		}
	}
}

func TestApprovedCatalogRequiresSingleParameterizedSelectAndExactContract(t *testing.T) {
	tool := validTool()
	if err := ValidateQueryTool(tool); err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{
		"DELETE FROM organization.policy_view WHERE id=$1",
		"SELECT id, title, content, source_url FROM organization.policy_view WHERE x=$1; SELECT 1",
		"SELECT * INTO copy_of_data FROM organization.policy_view WHERE x=$1",
		"SELECT pg_read_file('/etc/passwd') AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2",
		`SELECT "pg_read_file"('/etc/passwd') AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2`,
		`SELECT "pg_catalog"."pg_notify"('channel','payload') AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2`,
		`SELECT "pg_catalog"."pg_advisory_lock"(1) AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2`,
		`SELECT "pg_catalog"."nextval"('organization.seq') AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2`,
		`SELECT "pg_catalog"."set_config"('row_security','off',true) AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2`,
		`SELECT U&"pg_read\005ffile"('/etc/passwd') AS id, title, content, source_url FROM organization.policy_view WHERE x=$1 AND y=$2`,
		"SELECT id,title,content,source_url FROM organization.policy_view WHERE x=$2 AND y=$1",
		"SELECT id,title,content,source_url FROM organization.policy_view WHERE x=$1 -- ignored\n AND y=$2",
	} {
		bad := tool
		bad.SQL = query
		if err := ValidateQueryTool(bad); err == nil {
			t.Errorf("unsafe query accepted: %s", query)
		}
	}
	bad := tool
	bad.Parameters = []QueryParameter{{Name: "sql", Type: "text"}}
	if err := ValidateQueryTool(bad); err == nil {
		t.Fatal("model-controlled SQL parameter accepted")
	}
	bad = tool
	bad.OutputColumns = []string{"id:text", "secret:text"}
	if err := ValidateQueryTool(bad); err == nil {
		t.Fatal("unapproved result schema accepted")
	}
}

func TestQueryParametersAreFixedAndOutputSchemaIsBound(t *testing.T) {
	tool := validTool()
	if strings.Contains(strings.ToUpper(tool.SQL), "SET ROLE") || strings.Contains(strings.ToUpper(tool.SQL), "SESSION AUTHORIZATION") {
		t.Fatal("query catalog changes the authenticated database identity")
	}
	if !isApprovedSelect(tool.SQL) {
		t.Fatal("valid fixed SELECT rejected")
	}
}

func TestToolSelectionAllowsOnlyExactApprovedIDAndTypedLimit(t *testing.T) {
	tool := validTool()
	for _, raw := range []string{
		`{"tool":"policy_search","limit":2}`,
		`{"tool":null,"limit":0}`,
	} {
		if _, err := ParseToolSelection(raw, []QueryTool{tool}); err != nil {
			t.Errorf("valid selection %s rejected: %v", raw, err)
		}
	}
	for _, raw := range []string{
		`{"tool":"policy_search"}`,
		`{"tool":"policy_search","limit":2,"sql":"DELETE FROM x"}`,
		`{"tool":"unapproved","limit":1}`,
		`{"tool":"policy_search","limit":6}`,
		`{"tool":null,"limit":1}`,
		`{"tool":"policy_search","limit":"2"}`,
		`{"tool":"policy_search","limit":1} {"tool":"policy_search","limit":1}`,
		`{"tool":"policy_search","tool":"unapproved","limit":1}`,
	} {
		if _, err := ParseToolSelection(raw, []QueryTool{tool}); err == nil {
			t.Errorf("invalid selection %s accepted", raw)
		}
	}
}

func FuzzParseToolSelection(f *testing.F) {
	for _, raw := range []string{
		`{"tool":"policy_search","limit":2}`,
		`{"tool":null,"limit":0}`,
		`{"tool":"policy_search","limit":6}`,
		`{"tool":"policy_search","tool":"other","limit":1}`,
		`{"tool":"policy_search","limit":1} {"tool":"policy_search","limit":1}`,
		`{"tool":"policy_search","limit":1,"filters":{"state":"ready"}}`,
	} {
		f.Add(raw)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		selection, err := ParseToolSelection(raw, []QueryTool{validTool()})
		if err != nil || selection == nil {
			return
		}
		if selection.ToolID != "policy_search" || selection.Limit < 1 || selection.Limit > maxResults ||
			selection.Term != "" || len(selection.Filters) != 0 {
			t.Fatalf("parser accepted an invalid legacy selection: %#v", selection)
		}
	})
}

func TestProfileToolSelectionRequiresBoundTermAndRejectsSQLFields(t *testing.T) {
	p := BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: "public", Relation: "assets", KeyColumn: "asset_id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []ProfileColumn{{Name: "state", Type: "text"}}, Approval: "reviewed", SchemaFingerprint: strings.Repeat("a", 64)}
	query, err := CompileBusinessProfile(p)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(p)
	tool := QueryTool{ID: p.ID, Version: p.Version, Description: p.Label, SQL: query, Parameters: []QueryParameter{{Name: "term", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}}, OutputColumns: ProfileOutputColumns(p), ApprovalRecord: "reviewed", ProfileConfig: encoded}
	if err := ValidateQueryTool(tool); err != nil {
		t.Fatal(err)
	}
	selection, err := ParseToolSelection(`{"tool":"asset_lookup","term":"Laptop","limit":2}`, []QueryTool{tool})
	if err != nil || selection.Term != "Laptop" {
		t.Fatalf("profile selection=%#v err=%v", selection, err)
	}
	for _, raw := range []string{`{"tool":"asset_lookup","limit":2}`, `{"tool":"asset_lookup","term":"x","limit":1,"sql":"SELECT 1"}`, `{"tool":"asset_lookup","term":"   ","limit":1}`} {
		if _, err := ParseToolSelection(raw, []QueryTool{tool}); err == nil {
			t.Errorf("invalid selection accepted: %s", raw)
		}
	}
}

func TestValidSourceURLsRequireHttpsAndNoCredentials(t *testing.T) {
	for _, raw := range []string{"https://kb.example.com/policy/1", "https://tenant.sharepoint.com/sites/hr/policy"} {
		if !validSourceURL(raw) {
			t.Errorf("valid source URL %q rejected", raw)
		}
	}
	for _, raw := range []string{"http://kb.example.com/1", "https://user:pass@kb.example.com/1", "not a URL"} {
		if validSourceURL(raw) {
			t.Errorf("invalid source URL %q accepted", raw)
		}
	}
}
