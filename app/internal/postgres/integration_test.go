package postgres

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

func TestPostgresPerUserLoginAndRLSIntegration(t *testing.T) {
	baseDSN := integrationValue(t, "IQKB_PG_INTEGRATION_DSN_FILE", "")
	alexPassword := integrationValue(t, "IQKB_PG_ALEX_PASSWORD_FILE", "")
	blairPassword := integrationValue(t, "IQKB_PG_BLAIR_PASSWORD_FILE", "")
	if baseDSN == "" || alexPassword == "" || blairPassword == "" {
		t.Skip("set a disposable PostgreSQL connection template and two LOGIN-user password files")
	}
	connector, err := Open(t.Context(), baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	tool := QueryTool{
		ID:             "test_policy_search",
		Version:        1,
		Description:    "Search disposable test fixture data.",
		SQL:            `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_fixture.documents WHERE content ILIKE '%' || $1 || '%' ORDER BY id LIMIT $2`,
		Parameters:     []QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}},
		OutputColumns:  []string{"id:text", "title:text", "content:text", "source_url:text"},
		ApprovalRecord: "test-only DBA fixture",
	}
	alexPassword = strings.TrimSpace(alexPassword)
	blairPassword = strings.TrimSpace(blairPassword)
	for _, test := range []struct {
		identity string
		password string
		want     string
	}{
		{integrationValue(t, "IQKB_PG_ALEX_ID", "iqkb_alex_login"), alexPassword, "iqkb_alex_login policy"},
		{integrationValue(t, "IQKB_PG_BLAIR_ID", "iqkb_blair_login"), blairPassword, "iqkb_blair_login policy"},
	} {
		if err := connector.CheckIdentity(t.Context(), test.identity, test.password); err != nil {
			t.Fatalf("identity %s: %v", test.identity, err)
		}
		rows, err := connector.Search(t.Context(), test.identity, test.password, "retention policy", 5, tool)
		if err != nil {
			t.Fatalf("search as %s: %v", test.identity, err)
		}
		if len(rows) != 1 || rows[0].Name != test.want || !rows[0].PlainText {
			t.Fatalf("identity %s saw unexpected rows: %#v", test.identity, rows)
		}
	}
	if err := connector.CheckIdentity(t.Context(), integrationValue(t, "IQKB_PG_ALEX_ID", "iqkb_alex_login"), blairPassword); err == nil {
		t.Fatal("credentials for a different mapped identity were accepted")
	}
	alexID := integrationValue(t, "IQKB_PG_ALEX_ID", "iqkb_alex_login")
	if err := connector.CheckIdentity(t.Context(), integrationValue(t, "IQKB_PG_BLAIR_ID", "iqkb_blair_login"), alexPassword); err == nil {
		t.Fatal("identity mismatch was accepted")
	}
	assertLoginPermissions(t, baseDSN, alexID, alexPassword, true)
	assertLoginPermissions(t, baseDSN, integrationValue(t, "IQKB_PG_BLAIR_ID", "iqkb_blair_login"), blairPassword, false)
}

func TestPostgresBusinessProfileAndDiscoveryIntegration(t *testing.T) {
	baseDSN := integrationValue(t, "IQKB_PG_INTEGRATION_DSN_FILE", "")
	alexPassword := integrationValue(t, "IQKB_PG_ALEX_PASSWORD_FILE", "")
	blairPassword := integrationValue(t, "IQKB_PG_BLAIR_PASSWORD_FILE", "")
	adminPassword := integrationValue(t, "IQKB_PG_ADMIN_PASSWORD_FILE", "")
	if baseDSN == "" || alexPassword == "" || blairPassword == "" || adminPassword == "" {
		t.Skip("set a disposable PostgreSQL template and admin/LOGIN credentials")
	}
	connector, err := Open(t.Context(), baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	profile := BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: "iqkb_fixture", Relation: "ops_assets", KeyColumn: "asset_key", LabelColumn: "display_name", SearchColumns: []string{"display_name"}, ReturnColumns: []ProfileColumn{{Name: "lifecycle_state", Type: "text"}, {Name: "last_seen", Type: "timestamp"}, {Name: "due_date", Type: "date"}}, Approval: "test-only DBA fixture"}
	var alexProfile BusinessProfile
	for _, tc := range []struct {
		login, password, want string
		restricted            bool
	}{{"iqkb_alex_login", alexPassword, "Field Laptop", true}, {"iqkb_blair_login", blairPassword, "Warehouse Scanner", false}} {
		page, err := connector.Discover(t.Context(), tc.login, tc.password, "", "")
		if err != nil {
			t.Fatalf("discover as %s: %v", tc.login, err)
		}
		var found bool
		var restrictedFound bool
		var unsafeViewFound bool
		var invokerViewFound bool
		var unsafeFunctionViewFound bool
		var nestedDefinerViewFound bool
		var ownerRLSViewFound bool
		var writeOnlyFound bool
		for _, relation := range page.Relations {
			if relation.Schema != "iqkb_fixture" {
				continue
			}
			if relation.Name == "ops_assets_owner_view" {
				unsafeViewFound = true
				if relation.Supported || relation.Reason == "" {
					t.Fatalf("owner-executed view was offered as supported: %#v", relation)
				}
			}
			if relation.Name == "ops_assets_materialized_view" {
				if relation.Supported {
					t.Fatalf("materialized view was offered as a base table: %#v", relation)
				}
			}
			if relation.Name == "ops_assets_invoker_view" {
				invokerViewFound = true
				if !relation.Supported || !strings.Contains(relation.Reason, "duplicates") {
					t.Fatalf("safe invoker view was not available for a DBA-reviewed profile: %#v", relation)
				}
			}
			if relation.Name == "ops_assets_unsafe_function_view" {
				unsafeFunctionViewFound = true
				if relation.Supported || relation.Reason == "" {
					t.Fatalf("view with a volatile user function was offered as supported: %#v", relation)
				}
			}
			if relation.Name == "ops_assets_nested_definer_view" {
				nestedDefinerViewFound = true
				if relation.Supported || relation.Reason == "" {
					t.Fatalf("invoker view with a nested owner-rights view was offered as supported: %#v", relation)
				}
			}
			if relation.Name == "ops_assets_owner_rls_view" {
				ownerRLSViewFound = true
				if relation.Supported || relation.Reason == "" {
					t.Fatalf("invoker view over an owner-controlled unforced-RLS table was offered as supported: %#v", relation)
				}
			}
			if relation.Name == "write_only_records" {
				writeOnlyFound = true
			}
		}
		for _, col := range page.Columns {
			if col.Schema == "iqkb_fixture" && col.Relation == "ops_assets" {
				if col.Name == "display_name" {
					found = true
				}
				if col.Name == "restricted_note" {
					restrictedFound = true
				}
			}
		}
		if !found || restrictedFound != tc.restricted {
			t.Fatalf("login %s discovery visibility: relation found=%v restricted=%v", tc.login, found, restrictedFound)
		}
		if tc.login == "iqkb_alex_login" && (!unsafeViewFound || !invokerViewFound || !unsafeFunctionViewFound || !nestedDefinerViewFound || !ownerRLSViewFound || writeOnlyFound) {
			t.Fatalf("view security or SELECT-denied relation discovery: owner-view=%v invoker-view=%v function-view=%v nested-view=%v owner-RLS-view=%v write-only=%v", unsafeViewFound, invokerViewFound, unsafeFunctionViewFound, nestedDefinerViewFound, ownerRLSViewFound, writeOnlyFound)
		}
		var foundForeignKey, foundPrimaryKey bool
		for _, relationship := range page.Relationships {
			if relationship.SourceRelation == "ops_asset_events" && relationship.SourceColumns[0] == "asset_key" && relationship.TargetRelation == "ops_assets" && relationship.TargetColumns[0] == "asset_key" {
				foundForeignKey = true
			}
		}
		for _, key := range page.Keys {
			if key.Relation == "ops_asset_events" && key.Kind == "primary" && len(key.Columns) == 1 && key.Columns[0] == "event_id" {
				foundPrimaryKey = true
			}
		}
		if !foundForeignKey || !foundPrimaryKey {
			t.Fatalf("login %s did not see accessible key/FK metadata: keys=%#v relationships=%#v", tc.login, page.Keys, page.Relationships)
		}
		profile.SchemaFingerprint, err = connector.ProfileSchemaFingerprint(t.Context(), tc.login, tc.password, profile)
		if err != nil {
			t.Fatalf("schema fingerprint as %s: %v", tc.login, err)
		}
		if tc.login == "iqkb_alex_login" {
			alexProfile = profile
			viewProfile := profile
			viewProfile.ID = "asset_lookup_view"
			viewProfile.Relation = "ops_assets_invoker_view"
			viewProfile.ReturnColumns = []ProfileColumn{{Name: "lifecycle_state", Type: "text"}}
			viewProfile.SchemaFingerprint, err = connector.ProfileSchemaFingerprint(t.Context(), tc.login, tc.password, viewProfile)
			if err != nil {
				t.Fatalf("invoker-view profile fingerprint: %v", err)
			}
			viewRecords, err := connector.SearchProfile(t.Context(), tc.login, tc.password, "Laptop", 5, viewProfile)
			if err != nil || len(viewRecords) != 2 {
				t.Fatalf("invoker-view search: records=%#v err=%v", viewRecords, err)
			}
			duplicateView := viewProfile
			duplicateView.Relation = "ops_assets_duplicate_key_view"
			if _, err := connector.ProfileSchemaFingerprint(t.Context(), tc.login, tc.password, duplicateView); err == nil {
				t.Fatal("view with duplicate keys passed profile validation")
			}
		}
		term := "Laptop"
		if tc.login == "iqkb_blair_login" {
			term = "Scanner"
		}
		records, err := connector.SearchProfile(t.Context(), tc.login, tc.password, term, 5, profile)
		if err != nil {
			t.Fatalf("profile query as %s: %v", tc.login, err)
		}
		if (tc.login == "iqkb_blair_login" && len(records) != 1 || tc.login == "iqkb_alex_login" && len(records) != 2) || records[0].DisplayName != tc.want || records[0].Type != "Asset" || records[0].Attributes["lifecycle_state"] == "" {
			t.Fatalf("unexpected typed business records for %s: %#v", tc.login, records)
		}
		if _, ok := records[0].Attributes["last_seen"].(time.Time); !ok {
			t.Fatalf("timestamp was not parsed natively: %#v", records[0].Attributes["last_seen"])
		}
		if _, ok := records[0].Attributes["due_date"].(time.Time); !ok {
			t.Fatalf("date was not parsed natively: %#v", records[0].Attributes["due_date"])
		}
		if tc.login == "iqkb_alex_login" {
			ambiguous, err := connector.SearchProfile(t.Context(), tc.login, tc.password, "Field Laptop", 1, profile)
			if err != nil || len(ambiguous) != 2 {
				t.Fatalf("limit-one entity lookup did not fetch ambiguity candidates: %#v err=%v", ambiguous, err)
			}
		}
	}
	unsafeTerm := `%' OR true --`
	records, err := connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, unsafeTerm, 5, profile)
	if err != nil || len(records) != 0 {
		t.Fatalf("profile search treated user text as SQL: records=%#v err=%v", records, err)
	}
	records, err = connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, "asset-alex", 5, profile)
	if err != nil || len(records) != 1 || records[0].ID != "asset-alex" {
		t.Fatalf("exact identifier lookup records=%#v err=%v", records, err)
	}
	records, err = connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, "Please find asset-alex and show its owner", 5, profile)
	if err != nil || len(records) != 0 {
		t.Fatalf("whole natural-language question acted as a broad search term: records=%#v err=%v", records, err)
	}
	fullText := profile
	fullText.ID, fullText.Label, fullText.Capability = "asset_text_search", "Asset text", "text_search"
	fullText.SearchStrategy, fullText.Language = "full_text", "english"
	fullText.SchemaFingerprint, err = connector.ProfileSchemaFingerprint(t.Context(), "iqkb_alex_login", alexPassword, fullText)
	if err != nil {
		t.Fatalf("full-text profile metadata validation failed: %v", err)
	}
	records, err = connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, "Field Laptop", 5, fullText)
	if err != nil || len(records) != 2 || records[0].Relevance <= 0 || records[1].Relevance <= 0 || records[0].Relevance < records[1].Relevance {
		t.Fatalf("PostgreSQL full-text lookup records=%#v err=%v", records, err)
	}
	spanish := fullText
	spanish.ID, spanish.Label, spanish.Language = "asset_text_search_es", "Asset text Spanish", "spanish"
	spanish.SchemaFingerprint, err = connector.ProfileSchemaFingerprint(t.Context(), "iqkb_alex_login", alexPassword, spanish)
	if err != nil {
		t.Fatalf("Spanish full-text profile metadata validation failed: %v", err)
	}
	records, err = connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, "documento confidencial", 5, spanish)
	if err != nil || len(records) != 1 || records[0].ID != "asset-spanish" {
		t.Fatalf("PostgreSQL Spanish full-text lookup records=%#v err=%v", records, err)
	}
	related := BusinessProfile{ID: "asset_event_list", Version: 1, Label: "Asset event", Capability: "related_list", Schema: "iqkb_fixture", Relation: "ops_asset_events", KeyColumn: "event_id", LabelColumn: "event_name", ReturnColumns: []ProfileColumn{{Name: "event_name", Type: "text"}, {Name: "priority", Type: "integer"}}, Approval: "test-only DBA relationship review", Relationship: &RelatedRelationship{ParentProfileID: "asset_lookup", ParentSchema: "iqkb_fixture", ParentRelation: "ops_assets", ParentKeyColumn: "asset_key", ParentLabelColumn: "display_name", ParentSearchColumns: []string{"display_name"}, ChildForeignKey: "asset_key", Filters: []ProfileFilter{{Name: "event_kind", Column: "event_name", Type: "text", Required: true, Values: []ProfileFilterValue{{Label: "Assigned", Value: "assigned"}, {Label: "Inspection", Value: "inspection"}}}, {Name: "priority", Column: "priority", Type: "integer", Required: true, Values: []ProfileFilterValue{{Label: "Low", Value: "1"}, {Label: "High", Value: "2"}}}}}}
	related.ReturnColumns = append(related.ReturnColumns, ProfileColumn{Name: "event_url", Type: "text"})
	related.SourceURLColumn = "event_url"
	related.Relationship.Filters = append(related.Relationship.Filters, ProfileFilter{Name: "event_match", Column: "event_name", Type: "text", Values: []ProfileFilterValue{{Label: "Assigned", Value: "assigned"}}})
	related.SchemaFingerprint, err = connector.ProfileSchemaFingerprint(t.Context(), "iqkb_alex_login", alexPassword, related)
	if err != nil {
		t.Fatalf("related-list schema validation failed: %v", err)
	}
	if err := connector.ValidateRelatedProfile(t.Context(), "iqkb_alex_login", alexPassword, related); err != nil {
		t.Fatalf("content-free related query validation failed: %v", err)
	}
	items, candidates, err := connector.SearchRelatedProfile(t.Context(), "iqkb_alex_login", alexPassword, "asset-alex", 5, map[string]string{"event_kind": "assigned", "priority": "2"}, related)
	if err != nil || len(candidates) != 0 || len(items) != 1 || items[0].ID != "event-1" || items[0].Attributes["priority"] != int64(2) {
		t.Fatalf("related-list query items=%#v candidates=%#v err=%v", items, candidates, err)
	}
	if items[0].SourceURL != "https://assets.example.test/events/event-1" {
		t.Fatalf("related-list source URL was not retained: %#v", items[0])
	}
	items, candidates, err = connector.SearchRelatedProfile(t.Context(), "iqkb_alex_login", alexPassword, "asset-alex", 5, map[string]string{"event_kind": "assigned", "priority": "2", "event_match": "assigned"}, related)
	if err != nil || len(candidates) != 0 || len(items) != 1 || items[0].ID != "event-1" {
		t.Fatalf("selected optional text filter items=%#v candidates=%#v err=%v", items, candidates, err)
	}
	items, candidates, err = connector.SearchRelatedProfile(t.Context(), "iqkb_alex_login", alexPassword, "asset-alex", 5, map[string]string{"event_kind": "inspection", "priority": "1"}, related)
	if err != nil || len(candidates) != 0 || len(items) != 1 || items[0].SourceURL != "" || items[0].Attributes["event_url"] != nil {
		t.Fatalf("unsafe scheme was returned as a source URL: items=%#v candidates=%#v err=%v", items, candidates, err)
	}
	items, candidates, err = connector.SearchRelatedProfile(t.Context(), "iqkb_alex_login", alexPassword, "Field Laptop", 5, map[string]string{"event_kind": "assigned", "priority": "2"}, related)
	if err != nil || len(items) != 0 || len(candidates) != 2 {
		t.Fatalf("ambiguous parent ran related query or missed clarification: items=%#v candidates=%#v err=%v", items, candidates, err)
	}
	items, candidates, err = connector.SearchRelatedProfile(t.Context(), "iqkb_blair_login", blairPassword, "asset-alex", 5, map[string]string{"event_kind": "assigned", "priority": "2"}, related)
	if err != nil || len(items) != 0 || len(candidates) != 0 {
		t.Fatalf("RLS-hidden parent was exposed: items=%#v candidates=%#v err=%v", items, candidates, err)
	}
	adminConfig, err := pgx.ParseConfig(baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.User, adminConfig.Password = "postgres", adminPassword
	admin, err := pgx.ConnectConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err := admin.Exec(t.Context(), `REVOKE SELECT (lifecycle_state) ON iqkb_fixture.ops_assets FROM iqkb_alex_login`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), `GRANT SELECT (lifecycle_state) ON iqkb_fixture.ops_assets TO iqkb_alex_login`)
	}()
	if _, err := connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, "Laptop", 5, alexProfile); err == nil {
		t.Fatal("profile remained usable after a mapped-column SELECT grant was revoked")
	}
	if _, err := admin.Exec(t.Context(), `ALTER TABLE iqkb_fixture.ops_assets ALTER COLUMN due_date TYPE timestamp USING due_date::timestamp`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = admin.Exec(context.Background(), `ALTER TABLE iqkb_fixture.ops_assets ALTER COLUMN due_date TYPE date USING due_date::date`)
	}()
	if _, err := connector.SearchProfile(t.Context(), "iqkb_alex_login", alexPassword, "Laptop", 5, alexProfile); err == nil {
		t.Fatal("profile remained usable after a mapped column changed type")
	}
}

func TestPostgresRotatedPasswordsRejectOldCredentialsIntegration(t *testing.T) {
	baseDSN := integrationValue(t, "IQKB_PG_INTEGRATION_DSN_FILE", "")
	alexOldPassword := integrationValue(t, "IQKB_PG_ALEX_OLD_PASSWORD_FILE", "")
	blairOldPassword := integrationValue(t, "IQKB_PG_BLAIR_OLD_PASSWORD_FILE", "")
	if baseDSN == "" || alexOldPassword == "" || blairOldPassword == "" {
		t.Skip("set a disposable PostgreSQL connection template and pre-rotation password files")
	}
	connector, err := Open(t.Context(), baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	for _, test := range []struct{ identity, password string }{
		{integrationValue(t, "IQKB_PG_ALEX_ID", "iqkb_alex_login"), alexOldPassword},
		{integrationValue(t, "IQKB_PG_BLAIR_ID", "iqkb_blair_login"), blairOldPassword},
	} {
		if err := connector.CheckIdentity(t.Context(), test.identity, test.password); err == nil {
			t.Fatalf("pre-rotation password for %s was accepted", test.identity)
		}
	}
}

func TestPostgresNoLoginRevocationIntegration(t *testing.T) {
	baseDSN := integrationValue(t, "IQKB_PG_INTEGRATION_DSN_FILE", "")
	identity := integrationValue(t, "IQKB_PG_REVOKED_ID", "")
	password := integrationValue(t, "IQKB_PG_REVOKED_PASSWORD_FILE", "")
	if baseDSN == "" || identity == "" || password == "" {
		t.Skip("set a disposable PostgreSQL connection template and revoked LOGIN credentials")
	}
	connector, err := Open(t.Context(), baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	if err := connector.CheckIdentity(t.Context(), identity, password); err == nil {
		t.Fatalf("revoked LOGIN identity %s was accepted", identity)
	}
}

func TestPostgresStatementTimeoutIntegration(t *testing.T) {
	baseDSN := integrationValue(t, "IQKB_PG_INTEGRATION_DSN_FILE", "")
	alexPassword := integrationValue(t, "IQKB_PG_ALEX_PASSWORD_FILE", "")
	if baseDSN == "" || alexPassword == "" {
		t.Skip("set a disposable PostgreSQL connection template and LOGIN password file")
	}
	connector, err := Open(t.Context(), baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()
	tool := QueryTool{
		ID: "test_statement_timeout", Version: 1, Description: "Exercise the fixed statement timeout.",
		SQL:           `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_fixture.documents WHERE pg_sleep(6) IS NULL AND content ILIKE '%' || $1 || '%' LIMIT $2`,
		Parameters:    []QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}},
		OutputColumns: []string{"id:text", "title:text", "content:text", "source_url:text"}, ApprovalRecord: "test-only timeout fixture",
	}
	started := time.Now()
	_, err = connector.Search(t.Context(), integrationValue(t, "IQKB_PG_ALEX_ID", "iqkb_alex_login"), alexPassword, "retention policy", 1, tool)
	if err == nil {
		t.Fatal("slow PostgreSQL query unexpectedly completed")
	}
	if elapsed := time.Since(started); elapsed < 4*time.Second || elapsed > 7*time.Second {
		t.Fatalf("query did not fail near the configured five-second statement timeout: %s", elapsed)
	}
}

func TestPostgresLockTimeoutIntegration(t *testing.T) {
	baseDSN := integrationValue(t, "IQKB_PG_INTEGRATION_DSN_FILE", "")
	alexPassword := integrationValue(t, "IQKB_PG_ALEX_PASSWORD_FILE", "")
	adminPassword := integrationValue(t, "IQKB_PG_ADMIN_PASSWORD_FILE", "")
	if baseDSN == "" || alexPassword == "" || adminPassword == "" {
		t.Skip("set a disposable PostgreSQL DSN and user/admin password files")
	}
	connector, err := Open(t.Context(), baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer connector.Close()

	adminConfig, err := pgx.ParseConfig(baseDSN)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.User, adminConfig.Password = "postgres", adminPassword
	adminConn, err := pgx.ConnectConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer adminConn.Close(context.Background())
	lockTx, err := adminConn.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lockTx.Rollback(context.Background()) }()
	if _, err := lockTx.Exec(t.Context(), `LOCK TABLE iqkb_fixture.documents IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}

	tool := QueryTool{
		ID: "test_lock_timeout", Version: 1, Description: "Exercise the fixed lock timeout.",
		SQL:           `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_fixture.documents WHERE content ILIKE '%' || $1 || '%' LIMIT $2`,
		Parameters:    []QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}},
		OutputColumns: []string{"id:text", "title:text", "content:text", "source_url:text"}, ApprovalRecord: "test-only lock timeout fixture",
	}
	started := time.Now()
	_, err = connector.Search(t.Context(), integrationValue(t, "IQKB_PG_ALEX_ID", "iqkb_alex_login"), alexPassword, "retention policy", 1, tool)
	if err == nil {
		t.Fatal("query blocked by an exclusive table lock unexpectedly completed")
	}
	if elapsed := time.Since(started); elapsed < 500*time.Millisecond || elapsed > 3*time.Second {
		t.Fatalf("query did not fail near the configured one-second lock timeout: %s", elapsed)
	}
}

func assertLoginPermissions(t *testing.T, dsn, identity, password string, canReadAlexColumn bool) {
	t.Helper()
	config, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	config.User, config.Password = identity, password
	conn, err := pgx.ConnectConfig(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(context.Background())
	var sessionUser, currentUser string
	if err := conn.QueryRow(t.Context(), "SELECT session_user::text,current_user::text").Scan(&sessionUser, &currentUser); err != nil {
		t.Fatal(err)
	}
	if sessionUser != identity || currentUser != identity {
		t.Fatalf("connected as session_user=%s current_user=%s, expected %s", sessionUser, currentUser, identity)
	}
	var rows int
	if err := conn.QueryRow(t.Context(), "SELECT count(*) FROM iqkb_fixture.documents WHERE content ILIKE '%retention policy%'").Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("login %s saw %d policy rows, expected 1", identity, rows)
	}
	var private string
	err = conn.QueryRow(t.Context(), "SELECT alex_private FROM iqkb_fixture.documents WHERE id='alex-1'").Scan(&private)
	if canReadAlexColumn {
		if err != nil || private != "Alex-only column" {
			t.Fatalf("Alex column permission failed: value=%q err=%v", private, err)
		}
	} else if err == nil {
		t.Fatalf("login %s unexpectedly read a restricted column", identity)
	}
	tx, err := conn.BeginTx(t.Context(), pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		t.Fatal(err)
	}
	_, err = tx.Exec(t.Context(), "INSERT INTO iqkb_fixture.documents(id,title,content,source_url,owner_login,alex_private) VALUES ('write-test','x','x','https://kb.example.test/x',$1,'x')", identity)
	_ = tx.Rollback(t.Context())
	if err == nil {
		t.Fatalf("login %s was able to write in a read-only transaction", identity)
	}
}

func integrationValue(t *testing.T, variable, defaultValue string) string {
	t.Helper()
	value := os.Getenv(variable)
	if value == "" {
		return defaultValue
	}
	if strings.HasSuffix(variable, "_FILE") {
		data, err := os.ReadFile(value)
		if err != nil {
			t.Fatalf("could not read %s", variable)
		}
		return strings.TrimSpace(string(data))
	}
	return value
}
