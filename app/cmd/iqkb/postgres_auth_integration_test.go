package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestPostgresAdapterWorkflowIntegration(t *testing.T) {
	file := os.Getenv("IQKB_AUTH_TEST_DSN_FILE")
	if file == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("fixture DSN missing")
	}
	dsn := strings.TrimSpace(string(raw))
	pg, err := postgres.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x55}, 32)
	db := readyWorkflowDB(t, key)
	alex := identity.Principal{TenantID: "tenant-one", ObjectID: "22345678-1234-4234-9234-123456789abc", VerifiedEmail: "app-alex@example.com"}
	blair := identity.Principal{TenantID: alex.TenantID, ObjectID: "32345678-1234-4234-9234-123456789abc", VerifiedEmail: "app-blair@example.com"}
	if _, err = db.Exec(`INSERT INTO admin_assignments(tenant_id,object_id,created_at) VALUES(?,?,'now')`, alex.TenantID, alex.ObjectID); err != nil {
		t.Fatal(err)
	}
	request := func(handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	authHandler := authenticate(fixedTokenVerifier{alex}, db, true, postgresAuthHandler(db, key, pg))
	if rec := request(authHandler, "GET", "/api/admin/postgres/auth/discovery", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ready":true`) || strings.Contains(rec.Body.String(), "app-alex@example.com") {
		t.Fatalf("bootstrap discovery=%d %s", rec.Code, rec.Body.String())
	}
	body := `{"mode":"session_context","schema":"iqkb_auth","relation":"users","approvalRecord":"fixture-review"}`
	labelBody := `{"mode":"session_context","schema":"iqkb_auth","relation":"permission_directory","approvalRecord":"fixture-label","columns":{"email":"email","userId":"id","role":"role","active":"enabled"}}`
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", labelBody); rec.Code != 200 {
		t.Fatalf("label adapter save: %s", rec.Body.String())
	}
	labelHandler := authenticate(fixedTokenVerifier{alex}, db, false, postgresEmailHandler(db, key, pg))
	if rec := request(labelHandler, "PUT", "/api/postgres/email", `{"email":"app-alex@example.com"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"matched_permissions_required"`) || !strings.Contains(rec.Body.String(), `"applicationRole":"Reader"`) {
		t.Fatalf("label recognition: %d %s", rec.Code, rec.Body.String())
	}
	if _, _, _, err := postgresAccess(t.Context(), db, key, pg, alex); err != errPostgresPermissionMappingRequired {
		t.Fatal("role label alone granted database access")
	}
	labelStatus := authenticate(fixedTokenVerifier{alex}, db, false, postgresCredentialHandler(db, key, pg))
	if rec := request(labelStatus, "GET", "/api/postgres/credentials", ""); !strings.Contains(rec.Body.String(), `"configured":false`) || !strings.Contains(rec.Body.String(), `"applicationRole":"Reader"`) {
		t.Fatalf("label status lost separation: %s", rec.Body.String())
	}
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", body); rec.Code != 200 {
		t.Fatalf("save adapter=%d %s", rec.Code, rec.Body.String())
	}
	if rec := request(authHandler, "POST", "/api/admin/postgres/auth/check", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "iqkb_application") {
		t.Fatalf("check=%d %s", rec.Code, rec.Body.String())
	}
	denied := authenticate(fixedTokenVerifier{blair}, db, true, postgresAuthHandler(db, key, pg))
	if rec := request(denied, "GET", "/api/admin/postgres/auth/discovery", ""); rec.Code != 403 {
		t.Fatal("non-admin bootstrap discovery allowed")
	}
	if rec := request(denied, "GET", "/api/admin/postgres/auth/resources", ""); rec.Code != 403 {
		t.Fatal("non-admin bootstrap resource discovery allowed")
	}
	if rec := request(denied, "PUT", "/api/admin/postgres/auth", body); rec.Code != 403 {
		t.Fatal("non-admin adapter edit allowed")
	}
	creds := authenticate(fixedTokenVerifier{alex}, db, false, postgresCredentialHandler(db, key, pg))
	if rec := request(creds, "GET", "/api/postgres/credentials", ""); !strings.Contains(rec.Body.String(), `"status":"email_confirmation_required"`) {
		t.Fatalf("confirmation was not required: %s", rec.Body.String())
	}
	if _, _, _, err := postgresAccess(t.Context(), db, key, pg, alex); err != errPostgresEmailConfirmationRequired {
		t.Fatal("unconfirmed user received database access")
	}
	for _, user := range []identity.Principal{alex, blair} {
		emailHandler := authenticate(fixedTokenVerifier{user}, db, false, postgresEmailHandler(db, key, pg))
		if rec := request(emailHandler, "PUT", "/api/postgres/email", `{"email":"someone-else@example.com"}`); rec.Code != 403 {
			t.Fatal("another person's email was accepted")
		}
		if rec := request(emailHandler, "PUT", "/api/postgres/email", `{"email":"`+strings.ToUpper(user.VerifiedEmail)+`"}`); rec.Code != 200 {
			t.Fatalf("email confirmation=%d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := request(creds, "GET", "/api/postgres/credentials", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mode":"shared-adapter"`) || !strings.Contains(rec.Body.String(), `"mapped":true`) {
		t.Fatalf("credentials status=%d %s", rec.Code, rec.Body.String())
	}
	if rec := request(creds, "PUT", "/api/postgres/credentials", `{"password":"must-not-be-used"}`); rec.Code != 409 {
		t.Fatal("shared mode accepted user password")
	}
	profile := postgres.BusinessProfile{ID: "policies", Label: "Policies", Capability: "entity_lookup", Schema: "iqkb_data", Relation: "documents", KeyColumn: "id", LabelColumn: "title", SearchColumns: []string{"title"}, ReturnColumns: []postgres.ProfileColumn{{Name: "content", Type: "text"}}, Approval: "fixture-review"}
	tool, err := prepareBusinessProfile(t.Context(), db, key, pg, alex, profile)
	if err != nil {
		t.Fatal(err)
	}
	params, _ := json.Marshal(tool.Parameters)
	outputs, _ := json.Marshal(tool.OutputColumns)
	if _, err = db.Exec(`INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config) VALUES(?,?,?,?,?,?,?,?)`, tool.ID, tool.Version, tool.Description, tool.SQL, params, outputs, tool.ApprovalRecord, tool.ProfileConfig); err != nil {
		t.Fatal(err)
	}
	tools, err := postgres.Catalog(db)
	if err != nil {
		t.Fatal(err)
	}
	for index, principal := range []identity.Principal{alex, blair} {
		handler := authenticate(fixedTokenVerifier{principal}, db, false, postgresProfileTestHandler(db, key, pg))
		if rec := request(handler, "POST", "/api/postgres/profiles/policies/test", ""); rec.Code != 200 {
			t.Fatalf("profile test=%d %s", rec.Code, rec.Body.String())
		}
		if ready := postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools); ready != (index == 1) {
			t.Fatalf("two-user evidence ready=%v at index %d", ready, index)
		}
	}
	if _, err = db.Exec(`UPDATE source_boundaries SET enabled=0`); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',1)`); err != nil {
		t.Fatal(err)
	}
	if state, err := checkEnabledSourceAccess(t.Context(), db, key, "assertion", "unused", pg, alex); err != nil || state != "connected" {
		t.Fatalf("activation state=%s err=%v", state, err)
	}
	for _, principal := range []identity.Principal{alex, blair} {
		if _, err := db.Exec(`UPDATE source_boundaries SET enabled=1 WHERE source_id='user-onedrive'`); err != nil {
			t.Fatal(err)
		}
		approved, err := approvedPostgresToolsForUser(t.Context(), db, key, pg, principal)
		if err != nil || len(approved) != 1 {
			t.Fatalf("catalog=%#v err=%v", approved, err)
		}
		selection := &postgres.ToolSelection{ToolID: "policies", Term: "Policy", Limit: 5}
		scopedContext := context.WithValue(t.Context(), searchScopeKey{}, "database")
		sources, failures, err := retrieveEnabledSources(scopedContext, db, key, pg, principal, "unused", "assertion", "Policy", selection)
		wanted := "alex-doc"
		if principal.ObjectID == blair.ObjectID {
			wanted = "blair-doc"
		}
		if err != nil || failures != 0 || len(sources.records) != 1 || sources.records[0].ID != wanted {
			t.Fatalf("retrieval failed=%d err=%v records=%#v", failures, err, sources.records)
		}
	}
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.User, adminConfig.Password = "postgres", "IQKB-test-admin-only"
	admin, err := pgx.ConnectConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err = admin.Exec(t.Context(), `UPDATE iqkb_auth.users SET permission_version='v2' WHERE email='app-blair@example.com'`); err != nil {
		t.Fatal(err)
	}
	if postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools) {
		t.Fatal("changed permissions reused old profile evidence")
	}
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", body); rec.Code != 200 {
		t.Fatal("adapter resave failed")
	}
	var count int
	if err = db.QueryRow(`SELECT COUNT(*) FROM postgres_adapter_profile_tests`).Scan(&count); err != nil || count != 0 {
		t.Fatal("adapter change retained evidence")
	}
	if err = db.QueryRow(`SELECT COUNT(*) FROM encrypted_secrets WHERE secret_id LIKE 'postgres_password:%'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("shared workflow stored per-user passwords")
	}
	// A single fixed query routes directly: no selector model call and no
	// Microsoft retrieval, even when OneDrive remains enabled globally.
	if _, err = db.Exec(`DELETE FROM query_tools`); err != nil {
		t.Fatal(err)
	}
	fixedSQL := `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_data.documents WHERE content ILIKE '%' || $1 || '%' ORDER BY id LIMIT $2`
	if _, err = db.Exec(`INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record) VALUES('policy_search',1,'Policies',?,'[{"name":"question","type":"text"},{"name":"limit","type":"integer[1,5]"}]','["id:text","title:text","content:text","source_url:text"]','fixture-review')`, fixedSQL); err != nil {
		t.Fatal(err)
	}
	selectorCalled := false
	ask := authenticate(fixedTokenVerifier{alex}, db, false, askHandlerWithRuntime(db, key, askRuntime{
		postgres: pg, postgresAvailable: true, modelAPIKey: testProviderAPIKey,
		selectTool: func(context.Context, string, string, string, string, string) (string, error) {
			selectorCalled = true
			return "", nil
		},
		retrieve: func(ctx context.Context, db *sql.DB, principal identity.Principal, assertion, question string, selection *postgres.ToolSelection) (retrievedSources, int, error) {
			return retrieveEnabledSources(ctx, db, key, pg, principal, "unused", assertion, question, selection)
		},
		generate: func(_ context.Context, _, _, _, _, prompt string) (string, error) {
			if !strings.Contains(prompt, "Alex private policy") || strings.Contains(prompt, "Blair private policy") {
				t.Fatal("answer prompt did not respect DB permissions")
			}
			return "Alex private policy [S1]", nil
		},
	}))
	if rec := request(ask, "POST", "/api/ask", `{"question":"policy","scope":"database"}`); rec.Code != 200 || selectorCalled || !strings.Contains(rec.Body.String(), `"kind":"database"`) || !strings.Contains(rec.Body.String(), `"results":1`) {
		t.Fatalf("database-only answer=%d %s selector=%v", rec.Code, rec.Body.String(), selectorCalled)
	}
}
