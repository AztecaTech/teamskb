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

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestPostgresAskWorkflowUsesReviewedLoginAndApprovedQuery(t *testing.T) {
	dsnPath := os.Getenv("IQKB_PG_INTEGRATION_DSN_FILE")
	if dsnPath == "" {
		t.Skip("set IQKB_PG_INTEGRATION_DSN_FILE to a disposable PG18 fixture DSN file")
	}
	dsn, err := os.ReadFile(dsnPath)
	if err != nil {
		t.Fatal("could not read PostgreSQL integration DSN file")
	}
	pg, err := postgres.Open(t.Context(), strings.TrimSpace(string(dsn)))
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	passwordPath := os.Getenv("IQKB_PG_ALEX_PASSWORD_FILE")
	if passwordPath == "" {
		t.Skip("set IQKB_PG_ALEX_PASSWORD_FILE for the disposable mapped LOGIN user")
	}
	passwordBytes, err := os.ReadFile(passwordPath)
	if err != nil {
		t.Fatal("could not read per-user integration password")
	}
	password := strings.TrimSpace(string(passwordBytes))

	key := bytes.Repeat([]byte{0x55}, 32)
	db := readyWorkflowDB(t, key)
	principal := identity.Principal{TenantID: "42345678-1234-4234-9234-123456789abc", ObjectID: "52345678-1234-4234-9234-123456789abc", VerifiedEmail: "alex@example.test"}
	if _, err := db.Exec(`UPDATE source_boundaries SET enabled=0 WHERE source_id='user-onedrive'`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail, "iqkb_alex_login", "test-admin", "2026-10-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	credentialHandler := authenticate(fixedTokenVerifier{principal}, db, false, postgresCredentialHandler(db, key, pg))
	badCredential := httptest.NewRecorder()
	badRequest := httptest.NewRequest(http.MethodPut, "/api/postgres/credentials", strings.NewReader(`{"password":"incorrect-test-password"}`))
	badRequest.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	credentialHandler.ServeHTTP(badCredential, badRequest)
	if badCredential.Code != http.StatusFailedDependency {
		t.Fatalf("invalid LOGIN password status=%d body=%s", badCredential.Code, badCredential.Body.String())
	}
	var storedCredentials int
	if err := db.QueryRow(`SELECT COUNT(*) FROM encrypted_secrets WHERE secret_id=?`, postgresSecretID(principal.TenantID, principal.ObjectID)).Scan(&storedCredentials); err != nil || storedCredentials != 0 {
		t.Fatalf("invalid password was persisted: count=%d err=%v", storedCredentials, err)
	}
	validCredential := httptest.NewRecorder()
	validRequest := httptest.NewRequest(http.MethodPut, "/api/postgres/credentials", strings.NewReader(`{"password":"`+password+`"}`))
	validRequest.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	credentialHandler.ServeHTTP(validCredential, validRequest)
	if validCredential.Code != http.StatusOK {
		t.Fatalf("valid LOGIN password status=%d body=%s", validCredential.Code, validCredential.Body.String())
	}
	storedPassword, err := loadPostgresPassword(db, key, principal.TenantID, principal.ObjectID)
	if err != nil || storedPassword != password {
		t.Fatalf("verified password was not saved encrypted: passwordMatched=%v err=%v", storedPassword == password, err)
	}
	tool := postgres.QueryTool{ID: "policy_search", Version: 1, Description: "Search the fixture policy view", SQL: `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_fixture.documents WHERE content ILIKE '%' || $1 || '%' ORDER BY id LIMIT $2`, Parameters: []postgres.QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}}, OutputColumns: []string{"id:text", "title:text", "content:text", "source_url:text"}, ApprovalRecord: "test fixture only"}
	parameters, _ := json.Marshal(tool.Parameters)
	outputs, _ := json.Marshal(tool.OutputColumns)
	if _, err := db.Exec(`INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record) VALUES(?,?,?,?,?,?,?)`, tool.ID, tool.Version, tool.Description, tool.SQL, parameters, outputs, tool.ApprovalRecord); err != nil {
		t.Fatal(err)
	}
	if tools, catalogErr := postgres.Catalog(db); catalogErr != nil || len(tools) != 1 {
		t.Fatalf("approved query missing from catalog: tools=%#v err=%v", tools, catalogErr)
	}
	state, err := checkEnabledSourceAccess(t.Context(), db, key, "synthetic-user-assertion", "unused", pg, principal)
	if err != nil || state != "connected" {
		t.Fatalf("valid PostgreSQL catalog failed activation check: state=%s err=%v", state, err)
	}
	brokenSQL := `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_fixture.missing_table WHERE content ILIKE '%' || $1 || '%' LIMIT $2`
	if _, err := db.Exec(`UPDATE query_tools SET fixed_sql=? WHERE tool_id=?`, brokenSQL, tool.ID); err != nil {
		t.Fatal(err)
	}
	state, err = checkEnabledSourceAccess(t.Context(), db, key, "synthetic-user-assertion", "unused", pg, principal)
	if err == nil || state != "approved_query_failed" {
		t.Fatalf("broken PostgreSQL catalog passed activation check: state=%s err=%v", state, err)
	}
	if _, err := db.Exec(`UPDATE query_tools SET fixed_sql=? WHERE tool_id=?`, tool.SQL, tool.ID); err != nil {
		t.Fatal(err)
	}
	runtime := askRuntime{
		modelAPIKey: testProviderAPIKey,
		retrieve: func(ctx context.Context, currentDB *sql.DB, current identity.Principal, assertion, question string, selection *postgres.ToolSelection) (retrievedSources, int, error) {
			return retrieveEnabledSources(ctx, currentDB, key, pg, current, "unused", assertion, question, selection)
		},
		selectTool: func(_ context.Context, _, _, _, _, prompt string) (string, error) {
			if strings.Contains(strings.ToUpper(prompt), "SELECT ") || strings.Contains(prompt, tool.SQL) {
				t.Fatal("executable SQL was exposed to the model tool selector")
			}
			return `{"tool":"policy_search","limit":5}`, nil
		},
		postgresAvailable: true,
		postgres:          pg,
		extract: func(context.Context, string, []byte) (string, error) {
			t.Fatal("plain-text PostgreSQL results should bypass document extraction")
			return "", nil
		},
		generate: func(_ context.Context, provider, model, _ string, _ string, prompt string) (string, error) {
			if provider != "openai" || model != "gpt-test" || !strings.Contains(prompt, "iqkb_alex_login policy") || strings.Contains(prompt, "iqkb_blair_login policy") {
				t.Fatalf("unexpected PostgreSQL prompt: %q", prompt)
			}
			return "The mapped policy applies to Alex. [S1]", nil
		},
	}
	handler := authenticate(fixedTokenVerifier{principal}, db, false, askHandlerWithRuntime(db, key, runtime))
	request := httptest.NewRequest(http.MethodPost, "/api/ask", strings.NewReader(`{"question":"retention policy"}`))
	request.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("ask status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Answer  string         `json:"answer"`
		Sources []answerSource `json:"sources"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Answer != "The mapped policy applies to Alex. [S1]" || len(result.Sources) != 1 || result.Sources[0].Name != "iqkb_alex_login policy" {
		t.Fatalf("unexpected PostgreSQL ask result: %s", response.Body.String())
	}
}

func TestPostgresBusinessProfileAdminWorkflowIntegration(t *testing.T) {
	dsnPath := os.Getenv("IQKB_PG_INTEGRATION_DSN_FILE")
	if dsnPath == "" {
		t.Skip("set IQKB_PG_INTEGRATION_DSN_FILE to a disposable PostgreSQL fixture")
	}
	dsn, err := os.ReadFile(dsnPath)
	if err != nil {
		t.Fatal(err)
	}
	alexPassword, err := os.ReadFile(os.Getenv("IQKB_PG_ALEX_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	blairPassword, err := os.ReadFile(os.Getenv("IQKB_PG_BLAIR_PASSWORD_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	pg, err := postgres.Open(t.Context(), strings.TrimSpace(string(dsn)))
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	db := testDB(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	tenant := "12345678-1234-4234-9234-123456789abc"
	bind := func(object, email, login, password string) identity.Principal {
		principal := identity.Principal{TenantID: tenant, ObjectID: object, VerifiedEmail: email}
		if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, tenant, object, email, login, "admin", "now"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO postgres_login_claims(tenant_id,database_identity,object_id) VALUES(?,?,?)`, tenant, login, object); err != nil {
			t.Fatal(err)
		}
		if err := storePostgresCredential(t.Context(), db, key, principal, login, strings.TrimSpace(password)); err != nil {
			t.Fatal(err)
		}
		return principal
	}
	alex := bind("22345678-1234-4234-9234-123456789abc", "alex@example.test", "iqkb_alex_login", string(alexPassword))
	blair := bind("32345678-1234-4234-9234-123456789abc", "blair@example.test", "iqkb_blair_login", string(blairPassword))
	handler := postgresHandler(db, key, pg)
	profileJSON := `{"id":"asset_lookup","version":1,"label":"Asset","synonyms":["equipment"],"capability":"entity_lookup","schema":"iqkb_fixture","relation":"ops_assets","keyColumn":"asset_key","labelColumn":"display_name","searchColumns":["display_name"],"returnColumns":[{"name":"lifecycle_state","type":"text"},{"name":"last_seen","type":"timestamp"},{"name":"due_date","type":"date"}],"approval":"disposable fixture review"}`
	previewRequest := httptest.NewRequest(http.MethodPost, "/api/admin/postgres/profiles/preview", strings.NewReader(profileJSON))
	previewRequest = previewRequest.WithContext(context.WithValue(previewRequest.Context(), identityContextKey{}, alex))
	previewResponse := httptest.NewRecorder()
	handler.ServeHTTP(previewResponse, previewRequest)
	if previewResponse.Code != http.StatusOK {
		t.Fatalf("profile preview status=%d body=%s", previewResponse.Code, previewResponse.Body.String())
	}
	var preview struct {
		SQL                   string   `json:"sql"`
		OutputColumns         []string `json:"outputColumns"`
		PermissionExplanation string   `json:"permissionExplanation"`
	}
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(preview.SQL, `"last_seen"`) || !strings.Contains(strings.Join(preview.OutputColumns, ","), "attribute:last_seen:timestamp") || !strings.Contains(preview.PermissionExplanation, "each mapped user's own PostgreSQL LOGIN") {
		t.Fatalf("typed preview is incomplete: %#v", preview)
	}
	var savedBeforePreview int
	if err := db.QueryRow(`SELECT COUNT(*) FROM query_tools`).Scan(&savedBeforePreview); err != nil || savedBeforePreview != 0 {
		t.Fatalf("preview persisted a profile: count=%d err=%v", savedBeforePreview, err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/admin/postgres/profiles", strings.NewReader(profileJSON))
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, alex))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("profile save status=%d body=%s", response.Code, response.Body.String())
	}
	tools, err := postgres.Catalog(db)
	if err != nil || len(tools) != 1 {
		t.Fatalf("profile catalog=%#v err=%v", tools, err)
	}
	relatedJSON := `{"id":"asset_event_list","version":1,"label":"Asset event","synonyms":["asset history"],"capability":"related_list","schema":"iqkb_fixture","relation":"ops_asset_events","keyColumn":"event_id","labelColumn":"event_name","searchColumns":[],"returnColumns":[{"name":"event_name","type":"text"},{"name":"priority","type":"integer"},{"name":"event_url","type":"text"}],"sourceURLColumn":"event_url","approval":"disposable relation review","relationship":{"parentProfileId":"asset_lookup","childForeignKey":"asset_key","filters":[{"name":"event_kind","column":"event_name","type":"text","required":true,"values":[{"label":"Assigned","value":"assigned"},{"label":"Inspection","value":"inspection"}]},{"name":"priority","column":"priority","type":"integer","required":true,"values":[{"label":"Low","value":"1"},{"label":"High","value":"2"}]}]}}`
	relatedRequest := httptest.NewRequest(http.MethodPost, "/api/admin/postgres/profiles/preview", strings.NewReader(relatedJSON))
	relatedRequest = relatedRequest.WithContext(context.WithValue(relatedRequest.Context(), identityContextKey{}, alex))
	relatedResponse := httptest.NewRecorder()
	handler.ServeHTTP(relatedResponse, relatedRequest)
	if relatedResponse.Code != http.StatusOK {
		t.Fatalf("related profile preview status=%d body=%s", relatedResponse.Code, relatedResponse.Body.String())
	}
	var relatedPreview struct {
		ParentSQL     string   `json:"parentSQL"`
		SQL           string   `json:"sql"`
		OutputColumns []string `json:"outputColumns"`
	}
	if err := json.Unmarshal(relatedResponse.Body.Bytes(), &relatedPreview); err != nil || !strings.Contains(relatedPreview.ParentSQL, `"ops_assets"`) || !strings.Contains(relatedPreview.SQL, `"ops_asset_events"`) || !strings.Contains(relatedPreview.SQL, `"asset_key"=$1::text`) || !strings.Contains(strings.Join(relatedPreview.OutputColumns, ","), "sourceURL:https") {
		t.Fatalf("related preview omitted parent/child statements: %#v err=%v", relatedPreview, err)
	}
	relatedSave := httptest.NewRequest(http.MethodPut, "/api/admin/postgres/profiles", strings.NewReader(relatedJSON))
	relatedSave = relatedSave.WithContext(context.WithValue(relatedSave.Context(), identityContextKey{}, alex))
	relatedSaved := httptest.NewRecorder()
	handler.ServeHTTP(relatedSaved, relatedSave)
	if relatedSaved.Code != http.StatusOK {
		t.Fatalf("related profile save status=%d body=%s", relatedSaved.Code, relatedSaved.Body.String())
	}
	tools, err = postgres.Catalog(db)
	if err != nil || len(tools) != 2 {
		t.Fatalf("related profile catalog=%#v err=%v", tools, err)
	}
	tester := postgresProfileTestHandler(db, key, pg)
	for _, toolID := range []string{"asset_lookup", "asset_event_list"} {
		for _, principal := range []identity.Principal{alex, blair} {
			req := httptest.NewRequest(http.MethodPost, "/api/postgres/profiles/"+toolID+"/test", nil)
			req.SetPathValue("toolID", toolID)
			req = req.WithContext(context.WithValue(req.Context(), identityContextKey{}, principal))
			rec := httptest.NewRecorder()
			tester.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("profile test %s status=%d body=%s", toolID, rec.Code, rec.Body.String())
			}
		}
	}
	if !postgresProfilesActivationReady(db, tenant, tools) {
		t.Fatal("two distinct mapped LOGIN users should satisfy profile-test activation gate")
	}
}
