package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"iq-kbteams/internal/answer"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
	"iq-kbteams/internal/store"
)

const testProviderAPIKey = "synthetic-test-key"

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if err := store.Migrate(db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestAdminApprovedPostgresCatalogIsVersionedAndValidated(t *testing.T) {
	db := testDB(t)
	handler := postgresHandler(db, bytes.Repeat([]byte{1}, 32), nil)
	principal := identity.Principal{TenantID: "12345678-1234-4234-9234-123456789abc", ObjectID: "22345678-1234-4234-9234-123456789abc"}
	put := func(tool postgres.QueryTool) *httptest.ResponseRecorder {
		body, _ := json.Marshal(tool)
		request := httptest.NewRequest(http.MethodPut, "/api/admin/postgres/queries", bytes.NewReader(body))
		request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, principal))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	tool := postgres.QueryTool{ID: "policy_search", Version: 1, Description: "Approved policy search", SQL: "SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM org.policy WHERE text @@ plainto_tsquery('simple',$1) LIMIT $2", Parameters: []postgres.QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}}, OutputColumns: []string{"id:text", "title:text", "content:text", "source_url:text"}, ApprovalRecord: "DBA review ticket 17"}
	if response := put(tool); response.Code != http.StatusOK {
		t.Fatalf("catalog insert status=%d body=%s", response.Code, response.Body.String())
	}
	tool.SQL = "UPDATE org.policy SET content=$1 WHERE id=$2"
	tool.Version = 2
	if response := put(tool); response.Code != http.StatusBadRequest {
		t.Fatalf("mutating query status=%d body=%s", response.Code, response.Body.String())
	}
	tool.SQL = "SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM org.policy WHERE text @@ plainto_tsquery('simple',$1) LIMIT $2"
	if response := put(tool); response.Code != http.StatusOK {
		t.Fatalf("catalog update status=%d body=%s", response.Code, response.Body.String())
	}
	if response := put(tool); response.Code != http.StatusConflict {
		t.Fatalf("non-incremented catalog version status=%d", response.Code)
	}
	var storedVersion int
	if err := db.QueryRow(`SELECT version FROM query_tools WHERE tool_id='policy_search'`).Scan(&storedVersion); err != nil || storedVersion != 2 {
		t.Fatalf("catalog version=%d err=%v", storedVersion, err)
	}
}

func TestAdminBusinessProfileSaveRequiresVerifiedDatabaseMetadata(t *testing.T) {
	db := testDB(t)
	key := bytes.Repeat([]byte{5}, 32)
	handler := postgresHandler(db, key, nil)
	principal := identity.Principal{TenantID: "12345678-1234-4234-9234-123456789abc", ObjectID: "22345678-1234-4234-9234-123456789abc"}
	input := `{"id":"asset_lookup","version":1,"label":"Asset","synonyms":["equipment"],"capability":"entity_lookup","schema":"ops","relation":"asset list","keyColumn":"asset_id","labelColumn":"display name","searchColumns":["display name"],"returnColumns":[{"name":"status","type":"text"}],"approval":"change-42"}`
	request := httptest.NewRequest(http.MethodPut, "/api/admin/postgres/profiles", strings.NewReader(input))
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, principal))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "postgres_not_configured") {
		t.Fatalf("profile without live metadata check status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestProfileActivationRequiresTwoUnambiguousUserLogins(t *testing.T) {
	db := testDB(t)
	profile := postgres.BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: "ops", Relation: "assets", KeyColumn: "asset_id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []postgres.ProfileColumn{{Name: "state", Type: "text"}}, Approval: "reviewed", SchemaFingerprint: strings.Repeat("a", 64)}
	config, _ := json.Marshal(profile)
	fingerprint, _ := postgres.ProfileFingerprint(profile)
	query, _ := postgres.CompileBusinessProfile(profile)
	params, _ := json.Marshal([]postgres.QueryParameter{{Name: "term", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}})
	outputs, _ := json.Marshal(postgres.ProfileOutputColumns(profile))
	if _, err := db.Exec(`INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config) VALUES(?,?,?,?,?,?,?,?)`, profile.ID, profile.Version, profile.Label, query, params, outputs, "reviewed", config); err != nil {
		t.Fatal(err)
	}
	tools, err := postgres.Catalog(db)
	if err != nil {
		t.Fatal(err)
	}
	for i, login := range []string{"login_a", "login_b"} {
		object := fmt.Sprintf("user-%d", i)
		updated := fmt.Sprintf("secret-%d", i)
		if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, "tenant", object, object+"@example.test", login, "admin", "now"); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO encrypted_secrets(secret_id,ciphertext,nonce,updated_at) VALUES(?,?,?,?)`, postgresSecretID("tenant", object), []byte("ciphertext"), []byte("nonce"), updated); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO postgres_profile_tests(tenant_id,tool_id,profile_version,object_id,database_identity,schema_fingerprint,tested_at,outcome,error_category,binding_email,binding_reviewed_at,credential_generation,profile_generation) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, "tenant", profile.ID, profile.Version, object, login, fingerprint, "now", "passed", "", object+"@example.test", "now", updated, fingerprint); err != nil {
			t.Fatal(err)
		}
	}
	if !postgresProfilesActivationReady(db, "tenant", tools) {
		t.Fatal("two passing distinct LOGIN tests should permit profile activation")
	}
	if _, err := db.Exec(`UPDATE encrypted_secrets SET updated_at='rotated' WHERE secret_id=?`, postgresSecretID("tenant", "user-0")); err != nil {
		t.Fatal(err)
	}
	if postgresProfilesActivationReady(db, "tenant", tools) {
		t.Fatal("credential rotation must invalidate activation evidence")
	}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, "tenant", "user-c", "c@example.test", "login_a", "admin", "now"); err != nil {
		t.Fatal(err)
	}
	if postgresProfilesActivationReady(db, "tenant", tools) {
		t.Fatal("duplicate LOGIN mapping should invalidate profile activation evidence")
	}
}

func TestProfileSelectorProviderPromptAndParserContract(t *testing.T) {
	profile := postgres.BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Synonyms: []string{"equipment"}, Capability: "entity_lookup", Schema: "ops", Relation: "assets", KeyColumn: "asset_id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []postgres.ProfileColumn{{Name: "state", Type: "text"}}, Approval: "reviewed", SchemaFingerprint: strings.Repeat("a", 64)}
	sql, err := postgres.CompileBusinessProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(profile)
	tool := postgres.QueryTool{ID: profile.ID, Version: profile.Version, Description: profile.Label, SQL: sql, Parameters: []postgres.QueryParameter{{Name: "term", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}}, OutputColumns: postgres.ProfileOutputColumns(profile), ApprovalRecord: "reviewed", ProfileConfig: config}
	prompt, err := postgres.SelectionPrompt("show equipment 42", []postgres.QueryTool{tool})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if len(request.Messages) != 2 || !strings.Contains(request.Messages[0].Content, `"term"`) || !strings.Contains(request.Messages[0].Content, "legacy tools") || !strings.Contains(request.Messages[1].Content, `term:text`) || strings.Contains(request.Messages[1].Content, sql) {
			t.Errorf("selector contract incomplete or SQL leaked: %#v", request.Messages)
		}
		w.Header().Set("Content-Type", "application/json")
		selectionJSON, _ := json.Marshal(map[string]any{"tool": "asset_lookup", "term": "42", "limit": 1})
		responseJSON, _ := json.Marshal(map[string]any{"choices": []any{map[string]any{"message": map[string]string{"role": "assistant", "content": string(selectionJSON)}}}})
		_, _ = w.Write(responseJSON)
	}))
	defer server.Close()
	raw, err := answer.SelectTool(context.Background(), "openai_compatible", "test-model", server.URL+"/v1", "model-key", prompt)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := postgres.ParseToolSelection(raw, []postgres.QueryTool{tool})
	if err != nil || selection == nil || selection.Term != "42" || selection.Limit != 1 {
		t.Fatalf("parsed selection=%#v raw=%q err=%v", selection, raw, err)
	}
}

func TestProviderConfigUsesOperatorKeyAndDoesNotStoreOrReturnIt(t *testing.T) {
	db := testDB(t)
	key := bytes.Repeat([]byte{0x3a}, 32)
	apiKey := "secret-api-key-123"
	handler := providerHandler(db, apiKey, key)
	input := `{"provider":"openai_compatible","model":"test-model","baseUrl":"https://models.example/v1"}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(input)))
	if response.Code != http.StatusOK {
		t.Fatalf("PUT status=%d body=%s", response.Code, response.Body.String())
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM encrypted_secrets`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("provider key was persisted in SQLite: count=%d err=%v", count, err)
	}

	response = httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/admin/provider", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("GET status=%d", response.Code)
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if _, exists := result["apiKey"]; exists || strings.Contains(response.Body.String(), apiKey) {
		t.Fatalf("provider GET exposed the API key: %s", response.Body.String())
	}
}

func TestProviderConfigRejectsUnsafeEndpointAndUnknownFields(t *testing.T) {
	db := testDB(t)
	handler := providerHandler(db, "synthetic-key-123", bytes.Repeat([]byte{1}, 32))
	for _, input := range []string{
		`{"provider":"openai_compatible","model":"m","baseUrl":"http://models.example/v1","extra":"x"}`,
		`{"provider":"openai_compatible","model":"m","baseUrl":"https://user:pass@models.example/v1"}`,
		`{"provider":"unknown","model":"m"}`,
		`{"provider":"openai","model":"m","apiKey":"secret-key-123"}`,
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(input)))
		if response.Code != http.StatusBadRequest {
			t.Errorf("input %s returned %d", input, response.Code)
		}
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM encrypted_secrets`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed writes left secrets: count=%d err=%v", count, err)
	}
}

func TestProviderDeleteRemovesConfigAndSecret(t *testing.T) {
	db := testDB(t)
	handler := providerHandler(db, "secret-key-123", bytes.Repeat([]byte{2}, 32))
	input := `{"provider":"openai","model":"gpt-test"}`
	put := httptest.NewRecorder()
	handler.ServeHTTP(put, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(input)))
	if put.Code != http.StatusOK {
		t.Fatal(put.Body.String())
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodDelete, "/api/admin/provider", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("DELETE status=%d body=%s", response.Code, response.Body.String())
	}
	if _, err := loadModelConfig(db); err != sql.ErrNoRows {
		t.Fatalf("config remains: %v", err)
	}
}

func TestProviderUpdateInvalidatesSuccessfulCheck(t *testing.T) {
	db := testDB(t)
	key := bytes.Repeat([]byte{7}, 32)
	apiKey := "secret-key-123"
	handler := providerHandler(db, apiKey, key)
	put := func(input string) *httptest.ResponseRecorder {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(input)))
		return response
	}
	if response := put(`{"provider":"openai","model":"gpt-test"}`); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	fingerprint, err := modelFingerprint(db, apiKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO settings(key,value) VALUES('model_test_fingerprint',?)`, []byte(fingerprint)); err != nil {
		t.Fatal(err)
	}
	if !modelTested(db, apiKey, key) {
		t.Fatal("expected saved fingerprint to match provider configuration")
	}
	if response := put(`{"provider":"openai","model":"gpt-next"}`); response.Code != http.StatusOK {
		t.Fatal(response.Body.String())
	}
	if modelTested(db, apiKey, key) {
		t.Fatal("provider update retained the prior successful-check marker")
	}
}

func TestProviderCheckSharesAskAdmissionLimit(t *testing.T) {
	db := testDB(t)
	key := bytes.Repeat([]byte{0x31}, 32)
	principal := identity.Principal{TenantID: "12345678-1234-4234-9234-123456789abc", ObjectID: "22345678-1234-4234-9234-123456789abc"}
	gate := newAskAdmissionGate(maxConcurrentAsks, maxConcurrentAsksPerUser)
	handler := providerHandlerWithControls(db, testProviderAPIKey, key, 10, gate)
	configured := httptest.NewRecorder()
	handler.ServeHTTP(configured, httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(`{"provider":"openai","model":"gpt-test"}`)))
	if configured.Code != http.StatusOK {
		t.Fatalf("configure provider status=%d body=%s", configured.Code, configured.Body.String())
	}
	userKey := strings.ToLower(principal.TenantID + ":" + principal.ObjectID)
	release1, _ := gate.acquire(userKey)
	release2, _ := gate.acquire(userKey)
	defer release1()
	defer release2()
	request := httptest.NewRequest(http.MethodPost, "/api/admin/provider/check", nil)
	request = request.WithContext(context.WithValue(request.Context(), identityContextKey{}, principal))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusTooManyRequests || !strings.Contains(response.Body.String(), "too_many_concurrent_requests") {
		t.Fatalf("provider check status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestIoReadRequestStopsAtLimit(t *testing.T) {
	body := strings.Repeat("x", 17<<10)
	request := httptest.NewRequest(http.MethodPut, "/api/admin/provider", strings.NewReader(body))
	if _, err := ioReadRequest(request); err == nil {
		t.Fatal("oversized request was accepted")
	}
}
