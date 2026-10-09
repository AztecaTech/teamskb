package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"iq-kbteams/internal/authorization"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestPostgresAdapterApplicationWorkflowIntegration(t *testing.T) {
	file := os.Getenv("IQKB_AUTH_TEST_DSN_FILE")
	if file == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("fixture URI missing")
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal("fixture URI invalid")
	}
	u.User = url.UserPassword("postgres", "IQKB-test-admin-only")
	pg, err := postgres.Open(t.Context(), u.String())
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
	adapter := postgres.AdapterConfig{Mode: "application_rules", Schema: "iqkb_auth", Relation: "permission_directory", ApprovalRecord: "fixture-review", Columns: &postgres.AuthorizationColumns{UserID: "id", Email: "email", Role: "role", Active: "enabled"}}
	encode := func(value any) string {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", encode(adapter)); rec.Code != 200 {
		t.Fatalf("save draft=%d %s", rec.Code, rec.Body.String())
	}
	if rec := request(authHandler, "GET", "/api/admin/postgres/auth/permissions", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mode":"internal"`) || !strings.Contains(rec.Body.String(), `"status":"internal_rules_required"`) || strings.Contains(rec.Body.String(), `"fields"`) {
		t.Fatalf("internal draft preview=%d %s", rec.Code, rec.Body.String())
	}
	emailHandler := authenticate(fixedTokenVerifier{alex}, db, false, postgresEmailHandler(db, key, pg))
	if rec := request(emailHandler, "PUT", "/api/postgres/email", `{"email":"app-alex@example.com"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"matched_permissions_required"`) {
		t.Fatalf("draft label received access: %d %s", rec.Code, rec.Body.String())
	}
	if _, err = db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',1)`); err != nil {
		t.Fatal(err)
	}
	readyHandler := authenticate(fixedTokenVerifier{alex}, db, true, postgresReadinessHandler(db, key, pg))
	if rec := request(readyHandler, "GET", "/api/admin/postgres/readiness", ""); !strings.Contains(rec.Body.String(), `"state":"application_resource_required"`) || !strings.Contains(rec.Body.String(), `"next":"application-permissions"`) {
		t.Fatalf("empty resource guidance: %s", rec.Body.String())
	}
	adapter.Rules = []authorization.Rule{{Label: "Reader", Schema: "iqkb_data", Relation: "app_documents", Fields: []string{}, Scope: authorization.Scope{Kind: "pending"}}}
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", encode(adapter)); rec.Code != 200 {
		t.Fatal("pending resource draft failed")
	}
	if rec := request(emailHandler, "PUT", "/api/postgres/email", `{"email":"app-alex@example.com"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"matched_permissions_required"`) {
		t.Fatal("unreviewed resource authorized search")
	}
	if rec := request(readyHandler, "GET", "/api/admin/postgres/readiness", ""); !strings.Contains(rec.Body.String(), `"state":"application_rule_review_required"`) || !strings.Contains(rec.Body.String(), `"next":"application-permissions"`) {
		t.Fatalf("draft review guidance: %s", rec.Body.String())
	}
	adapter.Rules = nil
	for _, label := range []string{"Reader", "Editor"} {
		adapter.Rules = append(adapter.Rules, authorization.Rule{Label: label, Schema: "iqkb_data", Relation: "app_documents", Fields: []string{"id", "title", "content"}, Scope: authorization.Scope{Kind: "user", Column: "owner_id"}, Reviewed: true})
	}
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", encode(adapter)); rec.Code != 200 {
		t.Fatalf("save rules=%d %s", rec.Code, rec.Body.String())
	}
	if rec := request(authHandler, "GET", "/api/admin/postgres/auth/permissions", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"mode":"internal"`) || !strings.Contains(rec.Body.String(), `"status":"resolved"`) || strings.Contains(rec.Body.String(), `"label":"Editor"`) {
		t.Fatalf("internal matched-user preview=%d %s", rec.Code, rec.Body.String())
	}
	saved, err := loadPostgresAdapter(db)
	if err != nil || len(saved.Rules) != 2 {
		t.Fatal("internal policy was discarded instead of stored in IQ Knowledge")
	}
	if rec := request(authHandler, "POST", "/api/admin/postgres/auth/check", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"authorizationMode":"application_rules"`) {
		t.Fatalf("check=%d %s", rec.Code, rec.Body.String())
	}
	denied := authenticate(fixedTokenVerifier{blair}, db, true, postgresAuthHandler(db, key, pg))
	if rec := request(denied, "PUT", "/api/admin/postgres/auth", encode(adapter)); rec.Code != 403 {
		t.Fatal("ordinary user edited permissions")
	}
	if _, _, _, err := postgresAccess(t.Context(), db, key, pg, alex); err != errPostgresEmailConfirmationRequired {
		t.Fatal("adapter change retained confirmation")
	}
	for _, user := range []identity.Principal{alex, blair} {
		handler := authenticate(fixedTokenVerifier{user}, db, false, postgresEmailHandler(db, key, pg))
		if rec := request(handler, "PUT", "/api/postgres/email", `{"email":"wrong@example.com"}`); rec.Code != 403 {
			t.Fatal("wrong email accepted")
		}
		if rec := request(handler, "PUT", "/api/postgres/email", encode(map[string]string{"email": user.VerifiedEmail})); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"authorizationMode":"application_rules"`) {
			t.Fatalf("confirm=%d %s", rec.Code, rec.Body.String())
		}
	}
	statusHandler := authenticate(fixedTokenVerifier{alex}, db, false, postgresCredentialHandler(db, key, pg))
	if rec := request(statusHandler, "GET", "/api/postgres/credentials", ""); !strings.Contains(rec.Body.String(), `"configured":true`) || !strings.Contains(rec.Body.String(), `"applicationRole":"Reader"`) {
		t.Fatalf("mode-aware status=%s", rec.Body.String())
	}
	adminHandler := authenticate(fixedTokenVerifier{alex}, db, true, postgresHandler(db, key, pg))
	if rec := request(adminHandler, "PUT", "/api/admin/postgres/queries", "{}"); rec.Code != 409 || !strings.Contains(rec.Body.String(), "application_rules_profiles_only") {
		t.Fatal("application mode accepted a fixed SQL catalog mutation")
	}
	if rec := request(adminHandler, "GET", "/api/admin/postgres/discovery", ""); rec.Code != 200 || strings.Contains(rec.Body.String(), `"name":"hidden"`) {
		t.Fatalf("scoped discovery=%d %s", rec.Code, rec.Body.String())
	}
	if rec := request(readyHandler, "GET", "/api/admin/postgres/readiness", ""); !strings.Contains(rec.Body.String(), `"state":"approved_query_required"`) || !strings.Contains(rec.Body.String(), `"next":"business-search-profile"`) {
		t.Fatalf("missing profile guidance: %s", rec.Body.String())
	}
	profile := postgres.BusinessProfile{ID: "app_docs", Label: "Documents", Capability: "entity_lookup", Schema: "iqkb_data", Relation: "app_documents", KeyColumn: "id", LabelColumn: "title", SearchColumns: []string{"title"}, ReturnColumns: []postgres.ProfileColumn{{Name: "content", Type: "text"}}}
	for _, step := range []struct{ method, path string }{{"POST", "/api/admin/postgres/profiles/preview"}, {"PUT", "/api/admin/postgres/profiles"}} {
		if rec := request(adminHandler, step.method, step.path, encode(profile)); rec.Code != 200 {
			t.Fatalf("profile %s=%d %s", step.path, rec.Code, rec.Body.String())
		}
	}
	tools, err := postgres.Catalog(db)
	if err != nil || len(tools) != 1 {
		t.Fatal("saved profile missing")
	}
	if !strings.Contains(tools[0].ApprovalRecord, alex.ObjectID) || !strings.Contains(tools[0].ApprovalRecord, "reviewed profile at") {
		t.Fatal("optional note lost trusted review audit")
	}
	for index, user := range []identity.Principal{alex, blair} {
		handler := authenticate(fixedTokenVerifier{user}, db, false, postgresProfileTestHandler(db, key, pg))
		if rec := request(handler, "POST", "/api/postgres/profiles/app_docs/test", ""); rec.Code != 200 {
			t.Fatalf("profile evidence=%d %s", rec.Code, rec.Body.String())
		}
		if ready := postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools); ready != (index == 1) {
			t.Fatal("two-user gate incorrect")
		}
	}
	if rec := request(readyHandler, "GET", "/api/admin/postgres/readiness", ""); !strings.Contains(rec.Body.String(), `"ready":true`) {
		t.Fatalf("reviewed app profiles not ready: %s", rec.Body.String())
	}
	for _, user := range []identity.Principal{alex, blair} {
		c, login, password, err := postgresAccess(t.Context(), db, key, pg, user)
		if err != nil {
			t.Fatal(err)
		}
		var saved postgres.BusinessProfile
		if json.Unmarshal(tools[0].ProfileConfig, &saved) != nil {
			t.Fatal("profile decode failed")
		}
		rows, err := c.SearchProfile(t.Context(), login, password, "Shared title", 5, saved)
		name := "alex"
		if user.ObjectID == blair.ObjectID {
			name = "blair"
		}
		if err != nil || len(rows) != 1 || rows[0].ID != name+"-app" {
			t.Fatalf("confirmed user isolation=%#v %v", rows, err)
		}
		ask := authenticate(fixedTokenVerifier{user}, db, false, askHandlerWithRuntime(db, key, askRuntime{
			postgres: pg, postgresAvailable: true, modelAPIKey: testProviderAPIKey,
			selectTool: func(_ context.Context, _, _, _, _, prompt string) (string, error) {
				if strings.Contains(prompt, tools[0].SQL) || strings.Contains(prompt, "Alex scoped content") || strings.Contains(prompt, "Blair scoped content") {
					t.Fatal("selector received SQL or business rows")
				}
				return `{"tool":"app_docs","term":"Shared title","limit":5}`, nil
			},
			retrieve: func(ctx context.Context, currentDB *sql.DB, principal identity.Principal, assertion, question string, selection *postgres.ToolSelection) (retrievedSources, int, error) {
				return retrieveEnabledSources(ctx, currentDB, key, pg, principal, "unused", assertion, question, selection)
			},
			generate: func(_ context.Context, _, _, _, _, prompt string) (string, error) {
				wanted, forbidden := "Alex scoped content", "Blair scoped content"
				if name == "blair" {
					wanted, forbidden = forbidden, wanted
				}
				if !strings.Contains(prompt, wanted) || strings.Contains(prompt, forbidden) || strings.Contains(prompt, "hidden value") {
					t.Fatal("answer prompt violated application permissions")
				}
				return wanted + " [S1]", nil
			},
		}))
		if rec := request(ask, "POST", "/api/ask", `{"question":"Shared title","scope":"database"}`); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"results":1`) {
			t.Fatalf("application answer=%d %s", rec.Code, rec.Body.String())
		}
	}
	adapter.Rules[0].Reviewed = false
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", encode(adapter)); rec.Code != 200 {
		t.Fatal("permission revocation not saved")
	}
	if postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools) {
		t.Fatal("stale evidence retained")
	}
	if _, _, _, err := postgresAccess(t.Context(), db, key, pg, alex); err != errPostgresEmailConfirmationRequired {
		t.Fatal("stale permission confirmation retained")
	}
	if rec := request(authHandler, "POST", "/api/admin/postgres/auth/permission-drafts/obsolete/apply", ""); rec.Code != http.StatusGone {
		t.Fatal("retired database installer accessible")
	}
}
