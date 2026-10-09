package main

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"

	"iq-kbteams/internal/authorization"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestPostgresAdapterRoleLabelQuickSetupIntegration(t *testing.T) {
	file := os.Getenv("IQKB_AUTH_TEST_DSN_FILE")
	if file == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
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
	if _, err := db.Exec(`INSERT INTO admin_assignments(tenant_id,object_id,created_at) VALUES(?,?,'now')`, alex.TenantID, alex.ObjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',1)`); err != nil {
		t.Fatal(err)
	}
	request := func(user identity.Principal, method, path string, value any) *httptest.ResponseRecorder {
		body, _ := json.Marshal(value)
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
		rec := httptest.NewRecorder()
		authenticate(fixedTokenVerifier{user}, db, true, postgresAuthHandler(db, key, pg)).ServeHTTP(rec, req)
		return rec
	}
	mapping := postgres.AdapterConfig{Mode: "application_rules", Schema: "iqkb_auth", Relation: "permission_directory", Columns: &postgres.AuthorizationColumns{Email: "email", UserID: "id", Role: "role", Active: "enabled"}}
	input := postgresQuickSetupInput{Mapping: mapping, Email: alex.VerifiedEmail, Resources: []roleTableSelection{{Schema: "iqkb_data", Relation: "app_documents", Roles: []string{"Reader", "Editor"}}}}
	if rec := request(alex, "POST", "/api/admin/postgres/auth/labels", mapping); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"roles":["Editor","Reader"]`) || !strings.Contains(rec.Body.String(), `"currentRole":"Reader"`) {
		t.Fatalf("labels=%d %s", rec.Code, rec.Body.String())
	}
	if adapter, _ := loadPostgresAdapter(db); adapter != nil {
		t.Fatal("discovery saved configuration")
	}
	if rec := request(blair, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 403 {
		t.Fatal("ordinary user configured role access")
	}
	input.Email = "wrong@example.com"
	if rec := request(alex, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 403 {
		t.Fatal("mismatched email configured access")
	}
	input.Email = alex.VerifiedEmail
	input.Resources[0].Roles = []string{"Reader", "invented-role"}
	if rec := request(alex, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 400 {
		t.Fatal("undetected role accepted")
	}
	input.Resources[0].Roles = []string{"Reader", "Editor"}
	// Supplying rules/claims cannot override server-selected fields or tenant.
	input.Mapping.Claims = map[string]string{"fake": "hidden"}
	input.Mapping.TenantScope = "attacker-tenant"
	input.Mapping.Rules = []authorization.Rule{{Label: "*", Schema: "iqkb_data", Relation: "service_secret", Fields: []string{"id"}, Scope: authorization.Scope{Kind: "all"}, Reviewed: true}}
	if rec := request(alex, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 200 {
		t.Fatalf("quick setup=%d %s", rec.Code, rec.Body.String())
	}
	adapter, err := loadPostgresAdapter(db)
	if err != nil || !adapter.RoleLabelAccess || adapter.TenantScope != alex.TenantID || len(adapter.Claims) > 0 || len(adapter.Rules) != 2 {
		t.Fatalf("wrong policy: %#v %v", adapter, err)
	}
	tools, err := postgres.Catalog(db)
	if err != nil || len(tools) != 1 || !postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools) {
		t.Fatal("one validated user did not make the table policy ready")
	}
	var profile postgres.BusinessProfile
	if json.Unmarshal(tools[0].ProfileConfig, &profile) != nil {
		t.Fatal("profile missing")
	}
	if profile.KeyColumn != "id" || profile.Capability != "text_search" || slices.Contains(adapter.Rules[0].Fields, "details") {
		t.Fatal("unsafe or unrecognized automatic fields")
	}
	scoped, login, password, err := postgresAccess(t.Context(), db, key, pg, alex)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := scoped.SearchProfile(t.Context(), login, password, "Shared title", 5, profile)
	if err != nil || len(rows) != 2 {
		t.Fatalf("explicit all-row role policy=%d %v", len(rows), err)
	}
	ready := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/api/admin/postgres/readiness", nil)
	req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	authenticate(fixedTokenVerifier{alex}, db, true, postgresReadinessHandler(db, key, pg)).ServeHTTP(ready, req)
	if !strings.Contains(ready.Body.String(), `"ready":true`) {
		t.Fatalf("not ready: %s", ready.Body.String())
	}
	before := adapter.Fingerprint()
	input.Resources[0].Relation = "service_secret" // no existing unique key or search field
	if rec := request(alex, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 400 {
		t.Fatal("unsupported table accepted")
	}
	after, _ := loadPostgresAdapter(db)
	if after.Fingerprint() != before {
		t.Fatal("failed setup changed the previous working policy")
	}
	input.Resources[0].Relation = "app_documents"
	input.Resources[0].Roles = []string{"Reader"}
	if rec := request(alex, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 200 {
		t.Fatal("role revocation failed")
	}
	newAdapter, _ := loadPostgresAdapter(db)
	other, err := pg.ForSubject(*newAdapter, postgres.Subject{TenantID: blair.TenantID, ObjectID: blair.ObjectID, Email: blair.VerifiedEmail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = other.ResolveIdentity(t.Context(), "adapter_user", "adapter"); postgres.AuthorizationFailureCode(err) != "application_permission_rules_required" {
		t.Fatal("removed label retained search access")
	}
	// An existing reviewed own-row policy must not be silently broadened.
	newAdapter.RoleLabelAccess = false
	newAdapter.Rules[0].Scope = authorization.Scope{Kind: "user", Column: "owner_id"}
	if rec := request(alex, "PUT", "/api/admin/postgres/auth", newAdapter); rec.Code != 200 {
		t.Fatal("advanced save failed")
	}
	if rec := request(alex, "POST", "/api/admin/postgres/auth/quick-setup", input); rec.Code != 409 || !strings.Contains(rec.Body.String(), "advanced_permissions_preserved") {
		t.Fatal("quick setup broadened advanced permissions")
	}
}
