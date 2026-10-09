package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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

type workflowNativePermissions struct {
	revision string
	denied   bool
}

func (s *workflowNativePermissions) Fingerprint() string { return "workflow-native-permissions" }
func (s *workflowNativePermissions) Resolve(_ context.Context, subject authorization.PermissionSubject) (authorization.ResolvedPermissions, error) {
	if s.denied {
		return authorization.ResolvedPermissions{}, errors.New("permission_source_denied")
	}
	return authorization.ResolvedPermissions{Revision: s.revision, ClaimColumns: map[string]string{"native_owner": "id"}, Rules: []authorization.Rule{{Label: subject.Label, Schema: "iqkb_data", Relation: "app_documents", Fields: []string{"id", "title", "content"}, Scope: authorization.Scope{Kind: "claim", Column: "owner_id", Claim: "native_owner"}, Reviewed: true}}}, nil
}

func TestPostgresAdapterAutomaticWorkflowIntegration(t *testing.T) {
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
	source := &workflowNativePermissions{revision: "native-v1"}
	pg = pg.WithPermissionSource(source)
	key := bytes.Repeat([]byte{0x56}, 32)
	db := readyWorkflowDB(t, key)
	alex := identity.Principal{TenantID: "tenant-one", ObjectID: "22345678-1234-4234-9234-123456789abc", VerifiedEmail: "app-alex@example.com"}
	blair := identity.Principal{TenantID: alex.TenantID, ObjectID: "32345678-1234-4234-9234-123456789abc", VerifiedEmail: "app-blair@example.com"}
	if _, err = db.Exec(`INSERT INTO admin_assignments(tenant_id,object_id,created_at) VALUES(?,?,'now')`, alex.TenantID, alex.ObjectID); err != nil {
		t.Fatal(err)
	}
	request := func(handler http.Handler, method, path string, input any) *httptest.ResponseRecorder {
		var body []byte
		if input != nil {
			body, _ = json.Marshal(input)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	authHandler := authenticate(fixedTokenVerifier{alex}, db, true, postgresAuthHandler(db, key, pg))
	// No operator fields or scopes. An obsolete saved claim must also be ignored.
	adapter := postgres.AdapterConfig{Mode: "application_rules", PermissionSource: "external", Schema: "iqkb_auth", Relation: "permission_directory", Claims: map[string]string{"obsolete": "absent_column"}, Columns: &postgres.AuthorizationColumns{UserID: "id", Email: "email", Role: "role", Active: "enabled"}}
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", adapter); rec.Code != 200 {
		t.Fatalf("save mapping=%d %s", rec.Code, rec.Body.String())
	}
	preview := request(authHandler, "GET", "/api/admin/postgres/auth/permissions", nil)
	var selected postgres.PermissionPreview
	if json.Unmarshal(preview.Body.Bytes(), &selected) != nil || preview.Code != 200 || selected.Label != "Reader" || len(selected.Rules) != 1 || !selected.Rules[0].Reviewed || selected.ClaimColumns["native_owner"] != "id" {
		t.Fatalf("native selection=%d %s", preview.Code, preview.Body.String())
	}
	if strings.Contains(preview.Body.String(), "Alex scoped content") || strings.Contains(preview.Body.String(), "app-alex") || strings.Contains(preview.Body.String(), "hidden") {
		t.Fatal("preview exposed business rows or user attribute values")
	}
	adapter.Rules, adapter.Claims = selected.Rules, selected.ClaimColumns
	if rec := request(authHandler, "PUT", "/api/admin/postgres/auth", adapter); rec.Code != 200 {
		t.Fatal("saving automatic summary failed")
	}
	saved, err := loadPostgresAdapter(db)
	if err != nil || saved == nil || len(saved.Rules) != 0 || len(saved.Claims) != 0 {
		t.Fatal("native user snapshot was persisted as a manual permission grant")
	}
	ordinary := authenticate(fixedTokenVerifier{blair}, db, true, postgresAuthHandler(db, key, pg))
	if rec := request(ordinary, "GET", "/api/admin/postgres/auth/permissions", nil); rec.Code != 403 {
		t.Fatal("ordinary account accessed administrator permission preview")
	}
	for _, user := range []identity.Principal{alex, blair} {
		handler := authenticate(fixedTokenVerifier{user}, db, false, postgresEmailHandler(db, key, pg))
		if rec := request(handler, "PUT", "/api/postgres/email", map[string]string{"email": user.VerifiedEmail}); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"connected"`) {
			t.Fatalf("native email authorization=%d %s", rec.Code, rec.Body.String())
		}
	}
	admin := authenticate(fixedTokenVerifier{alex}, db, true, postgresHandler(db, key, pg))
	profile := postgres.BusinessProfile{ID: "native_docs", Label: "Documents", Capability: "entity_lookup", Schema: "iqkb_data", Relation: "app_documents", KeyColumn: "id", LabelColumn: "title", SearchColumns: []string{"title"}, ReturnColumns: []postgres.ProfileColumn{{Name: "content", Type: "text"}}}
	if rec := request(admin, "PUT", "/api/admin/postgres/profiles", profile); rec.Code != 200 {
		t.Fatalf("native profile=%d %s", rec.Code, rec.Body.String())
	}
	tools, err := postgres.Catalog(db)
	if err != nil || len(tools) != 1 {
		t.Fatal("native profile catalog missing")
	}
	for index, user := range []identity.Principal{alex, blair} {
		handler := authenticate(fixedTokenVerifier{user}, db, false, postgresProfileTestHandler(db, key, pg))
		if rec := request(handler, "POST", "/api/postgres/profiles/native_docs/test", nil); rec.Code != 200 {
			t.Fatalf("native profile evidence=%d %s", rec.Code, rec.Body.String())
		}
		if ready := postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools); ready != (index == 1) {
			t.Fatal("native profile two-user gate incorrect")
		}
	}
	source.revision = "native-v2"
	if postgresProfilesReady(t.Context(), db, pg, alex.TenantID, tools) {
		t.Fatal("native permission revision retained stale profile evidence")
	}
	source.denied = true
	if rec := request(authHandler, "GET", "/api/admin/postgres/auth/permissions", nil); rec.Code != 424 || !strings.Contains(rec.Body.String(), "permission_source_denied") || strings.Contains(rec.Body.String(), `"rules"`) {
		t.Fatalf("native revocation ignored=%d %s", rec.Code, rec.Body.String())
	}
	if _, err := pg.WithPermissionSource(nil).ForSubject(*saved, postgres.Subject{TenantID: alex.TenantID, ObjectID: alex.ObjectID, Email: alex.VerifiedEmail}); postgres.AuthorizationFailureCode(err) != "permission_source_not_configured" {
		t.Fatal("disconnected native source fell back to a saved user snapshot")
	}
}

func TestExternalPermissionsNotConfiguredNeedsNoDatabase(t *testing.T) {
	request := httptest.NewRequest("GET", "/api/admin/postgres/auth/permissions", nil)
	response := httptest.NewRecorder()
	postgresAuthHandler(nil, nil, nil).ServeHTTP(response, request)
	if response.Code != 503 || !strings.Contains(response.Body.String(), `"error":"postgres_not_configured"`) {
		t.Fatal("missing database was not reported without opening a connection")
	}
}
