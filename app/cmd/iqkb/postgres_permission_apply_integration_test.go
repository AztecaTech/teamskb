package main

import (
	"bytes"
	"context"
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

func TestPostgresAdapterApplyWorkflowIntegration(t *testing.T) {
	file := os.Getenv("IQKB_AUTH_TEST_DSN_FILE")
	if file == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	dsn := strings.TrimSpace(string(raw))
	adminDSN := strings.Replace(dsn, "iqkb_service:IQKB-test-service-only", "postgres:IQKB-test-admin-only", 1)
	pg, err := postgres.Open(t.Context(), adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(t.Context(), adminDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	if _, err = admin.Exec(t.Context(), `CREATE SCHEMA iqkb_apply_test;
CREATE TABLE iqkb_apply_test.records(id text,title text,content text,source_url text,owner_id text,private_note text);
INSERT INTO iqkb_apply_test.records VALUES('alex-row','Policy','Alex only','https://example.com/alex','alex','hidden'),('blair-row','Policy','Blair only','https://example.com/blair','blair','hidden');
GRANT USAGE ON SCHEMA iqkb_apply_test TO iqkb_service;
GRANT SELECT(id,title,content,source_url,owner_id) ON iqkb_apply_test.records TO iqkb_service;`); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x66}, 32)
	db := readyWorkflowDB(t, key)
	alex := identity.Principal{TenantID: "tenant-one", ObjectID: "22345678-1234-4234-9234-123456789abc", VerifiedEmail: "app-alex@example.com"}
	blair := identity.Principal{TenantID: alex.TenantID, ObjectID: "32345678-1234-4234-9234-123456789abc", VerifiedEmail: "app-blair@example.com"}
	if _, err = db.Exec(`INSERT INTO admin_assignments(tenant_id,object_id,created_at) VALUES(?,?,'now')`, alex.TenantID, alex.ObjectID); err != nil {
		t.Fatal(err)
	}
	request := func(handler http.Handler, method, path string, body any) *httptest.ResponseRecorder {
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	auth := authenticate(fixedTokenVerifier{alex}, db, true, postgresAuthHandler(db, key, pg))
	adapter := postgres.AdapterConfig{Mode: "postgres_role", Schema: "iqkb_auth", Relation: "permission_directory", Columns: &postgres.AuthorizationColumns{Email: "email", UserID: "id", Role: "role", Active: "enabled"}}
	if rec := request(auth, "PUT", "/api/admin/postgres/auth", adapter); rec.Code != 200 {
		t.Fatalf("save: %s", rec.Body.String())
	}
	emailHandler := authenticate(fixedTokenVerifier{alex}, db, false, postgresEmailHandler(db, key, pg))
	if rec := request(emailHandler, "PUT", "/api/postgres/email", map[string]string{"email": alex.VerifiedEmail}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "matched_permissions_required") {
		t.Fatalf("recognition: %s", rec.Body.String())
	}
	drafts := []postgres.PermissionDraft{{Label: "Reader", ExecutionRole: "iqkb_apply_reader", Resources: []postgres.ResourcePermission{{Schema: "iqkb_apply_test", Relation: "records", Fields: []string{"id", "title", "content", "source_url", "owner_id"}, Scope: "user", UserColumn: "owner_id", Reviewed: true}}}}
	previewResponse := request(auth, "POST", "/api/admin/postgres/auth/permission-drafts/preview", drafts)
	if previewResponse.Code != 200 {
		t.Fatalf("preview: %s", previewResponse.Body.String())
	}
	var review permissionApplyRequest
	if json.Unmarshal(previewResponse.Body.Bytes(), &review) != nil || review.PreviewToken == "" {
		t.Fatal("preview lacked signed review")
	}
	review.Drafts = drafts
	review.AcknowledgeImpact = true
	denied := authenticate(fixedTokenVerifier{blair}, db, true, postgresAuthHandler(db, key, pg))
	if rec := request(denied, "POST", "/api/admin/postgres/auth/permission-drafts/apply", review); rec.Code != 403 {
		t.Fatal("non-administrator deployed roles")
	}
	unsigned := review
	unsigned.PreviewToken = strings.Repeat("0", 64)
	if rec := request(auth, "POST", "/api/admin/postgres/auth/permission-drafts/apply", unsigned); rec.Code != 424 || !strings.Contains(rec.Body.String(), "permission_preview_changed_or_expired") {
		t.Fatalf("unsigned deployment: %s", rec.Body.String())
	}
	var exists bool
	if err = admin.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='iqkb_apply_reader')`).Scan(&exists); err != nil || exists {
		t.Fatal("unsigned deployment created role")
	}
	// Read access alone does not authorize database setup, and no partial role
	// or RLS change may survive a failed application.
	service, err := postgres.Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err = service.ApplyPermissionDrafts(t.Context(), drafts, func(string) bool { return true }); postgres.PermissionDeploymentFailureCode(err) != "database_setup_privileges_required" {
		t.Fatalf("service setup error: %v", err)
	}
	if rec := request(auth, "POST", "/api/admin/postgres/auth/permission-drafts/apply", review); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"accessStatus":"connected"`) {
		t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
	}
	saved, err := loadPostgresAdapter(db)
	if err != nil || saved.RoleMappings["Reader"] != "iqkb_apply_reader" {
		t.Fatal("installed label translation not saved")
	}
	scoped, login, password, err := postgresAccess(t.Context(), db, key, pg, alex)
	if err != nil {
		t.Fatalf("previously confirmed email did not reconnect: %v", err)
	}
	tool := postgres.QueryTool{ID: "apply_policy", Version: 1, Description: "Policies", SQL: `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_apply_test.records WHERE title ILIKE '%' || $1 || '%' LIMIT $2`, ApprovalRecord: "fixture-review", Parameters: []postgres.QueryParameter{{Name: "question", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}}, OutputColumns: []string{"id:text", "title:text", "content:text", "source_url:text"}}
	docs, err := scoped.Search(t.Context(), login, password, "Policy", 5, tool)
	if err != nil || len(docs) != 1 || docs[0].ID != "alex-row" {
		t.Fatalf("applied mapping leaked rows or failed: %#v %v", docs, err)
	}
	tool.SQL = `SELECT id::text AS id,title::text AS title,private_note::text AS content,source_url::text AS source_url FROM iqkb_apply_test.records WHERE title ILIKE '%' || $1 || '%' LIMIT $2`
	if scoped.CheckToolAccess(t.Context(), login, password, tool) == nil {
		t.Fatal("unselected field readable")
	}
	unmapped, err := pg.ForSubject(*saved, postgres.Subject{TenantID: blair.TenantID, ObjectID: blair.ObjectID, Email: blair.VerifiedEmail})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = unmapped.ResolveIdentity(t.Context(), "adapter_user", "adapter"); postgres.AuthorizationFailureCode(err) != "application_role_mapping_required" {
		t.Fatal("pending label inherited installed label permissions")
	}
	if rec := request(auth, "POST", "/api/admin/postgres/auth/permission-drafts/apply", review); rec.Code != 409 {
		t.Fatalf("stale adapter review accepted: %s", rec.Body.String())
	}
	// Installing a reviewed mapping never confirms an email that the user has
	// not already entered and matched, even for the installing administrator.
	freshDB := readyWorkflowDB(t, key)
	if _, err = freshDB.Exec(`INSERT INTO admin_assignments(tenant_id,object_id,created_at) VALUES(?,?,'now')`, alex.TenantID, alex.ObjectID); err != nil {
		t.Fatal(err)
	}
	freshAuth := authenticate(fixedTokenVerifier{alex}, freshDB, true, postgresAuthHandler(freshDB, key, pg))
	if rec := request(freshAuth, "PUT", "/api/admin/postgres/auth", adapter); rec.Code != 200 {
		t.Fatal(rec.Body.String())
	}
	unconfirmedDraft := []postgres.PermissionDraft{{Label: "Reader", ExecutionRole: "iqkb_apply_unconfirmed", Resources: drafts[0].Resources}}
	previewResponse = request(freshAuth, "POST", "/api/admin/postgres/auth/permission-drafts/preview", unconfirmedDraft)
	if previewResponse.Code != 200 {
		t.Fatal(previewResponse.Body.String())
	}
	var freshReview permissionApplyRequest
	if json.Unmarshal(previewResponse.Body.Bytes(), &freshReview) != nil {
		t.Fatal("invalid fresh preview")
	}
	freshReview.Drafts = unconfirmedDraft
	freshReview.AcknowledgeImpact = true
	if rec := request(freshAuth, "POST", "/api/admin/postgres/auth/permission-drafts/apply", freshReview); rec.Code != 200 || !strings.Contains(rec.Body.String(), `"accessStatus":"database_email_confirmation_required"`) {
		t.Fatalf("installation bypassed initial email confirmation: %s", rec.Body.String())
	}
	if _, _, _, err = postgresAccess(t.Context(), freshDB, key, pg, alex); err != errPostgresEmailConfirmationRequired {
		t.Fatalf("unconfirmed installation granted access: %v", err)
	}
}
