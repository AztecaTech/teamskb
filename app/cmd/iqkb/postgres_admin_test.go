package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
	"iq-kbteams/internal/store"
)

func TestPostgresIdentityMappingRejectsDuplicateLoginAndNonAdminAccess(t *testing.T) {
	db := testDB(t)
	tenant := "12345678-1234-4234-9234-123456789abc"
	admin := identity.Principal{TenantID: tenant, ObjectID: "22345678-1234-4234-9234-123456789abc"}
	firstObject := "32345678-1234-4234-9234-123456789abc"
	secondObject := "42345678-1234-4234-9234-123456789abc"
	if err := store.SeedAdmin(db, tenant, admin.ObjectID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, tenant, firstObject, "first@example.test", "shared_login", "admin", "reviewed"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO postgres_login_claims(tenant_id,database_identity,object_id) VALUES(?,?,?)`, tenant, "shared_login", firstObject); err != nil {
		t.Fatal(err)
	}
	pg, err := postgres.Open(t.Context(), "postgres://localhost:1/fixture?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	handler := authenticate(fixedTokenVerifier{admin}, db, true, postgresHandler(db, make([]byte, 32), pg))
	request := httptest.NewRequest(http.MethodPut, "/api/admin/postgres/identities", strings.NewReader(`{"objectId":"`+secondObject+`","verifiedEmail":"second@example.test","databaseIdentity":"shared_login"}`))
	request.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("duplicate LOGIN mapping status=%d body=%s", response.Code, response.Body.String())
	}
	var mappings, claims int
	if err := db.QueryRow(`SELECT COUNT(*) FROM identity_bindings WHERE tenant_id=? AND database_identity=?`, tenant, "shared_login").Scan(&mappings); err != nil || mappings != 1 {
		t.Fatalf("duplicate LOGIN mappings=%d err=%v", mappings, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM postgres_login_claims WHERE tenant_id=? AND database_identity=? AND object_id=?`, tenant, "shared_login", firstObject).Scan(&claims); err != nil || claims != 1 {
		t.Fatalf("original LOGIN claim count=%d err=%v", claims, err)
	}

	nonAdmin := identity.Principal{TenantID: tenant, ObjectID: secondObject}
	nonAdminHandler := authenticate(fixedTokenVerifier{nonAdmin}, db, true, postgresHandler(db, nil, pg))
	list := httptest.NewRequest(http.MethodGet, "/api/admin/postgres/identities", nil)
	list.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	denied := httptest.NewRecorder()
	nonAdminHandler.ServeHTTP(denied, list)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("non-admin identity list status=%d body=%s", denied.Code, denied.Body.String())
	}
}

func TestStorePostgresCredentialRejectsAChangedIdentityBinding(t *testing.T) {
	db := testDB(t)
	principal := identity.Principal{
		TenantID:      "12345678-1234-4234-9234-123456789abc",
		ObjectID:      "22345678-1234-4234-9234-123456789abc",
		VerifiedEmail: "user@example.test",
	}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail, "new_login", "admin", "2026-10-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}

	err := storePostgresCredential(context.Background(), db, make([]byte, 32), principal, "old_login", "synthetic-password")
	if !errors.Is(err, errIdentityBindingChanged) {
		t.Fatalf("stale binding error=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM encrypted_secrets WHERE secret_id=?`, postgresSecretID(principal.TenantID, principal.ObjectID)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale credential was persisted: count=%d", count)
	}
}

func TestStaleProfileTestCannotRestoreEvidenceAfterCredentialRotation(t *testing.T) {
	db := testDB(t)
	principal := identity.Principal{TenantID: "12345678-1234-4234-9234-123456789abc", ObjectID: "22345678-1234-4234-9234-123456789abc", VerifiedEmail: "user@example.test"}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail, "current_login", "admin", "review-1"); err != nil {
		t.Fatal(err)
	}
	profile := postgres.BusinessProfile{ID: "asset_lookup", Version: 1, Label: "Asset", Capability: "entity_lookup", Schema: "ops", Relation: "assets", KeyColumn: "id", LabelColumn: "name", SearchColumns: []string{"name"}, ReturnColumns: []postgres.ProfileColumn{{Name: "state", Type: "text"}}, Approval: "ticket-1", SchemaFingerprint: strings.Repeat("a", 64)}
	config, _ := json.Marshal(profile)
	query, _ := postgres.CompileBusinessProfile(profile)
	params, _ := json.Marshal([]postgres.QueryParameter{{Name: "term", Type: "text"}, {Name: "limit", Type: "integer[1,5]"}})
	outputs, _ := json.Marshal(postgres.ProfileOutputColumns(profile))
	if _, err := db.Exec(`INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config) VALUES(?,?,?,?,?,?,?,?)`, profile.ID, profile.Version, profile.Label, query, params, outputs, profile.Approval, config); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if err := storePostgresCredential(context.Background(), db, key, principal, "current_login", "first-password"); err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := loadProfileTestSnapshot(context.Background(), db, key, principal, profile.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE encrypted_secrets SET updated_at='rotated-after-snapshot' WHERE secret_id=?`, postgresSecretID(principal.TenantID, principal.ObjectID)); err != nil {
		t.Fatal(err)
	}
	if err := saveProfileTestEvidence(context.Background(), db, snapshot, "passed", ""); !errors.Is(err, errProfileTestStale) {
		t.Fatalf("stale evidence save error=%v", err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM postgres_profile_tests`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("stale profile test restored evidence rows: %d", count)
	}
}

func TestStorePostgresCredentialPersistsForCurrentIdentityBinding(t *testing.T) {
	db := testDB(t)
	principal := identity.Principal{
		TenantID:      "12345678-1234-4234-9234-123456789abc",
		ObjectID:      "22345678-1234-4234-9234-123456789abc",
		VerifiedEmail: "user@example.test",
	}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail, "current_login", "admin", "2026-10-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if err := storePostgresCredential(context.Background(), db, key, principal, "current_login", "synthetic-password"); err != nil {
		t.Fatal(err)
	}
	if got, err := loadPostgresPassword(db, key, principal.TenantID, principal.ObjectID); err != nil || got != "synthetic-password" {
		t.Fatalf("stored password=%q err=%v", got, err)
	}
}
