package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestSharedPostgresReportsAdapterBeforeMissingEmail(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	db := readyWorkflowDB(t, key)
	if _, err := db.Exec(`UPDATE source_boundaries SET enabled=0`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',1)`); err != nil {
		t.Fatal(err)
	}
	pg, err := postgres.Open(t.Context(), "postgres://service:secret@localhost:1/db?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	principal := identity.Principal{TenantID: "tenant", ObjectID: "object"}
	state, err := checkEnabledSourceAccess(t.Context(), db, key, "assertion", "unused", pg, principal)
	if state != "postgres_adapter_required" || !errors.Is(err, errPostgresAdapterRequired) {
		t.Fatalf("state=%s err=%v", state, err)
	}
	adapter := postgres.AdapterConfig{Mode: "postgres_role", Schema: "auth", Relation: "users", ApprovalRecord: "ticket"}
	raw, _ := json.Marshal(adapter)
	if _, err := db.Exec(`INSERT INTO settings(key,value) VALUES('postgres_auth_adapter',?)`, raw); err != nil {
		t.Fatal(err)
	}
	state, err = checkEnabledSourceAccess(t.Context(), db, key, "assertion", "unused", pg, principal)
	if state != "postgres_verified_email_required" || !errors.Is(err, errPostgresEmailRequired) {
		t.Fatalf("state=%s err=%v", state, err)
	}
}
