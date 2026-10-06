package store

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func migrationDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)
	return db
}

func TestMigrateCreatesSchemaAndIsIdempotent(t *testing.T) {
	db := migrationDB(t)
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("second migration: %v", err)
	}
	var version, count int
	if err := db.QueryRow(`SELECT MAX(version), COUNT(*) FROM schema_migrations`).Scan(&version, &count); err != nil {
		t.Fatal(err)
	}
	if version != latestSchemaVersion || count != latestSchemaVersion {
		t.Fatalf("migration versions: latest=%d rows=%d", version, count)
	}
	var tables int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('settings','admin_assignments','identity_bindings','encrypted_secrets','audit_events','audit_event_state','model_attempt_counters')`).Scan(&tables); err != nil {
		t.Fatal(err)
	}
	if tables != 7 {
		t.Fatalf("migrated schema has %d expected tables", tables)
	}
	var auditIndex int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='audit_events_created_at_idx'`).Scan(&auditIndex); err != nil || auditIndex != 1 {
		t.Fatalf("audit timestamp index count=%d err=%v", auditIndex, err)
	}
}

func TestAuditCapacityMigrationCountsExistingEvents(t *testing.T) {
	db := migrationDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	script, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(script), ";") {
		if strings.TrimSpace(statement) != "" {
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(`INSERT INTO audit_events(event_id,created_at,request_id,actor_id,action,outcome,details) VALUES('legacy','2026-10-01T00:00:00Z','request','tenant:user','private_ask','answered',x'7b7d')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(1,'now')`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT event_count FROM audit_event_state WHERE id=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("legacy audit count=%d err=%v", count, err)
	}
}

func TestMigrateAddsAuditIndexToSchemaVersionFour(t *testing.T) {
	db := migrationDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 4; version++ {
		script, err := migrations.ReadFile("migrations/" + fmt.Sprintf("%03d_%s.sql", version, migrationName(version)))
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range strings.Split(string(script), ";") {
			if strings.TrimSpace(statement) != "" {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?, 'now')`, version); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(db); err != nil {
		t.Fatalf("upgrade from schema 4: %v", err)
	}
	var indexCount, version int
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='audit_events_created_at_idx'`).Scan(&indexCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT MAX(version) FROM schema_migrations`).Scan(&version); err != nil {
		t.Fatal(err)
	}
	if indexCount != 1 || version != latestSchemaVersion {
		t.Fatalf("after schema 4 upgrade: index count=%d schema version=%d", indexCount, version)
	}
}

func TestMigrateRemovesLegacySharedRoleMode(t *testing.T) {
	db := migrationDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	script, err := migrations.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(script), ";") {
		if strings.TrimSpace(statement) != "" {
			if _, err := db.Exec(statement); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(1,'now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_role,reviewed_by,reviewed_at) VALUES('tenant','user','person@example.test','','admin','now')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','public.iqkb_knowledge',1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO query_tools(tool_id,version,fixed_sql,parameter_schema,output_columns,approval_record) VALUES('knowledge_search',1,'SELECT 1','[]','[]','builtin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO encrypted_secrets(secret_id,ciphertext,nonce,updated_at) VALUES('model_api_key',x'01',x'02','now')`); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	var databaseIdentity string
	if err := db.QueryRow(`SELECT database_identity FROM identity_bindings WHERE tenant_id='tenant' AND object_id='user'`).Scan(&databaseIdentity); err != nil || databaseIdentity != "" {
		t.Fatalf("legacy binding identity=%q err=%v", databaseIdentity, err)
	}
	for _, query := range []string{
		`SELECT 1 FROM source_boundaries WHERE source_id='user-postgres'`,
		`SELECT 1 FROM query_tools WHERE tool_id='knowledge_search'`,
		`SELECT 1 FROM encrypted_secrets WHERE secret_id='model_api_key'`,
	} {
		var value int
		if err := db.QueryRow(query).Scan(&value); err != sql.ErrNoRows {
			t.Fatalf("legacy shared-role config survived migration: %s err=%v", query, err)
		}
	}
}

func TestMigrateRejectsDatabaseFromNewerApplication(t *testing.T) {
	db := migrationDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?, 'now')`, latestSchemaVersion+1); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(db); err == nil {
		t.Fatal("newer schema version was accepted")
	}
	if _, err := db.Exec(`SELECT * FROM settings`); err == nil {
		t.Fatal("unsupported schema was partially migrated")
	}
}

func TestPostgresLoginClaimsPreserveLegacyDuplicatesAndSeedUnambiguousMappings(t *testing.T) {
	db := migrationDB(t)
	if _, err := db.Exec(`CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	for version := 1; version <= 5; version++ {
		script, err := migrations.ReadFile("migrations/" + fmt.Sprintf("%03d_%s.sql", version, migrationName(version)))
		if err != nil {
			t.Fatal(err)
		}
		for _, statement := range strings.Split(string(script), ";") {
			if strings.TrimSpace(statement) != "" {
				if _, err := db.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
		}
		if _, err := db.Exec(`INSERT INTO schema_migrations(version,applied_at) VALUES(?, 'now')`, version); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range [][3]string{{"a", "a@example.test", "legacy"}, {"b", "b@example.test", "legacy"}, {"c", "c@example.test", "unique_login"}} {
		if _, err := db.Exec(`INSERT INTO identity_bindings(tenant_id,object_id,verified_email,database_identity,reviewed_by,reviewed_at) VALUES(?,?,?,?,?,?)`, "t", row[0], row[1], row[2], "admin", "now"); err != nil {
			t.Fatal(err)
		}
	}
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	var bindings, claims int
	if err := db.QueryRow(`SELECT COUNT(*) FROM identity_bindings WHERE database_identity='legacy'`).Scan(&bindings); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM postgres_login_claims WHERE database_identity='legacy'`).Scan(&claims); err != nil {
		t.Fatal(err)
	}
	if bindings != 2 || claims != 0 {
		t.Fatalf("legacy ambiguity changed: bindings=%d claims=%d", bindings, claims)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM postgres_login_claims WHERE database_identity='unique_login'`).Scan(&claims); err != nil || claims != 1 {
		t.Fatalf("unique login claim count=%d err=%v", claims, err)
	}
}
