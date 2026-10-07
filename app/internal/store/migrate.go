package store

import (
	"database/sql"
	"embed"
	"fmt"
	"regexp"
	"strings"
)

//go:embed migrations/*.sql
var migrations embed.FS

var guid = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const latestSchemaVersion = 9

func SeedAdmin(db *sql.DB, tenantID, objectID string) error {
	if !guid.MatchString(tenantID) || !guid.MatchString(objectID) {
		return fmt.Errorf("tenant and initial administrator IDs must be GUIDs")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	var seeded int
	err = tx.QueryRow(`SELECT 1 FROM settings WHERE key='initial_admin_seeded'`).Scan(&seeded)
	if err == nil {
		return tx.Commit()
	}
	if err != sql.ErrNoRows {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT OR IGNORE INTO admin_assignments(tenant_id, object_id, created_at) VALUES (?, ?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, strings.ToLower(tenantID), strings.ToLower(objectID)); err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.Exec(`INSERT INTO settings(key, value) VALUES ('initial_admin_seeded', x'31')`); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func Migrate(db *sql.DB) error {
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)`); err != nil {
		return err
	}
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&version); err != nil {
		return err
	}
	if version > latestSchemaVersion {
		return fmt.Errorf("database schema version %d is newer than this application supports (latest %d)", version, latestSchemaVersion)
	}
	for next := version + 1; next <= latestSchemaVersion; next++ {
		script, err := migrations.ReadFile(fmt.Sprintf("migrations/%03d_%s.sql", next, migrationName(next)))
		if err != nil {
			return err
		}
		tx, err := db.Begin()
		if err != nil {
			return err
		}
		for _, statement := range strings.Split(string(script), ";") {
			if strings.TrimSpace(statement) == "" {
				continue
			}
			if _, err := tx.Exec(statement); err != nil {
				_ = tx.Rollback()
				return fmt.Errorf("apply migration %d: %w", next, err)
			}
		}
		if _, err := tx.Exec(`INSERT INTO schema_migrations(version, applied_at) VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ','now'))`, next); err != nil {
			_ = tx.Rollback()
			return err
		}
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func migrationName(version int) string {
	switch version {
	case 1:
		return "initial"
	case 2:
		return "user_postgres"
	case 3:
		return "operator_provider_key"
	case 4:
		return "model_attempt_budget"
	case 5:
		return "audit_created_at_index"
	case 6:
		return "postgres_mapping_profiles"
	case 7:
		return "postgres_profile_test_generations"
	case 8:
		return "audit_event_capacity"
	case 9:
		return "postgres_auth_adapter"
	default:
		return "unknown"
	}
}
