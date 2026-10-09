package postgres

import (
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresAdapterReadOnlyIntegration(t *testing.T) {
	dsn := integrationValue(t, "IQKB_AUTH_TEST_DSN_FILE", "")
	if dsn == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	// Even privileged URI credentials used for metadata/bootstrap must enter a
	// read-only transaction. These attempts target only the disposable fixture.
	metadata, err := Open(t.Context(), strings.Replace(dsn, "iqkb_service:IQKB-test-service-only", "postgres:IQKB-test-admin-only", 1))
	if err != nil {
		t.Fatal(err)
	}
	metadata.metadataOnly = true
	for _, statement := range []string{
		`CREATE TABLE iqkb_auth.iqkb_forbidden_table(id integer)`,
		`ALTER TABLE iqkb_auth.users ADD COLUMN iqkb_forbidden_column integer`,
		`ALTER TABLE iqkb_data.documents DISABLE ROW LEVEL SECURITY`,
		`CREATE ROLE iqkb_forbidden_role NOLOGIN`,
		`GRANT SELECT ON iqkb_auth.users TO iqkb_alex`,
		`CREATE POLICY iqkb_forbidden_policy ON iqkb_auth.users USING (true)`,
		`INSERT INTO iqkb_auth.users(tenant_id,email,user_id,database_role,active,permission_version) VALUES('tenant-one','forbidden@example.com','forbidden','iqkb_alex',true,'v1')`,
		`UPDATE iqkb_auth.users SET active=false`,
		`DELETE FROM iqkb_auth.users`,
	} {
		t.Run(statement, func(t *testing.T) {
			conn, tx, _, err := metadata.beginAuthorized(t.Context(), metadata.service.User, metadata.service.Password)
			if err != nil {
				t.Fatal(err)
			}
			defer closeConnection(conn)
			defer tx.Rollback(t.Context())
			var mode string
			if err = tx.QueryRow(t.Context(), `SELECT current_setting('transaction_read_only')`).Scan(&mode); err != nil || mode != "on" {
				t.Fatalf("connection was not read-only: %s %v", mode, err)
			}
			_, err = tx.Exec(t.Context(), statement)
			var failure *pgconn.PgError
			if !errors.As(err, &failure) || failure.Code != "25006" {
				t.Fatalf("PostgreSQL did not prohibit mutation: %v", err)
			}
		})
	}
	page, err := metadata.DiscoverPermissionResources(t.Context(), "iqkb_data", "")
	if err != nil || len(page.Resources) == 0 {
		t.Fatalf("read-only resource discovery failed: %#v %v", page, err)
	}
}
