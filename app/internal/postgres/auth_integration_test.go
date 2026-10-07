package postgres

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPostgresAdapterPermissionsIntegration(t *testing.T) {
	dsn := integrationValue(t, "IQKB_AUTH_TEST_DSN_FILE", "")
	if dsn == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	connector, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	adapter := AdapterConfig{Mode: "postgres_role", Schema: "iqkb_auth", Relation: "users", ApprovalRecord: "fixture-review"}
	tool := validTool()
	tool.SQL = `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_data.documents WHERE title ILIKE '%' || $1 || '%' ORDER BY id LIMIT $2`
	for _, mode := range []string{"postgres_role", "session_context"} {
		adapter.Mode = mode
		for _, user := range []string{"alex", "blair", "alex"} {
			email := user + "@example.com"
			if mode == "session_context" {
				email = "app-" + email
			}
			scoped, err := connector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: user + "-object", Email: email})
			if err != nil {
				t.Fatal(err)
			}
			docs, err := scoped.Search(t.Context(), "adapter_user", "adapter", "Policy", 5, tool)
			if err != nil || len(docs) != 1 || docs[0].ID != user+"-doc" {
				t.Fatalf("%s %s rows=%#v err=%v", mode, user, docs, err)
			}
			if err := scoped.CheckToolAccess(t.Context(), "adapter_user", "adapter", tool); err != nil {
				t.Fatalf("zero-row permission check failed: %v", err)
			}
			deniedTool := tool
			deniedTool.SQL = `SELECT id::text AS id,id::text AS title,id::text AS content,id::text AS source_url FROM iqkb_data.service_secret WHERE id=$1 LIMIT $2`
			if scoped.CheckToolAccess(t.Context(), "adapter_user", "adapter", deniedTool) == nil {
				t.Fatal("zero-row check accepted unauthorized table")
			}
			page, err := scoped.Discover(t.Context(), "adapter_user", "adapter", "", "")
			if err != nil {
				t.Fatal(err)
			}
			for _, relation := range page.Relations {
				if relation.Name == "service_secret" || relation.Schema == "iqkb_auth" {
					t.Fatalf("discovery leaked service privileges: %#v", relation)
				}
			}
			profile := BusinessProfile{ID: "policies", Version: 1, Label: "Policies", Capability: "entity_lookup", Schema: "iqkb_data", Relation: "documents", KeyColumn: "id", LabelColumn: "title", SearchColumns: []string{"title"}, ReturnColumns: []ProfileColumn{{Name: "content", Type: "text"}}, Approval: "fixture-review"}
			fingerprint, err := scoped.ProfileSchemaFingerprint(t.Context(), "adapter_user", "adapter", profile)
			if err != nil {
				t.Fatal(err)
			}
			profile.SchemaFingerprint = fingerprint
			records, err := scoped.SearchProfile(t.Context(), "adapter_user", "adapter", "Policy", 5, profile)
			if err != nil || len(records) != 1 || records[0].ID != user+"-doc" {
				t.Fatalf("profile %s rows=%#v err=%v", user, records, err)
			}
			conn, tx, _, err := scoped.beginAuthorized(t.Context(), "adapter_user", "adapter")
			if err != nil {
				t.Fatal(err)
			}
			if _, err = tx.Exec(t.Context(), `UPDATE iqkb_data.documents SET title='changed'`); err == nil {
				t.Fatal("write allowed")
			}
			var writeError *pgconn.PgError
			if !errors.As(err, &writeError) || writeError.Code != "25006" {
				t.Fatalf("write was not rejected by read-only transaction: %v", err)
			}
			_ = tx.Rollback(t.Context())
			var role, subject string
			if err = conn.QueryRow(t.Context(), `SELECT current_user::text,COALESCE(current_setting('iqkb.user_id',true),'')`).Scan(&role, &subject); err != nil || role != "iqkb_service" || subject != "" {
				t.Fatalf("transaction context leaked: role=%s subject=%s err=%v", role, subject, err)
			}
			closeConnection(conn)
		}
	}
	adapter.Mode = "postgres_role"
	for _, email := range []string{"missing@example.com", "inactive@example.com", "duplicate@example.com", "unsafe@example.com", "service@example.com", "ungranted@example.com"} {
		scoped, _ := connector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: "object", Email: email})
		if _, err := scoped.ResolveIdentity(t.Context(), "adapter_user", "adapter"); err == nil {
			t.Fatalf("unauthorized %s accepted", email)
		}
	}
	applicationAdapter := adapter
	applicationAdapter.Mode = "session_context"
	ownerScope, _ := connector.ForSubject(applicationAdapter, Subject{TenantID: "tenant-one", ObjectID: "owner-object", Email: "owner@example.com"})
	if _, err := ownerScope.ResolveIdentity(t.Context(), "adapter_user", "adapter"); err == nil {
		t.Fatal("application execution role owning tables was accepted")
	}
	scoped, _ := connector.ForSubject(adapter, Subject{TenantID: "other-tenant", ObjectID: "object", Email: "alex@example.com"})
	if _, err := scoped.ResolveIdentity(t.Context(), "adapter_user", "adapter"); err == nil {
		t.Fatal("cross-tenant match accepted")
	}
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.User, adminConfig.Password = "postgres", "IQKB-test-admin-only"
	externalURI, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	params := externalURI.Query()
	params.Set("sslmode", "disable")
	externalURI.RawQuery = params.Encode()
	externalConnector, err := OpenWithMode(t.Context(), externalURI.String(), "external_plaintext")
	if err != nil {
		t.Fatal(err)
	}
	if result, err := externalConnector.DiscoverAuthorization(t.Context(), "", ""); err != nil || len(result.Candidates) == 0 {
		t.Fatalf("external plaintext mapping discovery failed: %v", err)
	}
	for _, email := range []string{"alex@example.com", "blair@example.com"} {
		user, err := externalConnector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: "external-object", Email: email})
		if err != nil {
			t.Fatal(err)
		}
		if documents, err := user.Search(t.Context(), "adapter_user", "adapter", "Policy", 5, tool); err != nil || len(documents) != 1 {
			t.Fatalf("external plaintext authorized search for %s: count=%d err=%v", email, len(documents), err)
		}
	}
	privateService := connector.service.Copy()
	privateService.TLSConfig, privateService.Fallbacks = nil, nil
	privateService.DialFunc = dialPrivatePostgres
	privateServiceConnector := &Connector{template: privateService.Copy(), service: privateService.Copy()}
	privateUser, err := privateServiceConnector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: "alex-object", Email: "alex@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if documents, err := privateUser.Search(t.Context(), "adapter_user", "adapter", "Policy", 5, tool); err != nil || len(documents) != 1 {
		t.Fatalf("private-network user search failed: count=%d err=%v", len(documents), err)
	}
	privateConfig := adminConfig.Copy()
	privateConfig.TLSConfig, privateConfig.Fallbacks = nil, nil
	privateConfig.DialFunc = dialPrivatePostgres
	privateConnector := &Connector{template: privateConfig.Copy(), service: privateConfig.Copy()}
	if result, err := privateConnector.DiscoverAuthorization(t.Context(), "", ""); err != nil || len(result.Candidates) == 0 {
		t.Fatalf("private-network metadata discovery failed: %v", err)
	}
	privateScope, err := privateConnector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: "alex-object", Email: "alex@example.com"})
	if err != nil {
		t.Fatal(err)
	}
	// An administrator URI remains unsuitable for user searches in either mode.
	if _, err := privateScope.ResolveIdentity(t.Context(), "adapter_user", "adapter"); !errors.Is(err, ErrUnsafeDatabaseRole) {
		t.Fatal("private transport bypassed service role restrictions")
	}
	adminConnector := &Connector{template: adminConfig.Copy(), service: adminConfig.Copy()}
	if result, err := adminConnector.DiscoverAuthorization(t.Context(), "", ""); err != nil || len(result.Candidates) == 0 {
		t.Fatalf("administrator-only metadata discovery failed: %v", err)
	}
	if _, err := adminConnector.ResolveIdentity(t.Context(), "postgres", "IQKB-test-admin-only"); !errors.Is(err, ErrUnsafeDatabaseRole) {
		t.Fatal("metadata exception allowed privileged data access")
	}
	admin, err := pgx.ConnectConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	scoped, _ = connector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: "alex-object", Email: "alex@example.com"})
	if _, err = admin.Exec(t.Context(), `UPDATE iqkb_auth.users SET active=false WHERE email='alex@example.com'`); err != nil {
		t.Fatal(err)
	}
	if _, err = scoped.Search(t.Context(), "adapter_user", "adapter", "Policy", 5, tool); err == nil {
		t.Fatal("revoked account still searched")
	}
	if _, err = admin.Exec(t.Context(), `UPDATE iqkb_auth.users SET active=true WHERE email='alex@example.com'; REVOKE iqkb_alex FROM iqkb_service`); err != nil {
		t.Fatal(err)
	}
	if _, err = scoped.Search(t.Context(), "adapter_user", "adapter", "Policy", 5, tool); err == nil {
		t.Fatal("revoked role still searched")
	}
}
