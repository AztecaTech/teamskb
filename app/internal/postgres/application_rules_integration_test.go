package postgres

import (
	"net/url"
	"testing"

	"github.com/jackc/pgx/v5"
	"iq-kbteams/internal/authorization"
)

func TestPostgresAdapterApplicationRulesIntegration(t *testing.T) {
	dsn := integrationValue(t, "IQKB_AUTH_TEST_DSN_FILE", "")
	if dsn == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal("fixture URI invalid")
	}
	u.User = url.UserPassword("postgres", "IQKB-test-admin-only")
	connector, err := Open(t.Context(), u.String())
	if err != nil {
		t.Fatal(err)
	}
	admin, err := pgx.Connect(t.Context(), u.String())
	if err != nil {
		t.Fatal("fixture connection failed")
	}
	defer admin.Close(t.Context())
	unusedSource := &fixtureNativePermissionSource{deny: true}
	connector = connector.WithPermissionSource(unusedSource)
	t.Cleanup(func() {
		if unusedSource.calls != 0 {
			t.Error("internal adapter contacted an external permission source")
		}
	})
	adapter := AdapterConfig{Mode: "application_rules", Schema: "iqkb_auth", Relation: "permission_directory", TenantScope: "tenant-one", ApprovalRecord: "fixture-review", Columns: &AuthorizationColumns{UserID: "id", Email: "email", Role: "role", Active: "enabled"}}
	for _, label := range []string{"Reader", "Editor"} {
		adapter.Rules = append(adapter.Rules, authorization.Rule{Label: label, Schema: "iqkb_data", Relation: "app_documents", Fields: []string{"id", "title", "content"}, Scope: authorization.Scope{Kind: "user", Column: "owner_id"}, Reviewed: true}, authorization.Rule{Label: label, Schema: "iqkb_data", Relation: "app_notes", Fields: []string{"id", "title", "content", "parent_id"}, Scope: authorization.Scope{Kind: "user", Column: "owner_id"}, Reviewed: true})
	}
	subject := func(name string) Subject {
		return Subject{TenantID: "tenant-one", ObjectID: name, Email: "app-" + name + "@example.com"}
	}
	scope := func(a AdapterConfig, name string) *Connector {
		t.Helper()
		c, err := connector.ForSubject(a, subject(name))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	profile := BusinessProfile{ID: "app_docs", Version: 1, Label: "Documents", Capability: "entity_lookup", Schema: "iqkb_data", Relation: "app_documents", KeyColumn: "id", LabelColumn: "title", SearchColumns: []string{"title"}, ReturnColumns: []ProfileColumn{{Name: "content", Type: "text"}}, Approval: "fixture-review"}
	for _, name := range []string{"alex", "blair"} {
		c := scope(adapter, name)
		preview, err := c.PreviewPermissions(t.Context())
		if err != nil || preview.Mode != "internal" || preview.Status != "resolved" || preview.UserID != name || len(preview.Rules) != 2 {
			t.Fatalf("internal permission preview: %#v %v", preview, err)
		}
		for _, rule := range preview.Rules {
			if rule.Label != preview.Label {
				t.Fatal("another label's permission was selected")
			}
		}
		id, err := c.ResolveIdentity(t.Context(), "unused", "unused")
		if err != nil || id.UserID != name || id.Role != id.ApplicationRole {
			t.Fatalf("application identity failed: %#v %v", id, err)
		}
		p := profile
		p.SchemaFingerprint, err = c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.SearchProfile(t.Context(), "unused", "unused", "Shared", 5, p)
		if err != nil || len(rows) != 1 || rows[0].ID != name+"-app" || len(rows[0].Attributes) != 1 {
			t.Fatalf("cross-user or field leakage: %#v %v", rows, err)
		}
		other := "blair-app"
		if name == "blair" {
			other = "alex-app"
		}
		rows, err = c.SearchProfile(t.Context(), "unused", "unused", other, 5, p)
		if err != nil || len(rows) != 0 {
			t.Fatal("other user's exact key was visible")
		}
		page, err := c.Discover(t.Context(), "unused", "unused", "", "")
		if err != nil || len(page.Relations) != 2 || len(page.Keys) != 2 || len(page.Relationships) != 1 {
			t.Fatalf("filtered discovery: %#v %v", page, err)
		}
		for _, col := range page.Columns {
			if col.Name == "hidden" || col.Name == "owner_id" || col.Name == "details" {
				t.Fatal("unreviewed column metadata disclosed")
			}
		}
		if _, err = c.Search(t.Context(), "unused", "unused", "Shared", 5, validTool()); AuthorizationFailureCode(err) != "application_rules_profiles_only" {
			t.Fatal("arbitrary SQL enabled")
		}
		if err = c.CheckToolAccess(t.Context(), "unused", "unused", validTool()); AuthorizationFailureCode(err) != "application_rules_profiles_only" {
			t.Fatal("arbitrary SQL access check enabled")
		}
		conn, tx, _, err := c.beginAuthorized(t.Context(), "unused", "unused")
		if err != nil {
			t.Fatal(err)
		}
		var mode, path string
		err = tx.QueryRow(t.Context(), `SELECT current_setting('transaction_read_only'),current_setting('search_path')`).Scan(&mode, &path)
		if err != nil || mode != "on" || path != "pg_catalog" {
			t.Fatal("unsafe application transaction")
		}
		tx.Rollback(t.Context())
		closeConnection(conn)
	}
	t.Run("hidden search and return fields denied", func(t *testing.T) {
		c := scope(adapter, "alex")
		for _, field := range []string{"hidden", "owner_id", "details"} {
			p := profile
			p.ReturnColumns = []ProfileColumn{{Name: field, Type: "text"}}
			if _, err := c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p); err == nil {
				t.Fatalf("unreviewed field %s allowed", field)
			}
			p = profile
			p.SearchColumns = []string{field}
			if _, err := c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p); err == nil {
				t.Fatal("hidden search field allowed")
			}
		}
	})
	t.Run("unsupported structured fields and views denied", func(t *testing.T) {
		a := adapter
		a.Rules = append([]authorization.Rule(nil), adapter.Rules...)
		a.Rules[0].Fields = append([]string{"details"}, a.Rules[0].Fields...)
		p := profile
		p.ReturnColumns = []ProfileColumn{{Name: "details", Type: "text"}}
		if _, err := scope(a, "alex").ProfileSchemaFingerprint(t.Context(), "unused", "unused", p); err == nil {
			t.Fatal("JSON visibility assumed")
		}
		a.Rules[0].Relation = "app_document_view"
		p = profile
		p.Relation = "app_document_view"
		if _, err := scope(a, "alex").ProfileSchemaFingerprint(t.Context(), "unused", "unused", p); err == nil {
			t.Fatal("unverified view allowed")
		}
	})
	t.Run("email and trusted attributes", func(t *testing.T) {
		for _, kind := range []string{"email", "claim"} {
			a := adapter
			a.Rules = append([]authorization.Rule(nil), adapter.Rules...)
			a.Rules[0].Scope = authorization.Scope{Kind: kind, Column: "owner_email"}
			if kind == "claim" {
				a.Claims = map[string]string{"native_person": "id"}
				a.Rules[0].Scope = authorization.Scope{Kind: kind, Column: "owner_id", Claim: "native_person"}
			}
			c := scope(a, "alex")
			p := profile
			p.SchemaFingerprint, err = c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := c.SearchProfile(t.Context(), "unused", "unused", "Shared", 5, p)
			if err != nil || len(rows) != 1 || rows[0].ID != "alex-app" {
				t.Fatalf("%s isolation failed: %#v %v", kind, rows, err)
			}
		}
	})
	t.Run("membership and live revocation", func(t *testing.T) {
		a := adapter
		a.Rules = append([]authorization.Rule(nil), adapter.Rules...)
		a.Rules[0].Scope = authorization.Scope{Kind: "membership", Column: "group_id", Membership: &authorization.Membership{Schema: "iqkb_data", Relation: "app_groups", UserColumn: "member_id", GroupColumn: "group_id", ActiveColumn: "active", TenantColumn: "tenant"}}
		c := scope(a, "alex")
		p := profile
		p.SchemaFingerprint, err = c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.SearchProfile(t.Context(), "unused", "unused", "Shared", 5, p)
		if err != nil || len(rows) != 1 || rows[0].ID != "alex-app" {
			t.Fatalf("membership/tenant isolation: %#v %v", rows, err)
		}
		if _, err = admin.Exec(t.Context(), `UPDATE iqkb_data.app_groups SET active=false WHERE member_id='alex' AND group_id='group-a'`); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec(t.Context(), `UPDATE iqkb_data.app_groups SET active=true WHERE member_id='alex' AND group_id='group-a'`)
		rows, err = c.SearchProfile(t.Context(), "unused", "unused", "Shared", 5, p)
		if err != nil || len(rows) != 0 {
			t.Fatal("revoked membership retained access")
		}
	})
	t.Run("both parent and child scoped", func(t *testing.T) {
		c := scope(adapter, "alex")
		p := BusinessProfile{ID: "app_notes", Version: 1, Label: "Notes", Capability: "related_list", Schema: "iqkb_data", Relation: "app_notes", KeyColumn: "id", LabelColumn: "title", ReturnColumns: []ProfileColumn{{Name: "content", Type: "text"}}, Approval: "fixture-review", Relationship: &RelatedRelationship{ParentProfileID: "app_docs", ParentSchema: "iqkb_data", ParentRelation: "app_documents", ParentKeyColumn: "id", ParentLabelColumn: "title", ParentSearchColumns: []string{"title"}, ParentKeyType: "text", ChildForeignKey: "parent_id", ChildForeignKeyType: "text", Filters: []ProfileFilter{{Name: "kind", Column: "title", Type: "text", Values: []ProfileFilterValue{{Label: "Note", Value: "Note"}}}}}}
		p.SchemaFingerprint, err = c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p)
		if err != nil {
			t.Fatal(err)
		}
		rows, clarify, err := c.SearchRelatedProfile(t.Context(), "unused", "unused", "Shared title", 5, nil, p)
		if err != nil || clarify != nil || len(rows) != 1 || rows[0].ID != "alex-note" {
			t.Fatalf("parent ambiguity or child leak: %#v %#v %v", rows, clarify, err)
		}
		rows, clarify, err = c.SearchRelatedProfile(t.Context(), "unused", "unused", "blair-app", 5, nil, p)
		if err != nil || clarify != nil || len(rows) != 0 {
			t.Fatal("unauthorized parent resolved")
		}
	})
	t.Run("unmapped labels and inactive users denied", func(t *testing.T) {
		a := adapter
		a.Rules = nil
		preview, err := scope(a, "alex").PreviewPermissions(t.Context())
		if err != nil || preview.Mode != "internal" || preview.Status != "internal_rules_required" || len(preview.Rules) != 0 {
			t.Fatal("unconfigured labels acquired default permissions")
		}
		if _, err := scope(a, "alex").ResolveIdentity(t.Context(), "unused", "unused"); AuthorizationFailureCode(err) != "application_permission_rules_required" {
			t.Fatal("no rules granted access")
		}
		if _, err = admin.Exec(t.Context(), `UPDATE iqkb_auth.users SET active=false WHERE email='app-alex@example.com'`); err != nil {
			t.Fatal(err)
		}
		defer admin.Exec(t.Context(), `UPDATE iqkb_auth.users SET active=true WHERE email='app-alex@example.com'`)
		if _, err := scope(adapter, "alex").ResolveIdentity(t.Context(), "unused", "unused"); AuthorizationFailureCode(err) != "user_inactive" {
			t.Fatal("inactive identity allowed")
		}
	})
}
