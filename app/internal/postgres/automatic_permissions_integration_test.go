package postgres

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"iq-kbteams/internal/authorization"
)

type fixtureNativePermissionSource struct {
	revision string
	deny     bool
	calls    int
}

func (s *fixtureNativePermissionSource) Fingerprint() string { return "fixture-native-source" }
func (s *fixtureNativePermissionSource) Resolve(_ context.Context, subject authorization.PermissionSubject) (authorization.ResolvedPermissions, error) {
	s.calls++
	if s.deny {
		return authorization.ResolvedPermissions{}, errors.New("permission_source_denied")
	}
	return authorization.ResolvedPermissions{Revision: s.revision, ClaimColumns: map[string]string{"native_owner": "id"}, Rules: []authorization.Rule{{Label: subject.Label, Schema: "iqkb_data", Relation: "app_documents", Fields: []string{"id", "title", "content"}, Scope: authorization.Scope{Kind: "claim", Column: "owner_id", Claim: "native_owner"}, Reviewed: true}}}, nil
}
func TestPostgresAdapterAutomaticPermissionsIntegration(t *testing.T) {
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
	source := &fixtureNativePermissionSource{revision: "native-v1"}
	connector = connector.WithPermissionSource(source)
	// No manual readable fields or row scope have been supplied by the operator.
	adapter := AdapterConfig{Mode: "application_rules", Schema: "iqkb_auth", Relation: "permission_directory", TenantScope: "tenant-one", ApprovalRecord: "fixture", Columns: &AuthorizationColumns{Email: "email", UserID: "id", Role: "role", Active: "enabled"}}
	profile := BusinessProfile{ID: "native_records", Version: 1, Label: "Records", Capability: "text_search", SearchStrategy: "keyword", Schema: "iqkb_data", Relation: "app_documents", KeyColumn: "id", LabelColumn: "title", SearchColumns: []string{"title"}, ReturnColumns: []ProfileColumn{{Name: "content", Type: "text"}}, Approval: "fixture"}
	for _, name := range []string{"alex", "blair"} {
		c, err := connector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: name, Email: "app-" + name + "@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		preview, err := c.PreviewAutomaticPermissions(t.Context())
		if err != nil || len(preview.Rules) != 1 || preview.ClaimColumns["native_owner"] != "id" || preview.Rules[0].Scope.Kind != "claim" {
			t.Fatalf("automatic preview missing: %#v %v", preview, err)
		}
		p := profile
		p.SchemaFingerprint, err = c.ProfileSchemaFingerprint(t.Context(), "unused", "unused", p)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := c.SearchProfile(t.Context(), "unused", "unused", "Shared", 5, p)
		if err != nil || len(rows) != 1 || rows[0].ID != name+"-app" {
			t.Fatalf("native isolation failed: %#v %v", rows, err)
		}
		page, err := c.Discover(t.Context(), "unused", "unused", "", "")
		if err != nil || len(page.Relations) != 1 || len(page.Columns) != 3 {
			t.Fatal("automatic permission discovery not scoped")
		}
		before, err := c.ResolveIdentity(t.Context(), "unused", "unused")
		if err != nil {
			t.Fatal(err)
		}
		source.revision = "native-v2"
		after, err := c.ResolveIdentity(t.Context(), "unused", "unused")
		if err != nil || before.PermissionVersion == after.PermissionVersion {
			t.Fatal("native revision did not invalidate profile evidence")
		}
		source.deny = true
		// A stale manual all-row rule must never override a native denial.
		fallback := adapter
		fallback.Rules = []authorization.Rule{{Label: before.ApplicationRole, Schema: "iqkb_data", Relation: "app_documents", Fields: []string{"id", "title", "content"}, Scope: authorization.Scope{Kind: "all"}, Reviewed: true}}
		blocked, _ := connector.ForSubject(fallback, Subject{TenantID: "tenant-one", ObjectID: name, Email: "app-" + name + "@example.com"})
		if _, err := blocked.SearchProfile(t.Context(), "unused", "unused", "Shared", 5, p); err == nil {
			t.Fatal("manual fallback bypassed native denial")
		}
		source.deny = false
		source.revision = "native-v1"
	}
	if source.calls < 8 {
		t.Fatal("native permissions were not rechecked")
	}
}
