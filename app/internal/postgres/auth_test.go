package postgres

import "testing"

func TestAdapterRejectsUnreviewedOrUnsafeConfiguration(t *testing.T) {
	good := AdapterConfig{Mode: "postgres_role", Schema: "iqkb_auth", Relation: "users", ApprovalRecord: "review-1"}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []AdapterConfig{
		{Mode: "application_rules", PermissionSource: "guess", Schema: "public", Relation: "users", ApprovalRecord: "ticket"},
		{Mode: "postgres_role", PermissionSource: "internal", Schema: "public", Relation: "users", ApprovalRecord: "ticket"},
		{Mode: "ignore_permissions", Schema: "public", Relation: "users", ApprovalRecord: "ticket"},
		{Mode: "postgres_role", Schema: "public; DROP TABLE users", Relation: "users", ApprovalRecord: "ticket"},
		{Mode: "session_context", Schema: "public", Relation: "users"},
	} {
		if bad.Validate() == nil {
			t.Fatalf("unsafe adapter accepted: %#v", bad)
		}
	}
	connector, err := Open(t.Context(), "postgres://service:secret@localhost:1/company?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if !connector.SharedCredentialsConfigured() {
		t.Fatal("service credentials discarded")
	}
	for _, subject := range []Subject{{TenantID: "tenant", ObjectID: "object"}, {Email: "person@example.com", ObjectID: "object"}, {Email: "person@example.com", TenantID: "tenant"}} {
		if _, err := connector.ForSubject(good, subject); err == nil {
			t.Fatal("untrusted subject accepted")
		}
	}
}
