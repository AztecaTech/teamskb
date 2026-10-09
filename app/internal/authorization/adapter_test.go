package authorization

import (
	"context"
	"errors"
	"testing"
)

func TestApplicationRulesRequireTrustedIdentityAndExplicitPermissions(t *testing.T) {
	rule := Rule{Label: "custom reviewer", Schema: "business", Relation: "items", Fields: []string{"id", "title"}, Scope: Scope{Kind: "claim", Column: "organization", Claim: "organization"}, Reviewed: true}
	adapter, err := NewRegistry().Create("application_rules", []Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	id := Identity{ID: "person-1", Email: "person@example.com", TenantID: "tenant", Label: rule.Label, Revision: "v1", Claims: map[string]string{"organization": "org-1"}}
	resource := Resource{Namespace: rule.Schema, Name: rule.Relation, Fields: []string{"id", "title"}}
	if decision, err := adapter.Authorize(t.Context(), id, resource); err != nil || decision.Delegated || decision.Scope.Claim != "organization" {
		t.Fatalf("valid explicit rule: %#v %v", decision, err)
	}
	for _, label := range []string{"admin", "user", "Custom reviewer", "unknown"} {
		other := id
		other.Label = label
		if _, err := adapter.Authorize(t.Context(), other, resource); !errors.Is(err, ErrDenied) {
			t.Fatalf("invented privilege for %q", label)
		}
	}
	for _, field := range []string{"hidden", "organization"} {
		other := resource
		other.Fields = []string{field}
		if _, err := adapter.Authorize(t.Context(), id, other); !errors.Is(err, ErrDenied) {
			t.Fatalf("unreviewed field %q allowed", field)
		}
	}
	for _, missing := range []string{"id", "email", "tenant", "revision", "claim"} {
		other := id
		switch missing {
		case "id":
			other.ID = ""
		case "email":
			other.Email = ""
		case "tenant":
			other.TenantID = ""
		case "revision":
			other.Revision = ""
		case "claim":
			other.Claims = nil
		}
		if _, err := adapter.Authorize(t.Context(), other, resource); !errors.Is(err, ErrDenied) {
			t.Fatalf("missing trusted %s allowed", missing)
		}
	}
	rule.Reviewed = false
	unreviewed, _ := NewRegistry().Create("application_rules", []Rule{rule})
	if _, err := unreviewed.Authorize(t.Context(), id, resource); !errors.Is(err, ErrDenied) {
		t.Fatal("draft granted access")
	}
	rule.Scope = Scope{Kind: "pending"}
	pending, _ := NewRegistry().Create("application_rules", []Rule{rule})
	if _, err := pending.Authorize(t.Context(), id, resource); !errors.Is(err, ErrDenied) {
		t.Fatal("pending scope granted access")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := adapter.Authorize(ctx, id, resource); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation ignored")
	}
}

func TestAdaptersRejectUnsupportedProvidersAndScopes(t *testing.T) {
	r := NewRegistry()
	if _, err := r.Create("unreviewed_native_api", nil); err == nil {
		t.Fatal("unsupported provider enabled")
	}
	if err := r.Register("database_policy", func([]Rule) (Adapter, error) { return databaseAdapter{}, nil }); err == nil {
		t.Fatal("duplicate registration accepted")
	}
	if err := r.Register("custom", func([]Rule) (Adapter, error) { return databaseAdapter{}, nil }); err != nil {
		t.Fatal(err)
	}
	adapter, _ := r.Create("custom", nil)
	if _, err := adapter.Authorize(t.Context(), Identity{}, Resource{}); !errors.Is(err, ErrDenied) {
		t.Fatal("unverified database policy trusted")
	}
	if d, err := adapter.Authorize(t.Context(), Identity{DatabasePolicyVerified: true}, Resource{Fields: []string{"id"}}); err != nil || !d.Delegated {
		t.Fatal("verified policy denied")
	}
	for _, scope := range []Scope{{Kind: "json_visibility"}, {Kind: "pending"}, {Kind: "membership", Column: "team", Membership: &Membership{Schema: "business"}}, {Kind: "all", Column: "owner"}} {
		rule := Rule{Label: "custom", Schema: "business", Relation: "items", Fields: []string{"id"}, Scope: scope, Reviewed: true}
		if _, err := r.Create("application_rules", []Rule{rule}); err == nil {
			t.Fatalf("invalid reviewed scope accepted: %#v", scope)
		}
	}
}
