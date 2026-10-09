package postgres

import (
	"slices"
	"testing"

	"iq-kbteams/internal/authorization"
)

func TestRoleLabelPolicyCannotRelaxAdvancedVerification(t *testing.T) {
	a := AdapterConfig{Mode: "application_rules", RoleLabelAccess: true, Schema: "custom", Relation: "accounts", ApprovalRecord: "review", Rules: []authorization.Rule{{Label: "Operators", Schema: "custom", Relation: "documents", Fields: []string{"key", "caption"}, Scope: authorization.Scope{Kind: "all"}, Reviewed: true}}}
	if a.Validate() != nil || a.RequiredProfileTestUsers() != 1 {
		t.Fatal("table policy requires a second user")
	}
	for _, change := range []func(*AdapterConfig){
		func(a *AdapterConfig) { a.PermissionSource = "external" },
		func(a *AdapterConfig) { a.Mode = "postgres_role" },
		func(a *AdapterConfig) { a.Claims = map[string]string{"department": "department"} },
		func(a *AdapterConfig) { a.Rules[0].Scope = authorization.Scope{Kind: "user", Column: "owner"} },
		func(a *AdapterConfig) { a.Rules[0].Reviewed = false },
	} {
		bad := a
		bad.Rules = append([]authorization.Rule(nil), a.Rules...)
		change(&bad)
		if bad.Validate() == nil || bad.RequiredProfileTestUsers() != 2 {
			t.Fatal("advanced policy bypassed verification")
		}
	}
}

func TestRoleProfileUsesMetadataAndExcludesSensitiveStructuredFields(t *testing.T) {
	p := roleSearchProfile("schema.with.dot", "arbitrary_relation", "record_key", []string{"record_key", "caption", "password_hash", "payload", "count"}, []string{"int8", "text", "text", "jsonb", "int4"})
	if p == nil || p.KeyColumn != "record_key" || p.LabelColumn != "caption" || p.Schema != "schema.with.dot" {
		t.Fatal("metadata not recognized")
	}
	fields := RoleSearchFields(*p)
	if slices.Contains(fields, "password_hash") || slices.Contains(fields, "payload") || len(fields) != 3 {
		t.Fatal("unsafe fields in automatic profile")
	}
	if roleSearchProfile("s", "r", "", []string{"caption"}, []string{"text"}) != nil || roleSearchProfile("s", "r", "key", []string{"key", "count"}, []string{"int8", "int4"}) != nil {
		t.Fatal("invented missing key or search field")
	}
}
