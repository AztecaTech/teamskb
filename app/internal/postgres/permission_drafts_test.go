package postgres

import (
	"strings"
	"testing"
)

func TestPermissionDraftRequiresReviewAndExplicitFields(t *testing.T) {
	draft := PermissionDraft{Label: "custom-label", ExecutionRole: SuggestedExecutionRole("custom-label"), Resources: []ResourcePermission{{Schema: "example", Relation: "records", Scope: "pending"}}}
	if err := ValidatePermissionDrafts([]PermissionDraft{draft}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := CompilePermissionDrafts([]PermissionDraft{draft}); err == nil {
		t.Fatal("unreviewed draft granted access")
	}
	draft.Resources[0] = ResourcePermission{Schema: "example", Relation: "records", Fields: []string{"id", "owner_id", "title"}, Scope: "user", UserColumn: "owner_id", Reviewed: true}
	sql, err := CompilePermissionDrafts([]PermissionDraft{draft})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sql, "AS RESTRICTIVE") || !strings.Contains(sql, "current_setting('iqkb.user_id', true)") || strings.Contains(sql, "GRANT SELECT ON") || !strings.Contains(sql, "NOSUPERUSER NOBYPASSRLS NOINHERIT") {
		t.Fatal("deployment omitted scope or field restrictions")
	}
	draft.Resources[0].Fields = append(draft.Resources[0].Fields, "refreshTokenHash")
	if _, err := CompilePermissionDrafts([]PermissionDraft{draft}); err == nil {
		t.Fatal("credential field accepted")
	}
}

func TestPermissionDraftRejectsDuplicateRoleAndSQLIdentifiers(t *testing.T) {
	draft := PermissionDraft{Label: "anything", ExecutionRole: SuggestedExecutionRole("anything")}
	if ValidatePermissionDrafts([]PermissionDraft{draft, draft}, false) == nil {
		t.Fatal("duplicate roles accepted")
	}
	draft.ExecutionRole = "x;RESET ROLE"
	if ValidatePermissionDrafts([]PermissionDraft{draft}, false) == nil {
		t.Fatal("SQL identifier injection accepted")
	}
}
