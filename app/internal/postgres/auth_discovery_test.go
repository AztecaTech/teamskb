package postgres

import (
	"context"
	"testing"
)

func TestMetadataSessionRequiresUnchangedAuthenticatedRole(t *testing.T) {
	if !validMetadataSession("postgres", "postgres") {
		t.Fatal("canonical server identity was rejected")
	}
	if validMetadataSession("postgres", "another_role") || validMetadataSession("", "") {
		t.Fatal("changed or empty session identity was accepted")
	}
}

func TestMetadataSetupFailurePreservesStageAndCause(t *testing.T) {
	err := &AuthorizationDiscoveryError{Stage: "session_identity", Cause: context.DeadlineExceeded}
	if DiscoveryFailureStage(err) != "session_identity" || DiscoveryFailureCode(err) != "database_timeout" {
		t.Fatal("setup failure lost its stage or cause")
	}
	err.Cause = ErrMetadataIdentityMismatch
	if DiscoveryFailureCode(err) != "metadata_identity_mismatch" {
		t.Fatal("identity mismatch was reported as a generic connection error")
	}
}

func TestAuthorizationCandidatesRecognizeEmailAliases(t *testing.T) {
	for _, name := range []string{"UserEmail", "email_address", "primary_email", "mail"} {
		page := DiscoveryPage{Relations: []DiscoveredRelation{{Schema: "public", Name: "members"}}, Columns: []DiscoveredColumn{{Schema: "public", Relation: "members", Name: name, DataType: "text"}}}
		candidates := authorizationCandidates(page)
		if len(candidates) != 1 || candidates[0].Ready || len(candidates[0].Columns) != 1 {
			t.Fatalf("alias %s: %#v", name, candidates)
		}
	}
}

func TestAuthorizationCandidatesRequireTheCompleteAdapterContract(t *testing.T) {
	page := DiscoveryPage{Relations: []DiscoveredRelation{{Schema: "auth", Name: "complete"}, {Schema: "auth", Name: "ordinary_users"}}}
	for _, name := range []string{"tenant_id", "email", "user_id", "database_role", "active", "permission_version"} {
		typ := "text"
		if name == "active" {
			typ = "boolean"
		}
		page.Columns = append(page.Columns, DiscoveredColumn{Schema: "auth", Relation: "complete", Name: name, DataType: typ})
	}
	page.Columns = append(page.Columns, DiscoveredColumn{Schema: "auth", Relation: "ordinary_users", Name: "email", DataType: "text"})
	result := authorizationCandidates(page)
	if len(result) != 2 || !result[0].Ready || result[1].Ready || len(result[1].MissingColumns) != 5 {
		t.Fatalf("candidates=%#v", result)
	}
	for i := range page.Columns {
		if page.Columns[i].Relation == "complete" && page.Columns[i].Name == "active" {
			page.Columns[i].DataType = "text"
		}
	}
	if authorizationCandidates(page)[0].Ready {
		t.Fatal("non-boolean account status treated as compatible")
	}
}

func TestPrefilledQueryMeetsReviewedQueryContract(t *testing.T) {
	tool := validTool()
	tool.SQL = `SELECT "id"::text AS id, "title"::text AS title, "content"::text AS content, "source_url"::text AS source_url FROM "company"."documents" WHERE (COALESCE("title"::text, '') || ' ' || COALESCE("content"::text, '')) ILIKE '%' || $1 || '%' ORDER BY "id" LIMIT $2`
	if err := ValidateQueryTool(tool); err != nil {
		t.Fatal(err)
	}
}
