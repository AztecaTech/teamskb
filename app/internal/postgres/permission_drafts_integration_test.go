package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPostgresAdapterDraftDeploymentIntegration(t *testing.T) {
	dsn := integrationValue(t, "IQKB_AUTH_TEST_DSN_FILE", "")
	if dsn == "" {
		t.Skip("run scripts/validate-postgres-auth.ps1")
	}
	connector, err := Open(t.Context(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	adminConfig.User, adminConfig.Password = "postgres", "IQKB-test-admin-only"
	admin, err := pgx.ConnectConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(context.Background())
	_, err = admin.Exec(t.Context(), `CREATE SCHEMA iqkb_rule_test;
GRANT USAGE ON SCHEMA iqkb_rule_test TO iqkb_service;
CREATE TABLE iqkb_rule_test.records(id text,title text,content text,source_url text,owner_id text,private_note text);
INSERT INTO iqkb_rule_test.records VALUES('alex','Policy','Alex text','https://example.com/alex','alex','hidden'),('blair','Policy','Blair text','https://example.com/blair','blair','hidden');
GRANT SELECT(id,title,content,source_url,owner_id) ON iqkb_rule_test.records TO iqkb_service;
CREATE POLICY broad_existing_policy ON iqkb_rule_test.records FOR SELECT TO PUBLIC USING (true);`)
	if err != nil {
		t.Fatal(err)
	}
	drafts := []PermissionDraft{}
	for _, label := range []string{"label-alpha", "label-beta"} {
		drafts = append(drafts, PermissionDraft{Label: label, ExecutionRole: SuggestedExecutionRole(label), Resources: []ResourcePermission{{Schema: "iqkb_rule_test", Relation: "records", Fields: []string{"id", "title", "content", "source_url", "owner_id"}, Scope: "user", UserColumn: "owner_id", Reviewed: true}}})
	}
	preview, err := connector.PreviewPermissionDrafts(t.Context(), drafts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(t.Context(), preview); err != nil {
		t.Fatal(err)
	}
	adapter := AdapterConfig{Mode: "postgres_role", Schema: "iqkb_auth", Relation: "users", ApprovalRecord: "fixture-rule-review", RoleMappings: map[string]string{"iqkb_alex": drafts[0].ExecutionRole, "iqkb_blair": drafts[1].ExecutionRole}}
	tool := validTool()
	tool.SQL = `SELECT id::text AS id,title::text AS title,content::text AS content,source_url::text AS source_url FROM iqkb_rule_test.records WHERE title ILIKE '%' || $1 || '%' LIMIT $2`
	for _, user := range []string{"alex", "blair"} {
		scope, err := connector.ForSubject(adapter, Subject{TenantID: "tenant-one", ObjectID: user, Email: user + "@example.com"})
		if err != nil {
			t.Fatal(err)
		}
		docs, err := scope.Search(t.Context(), "adapter_user", "adapter", "Policy", 5, tool)
		if err != nil || len(docs) != 1 || docs[0].ID != user {
			t.Fatalf("deployed rule leaked rows: %#v %v", docs, err)
		}
		denied := tool
		denied.SQL = `SELECT id::text AS id,title::text AS title,private_note::text AS content,source_url::text AS source_url FROM iqkb_rule_test.records WHERE title=$1 LIMIT $2`
		if scope.CheckToolAccess(t.Context(), "adapter_user", "adapter", denied) == nil {
			t.Fatal("unselected private field was readable")
		}
	}
	if _, err = connector.PreviewPermissionDrafts(t.Context(), drafts); err == nil {
		t.Fatal("existing execution role could be overwritten")
	}
	page, err := connector.DiscoverPermissionResources(t.Context(), "iqkb_rule_test", "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, resource := range page.Resources {
		if resource.Schema == "iqkb_rule_test" && resource.Relation == "records" {
			found = true
		}
	}
	if !found {
		t.Fatal("business resource without email/permission fields was omitted")
	}
	// A failure after role creation must roll back roles, grants and the RLS
	// change, rather than leaving a partially installed permission mapping.
	adminConnector, err := Open(t.Context(), strings.Replace(dsn, "iqkb_service:IQKB-test-service-only", "postgres:IQKB-test-admin-only", 1))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = admin.Exec(t.Context(), `CREATE TABLE iqkb_rule_test.rollback_records(id text)`); err != nil {
		t.Fatal(err)
	}
	rollbackDraft := PermissionDraft{Label: "rollback-label", ExecutionRole: "iqkb_rollback_role", Resources: []ResourcePermission{{Schema: "iqkb_rule_test", Relation: "rollback_records", Fields: []string{"id"}, Scope: "all", Reviewed: true}}}
	policyHash := sha256.Sum256([]byte(rollbackDraft.ExecutionRole + "\x00iqkb_rule_test\x00rollback_records"))
	policyName := "iqkb_rule_" + hex.EncodeToString(policyHash[:12])
	if _, err = admin.Exec(t.Context(), "CREATE POLICY "+pgx.Identifier{policyName}.Sanitize()+" ON iqkb_rule_test.rollback_records USING (true)"); err != nil {
		t.Fatal(err)
	}
	if err = adminConnector.ApplyPermissionDrafts(t.Context(), []PermissionDraft{rollbackDraft}, func(string) bool { return true }); err == nil {
		t.Fatal("colliding policy did not fail application")
	}
	var roleExists, rls bool
	if err = admin.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='iqkb_rollback_role'),relrowsecurity FROM pg_class WHERE oid='iqkb_rule_test.rollback_records'::regclass`).Scan(&roleExists, &rls); err != nil || roleExists || rls {
		t.Fatalf("partial deployment survived rollback: role=%v rls=%v err=%v", roleExists, rls, err)
	}
}
