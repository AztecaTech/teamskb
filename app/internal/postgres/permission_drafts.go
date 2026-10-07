package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

type PermissionDraft struct {
	Label         string               `json:"label"`
	ExecutionRole string               `json:"executionRole"`
	Resources     []ResourcePermission `json:"resources"`
}
type ResourcePermission struct {
	Schema     string   `json:"schema"`
	Relation   string   `json:"relation"`
	Fields     []string `json:"fields"`
	Scope      string   `json:"scope"`
	UserColumn string   `json:"userColumn,omitempty"`
	Reviewed   bool     `json:"reviewed"`
}

func SuggestedExecutionRole(label string) string {
	hash := sha256.Sum256([]byte(label))
	return "iqkb_mapped_" + hex.EncodeToString(hash[:8])
}

func ValidatePermissionDrafts(drafts []PermissionDraft, deployment bool) error {
	if len(drafts) > 100 {
		return errors.New("too many role drafts")
	}
	labels, roles := map[string]bool{}, map[string]bool{}
	total := 0
	for _, draft := range drafts {
		if strings.TrimSpace(draft.Label) == "" || len(draft.Label) > 256 || labels[draft.Label] || !ValidDatabaseIdentity(draft.ExecutionRole) || roles[draft.ExecutionRole] || len(draft.Resources) > 50 {
			return errors.New("invalid permission draft")
		}
		labels[draft.Label] = true
		roles[draft.ExecutionRole] = true
		if deployment && len(draft.Resources) == 0 {
			return errors.New("role has no reviewed resource rules")
		}
		resources := map[string]bool{}
		total += len(draft.Resources)
		if total > 100 {
			return errors.New("too many resource rules")
		}
		for _, rule := range draft.Resources {
			key := rule.Schema + "\x00" + rule.Relation
			if !ValidDatabaseIdentity(rule.Schema) || !ValidDatabaseIdentity(rule.Relation) || resources[key] || len(rule.Fields) > 32 {
				return errors.New("invalid resource rule")
			}
			resources[key] = true
			if rule.Scope != "all" && rule.Scope != "user" && rule.Scope != "pending" {
				return errors.New("invalid row scope")
			}
			if rule.Scope == "user" && !ValidDatabaseIdentity(rule.UserColumn) {
				return errors.New("user scope requires a mapped user column")
			}
			fields := map[string]bool{}
			for _, field := range rule.Fields {
				if !ValidDatabaseIdentity(field) || fields[field] || SensitiveAuthorizationField(field) {
					return errors.New("invalid or sensitive readable field")
				}
				fields[field] = true
			}
			if deployment && (!rule.Reviewed || len(rule.Fields) == 0 || rule.Scope == "pending" || (rule.Scope == "user" && !fields[rule.UserColumn])) {
				return errors.New("resource fields and row scope require review")
			}
		}
	}
	return nil
}

func SensitiveAuthorizationField(name string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(name, "_", ""))
	for _, signal := range []string{"password", "secret", "token", "backupcode"} {
		if strings.Contains(normalized, signal) {
			return true
		}
	}
	return false
}

// Produce a reviewable deployment artifact, never execute it automatically.
// New roles avoid collisions with existing policies whose OR combination could
// broaden the rules. Every role is read-only and every field is explicit.
func CompilePermissionDrafts(drafts []PermissionDraft) (string, error) {
	return compilePermissionDrafts(drafts, "")
}

func compilePermissionDrafts(drafts []PermissionDraft, grantee string) (string, error) {
	if len(drafts) == 0 {
		return "", errors.New("no permission drafts")
	}
	if err := ValidatePermissionDrafts(drafts, true); err != nil {
		return "", err
	}
	literal := func(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
	var sql strings.Builder
	sql.WriteString("-- Review before execution. Creates NEW restricted roles and enables RLS on selected tables.\n-- Existing policies and application behavior must be reviewed before deployment.\nBEGIN;\n")
	for _, draft := range drafts {
		role := pgx.Identifier{draft.ExecutionRole}.Sanitize()
		sql.WriteString("CREATE ROLE " + role + " NOLOGIN NOSUPERUSER NOBYPASSRLS NOINHERIT;\n")
		if grantee == "" {
			sql.WriteString("DO $iqkb_grant$ BEGIN EXECUTE format('GRANT %I TO %I', " + literal(draft.ExecutionRole) + ", current_user); END $iqkb_grant$;\n")
		} else {
			sql.WriteString("GRANT " + role + " TO " + pgx.Identifier{grantee}.Sanitize() + ";\n")
		}
		for _, rule := range draft.Resources {
			schema := pgx.Identifier{rule.Schema}.Sanitize()
			table := pgx.Identifier{rule.Schema, rule.Relation}.Sanitize()
			fields := []string{}
			for _, field := range rule.Fields {
				fields = append(fields, pgx.Identifier{field}.Sanitize())
			}
			predicate := "true"
			if rule.Scope == "user" {
				predicate = pgx.Identifier{rule.UserColumn}.Sanitize() + "::text = NULLIF(current_setting('iqkb.user_id', true), '')"
			}
			policyHash := sha256.Sum256([]byte(draft.ExecutionRole + "\x00" + rule.Schema + "\x00" + rule.Relation))
			policyName := "iqkb_rule_" + hex.EncodeToString(policyHash[:12])
			policy := pgx.Identifier{policyName}.Sanitize()
			sql.WriteString("GRANT USAGE ON SCHEMA " + schema + " TO " + role + ";\nGRANT SELECT (" + strings.Join(fields, ", ") + ") ON " + table + " TO " + role + ";\nALTER TABLE " + table + " ENABLE ROW LEVEL SECURITY;\nCREATE POLICY " + policy + " ON " + table + " AS RESTRICTIVE FOR SELECT TO " + role + " USING (" + predicate + ");\n")
			// A restrictive rule must be paired with a permissive policy to allow
			// rows. The restrictive rule still constrains existing PUBLIC policies.
			sql.WriteString("CREATE POLICY " + pgx.Identifier{policyName + "_allow"}.Sanitize() + " ON " + table + " FOR SELECT TO " + role + " USING (true);\n")
		}
	}
	sql.WriteString("COMMIT;\n")
	return sql.String(), nil
}

func (c *Connector) PreviewPermissionDrafts(ctx context.Context, drafts []PermissionDraft) (string, error) {
	_, err := CompilePermissionDrafts(drafts)
	if err != nil {
		return "", err
	}
	if !c.SharedCredentialsConfigured() {
		return "", errors.New("shared connection required")
	}
	metadata := *c
	metadata.adapter = nil
	metadata.subject = nil
	metadata.metadataOnly = true
	conn, tx, _, err := metadata.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return "", err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	for _, draft := range drafts {
		var exists bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=$1)`, draft.ExecutionRole).Scan(&exists); err != nil {
			return "", err
		}
		if exists {
			return "", errors.New("deployment requires a new execution role")
		}
		for _, rule := range draft.Resources {
			qualified := pgx.Identifier{rule.Schema, rule.Relation}.Sanitize()
			var table bool
			var publicGrant bool
			err = tx.QueryRow(ctx, `SELECT c.relkind IN ('r','p'),EXISTS(SELECT 1 FROM aclexplode(COALESCE(c.relacl,acldefault('r',c.relowner))) a WHERE a.grantee=0 AND a.privilege_type='SELECT') OR EXISTS(SELECT 1 FROM pg_attribute col CROSS JOIN LATERAL aclexplode(col.attacl) a WHERE col.attrelid=c.oid AND a.grantee=0 AND a.privilege_type='SELECT') FROM pg_class c WHERE c.oid=to_regclass($1)`, qualified).Scan(&table, &publicGrant)
			if err != nil || !table || publicGrant {
				return "", errors.New("resource must be an existing base table without PUBLIC SELECT grants")
			}
			for _, field := range rule.Fields {
				var readable bool
				err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=to_regclass($1) AND a.attname=$2 AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,a.attrelid,a.attnum,'SELECT'))`, qualified, field).Scan(&readable)
				if err != nil || !readable {
					return "", errors.New("resource field is missing or not readable")
				}
			}
		}
	}
	var grantee string
	if err = tx.QueryRow(ctx, `SELECT session_user::text`).Scan(&grantee); err != nil {
		return "", err
	}
	return compilePermissionDrafts(drafts, grantee)
}
