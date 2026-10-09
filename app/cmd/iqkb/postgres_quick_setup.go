package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"iq-kbteams/internal/authorization"
	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

type roleTableSelection struct {
	Schema   string   `json:"schema"`
	Relation string   `json:"relation"`
	Roles    []string `json:"roles"`
}

type postgresQuickSetupInput struct {
	Mapping   postgres.AdapterConfig `json:"mapping"`
	Email     string                 `json:"email"`
	Resources []roleTableSelection   `json:"resources"`
}

// Rebuild the policy from identity mapping and explicit table/role selections.
// Browser-supplied rules, claims, SQL, tenant and approval records are discarded.
func roleLabelMapping(input postgres.AdapterConfig, principal identity.Principal) postgres.AdapterConfig {
	adapter := postgres.AdapterConfig{Mode: "application_rules", PermissionSource: postgres.InternalPermissionSource, RoleLabelAccess: true, Schema: input.Schema, Relation: input.Relation, Columns: input.Columns, ApprovalRecord: "Administrator " + principal.ObjectID + " selected table access at " + time.Now().UTC().Format(time.RFC3339)}
	if adapter.Columns != nil && adapter.Columns.TenantID == "" {
		adapter.TenantScope = principal.TenantID
	}
	return adapter
}

func postgresLabelDiscoveryHandler(pg *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		input, decodeErr := httpx.DecodeOne[postgres.AdapterConfig](body)
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		adapter := roleLabelMapping(input, principal)
		if err != nil || decodeErr != nil || adapter.Validate() != nil {
			jsonResponse(w, 400, `{"error":"invalid_adapter"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		scoped, err := scopePostgresAdapter(pg, adapter, principal)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": postgresAccessFailureCode(err, "database_mapping_required")})
			return
		}
		labels, matched, err := scoped.DiscoverApplicationLabels(ctx)
		if err != nil {
			writeJSON(w, 424, map[string]string{"error": postgres.AuthorizationFailureCode(err)})
			return
		}
		writeJSON(w, 200, map[string]any{"roles": labels, "currentRole": matched.ApplicationRole})
	}
}

func postgresQuickSetupHandler(db *sql.DB, pg *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		input, decodeErr := httpx.DecodeOne[postgresQuickSetupInput](body)
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		if err != nil || decodeErr != nil || len(input.Resources) == 0 || len(input.Resources) > 20 {
			jsonResponse(w, 400, `{"error":"select_search_tables"}`)
			return
		}
		if !validVerifiedEmail(principal.VerifiedEmail) || strings.ToLower(strings.TrimSpace(input.Email)) != strings.ToLower(strings.TrimSpace(principal.VerifiedEmail)) {
			jsonResponse(w, 403, `{"error":"database_email_mismatch"}`)
			return
		}
		before, err := loadPostgresAdapter(db)
		if err != nil {
			jsonResponse(w, 503, `{"error":"adapter_unavailable"}`)
			return
		}
		// Never silently replace an existing scoped or native policy with table access.
		if before != nil && !before.RoleLabelAccess {
			if before.Mode != "application_rules" || before.UsesExternalPermissions() || slices.ContainsFunc(before.Rules, func(rule authorization.Rule) bool { return rule.Reviewed }) {
				jsonResponse(w, 409, `{"error":"advanced_permissions_preserved"}`)
				return
			}
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		adapter := roleLabelMapping(input.Mapping, principal)
		scoped, err := scopePostgresAdapter(pg, adapter, principal)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": postgresAccessFailureCode(err, "database_mapping_required")})
			return
		}
		labels, matched, err := scoped.DiscoverApplicationLabels(ctx)
		if err != nil {
			writeJSON(w, 424, map[string]string{"error": postgres.AuthorizationFailureCode(err)})
			return
		}
		profiles, err := prepareRoleTables(ctx, pg, &adapter, input.Resources, labels, matched.ApplicationRole)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": err.Error()})
			return
		}
		scoped, err = scopePostgresAdapter(pg, adapter, principal)
		if err != nil {
			jsonResponse(w, 400, `{"error":"invalid_table_access"}`)
			return
		}
		tools := []postgres.QueryTool{}
		for _, profile := range profiles {
			var current int
			err = db.QueryRowContext(ctx, `SELECT version FROM query_tools WHERE tool_id=?`, profile.ID).Scan(&current)
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				jsonResponse(w, 503, `{"error":"query_catalog_unavailable"}`)
				return
			}
			profile.Version = current + 1
			profile.Approval = adapter.ApprovalRecord
			profile.SchemaFingerprint, err = scoped.ProfileSchemaFingerprint(ctx, "adapter_user", "adapter", profile)
			if err == nil {
				err = testBusinessProfile(ctx, scoped, "adapter_user", "adapter", profile)
			}
			if err != nil {
				writeJSON(w, 424, map[string]string{"error": "table_access_check_failed", "table": profile.Schema + "." + profile.Relation})
				return
			}
			query, compileErr := postgres.CompileBusinessProfile(profile)
			raw, _ := json.Marshal(profile)
			tool := postgres.QueryTool{ID: profile.ID, Version: profile.Version, Description: profile.Label, SQL: query, Parameters: postgres.ProfileParameters(profile), OutputColumns: postgres.ProfileOutputColumns(profile), ApprovalRecord: profile.Approval, ProfileConfig: raw}
			if compileErr != nil || postgres.ValidateQueryTool(tool) != nil {
				jsonResponse(w, 400, `{"error":"table_search_unsupported"}`)
				return
			}
			tools = append(tools, tool)
		}
		current, err := scoped.ResolveIdentity(ctx, "adapter_user", "adapter")
		if err != nil || current.UserID != matched.UserID || current.Role != matched.Role || current.PermissionVersion != matched.PermissionVersion {
			jsonResponse(w, 409, `{"error":"profile_test_stale"}`)
			return
		}
		if err = saveRoleTableSetup(ctx, db, principal, before, adapter, current, tools); err != nil {
			jsonResponse(w, 409, `{"error":"setup_changed_retry"}`)
			return
		}
		writeJSON(w, 200, map[string]any{"status": "connected", "adapter": adapter, "role": current.ApplicationRole, "tables": len(tools)})
	}
}

func prepareRoleTables(ctx context.Context, pg *postgres.Connector, adapter *postgres.AdapterConfig, selections []roleTableSelection, labels []string, currentRole string) ([]postgres.BusinessProfile, error) {
	selected := map[[2]string][]string{}
	for _, item := range selections {
		key := [2]string{item.Schema, item.Relation}
		if len(item.Roles) == 0 || selected[key] != nil || key == [2]string{adapter.Schema, adapter.Relation} {
			return nil, errors.New("select_table_roles")
		}
		if !slices.Contains(item.Roles, currentRole) {
			return nil, errors.New("include_your_role_for_access_check")
		}
		for i, role := range item.Roles {
			if !slices.Contains(labels, role) || slices.Contains(item.Roles[:i], role) {
				return nil, errors.New("unknown_or_duplicate_role")
			}
		}
		selected[key] = item.Roles
	}
	profiles := []postgres.BusinessProfile{}
	afterSchema, afterName := "", ""
	for pages := 0; pages < 40; pages++ {
		page, err := pg.DiscoverPermissionResources(ctx, afterSchema, afterName)
		if err != nil {
			return nil, errors.New("table_metadata_unavailable")
		}
		for _, item := range page.Resources {
			key := [2]string{item.Schema, item.Relation}
			roles := selected[key]
			if roles == nil {
				continue
			}
			if item.SearchProfile == nil {
				return nil, errors.New("table_search_unsupported")
			}
			profile := *item.SearchProfile
			profiles = append(profiles, profile)
			for _, role := range roles {
				adapter.Rules = append(adapter.Rules, authorization.Rule{Label: role, Schema: item.Schema, Relation: item.Relation, Fields: postgres.RoleSearchFields(profile), Scope: authorization.Scope{Kind: "all"}, Reviewed: true})
			}
			delete(selected, key)
		}
		if len(selected) == 0 {
			return profiles, adapter.Validate()
		}
		if page.NextSchema == "" {
			break
		}
		afterSchema, afterName = page.NextSchema, page.NextName
	}
	return nil, errors.New("selected_table_not_found")
}

// All persistence is in IQ Knowledge's SQLite store, atomically after checks.
// The external PostgreSQL connector has only performed read-only transactions.
func saveRoleTableSetup(ctx context.Context, db *sql.DB, principal identity.Principal, before *postgres.AdapterConfig, adapter postgres.AdapterConfig, user postgres.ResolvedIdentity, tools []postgres.QueryTool) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var old []byte
	err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='postgres_auth_adapter'`).Scan(&old)
	if before == nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return errors.New("adapter changed")
		}
	} else {
		var current postgres.AdapterConfig
		if err != nil || json.Unmarshal(old, &current) != nil || current.Fingerprint() != before.Fingerprint() {
			return errors.New("adapter changed")
		}
	}
	raw, _ := json.Marshal(adapter)
	if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES('postgres_auth_adapter',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, raw); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM postgres_adapter_profile_tests`); err != nil {
		return err
	}
	// Replace the search catalog for this explicit table policy. This is local
	// application configuration; it never removes anything in PostgreSQL.
	if _, err = tx.ExecContext(ctx, `DELETE FROM query_tools`); err != nil {
		return err
	}
	for _, tool := range tools {
		params, _ := json.Marshal(tool.Parameters)
		outputs, _ := json.Marshal(tool.OutputColumns)
		if _, err = tx.ExecContext(ctx, `INSERT INTO query_tools(tool_id,version,description,fixed_sql,parameter_schema,output_columns,approval_record,profile_config) VALUES(?,?,?,?,?,?,?,?)`, tool.ID, tool.Version, tool.Description, tool.SQL, params, outputs, tool.ApprovalRecord, tool.ProfileConfig); err != nil {
			return err
		}
		var profile postgres.BusinessProfile
		if err = json.Unmarshal(tool.ProfileConfig, &profile); err != nil {
			return err
		}
		fingerprint, err := postgres.ProfileFingerprint(profile)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO postgres_adapter_profile_tests(tenant_id,object_id,email,tool_id,profile_generation,adapter_generation,user_id,database_role,permission_version,tested_at,outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail, tool.ID, fingerprint, adapter.Fingerprint(), user.UserID, user.Role, user.PermissionVersion, time.Now().UTC().Format(time.RFC3339Nano), "passed"); err != nil {
			return err
		}
	}
	for _, prefix := range []string{"", "match:"} {
		if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, prefix+databaseEmailKey(principal), strings.ToLower(strings.TrimSpace(principal.VerifiedEmail))+":"+adapter.Fingerprint()); err != nil {
			return err
		}
	}
	return tx.Commit()
}
