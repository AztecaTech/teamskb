package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"maps"
	"net/http"
	"time"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func testAdapterProfile(w http.ResponseWriter, r *http.Request, db *sql.DB, key []byte, pg *postgres.Connector, principal identity.Principal) {
	adapter, err := loadPostgresAdapter(db)
	if err != nil || adapter == nil {
		jsonResponse(w, 409, `{"error":"adapter_required"}`)
		return
	}
	scoped, login, password, err := postgresAccess(r.Context(), db, key, pg, principal)
	if err != nil {
		jsonResponse(w, 409, `{"error":"database_identity_resolution_required"}`)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	resolved, err := scoped.ResolveIdentity(ctx, login, password)
	if err != nil {
		jsonResponse(w, 424, `{"error":"database_authorization_check_failed"}`)
		return
	}
	var raw []byte
	if err = db.QueryRowContext(ctx, `SELECT profile_config FROM query_tools WHERE tool_id=? AND profile_config<>'{}'`, r.PathValue("toolID")).Scan(&raw); err != nil {
		jsonResponse(w, 404, `{"error":"profile_not_found"}`)
		return
	}
	var profile postgres.BusinessProfile
	if json.Unmarshal(raw, &profile) != nil {
		jsonResponse(w, 409, `{"error":"invalid_profile"}`)
		return
	}
	fingerprint, err := postgres.ProfileFingerprint(profile)
	if err != nil {
		jsonResponse(w, 409, `{"error":"invalid_profile"}`)
		return
	}
	outcome := "passed"
	if testBusinessProfile(ctx, scoped, login, password, profile) != nil {
		outcome = "failed"
	}
	current, err := scoped.ResolveIdentity(ctx, login, password)
	if err != nil || current.UserID != resolved.UserID || current.Role != resolved.Role || current.ApplicationRole != resolved.ApplicationRole || current.PermissionVersion != resolved.PermissionVersion || !maps.Equal(current.Claims, resolved.Claims) {
		jsonResponse(w, 409, `{"error":"profile_test_stale"}`)
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		jsonResponse(w, 503, `{"error":"unavailable"}`)
		return
	}
	defer tx.Rollback()
	var adapterRaw, profileRaw []byte
	if tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='postgres_auth_adapter'`).Scan(&adapterRaw) != nil || tx.QueryRowContext(ctx, `SELECT profile_config FROM query_tools WHERE tool_id=?`, profile.ID).Scan(&profileRaw) != nil {
		jsonResponse(w, 409, `{"error":"profile_test_stale"}`)
		return
	}
	var currentAdapter postgres.AdapterConfig
	var currentProfile postgres.BusinessProfile
	if json.Unmarshal(adapterRaw, &currentAdapter) != nil || json.Unmarshal(profileRaw, &currentProfile) != nil {
		jsonResponse(w, 409, `{"error":"profile_test_stale"}`)
		return
	}
	currentFingerprint, _ := postgres.ProfileFingerprint(currentProfile)
	if currentAdapter.Fingerprint() != adapter.Fingerprint() || currentFingerprint != fingerprint {
		jsonResponse(w, 409, `{"error":"profile_test_stale"}`)
		return
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO postgres_adapter_profile_tests(tenant_id,object_id,email,tool_id,profile_generation,adapter_generation,user_id,database_role,permission_version,tested_at,outcome) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,object_id,tool_id) DO UPDATE SET email=excluded.email,profile_generation=excluded.profile_generation,adapter_generation=excluded.adapter_generation,user_id=excluded.user_id,database_role=excluded.database_role,permission_version=excluded.permission_version,tested_at=excluded.tested_at,outcome=excluded.outcome`, principal.TenantID, principal.ObjectID, principal.VerifiedEmail, profile.ID, fingerprint, adapter.Fingerprint(), resolved.UserID, resolved.Role, resolved.PermissionVersion, time.Now().UTC().Format(time.RFC3339Nano), outcome)
	if err != nil || tx.Commit() != nil {
		jsonResponse(w, 503, `{"error":"profile_test_not_saved"}`)
		return
	}
	status := 200
	if outcome != "passed" {
		status = 424
	}
	writeJSON(w, status, map[string]string{"profileId": profile.ID, "status": outcome})
}

func postgresProfilesReady(ctx context.Context, db *sql.DB, pg *postgres.Connector, tenant string, tools []postgres.QueryTool) bool {
	if !pg.SharedCredentialsConfigured() {
		return postgresProfilesActivationReady(db, tenant, tools)
	}
	adapter, err := loadPostgresAdapter(db)
	if err != nil || adapter == nil {
		return false
	}
	for _, tool := range tools {
		if len(tool.ProfileConfig) == 0 || string(tool.ProfileConfig) == "{}" {
			continue
		}
		var profile postgres.BusinessProfile
		if json.Unmarshal(tool.ProfileConfig, &profile) != nil {
			return false
		}
		fingerprint, err := postgres.ProfileFingerprint(profile)
		if err != nil {
			return false
		}
		rows, err := db.QueryContext(ctx, `SELECT object_id,email,user_id,database_role,permission_version FROM postgres_adapter_profile_tests WHERE tenant_id=? AND tool_id=? AND profile_generation=? AND adapter_generation=? AND outcome='passed' ORDER BY tested_at DESC LIMIT 20`, tenant, tool.ID, fingerprint, adapter.Fingerprint())
		if err != nil {
			return false
		}
		type evidence struct {
			object, email string
			resolved      postgres.ResolvedIdentity
		}
		var entries []evidence
		for rows.Next() {
			var e evidence
			if err = rows.Scan(&e.object, &e.email, &e.resolved.UserID, &e.resolved.Role, &e.resolved.PermissionVersion); err != nil {
				break
			}
			entries = append(entries, e)
		}
		rowErr := rows.Err()
		rows.Close()
		if err != nil || rowErr != nil {
			return false
		}
		users := map[string]bool{}
		for _, e := range entries {
			scoped, err := pg.ForSubject(*adapter, postgres.Subject{TenantID: tenant, ObjectID: e.object, Email: e.email})
			if err != nil {
				continue
			}
			resolved, err := scoped.ResolveIdentity(ctx, "adapter_user", "adapter")
			if err == nil && (resolved.UserID == e.resolved.UserID && resolved.Role == e.resolved.Role && resolved.PermissionVersion == e.resolved.PermissionVersion) {
				users[resolved.UserID] = true
			}
			if len(users) >= 2 {
				break
			}
		}
		if len(users) < 2 {
			return false
		}
	}
	return true
}
