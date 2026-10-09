package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

var errPostgresAdapterRequired = errors.New("configure a database authorization adapter first")
var errPostgresEmailRequired = errors.New("trusted directory email is required")
var errPostgresEmailConfirmationRequired = errors.New("confirm your database email first")
var errPostgresPermissionMappingRequired = errors.New("email matched; existing permissions require an authorization mapping")

func databaseEmailKey(p identity.Principal) string {
	return "postgres_email:" + p.TenantID + ":" + p.ObjectID
}

func postgresAccess(ctx context.Context, db *sql.DB, key []byte, pg *postgres.Connector, principal identity.Principal) (*postgres.Connector, string, string, error) {
	scoped, login, password, err := postgresMappedAccess(ctx, db, key, pg, principal)
	if err != nil {
		return nil, "", "", err
	}
	adapter, err := loadPostgresAdapter(db)
	if err != nil {
		return nil, "", "", err
	}
	if adapter != nil {
		var saved string
		if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, databaseEmailKey(principal)).Scan(&saved); err != nil || saved != strings.ToLower(strings.TrimSpace(principal.VerifiedEmail))+":"+adapter.Fingerprint() {
			var matched string
			if db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, "match:"+databaseEmailKey(principal)).Scan(&matched) == nil && matched == strings.ToLower(strings.TrimSpace(principal.VerifiedEmail))+":"+adapter.Fingerprint() {
				return nil, "", "", errPostgresPermissionMappingRequired
			}
			return nil, "", "", errPostgresEmailConfirmationRequired
		}
	}
	return scoped, login, password, nil
}

func loadPostgresAdapter(db *sql.DB) (*postgres.AdapterConfig, error) {
	var raw []byte
	err := db.QueryRow(`SELECT value FROM settings WHERE key='postgres_auth_adapter'`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var adapter postgres.AdapterConfig
	if json.Unmarshal(raw, &adapter) != nil || adapter.Validate() != nil {
		return nil, errors.New("invalid saved database adapter")
	}
	return &adapter, nil
}

func postgresMappedAccess(ctx context.Context, db *sql.DB, key []byte, pg *postgres.Connector, principal identity.Principal) (*postgres.Connector, string, string, error) {
	if pg == nil {
		return nil, "", "", errors.New("PostgreSQL is not configured")
	}
	adapter, err := loadPostgresAdapter(db)
	if err != nil {
		return nil, "", "", err
	}
	if adapter != nil {
		if principal.VerifiedEmail == "" {
			return nil, "", "", errPostgresEmailRequired
		}
		scoped, err := pg.ForSubject(*adapter, postgres.Subject{TenantID: principal.TenantID, ObjectID: principal.ObjectID, Email: principal.VerifiedEmail})
		return scoped, "adapter_user", "adapter", err
	}
	if pg.SharedCredentialsConfigured() {
		return nil, "", "", errPostgresAdapterRequired
	}
	if principal.VerifiedEmail == "" {
		return nil, "", "", errPostgresEmailRequired
	}
	login, err := mappedDatabaseIdentity(ctx, db, principal)
	if err != nil {
		return nil, "", "", err
	}
	password, err := loadPostgresPassword(db, key, principal.TenantID, principal.ObjectID)
	return pg, login, password, err
}

func postgresAccessFailureCode(err error, fallback string) string {
	if errors.Is(err, errPostgresPermissionMappingRequired) {
		return "database_permission_mapping_required"
	}
	if errors.Is(err, errPostgresEmailConfirmationRequired) {
		return "database_email_confirmation_required"
	}
	if errors.Is(err, errPostgresAdapterRequired) {
		return "postgres_adapter_required"
	}
	if errors.Is(err, errPostgresEmailRequired) {
		return "postgres_verified_email_required"
	}
	return fallback
}

func postgresAuthHandler(db *sql.DB, key []byte, pg *postgres.Connector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/postgres/auth/permissions", func(w http.ResponseWriter, r *http.Request) {
		if pg == nil {
			writeJSON(w, 503, map[string]any{"mode": "internal", "error": "postgres_not_configured"})
			return
		}
		adapter, err := loadPostgresAdapter(db)
		if err != nil {
			writeJSON(w, 503, map[string]any{"mode": "internal", "error": "adapter_unavailable"})
			return
		}
		if adapter == nil || adapter.Mode != "application_rules" {
			writeJSON(w, 200, postgres.AutomaticPermissionPreview{Mode: "internal", Status: "application_adapter_required"})
			return
		}
		mode := "internal"
		if adapter.PermissionSource == "external" {
			mode = "external"
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		scoped, _, _, err := postgresMappedAccess(ctx, db, key, pg, principal)
		if err != nil {
			writeJSON(w, 409, map[string]any{"configured": true, "mode": mode, "error": postgresAccessFailureCode(err, postgres.AuthorizationFailureCode(err))})
			return
		}
		preview, err := scoped.PreviewAutomaticPermissions(ctx)
		if err != nil {
			writeJSON(w, 424, map[string]any{"configured": true, "mode": mode, "error": postgres.AuthorizationFailureCode(err)})
			return
		}
		writeJSON(w, 200, preview)
	})
	mux.HandleFunc("GET /api/admin/postgres/auth/resources", func(w http.ResponseWriter, r *http.Request) {
		if pg == nil {
			jsonResponse(w, 503, `{"error":"postgres_not_configured"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		page, err := pg.DiscoverPermissionResources(ctx, r.URL.Query().Get("afterSchema"), r.URL.Query().Get("afterName"))
		if err != nil {
			writeJSON(w, 424, map[string]string{"error": postgres.DiscoveryFailureCode(err)})
			return
		}
		writeJSON(w, 200, page)
	})
	// Reject former installation routes before opening any database connection.
	// A cached client must not be able to install roles, grants or policies.
	readOnly := func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusGone, map[string]string{"error": "postgres_read_only", "message": "PostgreSQL permission installation is disabled. Mapping uses existing permissions and is saved only in the app."})
	}
	mux.HandleFunc("/api/admin/postgres/auth/permission-drafts", readOnly)
	mux.HandleFunc("/api/admin/postgres/auth/permission-drafts/", readOnly)
	mux.HandleFunc("GET /api/admin/postgres/auth/roles", func(w http.ResponseWriter, r *http.Request) {
		if pg == nil {
			jsonResponse(w, 503, `{"error":"postgres_not_configured"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		result, err := pg.DiscoverRoleMappings(ctx, r.URL.Query().Get("schema"), r.URL.Query().Get("relation"), r.URL.Query().Get("column"))
		if err != nil {
			writeJSON(w, 424, map[string]string{"error": postgres.DiscoveryFailureCode(err)})
			return
		}
		writeJSON(w, 200, result)
	})
	mux.HandleFunc("GET /api/admin/postgres/auth/discovery", func(w http.ResponseWriter, r *http.Request) {
		if !pg.SharedCredentialsConfigured() {
			jsonResponse(w, http.StatusConflict, `{"error":"shared_database_credentials_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		result, err := pg.DiscoverAuthorization(ctx, r.URL.Query().Get("afterSchema"), r.URL.Query().Get("afterName"))
		if err != nil {
			writeJSON(w, http.StatusFailedDependency, map[string]string{"error": postgres.DiscoveryFailureCode(err), "stage": postgres.DiscoveryFailureStage(err)})
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	mux.HandleFunc("GET /api/admin/postgres/auth", func(w http.ResponseWriter, r *http.Request) {
		adapter, err := loadPostgresAdapter(db)
		if err != nil {
			jsonResponse(w, 503, `{"error":"adapter_unavailable"}`)
			return
		}
		writeJSON(w, 200, map[string]any{"adapter": adapter, "sharedCredentialsConfigured": pg.SharedCredentialsConfigured()})
	})
	mux.HandleFunc("PUT /api/admin/postgres/auth", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		adapter, decodeErr := httpx.DecodeOne[postgres.AdapterConfig](body)
		if strings.TrimSpace(adapter.ApprovalRecord) == "" {
			principal := r.Context().Value(identityContextKey{}).(identity.Principal)
			adapter.ApprovalRecord = "Administrator " + principal.ObjectID + " saved mapping at " + time.Now().UTC().Format(time.RFC3339)
		}
		if adapter.Columns != nil {
			adapter.TenantScope = ""
			if adapter.Columns.TenantID == "" {
				adapter.TenantScope = r.Context().Value(identityContextKey{}).(identity.Principal).TenantID
			}
		}
		if err != nil || decodeErr != nil || adapter.Validate() != nil {
			jsonResponse(w, 400, `{"error":"invalid_adapter"}`)
			return
		}
		if !pg.SharedCredentialsConfigured() {
			jsonResponse(w, 409, `{"error":"shared_database_credentials_required"}`)
			return
		}
		if adapter.PermissionSource == "external" {
			if !pg.ExternalPermissionSourceAvailable() {
				writeJSON(w, 409, map[string]string{"error": "permission_source_not_configured"})
				return
			}
			// The displayed per-user native snapshot is not a manual label grant.
			// Never retain it as a fallback if the source is later disconnected.
			adapter.Rules = nil
			adapter.Claims = nil
		}
		raw, _ := json.Marshal(adapter)
		tx, err := db.BeginTx(r.Context(), nil)
		if err != nil {
			jsonResponse(w, 503, `{"error":"unavailable"}`)
			return
		}
		defer tx.Rollback()
		if _, err = tx.ExecContext(r.Context(), `INSERT INTO settings(key,value) VALUES('postgres_auth_adapter',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, raw); err == nil {
			_, err = tx.ExecContext(r.Context(), `DELETE FROM postgres_adapter_profile_tests`)
		}
		if err != nil || tx.Commit() != nil {
			jsonResponse(w, 503, `{"error":"unavailable"}`)
			return
		}
		writeJSON(w, 200, adapter)
	})
	mux.HandleFunc("POST /api/admin/postgres/auth/check", func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		if err != nil || len(body) != 0 {
			jsonResponse(w, 400, `{"error":"invalid_request"}`)
			return
		}
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		scoped, login, password, err := postgresMappedAccess(r.Context(), db, key, pg, principal)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": postgresAccessFailureCode(err, "database_identity_resolution_required")})
			return
		}
		resolved, err := scoped.ResolveIdentity(r.Context(), login, password)
		if err != nil {
			writeJSON(w, 424, map[string]string{"error": postgres.AuthorizationFailureCode(err)})
			return
		}
		adapter, _ := loadPostgresAdapter(db)
		writeJSON(w, 200, map[string]any{"status": "connected", "userId": resolved.UserID, "databaseRole": resolved.Role, "authorizationMode": func() string {
			if adapter != nil {
				return adapter.Mode
			}
			return ""
		}(), "applicationRole": resolved.ApplicationRole})
	})
	return mux
}
