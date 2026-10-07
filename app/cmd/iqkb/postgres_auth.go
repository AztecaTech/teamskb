package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

var errPostgresAdapterRequired = errors.New("configure a database authorization adapter first")
var errPostgresEmailRequired = errors.New("trusted directory email is required")

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

func postgresAccess(ctx context.Context, db *sql.DB, key []byte, pg *postgres.Connector, principal identity.Principal) (*postgres.Connector, string, string, error) {
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

func postgresAuthHandler(db *sql.DB, key []byte, pg *postgres.Connector) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/admin/postgres/auth/discovery", func(w http.ResponseWriter, r *http.Request) {
		if !pg.SharedCredentialsConfigured() {
			jsonResponse(w, http.StatusConflict, `{"error":"shared_database_credentials_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		result, err := pg.DiscoverAuthorization(ctx, r.URL.Query().Get("afterSchema"), r.URL.Query().Get("afterName"))
		if err != nil {
			jsonResponse(w, http.StatusFailedDependency, `{"error":"authorization_metadata_discovery_failed"}`)
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
		if err != nil || decodeErr != nil || adapter.Validate() != nil {
			jsonResponse(w, 400, `{"error":"invalid_adapter"}`)
			return
		}
		if !pg.SharedCredentialsConfigured() {
			jsonResponse(w, 409, `{"error":"shared_database_credentials_required"}`)
			return
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
		scoped, login, password, err := postgresAccess(r.Context(), db, key, pg, principal)
		if err != nil {
			jsonResponse(w, 409, `{"error":"database_identity_resolution_required"}`)
			return
		}
		resolved, err := scoped.ResolveIdentity(r.Context(), login, password)
		if err != nil {
			jsonResponse(w, 424, `{"error":"database_authorization_check_failed"}`)
			return
		}
		writeJSON(w, 200, map[string]any{"status": "connected", "userId": resolved.UserID, "databaseRole": resolved.Role})
	})
	return mux
}
