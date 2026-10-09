package main

import (
	"context"
	"database/sql"
	"net/http"
	"time"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func postgresPermissionPreviewHandler(db *sql.DB, pg *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			writeJSON(w, 200, postgres.PermissionPreview{Mode: "internal", Status: "application_adapter_required"})
			return
		}
		mode := adapter.PermissionLocation()
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		ctx, cancel := context.WithTimeout(r.Context(), 12*time.Second)
		defer cancel()
		scoped, err := scopePostgresAdapter(pg, *adapter, principal)
		if err != nil {
			writeJSON(w, 409, map[string]any{"configured": true, "mode": mode, "error": postgresAccessFailureCode(err, postgres.AuthorizationFailureCode(err))})
			return
		}
		preview, err := scoped.PreviewPermissions(ctx)
		if err != nil {
			writeJSON(w, 424, map[string]any{"configured": true, "mode": mode, "error": postgres.AuthorizationFailureCode(err)})
			return
		}
		writeJSON(w, 200, preview)
	}
}
