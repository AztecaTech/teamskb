package main

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func postgresEmailHandler(db *sql.DB, key []byte, pg *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal := r.Context().Value(identityContextKey{}).(identity.Principal)
		body, err := ioReadRequest(r)
		input, decodeErr := httpx.DecodeOne[struct {
			Email string `json:"email"`
		}](body)
		email := strings.ToLower(strings.TrimSpace(input.Email))
		if err != nil || decodeErr != nil || !validVerifiedEmail(email) {
			jsonResponse(w, 400, `{"error":"invalid_database_email"}`)
			return
		}
		if principal.VerifiedEmail == "" {
			jsonResponse(w, 409, `{"error":"postgres_verified_email_required"}`)
			return
		}
		if email != strings.ToLower(strings.TrimSpace(principal.VerifiedEmail)) {
			jsonResponse(w, 403, `{"error":"database_email_mismatch"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		before, err := loadPostgresAdapter(db)
		if err != nil || before == nil {
			jsonResponse(w, 409, `{"error":"postgres_adapter_required"}`)
			return
		}
		scoped, login, password, err := postgresMappedAccess(ctx, db, key, pg, principal)
		if err != nil {
			writeJSON(w, 409, map[string]string{"error": postgresAccessFailureCode(err, "database_mapping_required")})
			return
		}
		matched, err := scoped.RecognizeUser(ctx)
		if err != nil { writeJSON(w,424,map[string]string{"error":postgres.AuthorizationFailureCode(err)});return }
		_, err = db.ExecContext(ctx,`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`,"match:"+databaseEmailKey(principal),email+":"+before.Fingerprint())
		if err != nil { jsonResponse(w,503,`{"error":"database_email_not_saved"}`);return }
		resolved, err := scoped.ResolveIdentity(ctx, login, password)
		if err != nil {
			failure := map[string]string{"error": postgres.AuthorizationFailureCode(err)}
			if failure["error"] == "execution_role_not_found" || failure["error"] == "application_role_mapping_required" || failure["error"] == "execution_role_invalid" {
				writeJSON(w,200,map[string]string{"status":"matched_permissions_required","userId":matched.UserID,"applicationRole":matched.ApplicationRole,"permissionError":failure["error"]})
				return
			}
			if failure["error"] == "execution_role_not_found" || failure["error"] == "application_role_mapping_required" {
				failure["applicationRole"] = resolved.ApplicationRole
				failure["databaseRole"] = resolved.Role
			}
			writeJSON(w, 424, failure)
			return
		}
		adapter, err := loadPostgresAdapter(db)
		if err != nil || adapter == nil || adapter.Fingerprint() != before.Fingerprint() {
			jsonResponse(w, 409, `{"error":"postgres_adapter_required"}`)
			return
		}
		_, err = db.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, databaseEmailKey(principal), email+":"+adapter.Fingerprint())
		if err != nil {
			jsonResponse(w, 503, `{"error":"database_email_not_saved"}`)
			return
		}
		writeJSON(w, 200, map[string]string{"status": "connected", "userId": resolved.UserID, "databaseRole": resolved.Role})
	}
}
