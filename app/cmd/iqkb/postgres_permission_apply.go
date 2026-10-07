package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"iq-kbteams/internal/httpx"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

type permissionApplyRequest struct {
	Drafts             []postgres.PermissionDraft `json:"drafts"`
	AdapterFingerprint string                     `json:"adapterFingerprint"`
	PreviewToken       string                     `json:"previewToken"`
	PreviewExpiresAt   int64                      `json:"previewExpiresAt"`
	AcknowledgeImpact  bool                       `json:"acknowledgeImpact"`
}

// Bind approval to the exact server-generated SQL, adapter, administrator and
// expiry. Browser-supplied SQL is never accepted or executed.
func permissionPreviewToken(key []byte, p identity.Principal, adapter, preview string, drafts []postgres.PermissionDraft, expires int64) string {
	data, _ := json.Marshal([]any{"postgres-permission-deployment-v1", p.TenantID, p.ObjectID, adapter, preview, drafts, expires})
	mac := hmac.New(sha256.New, key)
	mac.Write(data)
	return hex.EncodeToString(mac.Sum(nil))
}

func validPermissionPreview(key []byte, p identity.Principal, input permissionApplyRequest, preview string, now time.Time) bool {
	if !input.AcknowledgeImpact || input.PreviewExpiresAt <= now.Unix() || input.PreviewExpiresAt > now.Add(15*time.Minute).Unix() {
		return false
	}
	expected := permissionPreviewToken(key, p, input.AdapterFingerprint, preview, input.Drafts, input.PreviewExpiresAt)
	return hmac.Equal([]byte(expected), []byte(input.PreviewToken))
}

func postgresPermissionApplyHandler(db *sql.DB, key []byte, pg *postgres.Connector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, err := ioReadRequest(r)
		input, decodeErr := httpx.DecodeOne[permissionApplyRequest](body)
		if err != nil || decodeErr != nil || !input.AcknowledgeImpact || len(input.PreviewToken) != 64 || len(input.Drafts) == 0 || postgres.ValidatePermissionDrafts(input.Drafts, true) != nil {
			jsonResponse(w, 400, `{"error":"reviewed_preview_and_impact_confirmation_required"}`)
			return
		}
		if !pg.SharedCredentialsConfigured() {
			jsonResponse(w, 409, `{"error":"shared_database_credentials_required"}`)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		p := r.Context().Value(identityContextKey{}).(identity.Principal)
		adapter, err := loadPostgresAdapter(db)
		if err != nil || adapter == nil || adapter.Fingerprint() != input.AdapterFingerprint {
			jsonResponse(w, 409, `{"error":"authorization_mapping_changed_regenerate_preview"}`)
			return
		}
		// Preserve a previously entered email only after rechecking the same
		// active database user. Applying rules never substitutes for email entry.
		email := strings.ToLower(strings.TrimSpace(p.VerifiedEmail))
		confirmedUser := ""
		var marker string
		if email != "" && db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, "match:"+databaseEmailKey(p)).Scan(&marker) == nil && marker == email+":"+adapter.Fingerprint() {
			if scoped, scopeErr := pg.ForSubject(*adapter, postgres.Subject{TenantID: p.TenantID, ObjectID: p.ObjectID, Email: p.VerifiedEmail}); scopeErr == nil {
				if matched, matchErr := scoped.RecognizeUser(ctx); matchErr == nil {
					confirmedUser = matched.UserID
				}
			}
		}
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			jsonResponse(w, 503, `{"error":"mapping_store_unavailable"}`)
			return
		}
		defer tx.Rollback()
		// Hold the settings write lock so another request cannot change the
		// active adapter while the approved database deployment is running.
		if _, err = tx.ExecContext(ctx, `UPDATE settings SET value=value WHERE key='postgres_auth_adapter'`); err != nil {
			jsonResponse(w, 503, `{"error":"mapping_store_unavailable"}`)
			return
		}
		var raw []byte
		var current postgres.AdapterConfig
		if tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='postgres_auth_adapter'`).Scan(&raw) != nil || json.Unmarshal(raw, &current) != nil || current.Fingerprint() != input.AdapterFingerprint {
			jsonResponse(w, 409, `{"error":"authorization_mapping_changed_regenerate_preview"}`)
			return
		}
		if current.RoleMappings == nil {
			current.RoleMappings = map[string]string{}
		}
		installed := map[string]string{}
		for _, draft := range input.Drafts {
			current.RoleMappings[draft.Label] = draft.ExecutionRole
			installed[draft.Label] = draft.ExecutionRole
		}
		if current.Validate() != nil {
			jsonResponse(w, 400, `{"error":"invalid_role_translations"}`)
			return
		}
		if err = pg.ApplyPermissionDrafts(ctx, input.Drafts, func(preview string) bool { return validPermissionPreview(key, p, input, preview, time.Now()) }); err != nil {
			failure := postgres.PermissionDeploymentFailureCode(err)
			if failure == "database_deployment_outcome_unknown" {
				writeJSON(w, 424, map[string]any{"error": failure, "outcome": "unknown"})
			} else {
				writeJSON(w, 424, map[string]any{"error": failure, "deployed": false})
			}
			return
		}
		result := map[string]any{"status": "applied", "deployed": true, "roleMappings": installed, "accessStatus": "database_email_confirmation_required"}
		storeFailure := func() {
			result["error"] = "database_rules_applied_mapping_save_failed"
			result["status"] = "mapping_save_required"
			writeJSON(w, 503, result)
		}
		if confirmedUser != "" {
			if scoped, scopeErr := pg.ForSubject(current, postgres.Subject{TenantID: p.TenantID, ObjectID: p.ObjectID, Email: p.VerifiedEmail}); scopeErr == nil {
				if resolved, resolveErr := scoped.ResolveIdentity(ctx, "adapter_user", "adapter"); resolveErr == nil && resolved.UserID == confirmedUser {
					for _, settingKey := range []string{databaseEmailKey(p), "match:" + databaseEmailKey(p)} {
						if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, settingKey, email+":"+current.Fingerprint()); err != nil {
							storeFailure()
							return
						}
					}
					result["accessStatus"] = "connected"
					result["userId"] = resolved.UserID
					result["databaseRole"] = resolved.Role
				} else {
					result["accessStatus"] = "database_permission_mapping_required"
					if resolveErr != nil {
						result["accessError"] = postgres.AuthorizationFailureCode(resolveErr)
					}
					if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "match:"+databaseEmailKey(p), email+":"+current.Fingerprint()); err != nil {
						storeFailure()
						return
					}
				}
			}
		}
		raw, _ = json.Marshal(current)
		if _, err = tx.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='postgres_auth_adapter'`, raw); err != nil {
			storeFailure()
			return
		}
		if _, err = tx.ExecContext(ctx, `DELETE FROM postgres_adapter_profile_tests`); err != nil {
			storeFailure()
			return
		}
		for _, draft := range input.Drafts {
			record, _ := json.Marshal(map[string]any{"draft": draft, "administrator": p.ObjectID, "tenant": p.TenantID, "appliedAt": time.Now().UTC().Format(time.RFC3339)})
			if _, err = tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, "postgres_permission_deployment:"+draft.ExecutionRole, string(record)); err != nil {
				storeFailure()
				return
			}
		}
		if tx.Commit() != nil {
			storeFailure()
			return
		}
		writeJSON(w, 200, result)
	}
}
