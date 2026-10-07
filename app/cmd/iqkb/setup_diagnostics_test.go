package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/store"
)

func TestActivationNamesFailedSourceWithoutActivatingOrLeakingCause(t *testing.T) {
	for _, source := range []string{"onedrive", "sharepoint", "outlook", "teams-chats", "teams-channels", "postgres"} {
		t.Run(source, func(t *testing.T) {
			key := bytes.Repeat([]byte{0x55}, 32)
			db := readyWorkflowDB(t, key)
			if _, err := db.Exec(`DELETE FROM settings WHERE key='setup_activated'`); err != nil {
				t.Fatal(err)
			}
			principal := identity.Principal{TenantID: "12345678-1234-4234-9234-123456789abc", ObjectID: "32345678-1234-4234-9234-123456789abc"}
			if err := store.SeedAdmin(db, principal.TenantID, principal.ObjectID); err != nil {
				t.Fatal(err)
			}
			handler := setupHandlerWithCheck(db, "fixture-secret", testProviderAPIKey, key, func(context.Context, string, identity.Principal) (string, error) {
				return sourceAccessFailure(source, "unavailable", errors.New("private upstream connection details"))
			})
			request := httptest.NewRequest(http.MethodPost, "/api/setup/activate", nil)
			request.Header.Set("Authorization", "Bearer synthetic-user-assertion")
			request.Header.Set("X-Setup-Secret", "fixture-secret")
			rec := httptest.NewRecorder()
			authenticate(fixedTokenVerifier{principal}, db, true, handler).ServeHTTP(rec, request)
			var result map[string]string
			if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if rec.Code != 424 || result["source"] != source || result["status"] != "unavailable" || result["error"] != "source_check_failed" || strings.Contains(rec.Body.String(), "private upstream") {
				t.Fatalf("response=%d %s", rec.Code, rec.Body.String())
			}
			var active int
			if err := db.QueryRow(`SELECT COUNT(*) FROM settings WHERE key='setup_activated' AND value=x'31'`).Scan(&active); err != nil || active != 0 {
				t.Fatalf("failed checks activated workspace: count=%d err=%v", active, err)
			}
		})
	}
}
