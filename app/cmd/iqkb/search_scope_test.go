package main

import (
	"bytes"
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"iq-kbteams/internal/graph"
	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestMicrosoftScopeSkipsDatabaseSelectionAndPassesScopeToRetrieval(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	db := readyWorkflowDB(t, key)
	if _, err := db.Exec(`INSERT INTO source_boundaries(source_id,kind,canonical_boundary,enabled) VALUES('user-postgres','postgres','admin-approved-query-catalog',1)`); err != nil {
		t.Fatal(err)
	}
	selectorCalls := 0
	principal := identity.Principal{TenantID: "tenant", ObjectID: "object"}
	handler := authenticate(fixedTokenVerifier{principal}, db, false, askHandlerWithRuntime(db, key, askRuntime{
		postgresAvailable: true, modelAPIKey: testProviderAPIKey,
		selectTool: func(context.Context, string, string, string, string, string) (string, error) {
			selectorCalls++
			return "", nil
		},
		retrieve: func(ctx context.Context, _ *sql.DB, _ identity.Principal, _, _ string, selection *postgres.ToolSelection) (retrievedSources, int, error) {
			if searchScope(ctx) != "microsoft" || selection != nil {
				t.Error("Microsoft request routed to database")
			}
			return retrievedSources{documents: []graph.Document{{ID: "1", Name: "Microsoft policy", Content: []byte("approved"), PlainText: true}}}, 0, nil
		}, generate: func(context.Context, string, string, string, string, string) (string, error) {
			return "Approved [S1]", nil
		},
	}))
	req := httptest.NewRequest("POST", "/api/ask", strings.NewReader(`{"question":"policy","scope":"microsoft"}`))
	req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || selectorCalls != 0 || !strings.Contains(rec.Body.String(), `"database":"not_selected"`) {
		t.Fatalf("response=%d %s selectors=%d", rec.Code, rec.Body.String(), selectorCalls)
	}
}

func TestInvalidScopeCannotReachRetrieval(t *testing.T) {
	key := bytes.Repeat([]byte{0x55}, 32)
	db := readyWorkflowDB(t, key)
	called := false
	principal := identity.Principal{TenantID: "tenant", ObjectID: "object"}
	handler := authenticate(fixedTokenVerifier{principal}, db, false, askHandlerWithRuntime(db, key, askRuntime{modelAPIKey: testProviderAPIKey, retrieve: func(context.Context, *sql.DB, identity.Principal, string, string, *postgres.ToolSelection) (retrievedSources, int, error) {
		called = true
		return retrievedSources{}, 0, nil
	}}))
	req := httptest.NewRequest(http.MethodPost, "/api/ask", strings.NewReader(`{"question":"policy","scope":"unauthorized"}`))
	req.Header.Set("Authorization", "Bearer synthetic-user-assertion")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 400 || called {
		t.Fatalf("invalid scope status=%d retrieved=%v", rec.Code, called)
	}
}
