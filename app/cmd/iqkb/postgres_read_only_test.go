package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPostgresInstallationRoutesRejectCachedClients(t *testing.T) {
	// Nil stores/connectors prove these requests are rejected without opening
	// either the application's store or the external PostgreSQL connection.
	handler := postgresAuthHandler(nil, nil, nil)
	for _, route := range []struct{ method, path string }{
		{"POST", "/api/admin/postgres/auth/permission-drafts/apply"},
		{"POST", "/api/admin/postgres/auth/permission-drafts/preview"},
		{"PUT", "/api/admin/postgres/auth/permission-drafts"},
		{"GET", "/api/admin/postgres/auth/permission-drafts"},
	} {
		t.Run(route.method+route.path, func(t *testing.T) {
			request := httptest.NewRequest(route.method, route.path, strings.NewReader(`{"acknowledgeImpact":true,"sql":"CREATE ROLE unwanted"}`))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusGone || !strings.Contains(response.Body.String(), `"error":"postgres_read_only"`) {
				t.Fatalf("installation route was not disabled: %d %s", response.Code, response.Body.String())
			}
		})
	}
}
