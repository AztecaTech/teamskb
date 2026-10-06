package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessCheckRequiresReadyResponse(t *testing.T) {
	for _, test := range []struct {
		name       string
		statusCode int
		body       string
		wantErr    bool
	}{
		{name: "ready", statusCode: http.StatusOK, body: `{"status":"ready"}`},
		{name: "not ready", statusCode: http.StatusServiceUnavailable, body: `{"status":"not_ready"}`, wantErr: true},
		{name: "wrong body", statusCode: http.StatusOK, body: `{"status":"starting"}`, wantErr: true},
		{name: "invalid body", statusCode: http.StatusOK, body: `not json`, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.statusCode)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()

			err := readinessCheck(server.Client(), server.URL)
			if (err != nil) != test.wantErr {
				t.Fatalf("readinessCheck() error = %v, wantErr %v", err, test.wantErr)
			}
		})
	}
}
