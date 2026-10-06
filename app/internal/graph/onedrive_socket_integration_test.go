package graph

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestOneDriveRetrievalUsesOBOUnixSocketAndGraphContract(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix-domain OBO sockets are exercised in the Linux container")
	}
	socketPath := filepath.Join(t.TempDir(), "obo.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	oboServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/obo" || r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("unexpected OBO request: method=%s path=%s content-type=%s", r.Method, r.URL.Path, r.Header.Get("Content-Type"))
		}
		var payload struct {
			Assertion string `json:"assertion"`
			Profile   string `json:"profile"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil || payload.Assertion != "test-user-assertion" || payload.Profile != "onedrive" {
			t.Errorf("unexpected OBO payload: %+v err=%v", payload, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"delegated-test-token"}`))
	})}
	go func() { _ = oboServer.Serve(listener) }()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = oboServer.Shutdown(ctx)
	}()

	graphServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer delegated-test-token" {
			t.Errorf("Graph authorization header=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/me/drive/root/search(q='retention')":
			if r.URL.Query().Get("$top") != "2" {
				t.Errorf("Graph result limit=%q", r.URL.Query().Get("$top"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"value":[{"id":"file-1","name":"policy.pdf","webUrl":"https://tenant.sharepoint.com/policy"}]}`))
		case r.Method == http.MethodGet && r.URL.Path == "/v1.0/me/drive/items/file-1/content":
			_, _ = w.Write([]byte("fixture-pdf-bytes"))
		default:
			http.Error(w, "unexpected Graph request "+r.URL.String(), http.StatusNotFound)
		}
	}))
	defer graphServer.Close()

	connector := newOneDrive(unixTokenExchanger{socketPath: socketPath}, graphServer.URL+"/v1.0", graphServer.Client())
	documents, err := connector.RetrieveLimit(context.Background(), "test-user-assertion", "retention", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(documents) != 1 || documents[0].ID != "file-1" || documents[0].Name != "policy.pdf" ||
		documents[0].WebURL != "https://tenant.sharepoint.com/policy" || string(documents[0].Content) != "fixture-pdf-bytes" {
		t.Fatalf("unexpected retrieved documents: %+v", documents)
	}
}
