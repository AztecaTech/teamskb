package graph

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeExchanger struct {
	token   string
	err     error
	count   int
	profile string
}

func (f *fakeExchanger) Exchange(_ context.Context, assertion, profile string) (string, error) {
	f.count++
	f.profile = profile
	if assertion != "verified-assertion" {
		return "", context.Canceled
	}
	return f.token, f.err
}

func TestRetrieveUsesDelegatedTokenAndDownloadsSupportedFiles(t *testing.T) {
	var downloaded int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		switch {
		case strings.Contains(r.URL.Path, "/root/search(q='travel policy')"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(searchResponse{Value: []driveItem{
				{ID: "doc-1", Name: "policy.pdf", URL: "https://tenant.sharepoint.com/sites/hr/policy.pdf"},
				{ID: "doc-2", Name: "budget.csv", URL: "https://tenant.sharepoint.com/sites/hr/budget.csv"},
			}})
		case strings.HasSuffix(r.URL.Path, "/items/doc-1/content"):
			downloaded++
			_, _ = w.Write([]byte("%PDF-test-content"))
		default:
			t.Errorf("unexpected Graph path: %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newOneDrive(exchanger, server.URL+"/v1.0", server.Client())
	documents, err := client.Retrieve(context.Background(), "verified-assertion", "travel policy")
	if err != nil {
		t.Fatal(err)
	}
	if len(documents) != 1 || documents[0].Name != "policy.pdf" || string(documents[0].Content) != "%PDF-test-content" {
		t.Fatalf("unexpected documents: %#v", documents)
	}
	if exchanger.count != 1 || exchanger.profile != "onedrive" || downloaded != 1 {
		t.Fatalf("exchange=%d profile=%q downloads=%d", exchanger.count, exchanger.profile, downloaded)
	}
}

func TestRetrieveRejectsInvalidQueriesBeforeExchange(t *testing.T) {
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newOneDrive(exchanger, "https://graph.microsoft.com/v1.0", http.DefaultClient)
	for _, query := range []string{"", "hello\nworld", strings.Repeat("x", MaxQuestionRunes+1)} {
		if _, err := client.Retrieve(context.Background(), "verified-assertion", query); err == nil {
			t.Fatalf("query %q should be rejected", query)
		}
	}
	if exchanger.count != 0 {
		t.Fatalf("invalid query triggered %d token exchanges", exchanger.count)
	}
}

func TestDownloadEnforcesMaximumResponseSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", maxFileBytes+1)), maxFileBytes+1)
	}))
	defer server.Close()
	client := newOneDrive(&fakeExchanger{token: "graph-token"}, server.URL, server.Client())
	if _, err := client.download(context.Background(), "graph-token", "doc-1"); err == nil {
		t.Fatal("oversized download should be rejected")
	}
}

func TestTrustedWebURLAllowsOnlyHttpsMicrosoftStorageHosts(t *testing.T) {
	for _, raw := range []string{"https://tenant.sharepoint.com/a", "https://tenant.onedrive.com/a", "https://tenant.sharepoint.com:443/a"} {
		if !trustedWebURL(raw) {
			t.Errorf("expected trusted URL: %s", raw)
		}
	}
	for _, raw := range []string{"http://tenant.sharepoint.com/a", "https://sharepoint.com.attacker.net/a", "https://user@tenant.sharepoint.com/a", "https://tenant.sharepoint.com:8443/a"} {
		if trustedWebURL(raw) {
			t.Errorf("unexpectedly trusted URL: %s", raw)
		}
	}
}
