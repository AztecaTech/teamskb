package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateSharePointSiteURL(t *testing.T) {
	valid, err := ValidateSharePointSiteURL("https://tenant.sharepoint.com/sites/Research%20Library")
	if err != nil || valid != "https://tenant.sharepoint.com/sites/Research%20Library" {
		t.Fatalf("canonical=%q err=%v", valid, err)
	}
	for _, raw := range []string{
		"http://tenant.sharepoint.com/sites/hr",
		"https://tenant.sharepoint.com.attacker.test/sites/hr",
		"https://user@tenant.sharepoint.com/sites/hr",
		"https://tenant.sharepoint.com/",
		"https://tenant.sharepoint.com/sites/hr?redirect=https://attacker.test",
		"https://tenant.sharepoint.com/sites/../admin",
		"https://tenant.sharepoint.com/sites%2Fadmin",
		"https://tenant..sharepoint.com/sites/hr",
	} {
		if _, err := ValidateSharePointSiteURL(raw); err == nil {
			t.Errorf("accepted invalid site URL %q", raw)
		}
	}
}

func TestSharePointCheckVerifiesConfiguredSiteAndLibrary(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/sites/tenant.sharepoint.com:/sites/hr"):
			_ = json.NewEncoder(w).Encode(graphSite{ID: "tenant.sharepoint.com,site-guid,web-guid", WebURL: "https://tenant.sharepoint.com/sites/hr"})
		case strings.HasSuffix(r.URL.Path, "/drive"):
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "drive-id"})
		default:
			t.Errorf("unexpected Graph path: %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newSharePoint(exchanger, server.URL+"/v1.0", server.Client())
	state, err := client.Check(context.Background(), "verified-assertion", "https://tenant.sharepoint.com/sites/hr")
	if err != nil || state != "connected" || exchanger.profile != "sharepoint" {
		t.Fatalf("state=%q profile=%q err=%v", state, exchanger.profile, err)
	}
}

func TestSharePointRetrieveUsesDelegatedSiteAccess(t *testing.T) {
	var downloaded int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			t.Errorf("authorization header = %q", r.Header.Get("Authorization"))
		}
		switch {
		case strings.Contains(r.URL.Path, "/sites/tenant.sharepoint.com:/sites/hr"):
			_ = json.NewEncoder(w).Encode(graphSite{ID: "tenant.sharepoint.com,site-guid,web-guid", WebURL: "https://tenant.sharepoint.com/sites/hr"})
		case strings.HasSuffix(r.URL.Path, "/drive/root/search(q='travel policy')"):
			_ = json.NewEncoder(w).Encode(searchResponse{Value: []driveItem{
				{ID: "doc-1", Name: "policy.docx", URL: "https://tenant.sharepoint.com/sites/hr/policy.docx"},
				{ID: "doc-2", Name: "archive.exe", URL: "https://tenant.sharepoint.com/sites/hr/archive.exe"},
			}})
		case strings.HasSuffix(r.URL.Path, "/drive/items/doc-1/content"):
			downloaded++
			_, _ = w.Write([]byte("document content"))
		default:
			t.Errorf("unexpected Graph path: %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newSharePoint(exchanger, server.URL+"/v1.0", server.Client())
	documents, err := client.Retrieve(context.Background(), "verified-assertion", "https://tenant.sharepoint.com/sites/hr", "travel policy")
	if err != nil {
		t.Fatal(err)
	}
	if len(documents) != 1 || documents[0].Name != "policy.docx" || string(documents[0].Content) != "document content" {
		t.Fatalf("unexpected documents: %#v", documents)
	}
	if exchanger.count != 1 || exchanger.profile != "sharepoint" || downloaded != 1 {
		t.Fatalf("exchange=%d profile=%q downloads=%d", exchanger.count, exchanger.profile, downloaded)
	}
}

func TestSharePointRejectsInvalidQueriesBeforeExchange(t *testing.T) {
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newSharePoint(exchanger, graphBaseURL, http.DefaultClient)
	for _, query := range []string{"", "hello\nworld", strings.Repeat("x", MaxQuestionRunes+1)} {
		if _, err := client.Retrieve(context.Background(), "verified-assertion", "https://tenant.sharepoint.com/sites/hr", query); err == nil {
			t.Fatalf("query %q should be rejected", query)
		}
	}
	if exchanger.count != 0 {
		t.Fatalf("invalid query triggered %d token exchanges", exchanger.count)
	}
}
