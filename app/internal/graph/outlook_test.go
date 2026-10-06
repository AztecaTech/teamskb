package graph

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOutlookRetrieveUsesOwnMailboxAndTextBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/me/messages" || r.Header.Get("Authorization") != "Bearer graph-token" || r.Header.Get("Prefer") != `outlook.body-content-type="text"` || r.URL.Query().Get("$top") != "2" {
			t.Errorf("unexpected mail request: %s headers=%v", r.URL.RequestURI(), r.Header)
		}
		if r.URL.Query().Get("$search") != `"travel policy"` {
			t.Errorf("search=%q", r.URL.Query().Get("$search"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"value": []any{
			map[string]any{"id": "message-1", "subject": "Travel policy update", "webLink": "https://outlook.office.com/mail/id/message-1", "body": map[string]string{"content": "Use the approved travel process."}},
			map[string]any{"id": "message-2", "subject": "Bad link", "webLink": "https://attacker.example/mail", "body": map[string]string{"content": "ignored"}},
		}})
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newOutlook(exchanger, server.URL+"/v1.0", server.Client())
	docs, err := client.Retrieve(context.Background(), "verified-assertion", "travel policy", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) != 1 || docs[0].ID != "message-1" || docs[0].Name != "Travel policy update" || string(docs[0].Content) != "Use the approved travel process." || docs[0].ParserFilename != "message.txt" {
		t.Fatalf("unexpected documents: %#v", docs)
	}
	if exchanger.profile != "outlook" {
		t.Fatalf("profile=%q", exchanger.profile)
	}
}

func TestOutlookRejectsInvalidQueryBeforeExchange(t *testing.T) {
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newOutlook(exchanger, graphBaseURL, http.DefaultClient)
	for _, query := range []string{"", "invalid\nquery", strings.Repeat("x", MaxQuestionRunes+1)} {
		if _, err := client.Retrieve(context.Background(), "verified-assertion", query, 1); err == nil {
			t.Fatalf("accepted query %q", query)
		}
	}
	if exchanger.count != 0 {
		t.Fatalf("invalid query exchanged %d tokens", exchanger.count)
	}
}

func TestTrustedMailURLIsExactHttpsOutlookHost(t *testing.T) {
	for _, raw := range []string{"https://outlook.office.com/mail/", "https://outlook.office365.com/mail/"} {
		if !trustedMailURL(raw) {
			t.Errorf("rejected %s", raw)
		}
	}
	for _, raw := range []string{"http://outlook.office.com/mail/", "https://outlook.office.com.attacker.test/", "https://user@outlook.office.com/"} {
		if trustedMailURL(raw) {
			t.Errorf("accepted %s", raw)
		}
	}
}
