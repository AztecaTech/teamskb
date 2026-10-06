package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTeamsChatsRetrieveSearchesBoundedMessagesWithOwnToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1.0/me/chats":
			if r.URL.Query().Get("$top") != "10" {
				t.Errorf("chat limit=%q", r.URL.Query().Get("$top"))
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"chat-1","topic":"Planning"}]}`))
		case "/v1.0/chats/chat-1/messages":
			if r.URL.Query().Get("$top") != "20" {
				t.Errorf("message limit=%q", r.URL.Query().Get("$top"))
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"message-1","messageType":"message","subject":"","webUrl":"https://teams.microsoft.com/l/message/chat-1/1","createdDateTime":"2026-10-03T12:00:00Z","body":{"content":"<div>Approved travel policy &amp; expense rules.</div>"},"from":{"user":{"displayName":"Ada"}}},{"id":"bad-link","messageType":"message","webUrl":"https://evil.example/message","createdDateTime":"2026-10-03T12:01:00Z","body":{"content":"travel policy"}}]}`))
		default:
			t.Errorf("unexpected Graph route %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newTeamsChats(exchanger, server.URL+"/v1.0", server.Client())
	documents, err := client.Retrieve(context.Background(), "verified-assertion", "travel policy", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(documents) != 1 || documents[0].ID != "chat-1:message-1" || documents[0].Name != "Teams: Planning — Ada" || string(documents[0].Content) != "Approved travel policy & expense rules." || documents[0].ParserFilename != "message.txt" {
		t.Fatalf("unexpected documents: %#v", documents)
	}
	if exchanger.count != 1 || exchanger.profile != "teams" {
		t.Fatalf("exchange count=%d profile=%q", exchanger.count, exchanger.profile)
	}
}

func TestTeamsChatsRejectsInvalidQueryBeforeExchange(t *testing.T) {
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newTeamsChats(exchanger, graphBaseURL, http.DefaultClient)
	for _, query := range []string{"", "bad\nquery", strings.Repeat("x", MaxQuestionRunes+1)} {
		if _, err := client.Retrieve(context.Background(), "verified-assertion", query, 1); err == nil {
			t.Fatalf("accepted query %q", query)
		}
	}
	if exchanger.count != 0 {
		t.Fatalf("invalid query triggered %d token exchanges", exchanger.count)
	}
}

func TestTrustedTeamsURLAllowsOnlyMicrosoftTeamsHttps(t *testing.T) {
	for _, raw := range []string{"https://teams.microsoft.com/l/message/chat/1", "https://teams.microsoft.com:443/l/message/chat/1"} {
		if !trustedTeamsURL(raw) {
			t.Errorf("rejected %s", raw)
		}
	}
	for _, raw := range []string{"http://teams.microsoft.com/l/message/chat/1", "https://teams.microsoft.com.attacker.test/message", "https://user@teams.microsoft.com/message"} {
		if trustedTeamsURL(raw) {
			t.Errorf("accepted %s", raw)
		}
	}
}
