package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTeamsChannelsRetrieveUsesAssociatedTeamsAndDelegatedPermissions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer graph-token" {
			t.Errorf("authorization=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1.0/me/teamwork/associatedTeams":
			_, _ = w.Write([]byte(`{"value":[{"id":"team-1","displayName":"Research"}]}`))
		case "/v1.0/teams/team-1/allChannels":
			if r.URL.Query().Has("$top") {
				t.Error("unsupported channel list $top")
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"channel-1","displayName":"Policies"}]}`))
		case "/v1.0/teams/team-1/channels/channel-1/messages":
			if r.URL.Query().Has("$orderby") {
				t.Error("unsupported channel message $orderby")
			}
			if r.URL.Query().Get("$top") != "20" {
				t.Errorf("message limit=%q", r.URL.Query().Get("$top"))
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"message-1","messageType":"message","subject":"Travel policy","webUrl":"https://teams.microsoft.com/l/message/channel-1/1","createdDateTime":"2026-10-03T12:00:00Z","body":{"content":"<div>Approved travel policy &amp; expenses.</div>"}}]}`))
		default:
			t.Errorf("unexpected Graph request %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newTeamsChannels(exchanger, server.URL+"/v1.0", server.Client())
	documents, err := client.Retrieve(context.Background(), "verified-assertion", "travel policy", 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(documents) != 1 || documents[0].ID != "team-1:channel-1:message-1" || documents[0].Name != "Teams: Research / Policies" || documents[0].WebURL != "https://teams.microsoft.com/l/message/channel-1/1" || string(documents[0].Content) != "Approved travel policy & expenses." || exchanger.profile != "teams_channels" {
		t.Fatalf("documents=%#v profile=%q", documents, exchanger.profile)
	}
}

func TestTeamsChannelsCheckConfirmsDelegatedChannelAccess(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/me/teamwork/associatedTeams":
			_, _ = w.Write([]byte(`{"value":[{"id":"team-1"}]}`))
		case "/v1.0/teams/team-1/allChannels":
			_, _ = w.Write([]byte(`{"value":[{"id":"channel-1"}]}`))
		case "/v1.0/teams/team-1/channels/channel-1/messages":
			_, _ = w.Write([]byte(`{"value":[]}`))
		default:
			t.Errorf("unexpected Graph request %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	exchanger := &fakeExchanger{token: "graph-token"}
	client := newTeamsChannels(exchanger, server.URL+"/v1.0", server.Client())
	state, err := client.Check(context.Background(), "verified-assertion")
	if err != nil || state != "connected" || exchanger.profile != "teams_channels" {
		t.Fatalf("state=%q err=%v profile=%q", state, err, exchanger.profile)
	}
}

func TestTeamsChannelsIncludesIncomingSharedChannels(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.0/me/teamwork/associatedTeams":
			_, _ = w.Write([]byte(`{"value":[{"id":"host-team","displayName":"Partner"}]}`))
		case "/v1.0/teams/host-team/allChannels":
			if r.URL.Query().Get("$select") != "id,displayName,membershipType" {
				t.Errorf("select=%q", r.URL.Query().Get("$select"))
			}
			_, _ = w.Write([]byte(`{"value":[{"id":"shared-1","displayName":"Launch","membershipType":"shared"}]}`))
		case "/v1.0/teams/host-team/channels/shared-1/messages":
			_, _ = w.Write([]byte(`{"value":[{"id":"msg-1","webUrl":"https://teams.microsoft.com/l/message/shared-1/1","createdDateTime":"2026-10-04T12:00:00Z","body":{"content":"<p>Partner launch schedule</p>"}}]}`))
		default:
			t.Errorf("unexpected Graph request %s", r.URL.RequestURI())
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := newTeamsChannels(&fakeExchanger{token: "graph-token"}, server.URL+"/v1.0", server.Client())
	documents, err := client.Retrieve(context.Background(), "verified-assertion", "launch schedule", 2)
	if err != nil || len(documents) != 1 || documents[0].ID != "host-team:shared-1:msg-1" {
		t.Fatalf("documents=%#v err=%v", documents, err)
	}
}

func TestTeamsChannelsRejectsUntrustedCitationHosts(t *testing.T) {
	if !trustedTeamsURL("https://teams.microsoft.com/l/message/team/channel/1") {
		t.Fatal("expected Teams citation to be trusted")
	}
	if trustedTeamsURL("https://teams.microsoft.com.attacker.test/message") {
		t.Fatal("accepted attacker host")
	}
}
