package graph

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestChannelCheckUsesSupportedParametersAndSkipsInaccessibleChannel(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Has("$orderby") || (r.URL.Path == "/teams/team/allChannels" && r.URL.Query().Has("$top")) {
			http.Error(w, "unsupported parameter", 400)
			return
		}
		switch r.URL.Path {
		case "/me/teamwork/associatedTeams":
			_, _ = w.Write([]byte(`{"value":[{"id":"team"}]}`))
		case "/teams/team/allChannels":
			_, _ = w.Write([]byte(`{"value":[{"id":"private"},{"id":"standard"}]}`))
		case "/teams/team/channels/private/messages":
			requests++
			http.Error(w, "restricted", 403)
		case "/teams/team/channels/standard/messages":
			requests++
			_, _ = w.Write([]byte(`{"value":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := newTeamsChannels(&fakeExchanger{token: "token"}, server.URL, server.Client())
	state, err := client.Check(context.Background(), "verified-assertion")
	if state != "connected" || err != nil || requests != 2 {
		t.Fatalf("state=%s err=%v message checks=%d", state, err, requests)
	}
}

func TestChannelCheckPreservesFailureStageAndUpstreamStatus(t *testing.T) {
	for _, test := range []struct {
		code int
		want string
	}{{400, "invalid_request"}, {401, "consent_required"}, {403, "permission_denied"}, {404, "not_found"}, {429, "throttled"}, {503, "unavailable"}} {
		t.Run(test.want, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/me/teamwork/associatedTeams":
					_, _ = w.Write([]byte(`{"value":[{"id":"team"}]}`))
				case "/teams/team/allChannels":
					_, _ = w.Write([]byte(`{"value":[{"id":"channel"}]}`))
				default:
					http.Error(w, "private provider details", test.code)
				}
			}))
			defer server.Close()
			client := newTeamsChannels(&fakeExchanger{token: "token"}, server.URL, server.Client())
			state, err := client.Check(context.Background(), "verified-assertion")
			var detail *ChannelCheckError
			if state != test.want || !errors.As(err, &detail) || detail.Stage != "read_messages" || detail.HTTPStatus != test.code {
				t.Fatalf("state=%s err=%v diagnostic=%#v", state, err, detail)
			}
		})
	}
}
