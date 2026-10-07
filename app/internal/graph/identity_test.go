package graph

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDirectoryEmailRequiresMatchingMemberObjectAndMail(t *testing.T) {
	for _, test := range []struct{ name, body, want string }{
		{"member", `{"id":"object-one","mail":" Person@Example.com ","userType":"Member"}`, "person@example.com"},
		{"different object", `{"id":"object-two","mail":"person@example.com","userType":"Member"}`, ""},
		{"guest", `{"id":"object-one","mail":"person@example.com","userType":"Guest"}`, ""},
		{"no email fallback", `{"id":"object-one","userPrincipalName":"person@example.com","userType":"Member"}`, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/me" || r.URL.Query().Get("$select") != "id,mail,userType" || r.Header.Get("Authorization") != "Bearer graph-token" {
					t.Error("unexpected identity request")
				}
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			x := &fakeExchanger{token: "graph-token"}
			email, err := directoryEmail(context.Background(), x, server.Client(), server.URL, "verified-assertion", "object-one")
			if email != test.want || (err == nil) != (test.want != "") || x.profile != "identity" {
				t.Fatalf("email=%q err=%v profile=%s", email, err, x.profile)
			}
		})
	}
}
