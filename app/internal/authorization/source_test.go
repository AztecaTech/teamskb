package authorization

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativePermissionSourceBindsSubjectAndExplicitRules(t *testing.T) {
	subject := PermissionSubject{UserID: "7", Email: "person@example.com", TenantID: "tenant", ObjectID: "actor", Label: "custom label"}
	allowed := true
	policy := PermissionResponse{Subject: subject, Allowed: &allowed, Revision: "r1", Resources: []ReadPermission{{Schema: "custom", Relation: "records", Fields: []string{"id", "caption"}, Scope: Scope{Kind: "user", Column: "owner"}}}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.Header.Get("Authorization") != "Bearer fixture-server-credential" {
			t.Error("missing server authentication")
		}
		var request struct {
			Subject   PermissionSubject `json:"subject"`
			Operation string            `json:"operation"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil || request.Subject != subject || request.Operation != "read" {
			t.Error("wrong native subject or operation")
		}
		json.NewEncoder(w).Encode(policy)
	}))
	defer server.Close()
	source, err := NewHTTPPermissionSource(server.URL, "fixture-server-credential")
	if err != nil {
		t.Fatal(err)
	}
	source.client.Transport = server.Client().Transport
	result, err := source.Resolve(t.Context(), subject)
	if err != nil || len(result.Rules) != 1 || result.Rules[0].Label != subject.Label || !result.Rules[0].Reviewed || result.Rules[0].Scope.Column != "owner" {
		t.Fatalf("native decision was not imported: %#v %v", result, err)
	}
	for _, change := range []string{"email", "user", "tenant", "object", "label"} {
		policy.Subject = subject
		switch change {
		case "email":
			policy.Subject.Email = "other@example.com"
		case "user":
			policy.Subject.UserID = "8"
		case "tenant":
			policy.Subject.TenantID = "other"
		case "object":
			policy.Subject.ObjectID = "other"
		case "label":
			policy.Subject.Label = "admin"
		}
		if _, err := source.Resolve(t.Context(), subject); err == nil || err.Error() != "permission_source_identity_mismatch" {
			t.Fatalf("%s substitution allowed: %v", change, err)
		}
	}
	policy.Subject = subject
	allowed = false
	if _, err := source.Resolve(t.Context(), subject); err == nil || err.Error() != "permission_source_denied" {
		t.Fatal("native denial ignored")
	}
	allowed = true
	policy.Resources[0].Scope.Kind = "custom_expression"
	if _, err := source.Resolve(t.Context(), subject); err == nil {
		t.Fatal("unsupported native expression accepted")
	}
}

func TestNativePermissionSourceRejectsUntrustedTransportsAndReplies(t *testing.T) {
	for _, endpoint := range []string{"http://service/permissions", "https://user:password@service/permissions", "https://service/permissions?token=x", "https://service/permissions#x"} {
		if _, err := NewHTTPPermissionSource(endpoint, "credential"); err == nil {
			t.Fatal("unsafe source URL accepted")
		}
	}
	if _, err := NewHTTPPermissionSource("https://service/permissions", ""); err == nil {
		t.Fatal("unauthenticated source accepted")
	}
	subject := PermissionSubject{UserID: "7", Email: "person@example.com", TenantID: "tenant", ObjectID: "actor", Label: "label"}
	for _, response := range []struct {
		status int
		body   string
	}{{http.StatusFound, ""}, {http.StatusForbidden, ""}, {http.StatusOK, `{"allowed":true,"revision":"r1","resources":[]}`}, {http.StatusOK, `{} {}`}, {http.StatusOK, `{"unknown":"sql"}`}} {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(response.status)
			w.Write([]byte(response.body))
		}))
		source, _ := NewHTTPPermissionSource(server.URL, "credential")
		source.client.Transport = server.Client().Transport
		if _, err := source.Resolve(t.Context(), subject); err == nil {
			t.Fatal("invalid source reply accepted")
		}
		server.Close()
	}
}
