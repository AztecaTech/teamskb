package main

import (
	"bytes"
	"testing"
	"time"

	"iq-kbteams/internal/identity"
	"iq-kbteams/internal/postgres"
)

func TestPermissionPreviewRequiresExactAdministratorReview(t *testing.T) {
	key := bytes.Repeat([]byte{0x45}, 32)
	p := identity.Principal{TenantID: "tenant-one", ObjectID: "reviewer"}
	now := time.Now()
	preview := "reviewed server SQL"
	input := permissionApplyRequest{AdapterFingerprint: "adapter", AcknowledgeImpact: true, PreviewExpiresAt: now.Add(10 * time.Minute).Unix(), Drafts: []postgres.PermissionDraft{{Label: "label-a", ExecutionRole: "restricted_role"}}}
	input.PreviewToken = permissionPreviewToken(key, p, input.AdapterFingerprint, preview, input.Drafts, input.PreviewExpiresAt)
	if !validPermissionPreview(key, p, input, preview, now) {
		t.Fatal("valid review rejected")
	}
	for name, change := range map[string]func(*permissionApplyRequest){
		"unacknowledged":  func(r *permissionApplyRequest) { r.AcknowledgeImpact = false },
		"adapter changed": func(r *permissionApplyRequest) { r.AdapterFingerprint = "different" },
		"label changed with identical SQL": func(r *permissionApplyRequest) {
			r.Drafts = []postgres.PermissionDraft{{Label: "different-label", ExecutionRole: "restricted_role"}}
		},
		"expiry extended":   func(r *permissionApplyRequest) { r.PreviewExpiresAt += 60 },
		"missing signature": func(r *permissionApplyRequest) { r.PreviewToken = "" },
	} {
		t.Run(name, func(t *testing.T) {
			modified := input
			change(&modified)
			if validPermissionPreview(key, p, modified, preview, now) {
				t.Fatal("modified review accepted")
			}
		})
	}
	if validPermissionPreview(key, p, input, preview+"; additional SQL", now) {
		t.Fatal("changed SQL accepted")
	}
	if validPermissionPreview(key, identity.Principal{TenantID: p.TenantID, ObjectID: "another-reviewer"}, input, preview, now) {
		t.Fatal("another administrator reused approval")
	}
	if validPermissionPreview(key, identity.Principal{TenantID: "another-tenant", ObjectID: p.ObjectID}, input, preview, now) {
		t.Fatal("another tenant reused approval")
	}
	if validPermissionPreview(key, p, input, preview, now.Add(11*time.Minute)) {
		t.Fatal("expired approval accepted")
	}
}
