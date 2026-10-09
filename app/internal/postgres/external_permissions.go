package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/jackc/pgx/v5"
	"iq-kbteams/internal/authorization"
)

func (c *Connector) WithPermissionSource(source authorization.PermissionSource) *Connector {
	copy := *c
	copy.permissionSource = source
	return &copy
}
func (c *Connector) ExternalPermissionSourceAvailable() bool {
	return c != nil && c.permissionSource != nil
}

// External decisions require explicit adapter configuration. Merely retaining
// an old deployment URL never overrides IQ Knowledge's own saved permissions.
func (c *Connector) ExternalPermissionSourceActive() bool {
	return c != nil && c.adapter != nil && c.adapter.UsesExternalPermissions() && c.ExternalPermissionSourceAvailable()
}

func (c *Connector) resolveExternalPermissions(ctx context.Context, tx pgx.Tx, id ResolvedIdentity) (ResolvedIdentity, error) {
	policy, err := c.permissionSource.Resolve(ctx, authorization.PermissionSubject{UserID: id.UserID, Email: c.subject.Email, TenantID: c.subject.TenantID, ObjectID: c.subject.ObjectID, Label: id.ApplicationRole})
	if err != nil {
		return id, &AuthorizationError{Code: err.Error()}
	}
	config := *c.adapter
	config.Rules = policy.Rules
	config.Claims = policy.ClaimColumns
	if config.Validate() != nil {
		return id, &AuthorizationError{Code: "permission_source_response_invalid"}
	}
	// The provider names attributes; their values still come from the exact
	// active database user, rather than browser input or remote business rows.
	if len(policy.ClaimColumns) > 0 {
		copy := *c
		copy.adapter = &config
		current, err := copy.lookupMappedUser(ctx, tx)
		if err != nil {
			return id, err
		}
		if current.UserID != id.UserID || current.ApplicationRole != id.ApplicationRole {
			return id, &AuthorizationError{Code: "permission_source_identity_mismatch"}
		}
		id = current
	}
	for _, rule := range policy.Rules {
		decision := authorization.Decision{Fields: rule.Fields, Scope: rule.Scope}
		if rule.Scope.Kind == "claim" && id.Claims[rule.Scope.Claim] == "" {
			return id, &AuthorizationError{Code: "permission_source_identity_attribute_required"}
		}
		if _, err := scopedRelation(ctx, tx, rule.Schema, rule.Relation, decision); err != nil {
			return id, err
		}
	}
	material, _ := json.Marshal(struct {
		IdentityRevision, Source, Revision string
		Rules                              []authorization.Rule
		ClaimColumns                       map[string]string
	}{id.PermissionVersion, c.permissionSource.Fingerprint(), policy.Revision, policy.Rules, policy.ClaimColumns})
	hash := sha256.Sum256(material)
	id.PermissionVersion = hex.EncodeToString(hash[:])
	id.Rules = policy.Rules
	id.ExternalPermissions = true
	id.ExternalClaimColumns = policy.ClaimColumns
	return id, nil
}
