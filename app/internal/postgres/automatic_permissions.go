package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"
	"iq-kbteams/internal/authorization"
)

func (c *Connector) WithPermissionSource(source authorization.PermissionSource) *Connector {
	copy := *c
	copy.permissionSource = source
	return &copy
}
func (c *Connector) PermissionSourceConfigured() bool { return c != nil && c.permissionSource != nil }

func (c *Connector) resolveAutomaticPermissions(ctx context.Context, tx pgx.Tx, id ResolvedIdentity) (ResolvedIdentity, error) {
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
	id.AutomaticPermissions = true
	id.AutomaticClaimColumns = policy.ClaimColumns
	return id, nil
}

type AutomaticPermissionPreview struct {
	Configured   bool                 `json:"configured"`
	Status       string               `json:"status"`
	UserID       string               `json:"userId,omitempty"`
	Label        string               `json:"label,omitempty"`
	Rules        []authorization.Rule `json:"rules,omitempty"`
	ClaimColumns map[string]string    `json:"claimColumns,omitempty"`
}

func (c *Connector) PreviewAutomaticPermissions(ctx context.Context) (AutomaticPermissionPreview, error) {
	result := AutomaticPermissionPreview{Configured: c.PermissionSourceConfigured(), Status: "permission_source_not_configured"}
	if !result.Configured {
		return result, nil
	}
	if !c.applicationRules() || c.subject == nil {
		return result, errors.New("application permission mapping required")
	}
	conn, tx, id, err := c.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return result, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	result.Status = "resolved"
	result.UserID = id.UserID
	result.Label = id.ApplicationRole
	result.Rules = id.Rules
	// Claims in the preview are column mappings only, never attribute values.
	result.ClaimColumns = id.AutomaticClaimColumns
	return result, nil
}
