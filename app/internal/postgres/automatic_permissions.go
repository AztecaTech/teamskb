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
func (c *Connector) ExternalPermissionSourceAvailable() bool {
	return c != nil && c.permissionSource != nil
}

// External decisions require explicit adapter configuration. Merely retaining
// an old deployment URL never overrides IQ Knowledge's own saved permissions.
func (c *Connector) PermissionSourceConfigured() bool {
	return c != nil && c.applicationRules() && c.adapter.PermissionSource == "external" && c.ExternalPermissionSourceAvailable()
}

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
	Mode         string               `json:"mode"`
	Status       string               `json:"status"`
	UserID       string               `json:"userId,omitempty"`
	Label        string               `json:"label,omitempty"`
	Rules        []authorization.Rule `json:"rules,omitempty"`
	ClaimColumns map[string]string    `json:"claimColumns,omitempty"`
}

func (c *Connector) PreviewAutomaticPermissions(ctx context.Context) (AutomaticPermissionPreview, error) {
	if !c.applicationRules() || c.subject == nil {
		return AutomaticPermissionPreview{}, errors.New("application permission mapping required")
	}
	if c.adapter.PermissionSource != "external" {
		return c.previewInternalPermissions(ctx)
	}
	result := AutomaticPermissionPreview{Configured: true, Mode: "external", Status: "permission_source_not_configured"}
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

// Reuse administrator-reviewed policy stored in IQ Knowledge. Labels and all
// relation/column/scope mappings are data, never guessed from database metadata.
// Identity, mapped attributes and membership filters remain freshly resolved.
func (c *Connector) previewInternalPermissions(ctx context.Context) (AutomaticPermissionPreview, error) {
	result := AutomaticPermissionPreview{Configured: true, Mode: "internal", Status: "internal_rules_required"}
	id, err := c.RecognizeUser(ctx)
	if err != nil {
		return result, err
	}
	result.UserID, result.Label = id.UserID, id.ApplicationRole
	for _, rule := range c.adapter.Rules {
		if rule.Label == id.ApplicationRole && rule.Reviewed {
			result.Rules = append(result.Rules, rule)
		}
	}
	if len(result.Rules) == 0 {
		return result, nil
	}
	conn, tx, current, err := c.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return result, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	if current.UserID != id.UserID || current.ApplicationRole != id.ApplicationRole {
		return result, &AuthorizationError{Code: "permission_source_identity_mismatch"}
	}
	for _, rule := range result.Rules {
		decision, err := c.authorizeResource(ctx, current, rule.Schema, rule.Relation, rule.Fields)
		if err != nil {
			return result, err
		}
		if _, err = scopedRelation(ctx, tx, rule.Schema, rule.Relation, decision); err != nil {
			return result, err
		}
	}
	result.Status = "resolved"
	result.ClaimColumns = c.adapter.Claims
	return result, nil
}
