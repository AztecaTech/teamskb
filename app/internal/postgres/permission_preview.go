package postgres

import (
	"context"
	"errors"

	"iq-kbteams/internal/authorization"
)

type PermissionPreview struct {
	Configured   bool                 `json:"configured"`
	Mode         string               `json:"mode"`
	Status       string               `json:"status"`
	UserID       string               `json:"userId,omitempty"`
	Label        string               `json:"label,omitempty"`
	Rules        []authorization.Rule `json:"rules,omitempty"`
	ClaimColumns map[string]string    `json:"claimColumns,omitempty"`
}

func (c *Connector) PreviewPermissions(ctx context.Context) (PermissionPreview, error) {
	if !c.applicationRules() || c.subject == nil {
		return PermissionPreview{}, errors.New("application permission mapping required")
	}
	if !c.adapter.UsesExternalPermissions() {
		return c.previewInternalPermissions(ctx)
	}
	result := PermissionPreview{Configured: true, Mode: ExternalPermissionSource, Status: "permission_source_not_configured"}
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
	result.ClaimColumns = id.ExternalClaimColumns
	return result, nil
}

// Reuse administrator-reviewed policy stored in IQ Knowledge. Labels and all
// relation/column/scope mappings are data, never guessed from database metadata.
// Identity, mapped attributes and membership filters remain freshly resolved.
func (c *Connector) previewInternalPermissions(ctx context.Context) (PermissionPreview, error) {
	result := PermissionPreview{Configured: true, Mode: InternalPermissionSource, Status: "internal_rules_required"}
	conn, tx, id, err := c.beginIdentityLookup(ctx)
	if err != nil {
		return result, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	result.UserID, result.Label = id.UserID, id.ApplicationRole
	for _, rule := range c.adapter.Rules {
		if rule.Label == id.ApplicationRole && rule.Reviewed {
			result.Rules = append(result.Rules, rule)
		}
	}
	if len(result.Rules) == 0 {
		return result, nil
	}
	for _, rule := range result.Rules {
		decision, err := c.authorizeResource(ctx, id, rule.Schema, rule.Relation, rule.Fields)
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
