package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"iq-kbteams/internal/authorization"
)

// AdapterConfig maps an existing identity relation and a reviewed authorization
// provider. Clients never supply their effective label or identity attributes.
type AdapterConfig struct {
	Mode             string                `json:"mode"`
	PermissionSource string                `json:"permissionSource,omitempty"`
	Schema           string                `json:"schema"`
	Relation         string                `json:"relation"`
	ApprovalRecord   string                `json:"approvalRecord"`
	Columns          *AuthorizationColumns `json:"columns,omitempty"`
	TenantScope      string                `json:"tenantScope,omitempty"`
	RoleMappings     map[string]string     `json:"roleMappings,omitempty"`
	Rules            []authorization.Rule  `json:"rules,omitempty"`
	Claims           map[string]string     `json:"claims,omitempty"`
}

type AuthorizationColumns struct {
	Email             string `json:"email"`
	UserID            string `json:"userId"`
	Role              string `json:"role"`
	Active            string `json:"active"`
	TenantID          string `json:"tenantId,omitempty"`
	PermissionVersion string `json:"permissionVersion,omitempty"`
}

type Subject struct{ TenantID, ObjectID, Email string }
type ResolvedIdentity struct {
	UserID, Role, PermissionVersion, ApplicationRole string
	Claims                                           map[string]string
	Rules                                            []authorization.Rule
	ExternalPermissions                              bool
	ExternalClaimColumns                             map[string]string
}

type AuthorizationError struct {
	Code  string
	Cause error
}

func (e *AuthorizationError) Error() string { return e.Code }
func (e *AuthorizationError) Unwrap() error { return e.Cause }
func AuthorizationFailureCode(err error) string {
	var failure *AuthorizationError
	if errors.As(err, &failure) {
		return failure.Code
	}
	if errors.Is(err, ErrUnsafeDatabaseRole) {
		return "unsafe_service_login"
	}
	return DiscoveryFailureCode(err)
}

func (a AdapterConfig) Validate() error {
	if a.PermissionLocation() != InternalPermissionSource && a.PermissionLocation() != ExternalPermissionSource {
		return errors.New("invalid permission adapter location")
	}
	if a.PermissionSource != "" && a.Mode != "application_rules" {
		return errors.New("permission adapter location requires application rules")
	}
	if err := validateApplicationConfiguration(a); err != nil {
		return err
	}
	if len(a.RoleMappings) > 100 {
		return errors.New("too many role mappings")
	}
	for application, execution := range a.RoleMappings {
		if strings.TrimSpace(application) == "" || len(application) > 256 || !ValidDatabaseIdentity(execution) {
			return errors.New("invalid role translation")
		}
	}
	if a.Columns != nil {
		for _, column := range []string{a.Columns.Email, a.Columns.UserID, a.Columns.Role, a.Columns.Active} {
			if !ValidDatabaseIdentity(column) {
				return errors.New("invalid authorization column mapping")
			}
		}
		for _, column := range []string{a.Columns.TenantID, a.Columns.PermissionVersion} {
			if column != "" && !ValidDatabaseIdentity(column) {
				return errors.New("invalid authorization column mapping")
			}
		}
		if a.Columns.TenantID == "" && a.TenantScope == "" {
			return errors.New("single-tenant mapping requires a trusted tenant scope")
		}
	}
	if (a.Mode != "postgres_role" && a.Mode != "session_context" && a.Mode != "application_rules") || !ValidDatabaseIdentity(a.Schema) || !ValidDatabaseIdentity(a.Relation) || strings.TrimSpace(a.ApprovalRecord) == "" || len(a.ApprovalRecord) > 200 {
		return errors.New("invalid authorization adapter")
	}
	return nil
}

func (a AdapterConfig) Fingerprint() string {
	data, _ := json.Marshal(a)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (c *Connector) SharedCredentialsConfigured() bool {
	return c != nil && c.service != nil && c.service.User != "" && c.service.Password != ""
}

func (c *Connector) ForSubject(a AdapterConfig, subject Subject) (*Connector, error) {
	subject.Email = strings.ToLower(strings.TrimSpace(subject.Email))
	if a.Validate() != nil || !c.SharedCredentialsConfigured() || subject.TenantID == "" || subject.ObjectID == "" || !strings.Contains(subject.Email, "@") {
		return nil, errors.New("database adapter, shared credentials, and trusted email are required")
	}
	if a.Columns != nil && a.Columns.TenantID == "" && subject.TenantID != a.TenantScope {
		return nil, errors.New("database mapping belongs to a different tenant")
	}
	if a.UsesExternalPermissions() && !c.ExternalPermissionSourceAvailable() {
		return nil, &AuthorizationError{Code: "permission_source_not_configured"}
	}
	copy := *c
	copy.adapter, copy.subject = &a, &subject
	return &copy, nil
}

// All identity resolution and SET LOCAL state share the query's read-only
// transaction. Native modes switch execution role; application-rules mode only
// permits server-compiled, field- and row-scoped profile queries.
func (c *Connector) beginAuthorized(ctx context.Context, login, password string) (*pgx.Conn, pgx.Tx, ResolvedIdentity, error) {
	var resolved ResolvedIdentity
	setupError := func(stage string, err error) error {
		if c.metadataOnly {
			return &AuthorizationDiscoveryError{Stage: stage, Cause: err}
		}
		return err
	}
	conn, err := c.connect(ctx, login, password)
	if err != nil {
		return nil, nil, resolved, setupError("connection", err)
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		closeConnection(conn)
		return nil, nil, resolved, setupError("transaction_begin", err)
	}
	fail := func(err error) (*pgx.Conn, pgx.Tx, ResolvedIdentity, error) {
		_ = tx.Rollback(ctx)
		closeConnection(conn)
		return nil, nil, resolved, err
	}
	if err = setLimits(ctx, tx); err != nil {
		return fail(setupError("session_limits", err))
	}
	if c.applicationRules() {
		if _, err = tx.Exec(ctx, `SET LOCAL search_path = pg_catalog`); err != nil {
			return fail(err)
		}
	}
	if c.metadataOnly {
		var session, current string
		if err = tx.QueryRow(ctx, `SELECT session_user::text,current_user::text`).Scan(&session, &current); err != nil {
			return fail(setupError("session_identity", err))
		}
		// Proxies may translate a URI login (for example user.project) to a
		// canonical PostgreSQL session user. Metadata requires an unchanged
		// authenticated session role, rather than equality with the URI alias.
		if !validMetadataSession(session, current) {
			return fail(setupError("session_identity", ErrMetadataIdentityMismatch))
		}
		return conn, tx, resolved, nil
	}
	if c.adapter == nil {
		if err = checkExecutionIdentity(ctx, tx, login); err != nil {
			return fail(err)
		}
		return conn, tx, ResolvedIdentity{UserID: login, Role: login}, nil
	}
	var serviceSession, serviceCurrent string
	var serviceSuperuser bool
	if err = tx.QueryRow(ctx, `SELECT session_user::text,current_user::text,r.rolsuper FROM pg_roles r WHERE r.rolname=current_user`).Scan(&serviceSession, &serviceCurrent, &serviceSuperuser); err != nil || !validMetadataSession(serviceSession, serviceCurrent) {
		return fail(&AuthorizationError{Code: "service_identity_mismatch", Cause: err})
	}
	lookup := *c
	if c.applicationRules() && c.ExternalPermissionSourceActive() {
		// Native decisions replace saved attribute mappings as well as rules.
		// Resolve the base identity first, then read only native-selected claims.
		config := *c.adapter
		config.Claims = nil
		lookup.adapter = &config
	}
	resolved, err = lookup.lookupMappedUser(ctx, tx)
	if err != nil {
		return fail(err)
	}
	if c.applicationRules() {
		if c.ExternalPermissionSourceActive() {
			resolved, err = c.resolveExternalPermissions(ctx, tx, resolved)
			if err != nil {
				return fail(err)
			}
		}
		allowed := false
		rules := c.adapter.Rules
		if resolved.ExternalPermissions {
			rules = resolved.Rules
		}
		for _, rule := range rules {
			if rule.Label == resolved.ApplicationRole && rule.Reviewed {
				allowed = true
			}
		}
		if !allowed {
			return fail(&AuthorizationError{Code: "application_permission_rules_required"})
		}
		claims, _ := json.Marshal(resolved.Claims)
		if _, err = tx.Exec(ctx, `SELECT set_config('iqkb.user_id',$1,true),set_config('iqkb.email',$2,true),set_config('iqkb.tenant_id',$3,true),set_config('iqkb.claims',$4,true)`, resolved.UserID, c.subject.Email, c.subject.TenantID, string(claims)); err != nil {
			return fail(err)
		}
		return conn, tx, resolved, nil
	}
	if len(c.adapter.RoleMappings) > 0 {
		translated, ok := c.adapter.RoleMappings[resolved.ApplicationRole]
		if !ok {
			return fail(&AuthorizationError{Code: "application_role_mapping_required"})
		}
		resolved.Role = translated
		versionHash := sha256.Sum256([]byte(resolved.PermissionVersion + "\x00" + resolved.ApplicationRole))
		resolved.PermissionVersion = hex.EncodeToString(versionHash[:])
	}
	if resolved.UserID == "" || len(resolved.UserID) > 256 || resolved.PermissionVersion == "" || len(resolved.PermissionVersion) > 256 {
		return fail(&AuthorizationError{Code: "user_mapping_values_invalid"})
	}
	if !ValidDatabaseIdentity(resolved.Role) || resolved.Role == c.service.User || resolved.Role == serviceSession {
		return fail(&AuthorizationError{Code: "execution_role_invalid"})
	}
	var unsafe bool
	if err = tx.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=$1`, resolved.Role).Scan(&unsafe); errors.Is(err, pgx.ErrNoRows) {
		return fail(&AuthorizationError{Code: "execution_role_not_found"})
	} else if err != nil {
		return fail(&AuthorizationError{Code: "execution_role_check_failed", Cause: err})
	}
	if unsafe {
		return fail(&AuthorizationError{Code: "execution_role_unsafe"})
	}
	{
		var ownsTables bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname=$1) AND relkind IN ('r','p'))`, resolved.Role).Scan(&ownsTables); err != nil || ownsTables {
			return fail(&AuthorizationError{Code: "execution_role_owns_tables", Cause: err})
		}
	}
	if serviceSuperuser {
		// A privileged bootstrap connection must relinquish both session and
		// execution identity before returning a transaction to search callers.
		if _, err = tx.Exec(ctx, `SET LOCAL SESSION AUTHORIZATION `+pgx.Identifier{resolved.Role}.Sanitize()); err != nil {
			return fail(&AuthorizationError{Code: "execution_role_switch_failed", Cause: err})
		}
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{resolved.Role}.Sanitize()); err != nil {
		return fail(&AuthorizationError{Code: "execution_role_not_granted", Cause: err})
	}
	if _, err = tx.Exec(ctx, `SET LOCAL row_security = on`); err != nil {
		return fail(err)
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('iqkb.user_id',$1,true),set_config('iqkb.email',$2,true),set_config('iqkb.tenant_id',$3,true),set_config('iqkb.teams_object_id',$4,true)`, resolved.UserID, c.subject.Email, c.subject.TenantID, c.subject.ObjectID); err != nil {
		return fail(err)
	}
	if c.adapter.Mode == "session_context" {
		claims, _ := json.Marshal(map[string]string{"sub": resolved.UserID, "email": c.subject.Email, "role": resolved.ApplicationRole, "database_role": resolved.Role, "tenant_id": c.subject.TenantID, "teams_object_id": c.subject.ObjectID})
		if _, err = tx.Exec(ctx, `SELECT set_config('request.jwt.claims',$1,true)`, string(claims)); err != nil {
			return fail(err)
		}
	}
	var current, session string
	var effectiveUnsafe bool
	if err = tx.QueryRow(ctx, `SELECT current_user::text,session_user::text,r.rolsuper OR r.rolbypassrls FROM pg_roles r WHERE r.rolname=current_user`).Scan(&current, &session, &effectiveUnsafe); err != nil || current != resolved.Role || effectiveUnsafe || (serviceSuperuser && session != resolved.Role) {
		return fail(&AuthorizationError{Code: "execution_role_switch_failed", Cause: err})
	}
	return conn, tx, resolved, nil
}

var ErrMetadataIdentityMismatch = errors.New("metadata connection identity mismatch")

func validMetadataSession(session, current string) bool {
	return session != "" && session == current
}

func (c *Connector) ResolveIdentity(ctx context.Context, login, password string) (ResolvedIdentity, error) {
	conn, tx, resolved, err := c.beginAuthorized(ctx, login, password)
	if err != nil {
		return resolved, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	return resolved, nil
}
