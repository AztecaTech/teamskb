package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

// AdapterConfig points at a DBA-maintained view of the external auth system.
// Only this view translates external roles; clients never supply their role.
type AdapterConfig struct {
	Mode           string                `json:"mode"`
	Schema         string                `json:"schema"`
	Relation       string                `json:"relation"`
	ApprovalRecord string                `json:"approvalRecord"`
	Columns        *AuthorizationColumns `json:"columns,omitempty"`
	TenantScope    string                `json:"tenantScope,omitempty"`
	RoleMappings   map[string]string     `json:"roleMappings,omitempty"`
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
type ResolvedIdentity struct{ UserID, Role, PermissionVersion, ApplicationRole string }

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
	if (a.Mode != "postgres_role" && a.Mode != "session_context") || !ValidDatabaseIdentity(a.Schema) || !ValidDatabaseIdentity(a.Relation) || strings.TrimSpace(a.ApprovalRecord) == "" || len(a.ApprovalRecord) > 200 {
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
	if a.Validate() != nil || !c.SharedCredentialsConfigured() || subject.TenantID == "" || subject.ObjectID == "" || !strings.Contains(subject.Email, "@") {
		return nil, errors.New("database adapter, shared credentials, and trusted email are required")
	}
	if a.Columns != nil && a.Columns.TenantID == "" && subject.TenantID != a.TenantScope {
		return nil, errors.New("database mapping belongs to a different tenant")
	}
	copy := *c
	copy.adapter, copy.subject = &a, &subject
	return &copy, nil
}

// All identity resolution and SET LOCAL state share the query's read-only
// transaction. Nothing runs as the service account after resolution.
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
	resolved, err = c.lookupMappedUser(ctx, tx)
	if err != nil {
		return fail(err)
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

// RecognizeUser only identifies a unique active account. It never returns a
// transaction or establishes permission to search as the connection account.
func (c *Connector) RecognizeUser(ctx context.Context) (ResolvedIdentity, error) {
	if c.adapter == nil || c.subject == nil {
		return ResolvedIdentity{}, errors.New("scoped adapter required")
	}
	metadata := *c
	metadata.adapter = nil
	metadata.subject = nil
	metadata.metadataOnly = true
	conn, tx, _, err := metadata.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return ResolvedIdentity{}, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	return c.lookupMappedUser(ctx, tx)
}

func (c *Connector) lookupMappedUser(ctx context.Context, tx pgx.Tx) (ResolvedIdentity, error) {
	var resolved ResolvedIdentity
	relation := pgx.Identifier{c.adapter.Schema, c.adapter.Relation}.Sanitize()
	columns := AuthorizationColumns{UserID: "user_id", Role: "database_role", PermissionVersion: "permission_version", Active: "active", TenantID: "tenant_id", Email: "email"}
	if c.adapter.Columns != nil {
		columns = *c.adapter.Columns
	}
	quote := func(name string) string { return "u." + pgx.Identifier{name}.Sanitize() }
	tenant := "$1::text"
	if columns.TenantID != "" {
		tenant = quote(columns.TenantID) + "::text"
	}
	version := "md5(to_jsonb(u)::text)"
	if columns.PermissionVersion != "" {
		version = quote(columns.PermissionVersion) + "::text"
	}
	lookup := `SELECT ` + quote(columns.UserID) + `::text,` + quote(columns.Role) + `::text,` + version + `,` + quote(columns.Active) + `::boolean FROM ` + relation + ` u WHERE ` + tenant + `=$1::text AND lower(btrim(` + quote(columns.Email) + `::text))=$2 LIMIT 2`
	rows, err := tx.Query(ctx, lookup, c.subject.TenantID, strings.ToLower(strings.TrimSpace(c.subject.Email)))
	if err != nil {
		return resolved, &AuthorizationError{Code: "user_mapping_query_failed", Cause: err}
	}
	count := 0
	active := false
	for rows.Next() {
		count++
		if err = rows.Scan(&resolved.UserID, &resolved.Role, &resolved.PermissionVersion, &active); err != nil {
			break
		}
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return resolved, &AuthorizationError{Code: "user_mapping_values_invalid", Cause: errors.Join(err, rowErr)}
	}
	if count == 0 {
		return resolved, &AuthorizationError{Code: "user_email_not_found"}
	}
	if count != 1 {
		return resolved, &AuthorizationError{Code: "user_email_ambiguous"}
	}
	if !active {
		return resolved, &AuthorizationError{Code: "user_inactive"}
	}
	resolved.ApplicationRole = resolved.Role

	if resolved.UserID == "" || len(resolved.UserID) > 256 || resolved.ApplicationRole == "" || len(resolved.ApplicationRole) > 256 || resolved.PermissionVersion == "" || len(resolved.PermissionVersion) > 256 {
		return resolved, &AuthorizationError{Code: "user_mapping_values_invalid"}
	}
	return resolved, nil
}
