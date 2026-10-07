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
type ResolvedIdentity struct{ UserID, Role, PermissionVersion string }

func (a AdapterConfig) Validate() error {
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
	if err = checkExecutionIdentity(ctx, tx, c.service.User); err != nil {
		return fail(err)
	}
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
		return fail(errors.New("database user lookup failed"))
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
	if err != nil || rowErr != nil || count != 1 || !active || resolved.UserID == "" || len(resolved.UserID) > 256 || resolved.PermissionVersion == "" || len(resolved.PermissionVersion) > 256 || !ValidDatabaseIdentity(resolved.Role) || resolved.Role == c.service.User {
		return fail(errors.New("database user is missing, inactive, ambiguous, or has an invalid role"))
	}
	var unsafe bool
	if err = tx.QueryRow(ctx, `SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname=$1`, resolved.Role).Scan(&unsafe); err != nil || unsafe {
		return fail(errors.New("database execution role is unsafe"))
	}
	if c.adapter.Mode == "session_context" {
		var ownsTables bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_class WHERE relowner=(SELECT oid FROM pg_roles WHERE rolname=$1) AND relkind IN ('r','p'))`, resolved.Role).Scan(&ownsTables); err != nil || ownsTables {
			return fail(errors.New("application authorization requires a non-owning execution role"))
		}
	}
	if _, err = tx.Exec(ctx, `SET LOCAL ROLE `+pgx.Identifier{resolved.Role}.Sanitize()); err != nil {
		return fail(errors.New("database execution role is not granted to the service login"))
	}
	if _, err = tx.Exec(ctx, `SET LOCAL row_security = on`); err != nil {
		return fail(err)
	}
	if _, err = tx.Exec(ctx, `SELECT set_config('iqkb.user_id',$1,true),set_config('iqkb.email',$2,true),set_config('iqkb.tenant_id',$3,true),set_config('iqkb.teams_object_id',$4,true)`, resolved.UserID, c.subject.Email, c.subject.TenantID, c.subject.ObjectID); err != nil {
		return fail(err)
	}
	if c.adapter.Mode == "session_context" {
		claims, _ := json.Marshal(map[string]string{"sub": resolved.UserID, "email": c.subject.Email, "role": resolved.Role, "tenant_id": c.subject.TenantID, "teams_object_id": c.subject.ObjectID})
		if _, err = tx.Exec(ctx, `SELECT set_config('request.jwt.claims',$1,true)`, string(claims)); err != nil {
			return fail(err)
		}
	}
	var current string
	if err = tx.QueryRow(ctx, `SELECT current_user::text`).Scan(&current); err != nil || current != resolved.Role {
		return fail(errors.New("database execution role mismatch"))
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
