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
	Mode           string `json:"mode"`
	Schema         string `json:"schema"`
	Relation       string `json:"relation"`
	ApprovalRecord string `json:"approvalRecord"`
}

type Subject struct{ TenantID, ObjectID, Email string }
type ResolvedIdentity struct{ UserID, Role, PermissionVersion string }

func (a AdapterConfig) Validate() error {
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
	copy := *c
	copy.adapter, copy.subject = &a, &subject
	return &copy, nil
}

// All identity resolution and SET LOCAL state share the query's read-only
// transaction. Nothing runs as the service account after resolution.
func (c *Connector) beginAuthorized(ctx context.Context, login, password string) (*pgx.Conn, pgx.Tx, ResolvedIdentity, error) {
	var resolved ResolvedIdentity
	conn, err := c.connect(ctx, login, password)
	if err != nil {
		return nil, nil, resolved, err
	}
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		closeConnection(conn)
		return nil, nil, resolved, err
	}
	fail := func(err error) (*pgx.Conn, pgx.Tx, ResolvedIdentity, error) {
		_ = tx.Rollback(ctx)
		closeConnection(conn)
		return nil, nil, resolved, err
	}
	if err = setLimits(ctx, tx); err != nil {
		return fail(err)
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
	rows, err := tx.Query(ctx, `SELECT user_id::text,database_role::text,permission_version::text,active FROM `+relation+` WHERE tenant_id::text=$1 AND lower(btrim(email::text))=$2 LIMIT 2`, c.subject.TenantID, strings.ToLower(strings.TrimSpace(c.subject.Email)))
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

func (c *Connector) ResolveIdentity(ctx context.Context, login, password string) (ResolvedIdentity, error) {
	conn, tx, resolved, err := c.beginAuthorized(ctx, login, password)
	if err != nil {
		return resolved, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	return resolved, nil
}
