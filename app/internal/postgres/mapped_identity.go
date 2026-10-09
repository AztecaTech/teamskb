package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"
)

// RecognizeUser only identifies a unique active account. It never returns a
// transaction or establishes permission to search as the connection account.
func (c *Connector) RecognizeUser(ctx context.Context) (ResolvedIdentity, error) {
	conn, tx, id, err := c.beginIdentityLookup(ctx)
	if err != nil {
		return id, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	return id, nil
}

// Only identity lookup and permission-preview code may use this transaction.
// Search callers must use beginAuthorized so reviewed permissions are enforced.
func (c *Connector) beginIdentityLookup(ctx context.Context) (*pgx.Conn, pgx.Tx, ResolvedIdentity, error) {
	if c == nil || c.adapter == nil || c.subject == nil {
		return nil, nil, ResolvedIdentity{}, errors.New("scoped adapter required")
	}
	metadata := *c
	metadata.adapter = nil
	metadata.subject = nil
	metadata.metadataOnly = true
	conn, tx, _, err := metadata.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return nil, nil, ResolvedIdentity{}, err
	}
	fail := func(err error) (*pgx.Conn, pgx.Tx, ResolvedIdentity, error) {
		_ = tx.Rollback(ctx)
		closeConnection(conn)
		return nil, nil, ResolvedIdentity{}, err
	}
	if c.applicationRules() {
		if _, err = tx.Exec(ctx, `SET LOCAL search_path = pg_catalog`); err != nil {
			return fail(err)
		}
	}
	lookup := *c
	if c.applicationRules() && c.ExternalPermissionSourceActive() {
		config := *c.adapter
		config.Claims = nil
		lookup.adapter = &config
	}
	id, err := lookup.lookupMappedUser(ctx, tx)
	if err != nil {
		return fail(err)
	}
	return conn, tx, id, nil
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
	claimNames := make([]string, 0, len(c.adapter.Claims))
	for name := range c.adapter.Claims {
		claimNames = append(claimNames, name)
	}
	sort.Strings(claimNames)
	if len(claimNames) > 0 {
		// Attribute values may come from an existing view, but only builtin
		// scalar columns are accepted; custom casts and structured values are
		// outside this adapter's permission model.
		for _, name := range claimNames {
			var safe bool
			err := tx.QueryRow(ctx, `SELECT tn.nspname='pg_catalog' AND t.typname IN ('text','varchar','bpchar','name','uuid','int2','int4','int8','numeric','float4','float8','bool','date','timestamp','timestamptz') FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace WHERE n.nspname=$1 AND c.relname=$2 AND a.attname=$3 AND a.attnum>0 AND NOT a.attisdropped`, c.adapter.Schema, c.adapter.Relation, c.adapter.Claims[name]).Scan(&safe)
			if err != nil || !safe {
				return resolved, &AuthorizationError{Code: "identity_attribute_unsupported", Cause: err}
			}
		}
		parts := []string{}
		for _, name := range claimNames {
			parts = append(parts, "'"+name+"'", quote(c.adapter.Claims[name])+"::text")
		}
		lookup = strings.Replace(lookup, "::boolean FROM ", "::boolean,jsonb_build_object("+strings.Join(parts, ",")+") FROM ", 1)
	}
	rows, err := tx.Query(ctx, lookup, c.subject.TenantID, strings.ToLower(strings.TrimSpace(c.subject.Email)))
	if err != nil {
		return resolved, &AuthorizationError{Code: "user_mapping_query_failed", Cause: err}
	}
	count := 0
	active := false
	for rows.Next() {
		count++
		values := []any{&resolved.UserID, &resolved.Role, &resolved.PermissionVersion, &active}
		var claimsJSON []byte
		if len(claimNames) > 0 {
			values = append(values, &claimsJSON)
		}
		err = rows.Scan(values...)
		if err == nil && len(claimNames) > 0 {
			err = json.Unmarshal(claimsJSON, &resolved.Claims)
			for _, value := range resolved.Claims {
				if len(value) > 512 {
					err = errors.New("identity attribute is too long")
				}
			}
		}
		if err != nil {
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
	if len(resolved.Claims) > 0 {
		data, _ := json.Marshal(resolved.Claims)
		hash := sha256.Sum256(append([]byte(resolved.PermissionVersion+"\x00"), data...))
		resolved.PermissionVersion = hex.EncodeToString(hash[:])
	}

	if resolved.UserID == "" || len(resolved.UserID) > 256 || resolved.ApplicationRole == "" || len(resolved.ApplicationRole) > 256 || resolved.PermissionVersion == "" || len(resolved.PermissionVersion) > 256 {
		return resolved, &AuthorizationError{Code: "user_mapping_values_invalid"}
	}
	return resolved, nil
}
