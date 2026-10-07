package postgres

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5"
	"strings"
)

type ExecutionRole struct {
	Name     string `json:"name"`
	Policies int    `json:"policies"`
}
type RoleDiscovery struct {
	ApplicationRoles []string        `json:"applicationRoles"`
	ExecutionRoles   []ExecutionRole `json:"executionRoles"`
	Truncated        bool            `json:"truncated"`
}

func (c *Connector) DiscoverRoleMappings(ctx context.Context, schema, relation, column string) (RoleDiscovery, error) {
	result := RoleDiscovery{ApplicationRoles: []string{}, ExecutionRoles: []ExecutionRole{}}
	if !c.SharedCredentialsConfigured() || !ValidDatabaseIdentity(schema) || !ValidDatabaseIdentity(relation) || !ValidDatabaseIdentity(column) {
		return result, errors.New("invalid role discovery")
	}
	switch strings.ToLower(strings.ReplaceAll(column, "_", "")) {
	case "role", "rolename", "databaserole", "postgresrole", "dbrole":
	default:
		return result, errors.New("unsupported role column")
	}
	metadata := *c
	metadata.adapter = nil
	metadata.subject = nil
	metadata.metadataOnly = true
	conn, tx, _, err := metadata.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return result, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT DISTINCT `+pgx.Identifier{column}.Sanitize()+`::text FROM `+pgx.Identifier{schema, relation}.Sanitize()+` WHERE `+pgx.Identifier{column}.Sanitize()+` IS NOT NULL AND length(`+pgx.Identifier{column}.Sanitize()+`::text) BETWEEN 1 AND 256 ORDER BY 1 LIMIT 101`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var role string
		if err = rows.Scan(&role); err != nil {
			break
		}
		if len(result.ApplicationRoles) == 100 {
			result.Truncated = true
			break
		}
		result.ApplicationRoles = append(result.ApplicationRoles, role)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return result, errors.Join(err, rowErr)
	}
	rows, err = tx.Query(ctx, `SELECT r.rolname::text,(SELECT count(*)::integer FROM pg_policy p WHERE r.oid=ANY(p.polroles)) FROM pg_roles r WHERE NOT r.rolsuper AND NOT r.rolbypassrls AND r.rolname<>session_user AND ((SELECT rolsuper FROM pg_roles WHERE rolname=session_user) OR pg_has_role(session_user,r.oid,'MEMBER')) AND r.rolname NOT LIKE 'pg\_%' AND NOT EXISTS(SELECT 1 FROM pg_class c WHERE c.relowner=r.oid AND c.relkind IN ('r','p')) ORDER BY r.rolname LIMIT 101`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var role ExecutionRole
		if err = rows.Scan(&role.Name, &role.Policies); err != nil {
			break
		}
		if len(result.ExecutionRoles) == 100 {
			result.Truncated = true
			break
		}
		result.ExecutionRoles = append(result.ExecutionRoles, role)
	}
	rowErr = rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return result, errors.Join(err, rowErr)
	}
	return result, tx.Commit(ctx)
}
