package postgres

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/jackc/pgx/v5"
)

// DiscoverApplicationLabels reads identifiers, not PostgreSQL execution roles.
// The identity lookup first verifies the selected mapping and the current user.
// Values are tenant-filtered and never acquire privileges based on their name.
func (c *Connector) DiscoverApplicationLabels(ctx context.Context) ([]string, ResolvedIdentity, error) {
	conn, tx, matched, err := c.beginIdentityLookup(ctx)
	if err != nil {
		return nil, matched, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	columns := AuthorizationColumns{Role: "database_role", Active: "active", TenantID: "tenant_id"}
	if c.adapter.Columns != nil {
		columns = *c.adapter.Columns
	}
	quote := func(name string) string { return pgx.Identifier{name}.Sanitize() }
	where := quote(columns.Active) + `=true`
	args := []any{}
	if columns.TenantID != "" {
		where += ` AND ` + quote(columns.TenantID) + `::text=$1`
		args = append(args, c.subject.TenantID)
	}
	column := quote(columns.Role)
	rows, err := tx.Query(ctx, `SELECT DISTINCT `+column+`::text FROM `+pgx.Identifier{c.adapter.Schema, c.adapter.Relation}.Sanitize()+` WHERE `+where+` AND length(`+column+`::text) BETWEEN 1 AND 256 ORDER BY 1 LIMIT 101`, args...)
	if err != nil {
		return nil, matched, err
	}
	defer rows.Close()
	labels := []string{}
	for rows.Next() {
		var label string
		if err := rows.Scan(&label); err != nil {
			return nil, matched, err
		}
		if len(labels) == 100 {
			return nil, matched, &AuthorizationError{Code: "application_labels_limit_exceeded"}
		}
		labels = append(labels, label)
	}
	return labels, matched, rows.Err()
}

// RoleSearchProfile is a data-free draft derived from safe catalog metadata.
// Approval and live schema verification are still required before execution.
func roleSearchProfile(schema, relation, key string, names, types []string) *BusinessProfile {
	if key == "" || len(names) != len(types) || SensitiveAuthorizationField(key) {
		return nil
	}
	digest := sha256.Sum256([]byte(schema + "\x00" + relation))
	p := BusinessProfile{ID: "table_" + hex.EncodeToString(digest[:12]), Version: 1, Label: strings.ReplaceAll(relation, "_", " "), Capability: "text_search", SearchStrategy: "keyword", Schema: schema, Relation: relation, KeyColumn: key}
	// Identifier limits are bytes; business labels have the same bounded limit.
	if len(p.Label) > 128 {
		p.Label = relation
	}
	keyFound := false
	for i, name := range names {
		if SensitiveAuthorizationField(name) {
			continue
		}
		if name == key {
			keyFound = true
			continue
		}
		typeName := roleProfileType(types[i])
		if typeName == "" {
			continue
		}
		if typeName == "text" && len(p.SearchColumns) < 12 {
			p.SearchColumns = append(p.SearchColumns, name)
		}
		if len(p.ReturnColumns) < 12 {
			p.ReturnColumns = append(p.ReturnColumns, ProfileColumn{Name: name, Type: typeName})
		}
	}
	if !keyFound || len(p.SearchColumns) == 0 || len(p.ReturnColumns) == 0 {
		return nil
	}
	p.LabelColumn = p.SearchColumns[0]
	return &p
}

func roleProfileType(t string) string {
	switch t {
	case "text", "varchar", "bpchar", "name", "uuid":
		return "text"
	case "int2", "int4", "int8":
		return "integer"
	case "numeric", "float4", "float8":
		return "number"
	case "bool":
		return "boolean"
	case "date":
		return "date"
	case "timestamp", "timestamptz":
		return "timestamp"
	}
	return ""
}

// Only the fields actually used by the generated profile receive a grant.
func RoleSearchFields(p BusinessProfile) []string { return profileFields(p) }
