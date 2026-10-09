package postgres

import (
	"context"
	"errors"
)

type PermissionResourcePage struct {
	Resources        []PermissionRelation `json:"resources"`
	NextSchema       string               `json:"nextSchema,omitempty"`
	NextName         string               `json:"nextName,omitempty"`
	ColumnsTruncated bool                 `json:"columnsTruncated"`
}

// An administrator can inspect resource metadata before the user mapping has
// executable permissions. This method never exposes a search transaction.
func (c *Connector) DiscoverPermissionResources(ctx context.Context, schemaAfter, nameAfter string) (PermissionResourcePage, error) {
	page := PermissionResourcePage{Resources: []PermissionRelation{}}
	if !c.SharedCredentialsConfigured() || len(schemaAfter) > 63 || len(nameAfter) > 63 {
		return page, errors.New("invalid resource discovery")
	}
	metadata := *c
	metadata.adapter = nil
	metadata.subject = nil
	metadata.metadataOnly = true
	conn, tx, _, err := metadata.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return page, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	rows, err := tx.Query(ctx, `SELECT n.nspname,c.relname,ARRAY(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT') ORDER BY a.attnum LIMIT 101),c.relrowsecurity,c.relforcerowsecurity,ARRAY(SELECT a.attname::text FROM pg_attribute a JOIN pg_type t ON t.oid=a.atttypid JOIN pg_namespace tn ON tn.oid=t.typnamespace WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND tn.nspname='pg_catalog' AND t.typname IN ('text','varchar','bpchar','name','uuid','int2','int4','int8','numeric','float4','float8','bool','date','timestamp','timestamptz') AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT') ORDER BY a.attnum LIMIT 101)
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND n.nspname NOT LIKE 'pg_temp%' AND c.relkind IN ('r','p')
AND (n.nspname::text,c.relname::text)>($1::text,$2::text)
AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT'))
ORDER BY n.nspname,c.relname LIMIT 26`, schemaAfter, nameAfter)
	if err != nil {
		return page, err
	}
	scanned := 0
	lastSchema, lastName := "", ""
	for rows.Next() {
		var item PermissionRelation
		if err = rows.Scan(&item.Schema, &item.Relation, &item.Columns, &item.RLSEnabled, &item.RLSForced, &item.ScalarColumns); err != nil {
			break
		}
		if scanned == 25 {
			page.NextSchema, page.NextName = lastSchema, lastName
			break
		}
		scanned++
		lastSchema, lastName = item.Schema, item.Relation
		if len(item.Columns) > 100 {
			item.Columns = item.Columns[:100]
			page.ColumnsTruncated = true
		}
		fields := []string{}
		for _, field := range item.Columns {
			if !SensitiveAuthorizationField(field) {
				fields = append(fields, field)
			}
		}
		item.Columns = fields
		scalar := []string{}
		allowed := map[string]bool{}
		for _, field := range fields {
			allowed[field] = true
		}
		for _, field := range item.ScalarColumns {
			if allowed[field] {
				scalar = append(scalar, field)
			}
		}
		item.ScalarColumns = scalar
		if len(fields) > 0 {
			item.Evidence = "readable resource metadata; access requires reviewed rules"
			page.Resources = append(page.Resources, item)
		}
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return page, errors.Join(err, rowErr)
	}
	return page, tx.Commit(ctx)
}
