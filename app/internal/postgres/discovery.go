package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

const (
	maxDiscoveryRelations   = 100
	maxDiscoveryColumns     = 2000
	maxDiscoveryKeys        = 100
	maxDiscoveryForeignKeys = 100
	maxDiscoveryBytes       = 256 << 10
)

type DiscoveredRelation struct {
	Schema       string `json:"schema"`
	Name         string `json:"name"`
	Kind         string `json:"kind"`
	Supported    bool   `json:"supported"`
	Reason       string `json:"reason,omitempty"`
	RLSEnabled   bool   `json:"rlsEnabled"`
	RLSForced    bool   `json:"rlsForced"`
	OwnedByLogin bool   `json:"ownedByLogin"`
	Comment      string `json:"comment,omitempty"`
}
type DiscoveredColumn struct {
	Schema   string `json:"schema"`
	Relation string `json:"relation"`
	Name     string `json:"name"`
	DataType string `json:"dataType"`
	Nullable bool   `json:"nullable"`
	Comment  string `json:"comment,omitempty"`
}
type DiscoveredKey struct {
	Schema   string   `json:"schema"`
	Relation string   `json:"relation"`
	Kind     string   `json:"kind"`
	Columns  []string `json:"columns"`
}
type DiscoveredRelationship struct {
	Name           string   `json:"name"`
	SourceSchema   string   `json:"sourceSchema"`
	SourceRelation string   `json:"sourceRelation"`
	SourceColumns  []string `json:"sourceColumns"`
	TargetSchema   string   `json:"targetSchema"`
	TargetRelation string   `json:"targetRelation"`
	TargetColumns  []string `json:"targetColumns"`
}
type DiscoveryPage struct {
	Relations     []DiscoveredRelation     `json:"relations"`
	Columns       []DiscoveredColumn       `json:"columns"`
	Keys          []DiscoveredKey          `json:"keys"`
	Relationships []DiscoveredRelationship `json:"relationships"`
	NextSchema    string                   `json:"nextSchema,omitempty"`
	NextName      string                   `json:"nextName,omitempty"`
}

// Discover returns privilege-filtered metadata only. It never executes a query
// against table rows and all work runs as the mapped login in a read-only tx.
func (c *Connector) Discover(ctx context.Context, databaseIdentity, password, schemaAfter, nameAfter string) (DiscoveryPage, error) {
	var page DiscoveryPage
	if !ValidDatabaseIdentity(databaseIdentity) || password == "" || len(schemaAfter) > 63 || len(nameAfter) > 63 {
		return page, errors.New("invalid PostgreSQL discovery request")
	}
	conn, err := c.connect(ctx, databaseIdentity, password)
	if err != nil {
		return page, errors.New("PostgreSQL discovery failed")
	}
	defer closeConnection(conn)
	tx, err := conn.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return page, errors.New("PostgreSQL discovery failed")
	}
	defer func() { _ = tx.Rollback(context.Background()) }()
	if err := setLimits(ctx, tx); err != nil {
		return page, errors.New("PostgreSQL discovery failed")
	}
	if err := checkExecutionIdentity(ctx, tx, databaseIdentity); err != nil {
		return page, err
	}
	rows, err := tx.Query(ctx, `SELECT c.oid::text,t.table_schema,t.table_name,t.table_type,c.relkind::text,COALESCE(obj_description(c.oid,'pg_class'),''),c.relrowsecurity,c.relforcerowsecurity,pg_get_userbyid(c.relowner)=session_user
FROM information_schema.tables t JOIN pg_namespace n ON n.nspname=t.table_schema JOIN pg_class c ON c.relnamespace=n.oid AND c.relname=t.table_name
WHERE t.table_type IN ('BASE TABLE','VIEW') AND t.table_schema NOT IN ('information_schema','pg_catalog')
AND (t.table_schema,t.table_name) > ($1,$2)
AND (has_table_privilege(session_user,quote_ident(t.table_schema)||'.'||quote_ident(t.table_name),'SELECT') OR has_any_column_privilege(session_user,quote_ident(t.table_schema)||'.'||quote_ident(t.table_name),'SELECT'))
ORDER BY t.table_schema,t.table_name LIMIT $3`, schemaAfter, nameAfter, maxDiscoveryRelations+1)
	if err != nil {
		return page, errors.New("PostgreSQL discovery failed")
	}
	type pendingView struct {
		index int
		oid   string
	}
	var views []pendingView
	for rows.Next() {
		var v DiscoveredRelation
		var oid, relationKind string
		if err := rows.Scan(&oid, &v.Schema, &v.Name, &v.Kind, &relationKind, &v.Comment, &v.RLSEnabled, &v.RLSForced, &v.OwnedByLogin); err != nil {
			rows.Close()
			return page, errors.New("PostgreSQL discovery failed")
		}
		v.Comment = boundedComment(v.Comment)
		v.Supported = v.Kind == "BASE TABLE" && (relationKind == "r" || relationKind == "p") && !(v.OwnedByLogin && v.RLSEnabled && !v.RLSForced)
		if v.Kind == "VIEW" {
			views = append(views, pendingView{index: len(page.Relations), oid: oid})
		}
		if !v.Supported {
			if v.Kind != "VIEW" {
				v.Reason = "Only ordinary or partitioned tables are supported; owner tables with unforced row security are unsafe for this login."
			}
		}
		if len(page.Relations) == maxDiscoveryRelations {
			page.NextSchema, page.NextName = nextRelationCursor(page.Relations)
			break
		}
		page.Relations = append(page.Relations, v)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return page, errors.New("PostgreSQL discovery failed")
	}
	rows.Close()
	for _, view := range views {
		_, viewErr := inspectInvokerView(ctx, tx, view.oid)
		if viewErr == nil {
			page.Relations[view.index].Supported = true
			page.Relations[view.index].Reason = "Invoker security verified; the selected key is checked for nulls and duplicates during each profile query."
		} else {
			page.Relations[view.index].Reason = "Views require invoker security and only safe base-table dependencies."
		}
	}
	if len(page.Relations) == 0 {
		return page, nil
	}
	first, last := page.Relations[0], page.Relations[len(page.Relations)-1]
	keys, err := tx.Query(ctx, `SELECT ns.nspname,c.relname,con.contype::text,array_agg(a.attname ORDER BY k.ordinality)
FROM pg_constraint con JOIN pg_class c ON c.oid=con.conrelid JOIN pg_namespace ns ON ns.oid=c.relnamespace
JOIN unnest(con.conkey) WITH ORDINALITY AS k(attnum,ordinality) ON true JOIN pg_attribute a ON a.attrelid=c.oid AND a.attnum=k.attnum
WHERE con.contype IN ('p','u') AND ns.nspname NOT IN ('information_schema','pg_catalog')
AND (ns.nspname,c.relname)>=($1,$2) AND (ns.nspname,c.relname)<=($3,$4)
AND (has_table_privilege(session_user,c.oid,'SELECT') OR has_any_column_privilege(session_user,c.oid,'SELECT'))
GROUP BY ns.nspname,c.relname,con.oid,con.contype HAVING bool_and(has_column_privilege(session_user,c.oid,a.attnum,'SELECT'))
ORDER BY ns.nspname,c.relname,con.oid LIMIT $5`, first.Schema, first.Name, last.Schema, last.Name, maxDiscoveryKeys+1)
	if err != nil {
		return page, errors.New("PostgreSQL key discovery failed")
	}
	for keys.Next() {
		var v DiscoveredKey
		var kind string
		if err := keys.Scan(&v.Schema, &v.Relation, &kind, &v.Columns); err != nil {
			keys.Close()
			return page, errors.New("PostgreSQL key discovery failed")
		}
		if len(page.Keys) == maxDiscoveryKeys {
			keys.Close()
			return page, errors.New("PostgreSQL key metadata exceeds the page limit")
		}
		v.Kind = "unique"
		if kind == "p" {
			v.Kind = "primary"
		}
		page.Keys = append(page.Keys, v)
	}
	if err := keys.Err(); err != nil {
		keys.Close()
		return page, errors.New("PostgreSQL key discovery failed")
	}
	keys.Close()
	relationships, err := tx.Query(ctx, `SELECT con.conname,sn.nspname,src.relname,array_agg(sa.attname ORDER BY sk.ordinality),tn.nspname,dst.relname,array_agg(da.attname ORDER BY tk.ordinality)
FROM pg_constraint con JOIN pg_class src ON src.oid=con.conrelid JOIN pg_namespace sn ON sn.oid=src.relnamespace
JOIN pg_class dst ON dst.oid=con.confrelid JOIN pg_namespace tn ON tn.oid=dst.relnamespace
JOIN unnest(con.conkey) WITH ORDINALITY AS sk(attnum,ordinality) ON true
JOIN unnest(con.confkey) WITH ORDINALITY AS tk(attnum,ordinality) ON tk.ordinality=sk.ordinality
JOIN pg_attribute sa ON sa.attrelid=src.oid AND sa.attnum=sk.attnum
JOIN pg_attribute da ON da.attrelid=dst.oid AND da.attnum=tk.attnum
WHERE con.contype='f' AND sn.nspname NOT IN ('information_schema','pg_catalog') AND tn.nspname NOT IN ('information_schema','pg_catalog')
AND (sn.nspname,src.relname)>=($1,$2) AND (sn.nspname,src.relname)<=($3,$4)
AND (has_table_privilege(session_user,src.oid,'SELECT') OR has_any_column_privilege(session_user,src.oid,'SELECT'))
AND (has_table_privilege(session_user,dst.oid,'SELECT') OR has_any_column_privilege(session_user,dst.oid,'SELECT'))
AND has_column_privilege(session_user,src.oid,sa.attnum,'SELECT') AND has_column_privilege(session_user,dst.oid,da.attnum,'SELECT')
GROUP BY con.oid,con.conname,sn.nspname,src.relname,tn.nspname,dst.relname ORDER BY sn.nspname,src.relname,con.conname LIMIT $5`, first.Schema, first.Name, last.Schema, last.Name, maxDiscoveryForeignKeys+1)
	if err != nil {
		return page, errors.New("PostgreSQL relationship discovery failed")
	}
	for relationships.Next() {
		var v DiscoveredRelationship
		if err := relationships.Scan(&v.Name, &v.SourceSchema, &v.SourceRelation, &v.SourceColumns, &v.TargetSchema, &v.TargetRelation, &v.TargetColumns); err != nil {
			relationships.Close()
			return page, errors.New("PostgreSQL relationship discovery failed")
		}
		if len(page.Relationships) == maxDiscoveryForeignKeys {
			relationships.Close()
			return page, errors.New("PostgreSQL relationship metadata exceeds the page limit")
		}
		page.Relationships = append(page.Relationships, v)
	}
	if err := relationships.Err(); err != nil {
		relationships.Close()
		return page, errors.New("PostgreSQL relationship discovery failed")
	}
	relationships.Close()
	cols, err := tx.Query(ctx, `SELECT c.table_schema,c.table_name,c.column_name,c.data_type,c.is_nullable,COALESCE(col_description((quote_ident(c.table_schema)||'.'||quote_ident(c.table_name))::regclass,c.ordinal_position),'')
FROM information_schema.columns c
WHERE (c.table_schema,c.table_name) >= ($1,$2) AND (c.table_schema,c.table_name) <= ($3,$4)
AND c.table_schema NOT IN ('information_schema','pg_catalog')
AND has_column_privilege(session_user,quote_ident(c.table_schema)||'.'||quote_ident(c.table_name),c.column_name,'SELECT')
ORDER BY c.table_schema,c.table_name,c.ordinal_position LIMIT $5`, first.Schema, first.Name, last.Schema, last.Name, maxDiscoveryColumns+1)
	if err != nil {
		return page, errors.New("PostgreSQL discovery failed")
	}
	for cols.Next() {
		var v DiscoveredColumn
		var nullable string
		if err := cols.Scan(&v.Schema, &v.Relation, &v.Name, &v.DataType, &nullable, &v.Comment); err != nil {
			cols.Close()
			return page, errors.New("PostgreSQL discovery failed")
		}
		v.Nullable = nullable == "YES"
		v.Comment = boundedComment(v.Comment)
		if len(page.Columns) == maxDiscoveryColumns {
			cols.Close()
			return page, errors.New("PostgreSQL metadata page exceeds the column limit")
		}
		page.Columns = append(page.Columns, v)
	}
	if err := cols.Err(); err != nil {
		cols.Close()
		return page, errors.New("PostgreSQL discovery failed")
	}
	cols.Close()
	encoded, _ := json.Marshal(page)
	if len(encoded) > maxDiscoveryBytes {
		return DiscoveryPage{}, errors.New("PostgreSQL metadata page exceeds the response limit")
	}
	if err := tx.Commit(ctx); err != nil {
		return DiscoveryPage{}, errors.New("PostgreSQL discovery failed")
	}
	return page, nil
}

func nextRelationCursor(relations []DiscoveredRelation) (string, string) {
	if len(relations) == 0 {
		return "", ""
	}
	last := relations[len(relations)-1]
	return last.Schema, last.Name
}

func boundedComment(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 512 {
		s = s[:512]
	}
	return s
}
