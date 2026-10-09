package postgres

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
)

type PermissionRelation struct {
	Schema        string           `json:"schema"`
	Relation      string           `json:"relation"`
	Columns       []string         `json:"columns"`
	ScalarColumns []string         `json:"scalarColumns,omitempty"`
	RLSEnabled    bool             `json:"rlsEnabled"`
	RLSForced     bool             `json:"rlsForced"`
	Evidence      string           `json:"evidence"`
	SearchProfile *BusinessProfile `json:"searchProfile,omitempty"`
}
type PermissionPolicy struct {
	Schema     string   `json:"schema"`
	Relation   string   `json:"relation"`
	Name       string   `json:"name"`
	Roles      []string `json:"roles"`
	Using      string   `json:"using"`
	Check      string   `json:"check"`
	RLSEnabled bool     `json:"rlsEnabled"`
}
type PermissionDiscovery struct {
	Relations     []PermissionRelation     `json:"relations"`
	Relationships []DiscoveredRelationship `json:"relationships"`
	Policies      []PermissionPolicy       `json:"policies"`
	Truncated     bool                     `json:"truncated"`
}

// Inspect authorization structure, never arbitrary business rows. Candidates
// are evidence for review; catalog structure alone is not an access decision.
func discoverPermissionStructure(ctx context.Context, tx pgx.Tx, schema, relation string) (PermissionDiscovery, error) {
	result := PermissionDiscovery{Relations: []PermissionRelation{}, Relationships: []DiscoveredRelationship{}, Policies: []PermissionPolicy{}}
	rows, err := tx.Query(ctx, `SELECT c.oid::bigint,n.nspname,c.relname,
ARRAY(SELECT a.attname::text FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT') ORDER BY a.attnum LIMIT 101),c.relrowsecurity,c.relforcerowsecurity,
CASE WHEN n.nspname=$1 AND c.relname=$2 THEN 'selected user relation'
WHEN EXISTS(SELECT 1 FROM pg_constraint f JOIN pg_class u ON u.oid=f.confrelid JOIN pg_namespace un ON un.oid=u.relnamespace WHERE f.contype='f' AND f.conrelid=c.oid AND un.nspname=$1 AND u.relname=$2) THEN 'foreign key to selected user relation'
ELSE 'authorization-related metadata; requires review' END
FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%' AND c.relkind IN ('r','p','v')
AND EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT'))
AND ((n.nspname=$1 AND c.relname=$2) OR EXISTS(SELECT 1 FROM pg_constraint f JOIN pg_class u ON u.oid=f.confrelid JOIN pg_namespace un ON un.oid=u.relnamespace WHERE f.contype='f' AND f.conrelid=c.oid AND un.nspname=$1 AND u.relname=$2)
OR EXISTS(SELECT 1 FROM pg_attribute a WHERE a.attrelid=c.oid AND a.attnum>0 AND NOT a.attisdropped AND has_column_privilege(current_user,c.oid,a.attnum,'SELECT') AND lower(a.attname) ~ '(permission|privilege|capability|access|role|team|scope)'))
ORDER BY (n.nspname=$1 AND c.relname=$2) DESC,n.nspname,c.relname LIMIT 51`, schema, relation)
	if err != nil {
		return result, err
	}
	ids := []int64{}
	for rows.Next() {
		var item PermissionRelation
		var id int64
		if err = rows.Scan(&id, &item.Schema, &item.Relation, &item.Columns, &item.RLSEnabled, &item.RLSForced, &item.Evidence); err != nil {
			break
		}
		if len(result.Relations) == 50 {
			result.Truncated = true
			break
		}
		if len(item.Columns) > 100 {
			item.Columns = item.Columns[:100]
			result.Truncated = true
		}
		ids = append(ids, id)
		result.Relations = append(result.Relations, item)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return result, errors.Join(err, rowErr)
	}
	rows, err = tx.Query(ctx, `SELECT f.conname,sn.nspname,s.relname,ARRAY(SELECT a.attname::text FROM unnest(f.conkey) WITH ORDINALITY k(num,position) JOIN pg_attribute a ON a.attrelid=s.oid AND a.attnum=k.num ORDER BY k.position),tn.nspname,t.relname,ARRAY(SELECT a.attname::text FROM unnest(f.confkey) WITH ORDINALITY k(num,position) JOIN pg_attribute a ON a.attrelid=t.oid AND a.attnum=k.num ORDER BY k.position)
FROM pg_constraint f JOIN pg_class s ON s.oid=f.conrelid JOIN pg_namespace sn ON sn.oid=s.relnamespace JOIN pg_class t ON t.oid=f.confrelid JOIN pg_namespace tn ON tn.oid=t.relnamespace
WHERE f.contype='f' AND (s.oid::bigint=ANY($1::bigint[]) OR t.oid::bigint=ANY($1::bigint[]))
AND NOT EXISTS(SELECT 1 FROM unnest(f.conkey) k WHERE NOT has_column_privilege(current_user,s.oid,k,'SELECT'))
AND NOT EXISTS(SELECT 1 FROM unnest(f.confkey) k WHERE NOT has_column_privilege(current_user,t.oid,k,'SELECT'))
ORDER BY sn.nspname,s.relname,f.conname LIMIT 101`, ids)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item DiscoveredRelationship
		if err = rows.Scan(&item.Name, &item.SourceSchema, &item.SourceRelation, &item.SourceColumns, &item.TargetSchema, &item.TargetRelation, &item.TargetColumns); err != nil {
			break
		}
		if len(result.Relationships) == 100 {
			result.Truncated = true
			break
		}
		result.Relationships = append(result.Relationships, item)
	}
	rowErr = rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return result, errors.Join(err, rowErr)
	}
	rows, err = tx.Query(ctx, `SELECT n.nspname,c.relname,p.polname,ARRAY(SELECT CASE WHEN id=0 THEN 'PUBLIC' ELSE COALESCE((SELECT rolname::text FROM pg_roles WHERE oid=id),'unknown') END FROM unnest(p.polroles) id),left(COALESCE(pg_get_expr(p.polqual,p.polrelid),''),4097),left(COALESCE(pg_get_expr(p.polwithcheck,p.polrelid),''),4097),c.relrowsecurity
FROM pg_policy p JOIN pg_class c ON c.oid=p.polrelid JOIN pg_namespace n ON n.oid=c.relnamespace
WHERE n.nspname NOT IN ('pg_catalog','information_schema') AND (has_table_privilege(current_user,c.oid,'SELECT') OR has_any_column_privilege(current_user,c.oid,'SELECT')) ORDER BY n.nspname,c.relname,p.polname LIMIT 101`)
	if err != nil {
		return result, err
	}
	for rows.Next() {
		var item PermissionPolicy
		if err = rows.Scan(&item.Schema, &item.Relation, &item.Name, &item.Roles, &item.Using, &item.Check, &item.RLSEnabled); err != nil {
			break
		}
		if len(result.Policies) == 100 {
			result.Truncated = true
			break
		}
		if len(item.Using) > 4096 || len(item.Check) > 4096 {
			result.Truncated = true
		}
		result.Policies = append(result.Policies, item)
	}
	rowErr = rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return result, errors.Join(err, rowErr)
	}
	classifyPermissionEvidence(&result, schema, relation)
	for {
		encoded, encodeErr := json.Marshal(result)
		if encodeErr != nil {
			return result, encodeErr
		}
		if len(encoded) <= 128<<10 {
			break
		}
		result.Truncated = true
		if len(result.Policies) > 0 {
			result.Policies = result.Policies[:len(result.Policies)-1]
		} else if len(result.Relationships) > 0 {
			result.Relationships = result.Relationships[:len(result.Relationships)-1]
		} else if len(result.Relations) > 0 {
			result.Relations = result.Relations[:len(result.Relations)-1]
		} else {
			break
		}
	}
	return result, nil
}

func classifyPermissionEvidence(result *PermissionDiscovery, schema, relation string) {
	for i := range result.Relations {
		item := &result.Relations[i]
		if item.Schema == schema && item.Relation == relation {
			continue
		}
		semantic := false
		for _, name := range item.Columns {
			normalized := strings.ToLower(strings.ReplaceAll(name, "_", ""))
			for _, signal := range []string{"permission", "privilege", "capability", "access", "role", "team", "scope"} {
				if strings.Contains(normalized, signal) {
					semantic = true
				}
			}
		}
		if semantic {
			item.Evidence = "permission-related fields; authorization meaning requires review"
			continue
		}
		linked, auditOnly := false, true
		for _, link := range result.Relationships {
			if link.SourceSchema != item.Schema || link.SourceRelation != item.Relation || link.TargetSchema != schema || link.TargetRelation != relation {
				continue
			}
			linked = true
			for _, column := range link.SourceColumns {
				switch strings.ToLower(strings.ReplaceAll(column, "_", "")) {
				case "createdby", "updatedby", "deletedby", "changedby", "archivedby":
				default:
					auditOnly = false
				}
			}
		}
		if linked && auditOnly {
			item.Evidence = "audit references only; no access rule demonstrated"
		} else if linked {
			item.Evidence = "user relationship; no access rule demonstrated"
		}
	}
}
