package postgres

import (
	"context"
	"errors"

	"strings"
)

type AuthorizationDiscoveryError struct {
	Stage string
	Cause error
}

func (e *AuthorizationDiscoveryError) Error() string {
	return "authorization discovery " + e.Stage + ": " + e.Cause.Error()
}
func (e *AuthorizationDiscoveryError) Unwrap() error { return e.Cause }
func DiscoveryFailureStage(err error) string {
	var failure *AuthorizationDiscoveryError
	if errors.As(err, &failure) {
		return failure.Stage
	}
	return "metadata"
}

const maxAuthorizationRelations = 25

type AuthorizationCandidate struct {
	Schema         string             `json:"schema"`
	Relation       string             `json:"relation"`
	Ready          bool               `json:"ready"`
	MissingColumns []string           `json:"missingColumns"`
	Columns        []DiscoveredColumn `json:"columns"`
}
type AuthorizationDiscovery struct {
	Candidates []AuthorizationCandidate `json:"candidates"`
	NextSchema string                   `json:"nextSchema,omitempty"`
	NextName   string                   `json:"nextName,omitempty"`
}

// Bootstrap discovery is metadata-only. It is exposed exclusively through an
// admin route and never grants a service-account data-search path.
func (c *Connector) DiscoverAuthorization(ctx context.Context, schemaAfter, nameAfter string) (AuthorizationDiscovery, error) {
	var result AuthorizationDiscovery
	if !c.SharedCredentialsConfigured() {
		return result, errors.New("shared credentials required")
	}
	metadata := *c
	metadata.adapter, metadata.subject = nil, nil
	metadata.metadataOnly = true
	conn, tx, _, err := metadata.beginAuthorized(ctx, c.service.User, c.service.Password)
	if err != nil {
		return result, err
	}
	defer closeConnection(conn)
	defer tx.Rollback(ctx)
	if len(schemaAfter) > 63 || len(nameAfter) > 63 {
		return result, errors.New("invalid metadata cursor")
	}
	// Restrict bootstrap work to relations containing likely email fields. Do
	// not scan every column/key/view dependency in the business database.
	rows, err := tx.Query(ctx, `SELECT t.table_schema,t.table_name,t.table_type FROM information_schema.tables t
WHERE t.table_schema NOT IN ('information_schema','pg_catalog') AND t.table_type IN ('BASE TABLE','VIEW')
AND (t.table_schema,t.table_name)>($1,$2)
AND EXISTS(SELECT 1 FROM information_schema.columns c WHERE c.table_schema=t.table_schema AND c.table_name=t.table_name
AND lower(replace(c.column_name,'_','')) IN ('email','emailaddress','useremail','mail','primaryemail')
AND has_column_privilege(current_user,quote_ident(c.table_schema)||'.'||quote_ident(c.table_name),c.column_name,'SELECT'))
ORDER BY t.table_schema,t.table_name LIMIT $3`, schemaAfter, nameAfter, maxAuthorizationRelations+1)
	if err != nil {
		return result, &AuthorizationDiscoveryError{Stage: "relations", Cause: err}
	}
	page := DiscoveryPage{}
	for rows.Next() {
		var relation DiscoveredRelation
		if err = rows.Scan(&relation.Schema, &relation.Name, &relation.Kind); err != nil {
			break
		}
		if len(page.Relations) == maxAuthorizationRelations {
			page.NextSchema, page.NextName = nextRelationCursor(page.Relations)
			break
		}
		page.Relations = append(page.Relations, relation)
	}
	rowErr := rows.Err()
	rows.Close()
	if err != nil || rowErr != nil {
		return result, &AuthorizationDiscoveryError{Stage: "relations", Cause: errors.Join(err, rowErr)}
	}
	if len(page.Relations) > 0 {
		first, last := page.Relations[0], page.Relations[len(page.Relations)-1]
		cols, err := tx.Query(ctx, `SELECT c.table_schema,c.table_name,c.column_name,c.data_type,c.is_nullable FROM information_schema.columns c
WHERE (c.table_schema,c.table_name)>=($1,$2) AND (c.table_schema,c.table_name)<=($3,$4)
AND EXISTS (SELECT 1 FROM information_schema.columns e WHERE e.table_schema=c.table_schema AND e.table_name=c.table_name
AND lower(replace(e.column_name,'_','')) IN ('email','emailaddress','useremail','mail','primaryemail')
AND has_column_privilege(current_user,quote_ident(e.table_schema)||'.'||quote_ident(e.table_name),e.column_name,'SELECT'))
AND lower(replace(c.column_name,'_','')) IN ('email','emailaddress','useremail','mail','primaryemail','id','userid','accountid','role','rolename','roleid','databaserole','postgresrole','dbrole','tenantid','organizationid','active','isactive','enabled','permissionversion','permissionsversion','authversion')
AND has_column_privilege(current_user,quote_ident(c.table_schema)||'.'||quote_ident(c.table_name),c.column_name,'SELECT')
ORDER BY c.table_schema,c.table_name,c.ordinal_position LIMIT $5`, first.Schema, first.Name, last.Schema, last.Name, maxDiscoveryColumns+1)
		if err != nil {
			return result, &AuthorizationDiscoveryError{Stage: "columns", Cause: err}
		}
		for cols.Next() {
			var column DiscoveredColumn
			var nullable string
			if err = cols.Scan(&column.Schema, &column.Relation, &column.Name, &column.DataType, &nullable); err != nil {
				break
			}
			column.Nullable = nullable == "YES"
			page.Columns = append(page.Columns, column)
		}
		rowErr := cols.Err()
		cols.Close()
		if err != nil || rowErr != nil {
			return result, &AuthorizationDiscoveryError{Stage: "columns", Cause: errors.Join(err, rowErr)}
		}
		if len(page.Columns) > maxDiscoveryColumns {
			return result, errors.New("authorization metadata column limit exceeded")
		}
	}
	if err = tx.Commit(ctx); err != nil {
		return result, &AuthorizationDiscoveryError{Stage: "transaction", Cause: err}
	}
	result.Candidates = authorizationCandidates(page)
	result.NextSchema, result.NextName = page.NextSchema, page.NextName
	return result, nil
}

func authorizationCandidates(page DiscoveryPage) []AuthorizationCandidate {
	result := make([]AuthorizationCandidate, 0)
	for _, relation := range page.Relations {
		columns := map[string]string{}
		for _, column := range page.Columns {
			if column.Schema == relation.Schema && column.Relation == relation.Name {
				columns[column.Name] = column.DataType
			}
		}
		hasEmail := false
		for name := range columns {
			switch strings.ToLower(strings.ReplaceAll(name, "_", "")) {
			case "email", "emailaddress", "useremail", "mail", "primaryemail":
				hasEmail = true
			}
		}
		if !hasEmail {
			continue
		}
		candidate := AuthorizationCandidate{Schema: relation.Schema, Relation: relation.Name, MissingColumns: []string{}}
		for _, column := range page.Columns {
			if column.Schema == relation.Schema && column.Relation == relation.Name {
				candidate.Columns = append(candidate.Columns, column)
			}
		}
		for _, name := range []string{"tenant_id", "email", "user_id", "database_role", "active", "permission_version"} {
			if columns[name] == "" || (name == "active" && columns[name] != "boolean") {
				candidate.MissingColumns = append(candidate.MissingColumns, name)
			}
		}
		candidate.Ready = len(candidate.MissingColumns) == 0 && ValidDatabaseIdentity(relation.Schema) && ValidDatabaseIdentity(relation.Name)
		result = append(result, candidate)
	}
	return result
}
