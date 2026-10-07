package postgres

import (
	"context"
	"errors"
)

type AuthorizationCandidate struct {
	Schema         string   `json:"schema"`
	Relation       string   `json:"relation"`
	Ready          bool     `json:"ready"`
	MissingColumns []string `json:"missingColumns"`
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
	page, err := metadata.Discover(ctx, c.service.User, c.service.Password, schemaAfter, nameAfter)
	if err != nil {
		return result, err
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
		if columns["email"] == "" && columns["email_address"] == "" && columns["mail"] == "" {
			continue
		}
		candidate := AuthorizationCandidate{Schema: relation.Schema, Relation: relation.Name, MissingColumns: []string{}}
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
