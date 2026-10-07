package main

import (
	"context"
	"database/sql"

	"iq-kbteams/internal/graph"
	"iq-kbteams/internal/identity"
)

type directoryTokenVerifier struct {
	base   tokenVerifier
	db     *sql.DB
	socket string
}

func (v directoryTokenVerifier) Verify(ctx context.Context, assertion string) (identity.Principal, error) {
	principal, err := v.base.Verify(ctx, assertion)
	if err != nil {
		return principal, err
	}
	adapter, adapterErr := loadPostgresAdapter(v.db)
	// A failed directory lookup leaves DB access denied, while administrators
	// can still open setup to repair consent/configuration.
	if adapterErr == nil && adapter != nil {
		principal.VerifiedEmail = ""
		if email, emailErr := graph.DirectoryEmail(ctx, v.socket, assertion, principal.ObjectID); emailErr == nil {
			principal.VerifiedEmail = email
		}
	}
	return principal, nil
}
