package main

import (
	"context"
	"database/sql"
	"errors"

	"iq-kbteams/internal/graph"
	"iq-kbteams/internal/identity"
)

type directoryTokenVerifier struct {
	base   tokenVerifier
	db     *sql.DB
	socket string
	shared bool
}

type deferDirectoryLookupKey struct{}

func (v directoryTokenVerifier) Verify(ctx context.Context, assertion string) (identity.Principal, error) {
	principal, err := v.base.Verify(ctx, assertion)
	if err != nil {
		return principal, err
	}
	adapter, adapterErr := loadPostgresAdapter(v.db)
	// A failed directory lookup leaves DB access denied, while administrators
	// can still open setup to repair consent/configuration.
	if v.shared || (adapterErr == nil && adapter != nil) {
		principal.VerifiedEmail = ""
		if deferred, _ := ctx.Value(deferDirectoryLookupKey{}).(bool); deferred {
			principal.DirectoryEmailStatus = "deferred"
			return principal, nil
		}
		principal.DirectoryEmailStatus = "directory_unavailable"
		if email, emailErr := graph.DirectoryEmail(ctx, v.socket, assertion, principal.ObjectID); emailErr == nil {
			principal.VerifiedEmail = email
			principal.DirectoryEmailStatus = "resolved"
		} else {
			var detail *graph.DirectoryIdentityError
			if errors.As(emailErr, &detail) {
				principal.DirectoryEmailStatus = detail.State
			}
		}
	}
	return principal, nil
}
