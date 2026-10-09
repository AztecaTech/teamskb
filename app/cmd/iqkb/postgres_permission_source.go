package main

import (
	"errors"

	"iq-kbteams/internal/authorization"
	"iq-kbteams/internal/postgres"
)

// Internal adapters need only the shared URI and the policy stored by IQ
// Knowledge. Obsolete external settings must not prevent their startup. An
// explicitly selected external adapter still fails closed on bad settings.
func configurePostgresPermissionSource(cfg config, pg *postgres.Connector, required bool) (*postgres.Connector, error) {
	if cfg.postgresPermissionSourceURL == "" && !required {
		return pg, nil
	}
	token, err := readSecret(cfg.postgresPermissionSourceTokenFile, "POSTGRES_PERMISSION_SOURCE_TOKEN")
	if err == nil && !pg.SharedCredentialsConfigured() {
		err = errors.New("shared connection required")
	}
	var source *authorization.HTTPPermissionSource
	if err == nil {
		source, err = authorization.NewHTTPPermissionSource(cfg.postgresPermissionSourceURL, token)
	}
	if err != nil {
		if required {
			return nil, errors.New("external permission source is not configured; check its URL and credential")
		}
		return pg, nil
	}
	return pg.WithPermissionSource(source), nil
}
