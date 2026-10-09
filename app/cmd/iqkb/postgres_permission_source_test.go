package main

import (
	"testing"

	"iq-kbteams/internal/postgres"
)

func TestInternalAdapterDoesNotRequireObsoleteExternalSettings(t *testing.T) {
	pg, err := postgres.Open(t.Context(), "postgres://fixture:fixture@localhost:1/fixture?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	defer pg.Close()
	t.Setenv("POSTGRES_PERMISSION_SOURCE_TOKEN", "")
	for _, cfg := range []config{
		{},
		{postgresPermissionSourceURL: "https://old-source.example/permissions"},
		{postgresPermissionSourceURL: "http://unsafe-source.example/permissions", postgresPermissionSourceTokenFile: "missing-fixture-secret"},
	} {
		got, err := configurePostgresPermissionSource(cfg, pg, false)
		if err != nil || got != pg {
			t.Fatal("internal startup depended on an external endpoint or credential")
		}
		if _, err = configurePostgresPermissionSource(cfg, pg, true); err == nil {
			t.Fatal("explicit external adapter used missing or invalid settings")
		}
	}
}
