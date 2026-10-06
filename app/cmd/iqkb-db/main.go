package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"iq-kbteams/internal/store"
	_ "modernc.org/sqlite"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) != 2 || (args[0] != "backup" && args[0] != "restore") {
		return errors.New("usage: iqkb-db backup <new-backup-path> | restore <backup-path>")
	}
	databasePath := os.Getenv("SQLITE_PATH")
	if databasePath == "" {
		databasePath = "/var/lib/iqkb/config.sqlite"
	}
	ctx := context.Background()
	if args[0] == "restore" {
		return store.Restore(ctx, args[1], databasePath)
	}
	databasePath, err := filepath.Abs(databasePath)
	if err != nil {
		return err
	}
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(databasePath)+"?_pragma=busy_timeout(5000)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := db.PingContext(ctx); err != nil {
		return err
	}
	return store.Backup(ctx, db, args[1])
}
