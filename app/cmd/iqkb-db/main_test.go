package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"iq-kbteams/internal/store"
	_ "modernc.org/sqlite"
)

func TestBackupAndRestoreCommands(t *testing.T) {
	dir := t.TempDir()
	databasePath := filepath.Join(dir, "config.sqlite")
	backupPath := filepath.Join(dir, "snapshot.sqlite")
	if err := createTestDatabase(databasePath, "before-backup"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SQLITE_PATH", databasePath)
	if err := run([]string{"backup", backupPath}); err != nil {
		t.Fatalf("backup command: %v", err)
	}
	if err := createTestDatabase(databasePath, "changed-after-backup"); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"restore", backupPath}); err != nil {
		t.Fatalf("restore command: %v", err)
	}
	if value := readDatabaseSetting(t, databasePath); value != "before-backup" {
		t.Fatalf("restored value=%q", value)
	}
	if value := readDatabaseSetting(t, databasePath+".pre-restore"); value != "changed-after-backup" {
		t.Fatalf("pre-restore value=%q", value)
	}
}

func TestCommandRejectsInvalidArguments(t *testing.T) {
	if err := run(nil); err == nil {
		t.Fatal("empty command accepted")
	}
	if err := run([]string{"remove", "database.sqlite"}); err == nil {
		t.Fatal("unknown command accepted")
	}
}

func createTestDatabase(path, value string) error {
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=journal_mode(WAL)")
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if err := store.Migrate(db); err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO settings(key,value) VALUES('backup-test',?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, []byte(value))
	return err
}

func readDatabaseSetting(t *testing.T, path string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value []byte
	if err := db.QueryRow(`SELECT value FROM settings WHERE key='backup-test'`).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return string(value)
}

func TestRestoreLeavesFileSystemUnchangedForUnsupportedArgs(t *testing.T) {
	backupPath := filepath.Join(t.TempDir(), "missing.sqlite")
	if err := run([]string{"restore", backupPath}); err == nil {
		t.Fatal("missing backup was accepted")
	}
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Fatalf("unexpected backup path state: %v", err)
	}
}
