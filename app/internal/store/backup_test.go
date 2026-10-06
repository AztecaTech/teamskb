package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	_ "modernc.org/sqlite"
)

func openFileDB(t *testing.T, path string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	if err := Migrate(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func TestBackupAndRestorePreserveSnapshotAndCurrentDatabase(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	sourcePath := filepath.Join(dir, "live.sqlite")
	backupPath := filepath.Join(dir, "snapshot.sqlite")
	db := openFileDB(t, sourcePath)
	if _, err := db.Exec(`INSERT INTO settings(key,value) VALUES('snapshot-value',x'31')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO encrypted_secrets(secret_id,ciphertext,nonce,updated_at) VALUES('postgres_password:tenant:user',x'0102',x'0304','now')`); err != nil {
		t.Fatal(err)
	}
	if err := Backup(ctx, db, backupPath); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE settings SET value=x'32' WHERE key='snapshot-value'`); err != nil {
		t.Fatal(err)
	}

	restorePath := filepath.Join(dir, "restore.sqlite")
	restoreDB := openFileDB(t, restorePath)
	if _, err := restoreDB.Exec(`INSERT INTO settings(key,value) VALUES('pre-restore','old')`); err != nil {
		t.Fatal(err)
	}
	if err := restoreDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := Restore(ctx, backupPath, restorePath); err != nil {
		t.Fatal(err)
	}
	if value := readSetting(t, restorePath, "snapshot-value"); value != "1" {
		t.Fatalf("restored snapshot value=%q", value)
	}
	if err := verifyDatabase(ctx, restorePath); err != nil {
		t.Fatalf("restored database integrity: %v", err)
	}
	previous := restorePath + ".pre-restore"
	if value := readSetting(t, previous, "pre-restore"); value != "old" {
		t.Fatalf("preserved database value=%q", value)
	}
	check, err := sql.Open("sqlite", "file:"+filepath.ToSlash(restorePath)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	var ciphertext []byte
	if err := check.QueryRow(`SELECT ciphertext FROM encrypted_secrets WHERE secret_id='postgres_password:tenant:user'`).Scan(&ciphertext); err != nil || len(ciphertext) != 2 {
		t.Fatalf("encrypted credential was not restored: %x err=%v", ciphertext, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(backupPath)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatalf("backup mode=%o, expected 600", info.Mode().Perm())
		}
	}
}

func TestRestoreRejectsCorruptionAndLeavesDestinationAlone(t *testing.T) {
	dir := t.TempDir()
	backupPath := filepath.Join(dir, "broken.sqlite")
	if err := os.WriteFile(backupPath, []byte("not a database"), 0600); err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(dir, "database.sqlite")
	if err := Restore(context.Background(), backupPath, destination); err == nil {
		t.Fatal("corrupt database restored")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt restore changed destination: %v", err)
	}
}

func readSetting(t *testing.T, path, key string) string {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+filepath.ToSlash(path)+"?mode=ro")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var value []byte
	if err := db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&value); err != nil {
		t.Fatal(err)
	}
	return string(value)
}
