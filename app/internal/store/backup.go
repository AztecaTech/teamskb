package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Backup writes a consistent SQLite snapshot to a new, private file. VACUUM
// INTO includes committed WAL contents and is safe while the app is running.
func Backup(ctx context.Context, db *sql.DB, destination string) error {
	path, err := absoluteNewPath(destination)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("create private backup file: %w", err)
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("source database failed integrity check")
	}
	if _, err := db.ExecContext(ctx, `VACUUM INTO ?`, path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("create database snapshot: %w", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("secure backup file: %w", err)
	}
	if err := verifyDatabase(ctx, path); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("verify backup: %w", err)
	}
	return nil
}

// Restore validates a snapshot and installs its staged copy at destination. If
// a database already exists, it is retained as <destination>.pre-restore.
// Callers must stop all database users before restoring.
func Restore(ctx context.Context, backupPath, destination string) error {
	source, err := absoluteExistingFile(backupPath)
	if err != nil {
		return fmt.Errorf("backup file: %w", err)
	}
	destination, err = filepath.Abs(destination)
	if err != nil {
		return err
	}
	if source == destination {
		return errors.New("backup and database paths must differ")
	}
	if err := verifyDatabase(ctx, source); err != nil {
		return fmt.Errorf("backup validation failed: %w", err)
	}
	if err := rejectSQLiteSidecars(destination); err != nil {
		return err
	}
	if info, err := os.Lstat(destination); err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("database destination must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	} else if err == nil {
		sourceInfo, statErr := os.Stat(source)
		if statErr != nil {
			return statErr
		}
		if os.SameFile(info, sourceInfo) {
			return errors.New("backup and database paths must differ")
		}
	}

	file, err := os.CreateTemp(filepath.Dir(destination), ".iqkb-restore-*")
	if err != nil {
		return fmt.Errorf("create restore staging file: %w", err)
	}
	temporary := file.Name()
	defer os.Remove(temporary)
	if err := file.Chmod(0600); err != nil {
		_ = file.Close()
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		_ = file.Close()
		return err
	}
	_, copyErr := io.Copy(file, input)
	closeInputErr := input.Close()
	syncErr := file.Sync()
	closeFileErr := file.Close()
	if err := errors.Join(copyErr, closeInputErr, syncErr, closeFileErr); err != nil {
		return fmt.Errorf("stage database restore: %w", err)
	}
	if err := verifyDatabase(ctx, temporary); err != nil {
		return fmt.Errorf("staged database validation failed: %w", err)
	}

	previous := destination + ".pre-restore"
	if _, err := os.Lstat(previous); err == nil {
		return errors.New("pre-restore database already exists; move it before retrying")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if _, err := os.Lstat(destination); err == nil {
		if err := os.Rename(destination, previous); err != nil {
			return fmt.Errorf("preserve current database: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(temporary, destination); err != nil {
		if _, statErr := os.Lstat(previous); statErr == nil {
			_ = os.Rename(previous, destination)
		}
		return fmt.Errorf("install restored database: %w", err)
	}
	return nil
}

func absoluteNewPath(path string) (string, error) {
	if path == "" {
		return "", errors.New("destination path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(absolute); err == nil {
		return "", errors.New("backup destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	info, err := os.Stat(filepath.Dir(absolute))
	if err != nil || !info.IsDir() {
		return "", errors.New("backup directory does not exist")
	}
	return absolute, nil
}

func absoluteExistingFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("backup path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(absolute)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("backup path must be a regular file")
	}
	return absolute, nil
}

func verifyDatabase(ctx context.Context, path string) error {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return err
	}
	defer db.Close()
	var integrity string
	if err := db.QueryRowContext(ctx, `PRAGMA integrity_check`).Scan(&integrity); err != nil || integrity != "ok" {
		return errors.New("SQLite integrity check failed")
	}
	var version int
	if err := db.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0) FROM schema_migrations`).Scan(&version); err != nil {
		return errors.New("schema migration metadata is missing")
	}
	if version != latestSchemaVersion {
		return fmt.Errorf("schema version %d is unsupported (expected %d)", version, latestSchemaVersion)
	}
	return nil
}

func rejectSQLiteSidecars(path string) error {
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, err := os.Lstat(path + suffix); err == nil {
			return fmt.Errorf("SQLite sidecar %s exists; stop the app and close all database handles before restore", suffix)
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
