package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	dailyAskLimit   = 100
	askRequestBurst = 10
	// ponytail: cap rate state at 16K active identities; raise it for larger single-process tenants.
	maxAskRateUsers                 = 16384
	defaultAuditRetentionDays       = 30
	auditWriteTimeout               = 2 * time.Second
	maxAuditEvents                  = 100_000
	defaultMonthlyModelAttemptLimit = 10000
	maxConcurrentAsks               = 10
	maxConcurrentAsksPerUser        = 2
)

func configuredMonthlyModelAttemptLimit() (int, error) {
	raw := strings.TrimSpace(os.Getenv("MODEL_MONTHLY_ATTEMPT_LIMIT"))
	if raw == "" {
		return defaultMonthlyModelAttemptLimit, nil
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 {
		return 0, fmt.Errorf("MODEL_MONTHLY_ATTEMPT_LIMIT must be a positive integer")
	}
	return limit, nil
}

func configuredAuditRetentionDays() (int, error) {
	raw := strings.TrimSpace(os.Getenv("AUDIT_RETENTION_DAYS"))
	if raw == "" {
		return defaultAuditRetentionDays, nil
	}
	days, err := strconv.Atoi(raw)
	if err != nil || days < 1 || days > 3650 {
		return 0, fmt.Errorf("AUDIT_RETENTION_DAYS must be an integer from 1 through 3650")
	}
	return days, nil
}

func reserveDailyAsk(ctx context.Context, db *sql.DB, tenantID, objectID string) (bool, error) {
	period := time.Now().UTC().Format("2006-01-02")
	subject := tenantID + ":" + objectID
	if _, err := db.ExecContext(ctx, `DELETE FROM usage_counters WHERE period_utc < ?`, time.Now().UTC().AddDate(0, 0, -31).Format("2006-01-02")); err != nil {
		return false, err
	}
	result, err := db.ExecContext(ctx, `INSERT INTO usage_counters(period_utc,subject_id,calls) VALUES(?,?,1) ON CONFLICT(period_utc,subject_id) DO UPDATE SET calls=usage_counters.calls+1 WHERE usage_counters.calls < ?`, period, subject, dailyAskLimit)
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	return updated == 1, err
}

func reserveMonthlyModelAttempt(ctx context.Context, db *sql.DB, limit int) (bool, error) {
	month := time.Now().UTC().Format("2006-01")
	if _, err := db.ExecContext(ctx, `DELETE FROM model_attempt_counters WHERE month_utc < ?`, month); err != nil {
		return false, err
	}
	result, err := db.ExecContext(ctx, `INSERT INTO model_attempt_counters(month_utc,attempts) VALUES(?,1) ON CONFLICT(month_utc) DO UPDATE SET attempts=model_attempt_counters.attempts+1 WHERE model_attempt_counters.attempts < ?`, month, limit)
	if err != nil {
		return false, err
	}
	updated, err := result.RowsAffected()
	return updated == 1, err
}

type askRateEntry struct {
	tokens     int
	lastRefill time.Time
}

type askRateGate struct {
	mu    sync.Mutex
	users map[string]askRateEntry
}

func newAskRateGate() *askRateGate {
	return &askRateGate{users: make(map[string]askRateEntry)}
}

func (g *askRateGate) allow(user string, now time.Time) (bool, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	entry, ok := g.users[user]
	if !ok {
		if len(g.users) >= maxAskRateUsers {
			for key, old := range g.users {
				if now.Sub(old.lastRefill) >= askRequestBurst*time.Second {
					delete(g.users, key)
				}
			}
			if len(g.users) >= maxAskRateUsers {
				return false, askRequestBurst
			}
		}
		g.users[user] = askRateEntry{tokens: askRequestBurst - 1, lastRefill: now}
		return true, 0
	}
	refilled := int(now.Sub(entry.lastRefill) / time.Second)
	if refilled > 0 {
		entry.tokens = min(askRequestBurst, entry.tokens+refilled)
		entry.lastRefill = entry.lastRefill.Add(time.Duration(refilled) * time.Second)
	}
	if entry.tokens == 0 {
		g.users[user] = entry
		return false, 1
	}
	entry.tokens--
	g.users[user] = entry
	return true, 0
}

type askAdmissionGate struct {
	mu        sync.Mutex
	active    int
	perUser   map[string]int
	globalMax int
	userMax   int
}

func newAskAdmissionGate(globalMax, userMax int) *askAdmissionGate {
	return &askAdmissionGate{perUser: make(map[string]int), globalMax: globalMax, userMax: userMax}
}

func (g *askAdmissionGate) acquire(user string) (func(), bool) {
	g.mu.Lock()
	if g.active >= g.globalMax || g.perUser[user] >= g.userMax {
		g.mu.Unlock()
		return func() {}, false
	}
	g.active++
	g.perUser[user]++
	g.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			g.mu.Lock()
			defer g.mu.Unlock()
			g.active--
			g.perUser[user]--
			if g.perUser[user] == 0 {
				delete(g.perUser, user)
			}
		})
	}, true
}

func recordAskAudit(ctx context.Context, db *sql.DB, requestID, actorID, outcome string, sourceCount int) {
	recordAskAuditWithLimit(ctx, db, requestID, actorID, outcome, sourceCount, maxAuditEvents)
}

func recordAskAuditWithLimit(ctx context.Context, db *sql.DB, requestID, actorID, outcome string, sourceCount, limit int) {
	var eventBytes [16]byte
	if _, err := rand.Read(eventBytes[:]); err != nil {
		return
	}
	details, err := json.Marshal(map[string]int{"sourceCount": sourceCount})
	if err != nil {
		return
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO audit_events(event_id,created_at,request_id,actor_id,action,outcome,details) VALUES(?,?,?,?,?,?,?)`, hex.EncodeToString(eventBytes[:]), time.Now().UTC().Format(time.RFC3339Nano), requestID, actorID, "private_ask", outcome, details); err != nil {
		_ = tx.Rollback()
		return
	}
	if _, err = tx.ExecContext(ctx, `UPDATE audit_event_state SET event_count=event_count+1 WHERE id=1`); err != nil {
		_ = tx.Rollback()
		return
	}
	if pruneErr := pruneAuditEventsToLimit(ctx, tx, limit); pruneErr != nil {
		_ = tx.Rollback()
		return
	}
	_ = tx.Commit()
}

func pruneExpiredAuditEvents(ctx context.Context, db *sql.DB, retentionDays int) error {
	if retentionDays < 1 || retentionDays > 3650 {
		return fmt.Errorf("audit retention days must be from 1 through 3650")
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays).Format(time.RFC3339)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	deleted, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE created_at < ?`, cutoff)
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	removed, err := deleted.RowsAffected()
	if err != nil {
		_ = tx.Rollback()
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE audit_event_state SET event_count=MAX(0,event_count-?) WHERE id=1`, removed); err != nil {
		_ = tx.Rollback()
		return err
	}
	if err := pruneAuditEventsToLimit(ctx, tx, maxAuditEvents); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func pruneAuditEventsToLimit(ctx context.Context, tx *sql.Tx, limit int) error {
	if limit < 1 {
		return fmt.Errorf("audit event limit must be positive")
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT event_count FROM audit_event_state WHERE id=1`).Scan(&count); err != nil {
		return err
	}
	if count <= limit {
		return nil
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE event_id IN (SELECT event_id FROM audit_events ORDER BY created_at ASC,event_id ASC LIMIT ?)`, count-limit)
	if err != nil {
		return err
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE audit_event_state SET event_count=MAX(0,event_count-?) WHERE id=1`, removed)
	return err
}

func startAuditRetentionWorker(ctx context.Context, db *sql.DB, retentionDays int) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				cleanupCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
				if err := pruneExpiredAuditEvents(cleanupCtx, db, retentionDays); err != nil {
					slog.Error("audit retention cleanup failed")
				}
				cancel()
			}
		}
	}()
	return done
}
