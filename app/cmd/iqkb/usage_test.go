package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReserveDailyAskEnforcesPerUserLimit(t *testing.T) {
	db := testDB(t)
	for i := 0; i < dailyAskLimit; i++ {
		reserved, err := reserveDailyAsk(context.Background(), db, "tenant-a", "user-a")
		if err != nil || !reserved {
			t.Fatalf("request %d reserved=%v err=%v", i+1, reserved, err)
		}
	}
	if reserved, err := reserveDailyAsk(context.Background(), db, "tenant-a", "user-a"); err != nil || reserved {
		t.Fatalf("request over limit reserved=%v err=%v", reserved, err)
	}
	if reserved, err := reserveDailyAsk(context.Background(), db, "tenant-a", "user-b"); err != nil || !reserved {
		t.Fatalf("different user reserved=%v err=%v", reserved, err)
	}
}

func TestReserveMonthlyModelAttemptEnforcesGlobalLimit(t *testing.T) {
	db := testDB(t)
	for i := 0; i < 2; i++ {
		reserved, err := reserveMonthlyModelAttempt(context.Background(), db, 2)
		if err != nil || !reserved {
			t.Fatalf("model attempt %d reserved=%v err=%v", i+1, reserved, err)
		}
	}
	if reserved, err := reserveMonthlyModelAttempt(context.Background(), db, 2); err != nil || reserved {
		t.Fatalf("attempt over global monthly limit reserved=%v err=%v", reserved, err)
	}
	var calls int
	if err := db.QueryRow(`SELECT attempts FROM model_attempt_counters WHERE month_utc=strftime('%Y-%m','now')`).Scan(&calls); err != nil || calls != 2 {
		t.Fatalf("attempt count=%d err=%v", calls, err)
	}
}

func TestAskAdmissionGateBoundsGlobalAndPerUserConcurrency(t *testing.T) {
	gate := newAskAdmissionGate(3, 2)
	releaseA1, ok := gate.acquire("tenant:user-a")
	if !ok {
		t.Fatal("first user A ask should be admitted")
	}
	releaseA2, ok := gate.acquire("tenant:user-a")
	if !ok {
		t.Fatal("second user A ask should be admitted")
	}
	if _, ok := gate.acquire("tenant:user-a"); ok {
		t.Fatal("third concurrent ask for user A should be rejected")
	}
	releaseB, ok := gate.acquire("tenant:user-b")
	if !ok {
		t.Fatal("user B ask should be admitted under the global limit")
	}
	if _, ok := gate.acquire("tenant:user-c"); ok {
		t.Fatal("ask exceeding global concurrency limit should be rejected")
	}
	releaseA1()
	releaseA1()
	releaseA3, ok := gate.acquire("tenant:user-a")
	if !ok {
		t.Fatal("released admission should be available again")
	}
	releaseA2()
	releaseA3()
	releaseB()
}

func TestAskRateGateAllowsBurstThenRefills(t *testing.T) {
	gate := newAskRateGate()
	now := time.Now()
	for i := 0; i < askRequestBurst; i++ {
		if allowed, _ := gate.allow("tenant:user", now); !allowed {
			t.Fatalf("burst request %d was rejected", i+1)
		}
	}
	if allowed, retryAfter := gate.allow("tenant:user", now); allowed || retryAfter != 1 {
		t.Fatal("request beyond burst should be rejected")
	}
	if allowed, _ := gate.allow("tenant:user", now.Add(time.Second)); !allowed {
		t.Fatal("one request should be replenished after one second")
	}
	if allowed, _ := gate.allow("tenant:user", now.Add(11*time.Second)); !allowed {
		t.Fatal("full bucket should recover after ten seconds")
	}
}

func TestAskRateGateBoundsTrackedIdentities(t *testing.T) {
	gate := newAskRateGate()
	now := time.Now()
	for i := 0; i < maxAskRateUsers; i++ {
		if allowed, _ := gate.allow(fmt.Sprintf("tenant:user-%d", i), now); !allowed {
			t.Fatalf("tracked identity %d was unexpectedly rejected", i)
		}
	}
	if allowed, retryAfter := gate.allow("tenant:new-user", now); allowed || retryAfter != askRequestBurst {
		t.Fatalf("identity cap should fail closed with a bounded retry: allowed=%v retry=%d", allowed, retryAfter)
	}
	if len(gate.users) != maxAskRateUsers {
		t.Fatalf("tracked identities=%d, want cap %d", len(gate.users), maxAskRateUsers)
	}
}

func TestAskAdmissionGateConcurrentAcquisitionRespectsGlobalLimit(t *testing.T) {
	const attempts = 24
	gate := newAskAdmissionGate(3, 2)
	type result struct {
		release  func()
		admitted bool
	}
	results := make(chan result, attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func(i int) {
			defer workers.Done()
			release, admitted := gate.acquire(string(rune('a' + i)))
			results <- result{release: release, admitted: admitted}
		}(i)
	}
	workers.Wait()
	close(results)
	count := 0
	for result := range results {
		if result.admitted {
			count++
			result.release()
		}
	}
	if count != 3 {
		t.Fatalf("concurrent admissions=%d, want global cap 3", count)
	}
}

func TestReserveMonthlyModelAttemptConcurrentAcquisitionRespectsLimit(t *testing.T) {
	const attempts, limit = 16, 5
	db := testDB(t)
	type result struct {
		reserved bool
		err      error
	}
	results := make(chan result, attempts)
	var workers sync.WaitGroup
	for i := 0; i < attempts; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			reserved, err := reserveMonthlyModelAttempt(context.Background(), db, limit)
			results <- result{reserved: reserved, err: err}
		}()
	}
	workers.Wait()
	close(results)
	count := 0
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.reserved {
			count++
		}
	}
	if count != limit {
		t.Fatalf("concurrent model reservations=%d, want limit %d", count, limit)
	}
}

func TestConfiguredMonthlyModelAttemptLimit(t *testing.T) {
	t.Setenv("MODEL_MONTHLY_ATTEMPT_LIMIT", "")
	if limit, err := configuredMonthlyModelAttemptLimit(); err != nil || limit != defaultMonthlyModelAttemptLimit {
		t.Fatalf("default limit=%d err=%v", limit, err)
	}
	t.Setenv("MODEL_MONTHLY_ATTEMPT_LIMIT", "17")
	if limit, err := configuredMonthlyModelAttemptLimit(); err != nil || limit != 17 {
		t.Fatalf("configured limit=%d err=%v", limit, err)
	}
	for _, invalid := range []string{"0", "-1", "not-an-integer"} {
		t.Setenv("MODEL_MONTHLY_ATTEMPT_LIMIT", invalid)
		if _, err := configuredMonthlyModelAttemptLimit(); err == nil {
			t.Errorf("invalid monthly limit %q accepted", invalid)
		}
	}
}

func TestConfiguredAuditRetentionDays(t *testing.T) {
	t.Setenv("AUDIT_RETENTION_DAYS", "")
	if days, err := configuredAuditRetentionDays(); err != nil || days != defaultAuditRetentionDays {
		t.Fatalf("default audit retention=%d err=%v", days, err)
	}
	t.Setenv("AUDIT_RETENTION_DAYS", "7")
	if days, err := configuredAuditRetentionDays(); err != nil || days != 7 {
		t.Fatalf("configured audit retention=%d err=%v", days, err)
	}
	for _, invalid := range []string{"0", "-1", "3651", "not-an-integer"} {
		t.Setenv("AUDIT_RETENTION_DAYS", invalid)
		if _, err := configuredAuditRetentionDays(); err == nil {
			t.Errorf("invalid audit retention %q accepted", invalid)
		}
	}
}

func TestPruneExpiredAuditEventsUsesConfiguredRetention(t *testing.T) {
	db := testDB(t)
	for index, age := range []int{31, 29} {
		created := time.Now().UTC().AddDate(0, 0, -age).Format(time.RFC3339)
		id := fmt.Sprintf("event-%d", index)
		if _, err := db.Exec(`INSERT INTO audit_events(event_id,created_at,request_id,actor_id,action,outcome,details) VALUES(?,?,?,?,?,?,?)`, id, created, "request-"+id, "tenant:user", "private_ask", "answered", []byte(`{"sourceCount":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE audit_event_state SET event_count=2 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if err := pruneExpiredAuditEvents(context.Background(), db, 30); err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_id='event-0'`).Scan(&remaining); err != nil || remaining != 0 {
		t.Fatalf("expired event count=%d err=%v", remaining, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_id='event-1'`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("recent event count=%d err=%v", remaining, err)
	}
	if err := db.QueryRow(`SELECT event_count FROM audit_event_state WHERE id=1`).Scan(&remaining); err != nil || remaining != 1 {
		t.Fatalf("recent event counter=%d err=%v", remaining, err)
	}
}

func TestPruneAuditEventCapacityKeepsNewestRows(t *testing.T) {
	db := testDB(t)
	for i, created := range []string{"2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z", "2026-10-03T00:00:00Z"} {
		id := fmt.Sprintf("event-%d", i)
		if _, err := db.Exec(`INSERT INTO audit_events(event_id,created_at,request_id,actor_id,action,outcome,details) VALUES(?,?,?,?,?,?,?)`, id, created, "request-"+id, "tenant:user", "private_ask", "answered", []byte(`{"sourceCount":1}`)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`UPDATE audit_event_state SET event_count=3 WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := pruneAuditEventsToLimit(context.Background(), tx, 2); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var rows, count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT event_count FROM audit_event_state WHERE id=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	var oldest int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_id='event-0'`).Scan(&oldest); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || count != 2 || oldest != 0 {
		t.Fatalf("capacity prune retained rows=%d counter=%d oldest=%d", rows, count, oldest)
	}
}

func TestRecordAskAuditEnforcesGlobalCapacity(t *testing.T) {
	db := testDB(t)
	for i := range 3 {
		recordAskAuditWithLimit(context.Background(), db, fmt.Sprintf("request-%d", i), "tenant:user", "answered", 1, 2)
	}
	var rows, count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM audit_events`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT event_count FROM audit_event_state WHERE id=1`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if rows != 2 || count != 2 {
		t.Fatalf("capacity insert retained rows=%d counter=%d", rows, count)
	}
}

func TestAuditRetentionWorkerStopsWhenContextIsCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := startAuditRetentionWorker(ctx, testDB(t), 30)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("audit retention worker did not stop after cancellation")
	}
}

func TestAskAuditStoresOnlyOperationalDetails(t *testing.T) {
	db := testDB(t)
	const requestID = "request-123"
	recordAskAudit(context.Background(), db, requestID, "tenant:user", "answered", 2)
	var details []byte
	var actor, action, outcome string
	if err := db.QueryRow(`SELECT actor_id, action, outcome, details FROM audit_events WHERE request_id=?`, requestID).Scan(&actor, &action, &outcome, &details); err != nil {
		t.Fatal(err)
	}
	var fields map[string]int
	if err := json.Unmarshal(details, &fields); err != nil {
		t.Fatal(err)
	}
	if actor != "tenant:user" || action != "private_ask" || outcome != "answered" || fields["sourceCount"] != 2 || len(fields) != 1 {
		t.Fatalf("unexpected audit entry: actor=%q action=%q outcome=%q details=%s", actor, action, outcome, details)
	}
	var count int
	if err := db.QueryRow(`SELECT event_count FROM audit_event_state WHERE id=1`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("event counter=%d err=%v", count, err)
	}
}
