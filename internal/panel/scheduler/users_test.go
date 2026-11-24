package scheduler_test

import (
	"context"
	"encoding/json"
	"math"
	"strings"
	"testing"
	"time"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

func TestSweepUsers_ExpiryHotSyncAlertToggleAndRecovery(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	sched := scheduler.NewScheduler(st, h, notifier, scheduler.WithNow(clk.Now))

	n, tok := createTestNode(t, st, "user-expiry-node", true)
	u := createTestUser(t, st, "expiring-alice", true)
	exp := clk.Now().Add(1 * time.Hour)
	u.ExpireAt = &exp
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatalf("update user: %v", err)
	}
	if err := st.SetUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatalf("set user nodes: %v", err)
	}

	conn, _ := dialAgent(t, h, tok)
	initEnv := readEnvelope(t, conn, 3*time.Second)
	var initCfg protocol.ServerConfigSync
	_ = json.Unmarshal(initEnv.Payload, &initCfg)
	if len(initCfg.SS.Users) != 1 || initCfg.SS.Users[0].UserID != u.ID {
		t.Fatalf("expected alice in initial config_sync, got %+v", initCfg.SS.Users)
	}

	// Before expiry -> no alerts, no sync.
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers before expiry: %v", err)
	}
	if len(notifier.Events()) != 0 {
		t.Fatalf("expected 0 alerts before expiry, got %+v", notifier.Events())
	}

	// Advance past expiry -> hot-sync removes alice, emits EventUserExpired ONCE.
	clk.Advance(2 * time.Hour)
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers at expiry: %v", err)
	}
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers repeat: %v", err)
	}

	evts := notifier.Events()
	if len(evts) != 1 || evts[0].Type != webhook.EventUserExpired || evts[0].TargetID != u.ID {
		t.Fatalf("expected exactly 1 user_expired alert, got %+v", evts)
	}

	syncEnv := readEnvelope(t, conn, 3*time.Second)
	var syncCfg protocol.ServerConfigSync
	_ = json.Unmarshal(syncEnv.Payload, &syncCfg)
	if len(syncCfg.SS.Users) != 0 || !syncCfg.Snell.Enabled {
		t.Fatalf("expected alice removed and snell untouched, got ss.users=%d snell.enabled=%v", len(syncCfg.SS.Users), syncCfg.Snell.Enabled)
	}

	// Extend expiry -> recovery hot-sync restores alice.
	newExp := clk.Now().Add(24 * time.Hour)
	u.ExpireAt = &newExp
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatalf("extend expire_at: %v", err)
	}
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers recovery: %v", err)
	}

	recEnv := readEnvelope(t, conn, 3*time.Second)
	var recCfg protocol.ServerConfigSync
	_ = json.Unmarshal(recEnv.Payload, &recCfg)
	if len(recCfg.SS.Users) != 1 || recCfg.SS.Users[0].UserID != u.ID {
		t.Fatalf("expected alice restored after expire_at extended, got %+v", recCfg.SS.Users)
	}

	// Disable alert_user_expired -> expire again -> syncs WITHOUT emitting alert.
	if err := st.SetSetting(ctx, "alert_user_expired", "off"); err != nil {
		t.Fatalf("set alert_user_expired=off: %v", err)
	}
	clk.Advance(48 * time.Hour)
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers with alert off: %v", err)
	}
	if len(notifier.Events()) != 1 {
		t.Fatalf("expected alert_user_expired=off to suppress second alert, got %+v", notifier.Events())
	}
	offEnv := readEnvelope(t, conn, 3*time.Second)
	var offCfg protocol.ServerConfigSync
	_ = json.Unmarshal(offEnv.Payload, &offCfg)
	if len(offCfg.SS.Users) != 0 {
		t.Fatalf("expected hot-sync even with alert disabled, got %+v", offCfg.SS.Users)
	}
}

func TestEvaluateUsers_QuotaExhaustionNodeDedupAndPrune(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	sched := scheduler.NewScheduler(st, h, notifier, scheduler.WithNow(clk.Now))

	n1, tok1 := createTestNode(t, st, "shared-node-1", true)
	n2, _ := createTestNode(t, st, "offline-node-2", true)

	u1 := createTestUser(t, st, "bob", true)
	u2 := createTestUser(t, st, "carol", true)
	u1.TrafficQuotaBytes = 100
	u2.TrafficQuotaBytes = 100
	_ = st.UpdateUser(ctx, u1)
	_ = st.UpdateUser(ctx, u2)
	_ = st.SetUserNodes(ctx, u1.ID, []int64{n1.ID, n2.ID})
	_ = st.SetUserNodes(ctx, u2.ID, []int64{n1.ID})

	conn, _ := dialAgent(t, h, tok1)
	_ = readEnvelope(t, conn, 3*time.Second) // initial sync

	// Exhaust BOTH users in one batch -> shared node n1 must be bumped & synced ONCE!
	if _, err := st.ApplyTrafficDeltas(ctx, n1.ID, 0, 0, []protocol.UserTrafficDelta{
		{UserID: u1.ID, Username: u1.Username, UpBytes: 60, DownBytes: 40},
		{UserID: u2.ID, Username: u2.Username, UpBytes: 50, DownBytes: 60},
	}, "2026-11-10"); err != nil {
		t.Fatalf("apply user deltas: %v", err)
	}

	beforeNode, _ := st.GetNodeByID(ctx, n1.ID)
	if err := sched.EvaluateUsers(ctx, []int64{u1.ID, u2.ID, u1.ID}); err != nil {
		t.Fatalf("EvaluateUsers: %v", err)
	}
	afterNode, _ := st.GetNodeByID(ctx, n1.ID)
	if afterNode.ConfigRevision != beforeNode.ConfigRevision+1 {
		t.Fatalf("expected deduplicated single config_revision bump (%d -> %d), got %d",
			beforeNode.ConfigRevision, beforeNode.ConfigRevision+1, afterNode.ConfigRevision)
	}

	env := readEnvelope(t, conn, 3*time.Second)
	var cfg protocol.ServerConfigSync
	_ = json.Unmarshal(env.Payload, &cfg)
	if len(cfg.SS.Users) != 0 {
		t.Fatalf("expected both exhausted users excluded, got %+v", cfg.SS.Users)
	}

	evts := notifier.Events()
	if len(evts) != 2 {
		t.Fatalf("expected 2 user_quota_exhausted alerts, got %+v", evts)
	}

	// Delete u2 and verify SweepUsers prunes without error.
	if err := st.DeleteUser(ctx, u2.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers after delete: %v", err)
	}
}

func TestEvaluateUsers_QuotaExhaustedLargeByteAlertNoOverflow(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	sched := scheduler.NewScheduler(st, nil, notifier, scheduler.WithNow(clk.Now))

	n, _ := createTestNode(t, st, "large-quota-node", true)
	u := createTestUser(t, st, "huge-traffic-user", true)
	u.TrafficQuotaBytes = math.MaxInt64
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatalf("update user: %v", err)
	}
	if err := st.SetUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatalf("set user nodes: %v", err)
	}

	const fiveExabytes uint64 = 5_000_000_000_000_000_000
	if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
		{UserID: u.ID, Username: u.Username, UpBytes: fiveExabytes, DownBytes: fiveExabytes},
	}, "2026-11-10"); err != nil {
		t.Fatalf("apply user deltas: %v", err)
	}

	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("SweepUsers: %v", err)
	}

	evts := notifier.Events()
	if len(evts) != 1 || evts[0].Type != webhook.EventUserQuotaExhausted {
		t.Fatalf("expected 1 user_quota_exhausted alert, got %+v", evts)
	}
	msg := evts[0].Message
	if !strings.Contains(msg, "(10000000000000000000 / 9223372036854775807 bytes)") || strings.Contains(msg, "(-") {
		t.Fatalf("expected non-overflowed 10000000000000000000 in alert message, got %q", msg)
	}
}

func TestTier5_EvaluateUsers_ColdStartAndSeededDefaultsBugB1(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	if err := st.SeedDefaults(ctx, store.SeedConfig{
		AdminUser:        "admin",
		AdminInitialPass: "pass12345",
		JWTSecret:        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}); err != nil {
		t.Fatalf("SeedDefaults: %v", err)
	}

	// Bug BUG-B1: SeedDefaults must explicitly seed alert_user_expired="true" and alert_user_quota_exhausted="true".
	vExp, err := st.GetSetting(ctx, "alert_user_expired")
	if err != nil || vExp != "true" {
		t.Fatalf("expected alert_user_expired=\"true\" after SeedDefaults, got %q err=%v", vExp, err)
	}
	vQuota, err := st.GetSetting(ctx, "alert_user_quota_exhausted")
	if err != nil || vQuota != "true" {
		t.Fatalf("expected alert_user_quota_exhausted=\"true\" after SeedDefaults, got %q err=%v", vQuota, err)
	}

	clk := newFakeClock(time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()
	n, tok := createTestNode(t, st, "cold-node", true)

	// User already expired AND quota-exhausted before Scheduler starts (cold start).
	u := createTestUser(t, st, "cold-user", true)
	past := clk.Now().Add(-2 * time.Hour)
	u.ExpireAt = &past
	u.TrafficQuotaBytes = 1000
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
		{UserID: u.ID, Username: u.Username, UpBytes: 600, DownBytes: 500},
	}, "2026-11-20"); err != nil {
		t.Fatal(err)
	}

	wsConn, wsCleanup := dialAgent(t, h, tok)
	defer wsCleanup()
	// Drain initial config_sync (user excluded due to expiry + quota exhaustion).
	initEnv := readEnvelope(t, wsConn, 2*time.Second)
	var initSync protocol.ServerConfigSync
	if err := json.Unmarshal(initEnv.Payload, &initSync); err != nil {
		t.Fatal(err)
	}
	if len(initSync.SS.Users) != 0 {
		t.Fatalf("expected cold-start expired/exhausted user excluded initially, got %+v", initSync.SS.Users)
	}

	sched := scheduler.NewScheduler(st, h, notifier, scheduler.WithNow(clk.Now))
	if err := sched.SweepUsers(ctx, clk.Now()); err != nil {
		t.Fatalf("cold-start SweepUsers: %v", err)
	}

	evts := notifier.Events()
	if len(evts) != 2 {
		t.Fatalf("expected 2 cold-start alerts (expired + quota_exhausted), got %+v", evts)
	}
	// Cold-start transition also triggers a config_sync excluding u.
	coldEnv := readEnvelope(t, wsConn, 2*time.Second)
	var coldSync protocol.ServerConfigSync
	if err := json.Unmarshal(coldEnv.Payload, &coldSync); err != nil {
		t.Fatal(err)
	}
	if len(coldSync.SS.Users) != 0 {
		t.Fatalf("expected user excluded in cold-start sync, got %+v", coldSync.SS.Users)
	}

	// Second sweep at same state should not re-fire.
	if err := sched.SweepUsers(ctx, clk.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if len(notifier.Events()) != 2 {
		t.Fatalf("expected deduplication on unchanged state, got %d events", len(notifier.Events()))
	}

	// Recover both expiry and traffic: scheduler must push server.config_sync re-enabling user AND reset userStates!
	future := clk.Now().Add(24 * time.Hour)
	u.ExpireAt = &future
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetUserTraffic(ctx, u.ID, clk.Now()); err != nil {
		t.Fatal(err)
	}
	if err := sched.SweepUsers(ctx, clk.Now().Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}

	recEnv := readEnvelope(t, wsConn, 2*time.Second)
	var recSync protocol.ServerConfigSync
	if err := json.Unmarshal(recEnv.Payload, &recSync); err != nil {
		t.Fatal(err)
	}
	if len(recSync.SS.Users) != 1 || recSync.SS.Users[0].UserID != u.ID {
		t.Fatalf("expected recovered user re-added in config_sync, got %+v", recSync.SS.Users)
	}

	// Re-exhausting after recovery triggers a fresh alert (proving userStates cleared).
	if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
		{UserID: u.ID, Username: u.Username, UpBytes: 1200, DownBytes: 0},
	}, "2026-11-20"); err != nil {
		t.Fatal(err)
	}
	if err := sched.SweepUsers(ctx, clk.Now().Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	all := notifier.Events()
	if len(all) != 3 || all[2].Type != webhook.EventUserQuotaExhausted {
		t.Fatalf("expected fresh user_quota_exhausted alert after recovery+re-exhaustion, got %+v", all)
	}
}
