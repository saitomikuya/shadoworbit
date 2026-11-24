package scheduler_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

func TestRunBillingResets_MonthEndClampingAndFebLeapYear(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil)

	// Node with billing_reset_day = 31 created in Jan 2024.
	n31, _ := createTestNode(t, st, "day-31-node", true)
	n31.BillingResetDay = 31
	if err := st.UpdateNode(ctx, n31); err != nil {
		t.Fatalf("update node: %v", err)
	}
	if err := st.ResetNodeCycleTraffic(ctx, n31.ID, time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed reset: %v", err)
	}

	// Node with billing_reset_day = 29 created in Jan 2024.
	n29, _ := createTestNode(t, st, "day-29-node", true)
	n29.BillingResetDay = 29
	if err := st.UpdateNode(ctx, n29); err != nil {
		t.Fatalf("update node 29: %v", err)
	}
	if err := st.ResetNodeCycleTraffic(ctx, n29.ID, time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed reset 29: %v", err)
	}

	// Feb 28, 2024 (leap year) -> neither day=31 nor day=29 should reset yet!
	if err := st.CalibrateNodeTraffic(ctx, n31.ID, 111, 222); err != nil {
		t.Fatalf("calibrate n31: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n29.ID, 333, 444); err != nil {
		t.Fatalf("calibrate n29: %v", err)
	}
	if err := sched.RunBillingResets(ctx, time.Date(2024, 2, 28, 23, 59, 59, 0, time.UTC)); err != nil {
		t.Fatalf("RunBillingResets Feb 28 2024: %v", err)
	}
	got31, _ := st.GetNodeByID(ctx, n31.ID)
	got29, _ := st.GetNodeByID(ctx, n29.ID)
	if got31.CycleRxBytes != 111 || got29.CycleRxBytes != 333 {
		t.Fatalf("leap year Feb 28 should NOT reset day 29/31: n31=%d n29=%d", got31.CycleRxBytes, got29.CycleRxBytes)
	}

	// Feb 29, 2024 00:00 -> BOTH day=31 and day=29 clamp to 29 and reset!
	if err := sched.RunBillingResets(ctx, time.Date(2024, 2, 29, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunBillingResets Feb 29 2024: %v", err)
	}
	got31, _ = st.GetNodeByID(ctx, n31.ID)
	got29, _ = st.GetNodeByID(ctx, n29.ID)
	if got31.CycleRxBytes != 0 || got29.CycleRxBytes != 0 {
		t.Fatalf("leap year Feb 29 should reset both day 29 and 31: n31=%d n29=%d", got31.CycleRxBytes, got29.CycleRxBytes)
	}

	// Non-leap year Feb 2025: Feb 28 00:00 resets BOTH day=31 and day=29!
	if err := st.CalibrateNodeTraffic(ctx, n31.ID, 500, 500); err != nil {
		t.Fatalf("calibrate n31: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n29.ID, 600, 600); err != nil {
		t.Fatalf("calibrate n29: %v", err)
	}
	if err := sched.RunBillingResets(ctx, time.Date(2025, 2, 28, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunBillingResets Feb 28 2025: %v", err)
	}
	got31, _ = st.GetNodeByID(ctx, n31.ID)
	got29, _ = st.GetNodeByID(ctx, n29.ID)
	if got31.CycleRxBytes != 0 || got29.CycleRxBytes != 0 {
		t.Fatalf("non-leap Feb 28 should reset day 29/31: n31=%d n29=%d", got31.CycleRxBytes, got29.CycleRxBytes)
	}

	// 30-day month (Apr 2025): Apr 29 does not reset day=31; Apr 30 00:00 resets day=31.
	if err := st.CalibrateNodeTraffic(ctx, n31.ID, 700, 800); err != nil {
		t.Fatalf("calibrate n31: %v", err)
	}
	if err := sched.RunBillingResets(ctx, time.Date(2025, 4, 29, 23, 59, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunBillingResets Apr 29: %v", err)
	}
	got31, _ = st.GetNodeByID(ctx, n31.ID)
	if got31.CycleRxBytes != 700 {
		t.Fatalf("Apr 29 should not reset day=31, got %d", got31.CycleRxBytes)
	}
	if err := sched.RunBillingResets(ctx, time.Date(2025, 4, 30, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunBillingResets Apr 30: %v", err)
	}
	got31, _ = st.GetNodeByID(ctx, n31.ID)
	if got31.CycleRxBytes != 0 {
		t.Fatalf("Apr 30 should reset day=31, got %d", got31.CycleRxBytes)
	}
}

func TestRunBillingResets_Timezone0000Boundary(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil)

	shanghai := time.FixedZone("CST", 8*3600)
	n, _ := createTestNode(t, st, "tz-node", true)
	n.BillingResetDay = 1
	if err := st.UpdateNode(ctx, n); err != nil {
		t.Fatalf("update node: %v", err)
	}
	// Last reset in November 2026.
	if err := st.ResetNodeCycleTraffic(ctx, n.ID, time.Date(2026, 11, 5, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed reset: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 900, 100); err != nil {
		t.Fatalf("calibrate: %v", err)
	}

	// 2026-11-30 23:59:59 CST (== 15:59:59 UTC) -> must NOT reset yet.
	beforeMidnight := time.Date(2026, 11, 30, 15, 59, 59, 0, time.UTC).In(shanghai)
	if err := sched.RunBillingResets(ctx, beforeMidnight); err != nil {
		t.Fatalf("RunBillingResets before midnight: %v", err)
	}
	got, _ := st.GetNodeByID(ctx, n.ID)
	if got.CycleRxBytes != 900 {
		t.Fatalf("expected no reset at 23:59:59 CST, got rx=%d", got.CycleRxBytes)
	}

	// 2026-12-01 00:00:00 CST (== 16:00:00 UTC) -> MUST reset!
	atMidnight := time.Date(2026, 11, 30, 16, 0, 0, 0, time.UTC).In(shanghai)
	if err := sched.RunBillingResets(ctx, atMidnight); err != nil {
		t.Fatalf("RunBillingResets at midnight: %v", err)
	}
	got, _ = st.GetNodeByID(ctx, n.ID)
	if got.CycleRxBytes != 0 || got.CycleTxBytes != 0 {
		t.Fatalf("expected reset at 00:00:00 CST, got rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}
}

func TestRunBillingResets_RestartIdempotencyAndCreationGuard(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	// Node created on Nov 23 with billing_reset_day=1 and immediately calibrated.
	n, _ := createTestNode(t, st, "created-mid-month", true)
	nowNov23 := time.Date(2026, 11, 23, 10, 0, 0, 0, time.UTC)
	if err := st.ResetNodeCycleTraffic(ctx, n.ID, nowNov23); err != nil {
		t.Fatalf("set LastResetAt to Nov 23: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 1234, 5678); err != nil {
		t.Fatalf("calibrate: %v", err)
	}

	sched1 := scheduler.NewScheduler(st, nil, nil)
	if err := sched1.RunBillingResets(ctx, nowNov23); err != nil {
		t.Fatalf("RunBillingResets on creation day: %v", err)
	}
	got, _ := st.GetNodeByID(ctx, n.ID)
	if got.CycleRxBytes != 1234 || got.CycleTxBytes != 5678 {
		t.Fatalf("creation/calibration guard failed: wiped calibrated traffic rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}

	// Next month Dec 1 -> resets once.
	dec1 := time.Date(2026, 12, 1, 0, 5, 0, 0, time.UTC)
	if err := sched1.RunBillingResets(ctx, dec1); err != nil {
		t.Fatalf("RunBillingResets Dec 1: %v", err)
	}
	got, _ = st.GetNodeByID(ctx, n.ID)
	if got.CycleRxBytes != 0 {
		t.Fatalf("expected Dec 1 reset, got rx=%d", got.CycleRxBytes)
	}

	marker, err := st.GetSetting(ctx, fmt.Sprintf("last_node_reset_month:%d", n.ID))
	if err != nil || marker != "2026-12" {
		t.Fatalf("expected marker 2026-12, got %q (err=%v)", marker, err)
	}

	// Simulate panel restart + new traffic accumulated later in Dec -> must NOT reset again in Dec!
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 42, 43); err != nil {
		t.Fatalf("calibrate dec: %v", err)
	}
	sched2 := scheduler.NewScheduler(st, nil, nil)
	if err := sched2.RunBillingResets(ctx, dec1.Add(2*time.Hour)); err != nil {
		t.Fatalf("RunBillingResets after restart: %v", err)
	}
	got, _ = st.GetNodeByID(ctx, n.ID)
	if got.CycleRxBytes != 42 || got.CycleTxBytes != 43 {
		t.Fatalf("restart idempotency failed: expected rx=42 tx=43, got rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}
}

func TestRunBillingResets_UsersDisabledAndPausedRecovery(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	sched := scheduler.NewScheduler(st, h, notifier, scheduler.WithNow(clk.Now))

	// Create node paused from October, connected online.
	n, tok := createTestNode(t, st, "paused-oct-node", true)
	if err := st.ResetNodeCycleTraffic(ctx, n.ID, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed oct reset: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 800, 300); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := st.SetNodeTrafficPaused(ctx, n.ID, true, "threshold reached"); err != nil {
		t.Fatalf("pause node: %v", err)
	}

	// User 1: billing_reset_day=1, exhausted in Oct -> should reset and hot-sync back into sing-box.
	uReset := createTestUser(t, st, "reset-user", true)
	uReset.TrafficQuotaBytes = 1000
	uReset.BillingResetDay = 1
	if err := st.UpdateUser(ctx, uReset); err != nil {
		t.Fatalf("update uReset: %v", err)
	}
	if err := st.ResetUserTraffic(ctx, uReset.ID, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed user oct reset: %v", err)
	}
	if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
		{UserID: uReset.ID, Username: uReset.Username, UpBytes: 600, DownBytes: 500},
	}, "2026-10-15"); err != nil {
		t.Fatalf("apply user traffic: %v", err)
	}
	if err := st.SetUserNodes(ctx, uReset.ID, []int64{n.ID}); err != nil {
		t.Fatalf("set uReset nodes: %v", err)
	}

	// User 2: billing_reset_day=0 -> NEVER reset.
	uNoReset := createTestUser(t, st, "no-reset-user", true)
	uNoReset.TrafficQuotaBytes = 1000
	uNoReset.BillingResetDay = 0
	if err := st.UpdateUser(ctx, uNoReset); err != nil {
		t.Fatalf("update uNoReset: %v", err)
	}
	if err := st.ResetUserTraffic(ctx, uNoReset.ID, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatalf("seed uNoReset oct: %v", err)
	}
	if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
		{UserID: uNoReset.ID, Username: uNoReset.Username, UpBytes: 400, DownBytes: 100},
	}, "2026-10-15"); err != nil {
		t.Fatalf("apply uNoReset traffic: %v", err)
	}

	conn, _ := dialAgent(t, h, tok)
	_ = readEnvelope(t, conn, 3*time.Second) // initial config_sync (paused + uReset excluded)

	// Run Nov 1 reset!
	if err := sched.RunBillingResets(ctx, clk.Now()); err != nil {
		t.Fatalf("RunBillingResets Nov 1: %v", err)
	}

	gotNode, _ := st.GetNodeByID(ctx, n.ID)
	if gotNode.IsTrafficPaused || gotNode.Status != protocol.NodeStatusOnline || gotNode.CycleRxBytes != 0 {
		t.Fatalf("expected unpaused online zeroed node, got paused=%v status=%s rx=%d", gotNode.IsTrafficPaused, gotNode.Status, gotNode.CycleRxBytes)
	}

	gotUReset, _ := st.GetUserByID(ctx, uReset.ID)
	if gotUReset.UsedUpBytes != 0 || gotUReset.UsedDownBytes != 0 {
		t.Fatalf("expected uReset traffic zeroed, got up=%d down=%d", gotUReset.UsedUpBytes, gotUReset.UsedDownBytes)
	}

	gotUNoReset, _ := st.GetUserByID(ctx, uNoReset.ID)
	if gotUNoReset.UsedUpBytes != 400 || gotUNoReset.UsedDownBytes != 100 {
		t.Fatalf("billing_reset_day=0 user should NOT reset, got up=%d down=%d", gotUNoReset.UsedUpBytes, gotUNoReset.UsedDownBytes)
	}

	// Verify agent received server.config_sync with uReset restored!
	env := readEnvelope(t, conn, 3*time.Second)
	if env.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected server.config_sync, got %s", env.Type)
	}
	var cfg protocol.ServerConfigSync
	if err := json.Unmarshal(env.Payload, &cfg); err != nil {
		t.Fatalf("unmarshal config_sync: %v", err)
	}
	// Drain potential second sync from user recovery; check BuildConfigSync authoritative state too.
	latestCfg, err := h.BuildConfigSync(ctx, n.ID)
	if err != nil {
		t.Fatalf("BuildConfigSync: %v", err)
	}
	if !latestCfg.SS.Enabled || len(latestCfg.SS.Users) != 1 || latestCfg.SS.Users[0].UserID != uReset.ID {
		t.Fatalf("expected uReset restored in SS users, got %+v", latestCfg.SS)
	}

	evts := notifier.Events()
	var sawRecovered bool
	for _, e := range evts {
		if e.Type == webhook.EventTrafficRecovered && e.Resolved && e.TargetID == n.ID {
			sawRecovered = true
		}
	}
	if !sawRecovered {
		t.Fatalf("expected resolved traffic_recovered event after billing reset of paused node, got %+v", evts)
	}
}

func TestRunBillingResets_DSTMidnightSpringForward(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name        string
		tz          string
		resetDay    int
		seedDate    [3]int // Y, M, D
		beforeTime  [6]int // Y, M, D, h, m, s (on effectiveDay - 1)
		afterTime   [6]int // Y, M, D, h, m, s (on effectiveDay after 00->01 jump)
		expectMonth string
	}{
		{
			name:        "America/Havana 2026-03-08",
			tz:          "America/Havana",
			resetDay:    8,
			seedDate:    [3]int{2026, 2, 15},
			beforeTime:  [6]int{2026, 3, 7, 23, 30, 0},
			afterTime:   [6]int{2026, 3, 8, 1, 0, 0},
			expectMonth: "2026-03",
		},
		{
			name:        "America/Santiago 2026-09-06",
			tz:          "America/Santiago",
			resetDay:    6,
			seedDate:    [3]int{2026, 8, 15},
			beforeTime:  [6]int{2026, 9, 5, 23, 30, 0},
			afterTime:   [6]int{2026, 9, 6, 1, 0, 0},
			expectMonth: "2026-09",
		},
		{
			name:        "America/Sao_Paulo 2018-11-04",
			tz:          "America/Sao_Paulo",
			resetDay:    4,
			seedDate:    [3]int{2018, 10, 15},
			beforeTime:  [6]int{2018, 11, 3, 23, 59, 59},
			afterTime:   [6]int{2018, 11, 4, 1, 0, 0},
			expectMonth: "2018-11",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.tz)
			if err != nil {
				t.Fatalf("load location %s: %v", tc.tz, err)
			}

			st := openTestStore(t)
			sched := scheduler.NewScheduler(st, nil, nil)

			n, _ := createTestNode(t, st, "dst-node", true)
			n.BillingResetDay = tc.resetDay
			if err := st.UpdateNode(ctx, n); err != nil {
				t.Fatalf("update node: %v", err)
			}
			seedAt := time.Date(tc.seedDate[0], time.Month(tc.seedDate[1]), tc.seedDate[2], 12, 0, 0, 0, loc)
			if err := st.ResetNodeCycleTraffic(ctx, n.ID, seedAt.UTC()); err != nil {
				t.Fatalf("seed node reset: %v", err)
			}
			if err := st.CalibrateNodeTraffic(ctx, n.ID, 1200, 3400); err != nil {
				t.Fatalf("calibrate node: %v", err)
			}

			u := createTestUser(t, st, "dst-user", true)
			u.BillingResetDay = tc.resetDay
			if err := st.UpdateUser(ctx, u); err != nil {
				t.Fatalf("update user: %v", err)
			}
			if err := st.ResetUserTraffic(ctx, u.ID, seedAt.UTC()); err != nil {
				t.Fatalf("seed user reset: %v", err)
			}
			if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
				{UserID: u.ID, Username: u.Username, UpBytes: 555, DownBytes: 777},
			}, seedAt.Format("2006-01-02")); err != nil {
				t.Fatalf("apply user traffic: %v", err)
			}

			// Step 1: On effectiveDay - 1 just before midnight DST jump -> MUST NOT reset.
			before := time.Date(tc.beforeTime[0], time.Month(tc.beforeTime[1]), tc.beforeTime[2],
				tc.beforeTime[3], tc.beforeTime[4], tc.beforeTime[5], 0, loc)
			if err := sched.RunBillingResets(ctx, before); err != nil {
				t.Fatalf("RunBillingResets before midnight: %v", err)
			}

			gotNode, err := st.GetNodeByID(ctx, n.ID)
			if err != nil {
				t.Fatalf("get node: %v", err)
			}
			if gotNode.CycleRxBytes != 1200 || gotNode.CycleTxBytes != 3400 {
				t.Fatalf("%s at %s prematurely reset node: rx=%d tx=%d", tc.tz, before.Format(time.RFC3339), gotNode.CycleRxBytes, gotNode.CycleTxBytes)
			}
			gotUser, err := st.GetUserByID(ctx, u.ID)
			if err != nil {
				t.Fatalf("get user: %v", err)
			}
			if gotUser.UsedUpBytes != 555 || gotUser.UsedDownBytes != 777 {
				t.Fatalf("%s at %s prematurely reset user: up=%d down=%d", tc.tz, before.Format(time.RFC3339), gotUser.UsedUpBytes, gotUser.UsedDownBytes)
			}

			// Step 2: On effectiveDay at 01:00:00 after DST spring-forward -> MUST reset once.
			after := time.Date(tc.afterTime[0], time.Month(tc.afterTime[1]), tc.afterTime[2],
				tc.afterTime[3], tc.afterTime[4], tc.afterTime[5], 0, loc)
			if err := sched.RunBillingResets(ctx, after); err != nil {
				t.Fatalf("RunBillingResets on reset day: %v", err)
			}

			gotNode, _ = st.GetNodeByID(ctx, n.ID)
			if gotNode.CycleRxBytes != 0 || gotNode.CycleTxBytes != 0 {
				t.Fatalf("%s at %s expected node reset to 0, got rx=%d tx=%d", tc.tz, after.Format(time.RFC3339), gotNode.CycleRxBytes, gotNode.CycleTxBytes)
			}
			gotUser, _ = st.GetUserByID(ctx, u.ID)
			if gotUser.UsedUpBytes != 0 || gotUser.UsedDownBytes != 0 {
				t.Fatalf("%s at %s expected user reset to 0, got up=%d down=%d", tc.tz, after.Format(time.RFC3339), gotUser.UsedUpBytes, gotUser.UsedDownBytes)
			}

			nodeMarker, err := st.GetSetting(ctx, fmt.Sprintf("last_node_reset_month:%d", n.ID))
			if err != nil || nodeMarker != tc.expectMonth {
				t.Fatalf("expected node marker %q, got %q (err=%v)", tc.expectMonth, nodeMarker, err)
			}
			userMarker, err := st.GetSetting(ctx, fmt.Sprintf("last_user_reset_month:%d", u.ID))
			if err != nil || userMarker != tc.expectMonth {
				t.Fatalf("expected user marker %q, got %q (err=%v)", tc.expectMonth, userMarker, err)
			}

			// Step 3: Accumulate traffic later that day and run again -> MUST NOT reset a second time.
			if err := st.CalibrateNodeTraffic(ctx, n.ID, 88, 99); err != nil {
				t.Fatalf("re-calibrate node: %v", err)
			}
			if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
				{UserID: u.ID, Username: u.Username, UpBytes: 33, DownBytes: 44},
			}, after.Format("2006-01-02")); err != nil {
				t.Fatalf("re-apply user traffic: %v", err)
			}
			if err := sched.RunBillingResets(ctx, after.Add(time.Hour)); err != nil {
				t.Fatalf("RunBillingResets idempotent rerun: %v", err)
			}
			gotNode, _ = st.GetNodeByID(ctx, n.ID)
			if gotNode.CycleRxBytes != 88 || gotNode.CycleTxBytes != 99 {
				t.Fatalf("expected node traffic preserved on rerun, got rx=%d tx=%d", gotNode.CycleRxBytes, gotNode.CycleTxBytes)
			}
			gotUser, _ = st.GetUserByID(ctx, u.ID)
			if gotUser.UsedUpBytes != 33 || gotUser.UsedDownBytes != 44 {
				t.Fatalf("expected user traffic preserved on rerun, got up=%d down=%d", gotUser.UsedUpBytes, gotUser.UsedDownBytes)
			}
		})
	}
}

func TestRunBillingResets_DSTMidnightCreationGuard(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name        string
		tz          string
		resetDay    int
		prevEvening [6]int // Y, M, D, h, m, s on effectiveDay - 1 at 23:30:00
		resetDay01  [6]int // Y, M, D, h, m, s on effectiveDay at 01:00:00
		expectMonth string
	}{
		{
			name:        "America/Havana 2026-03-07 23:30 -> 2026-03-08 01:00",
			tz:          "America/Havana",
			resetDay:    8,
			prevEvening: [6]int{2026, 3, 7, 23, 30, 0},
			resetDay01:  [6]int{2026, 3, 8, 1, 0, 0},
			expectMonth: "2026-03",
		},
		{
			name:        "America/Santiago 2026-09-05 23:30 -> 2026-09-06 01:00",
			tz:          "America/Santiago",
			resetDay:    6,
			prevEvening: [6]int{2026, 9, 5, 23, 30, 0},
			resetDay01:  [6]int{2026, 9, 6, 1, 0, 0},
			expectMonth: "2026-09",
		},
		{
			name:        "America/Sao_Paulo 2018-11-03 23:30 -> 2018-11-04 01:00",
			tz:          "America/Sao_Paulo",
			resetDay:    4,
			prevEvening: [6]int{2018, 11, 3, 23, 30, 0},
			resetDay01:  [6]int{2018, 11, 4, 1, 0, 0},
			expectMonth: "2018-11",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			loc, err := time.LoadLocation(tc.tz)
			if err != nil {
				t.Fatalf("load location %s: %v", tc.tz, err)
			}

			st := openTestStore(t)
			sched := scheduler.NewScheduler(st, nil, nil)

			prevEvening := time.Date(tc.prevEvening[0], time.Month(tc.prevEvening[1]), tc.prevEvening[2],
				tc.prevEvening[3], tc.prevEvening[4], tc.prevEvening[5], 0, loc)
			resetDay01 := time.Date(tc.resetDay01[0], time.Month(tc.resetDay01[1]), tc.resetDay01[2],
				tc.resetDay01[3], tc.resetDay01[4], tc.resetDay01[5], 0, loc)

			// Node & User created/calibrated on effectiveDay - 1 at 23:30:00 (no last_*_reset_month marker yet).
			n, _ := createTestNode(t, st, "guard-node", true)
			n.BillingResetDay = tc.resetDay
			if err := st.UpdateNode(ctx, n); err != nil {
				t.Fatalf("update node: %v", err)
			}
			if err := st.ResetNodeCycleTraffic(ctx, n.ID, prevEvening.UTC()); err != nil {
				t.Fatalf("set node LastResetAt: %v", err)
			}
			if err := st.CalibrateNodeTraffic(ctx, n.ID, 400, 600); err != nil {
				t.Fatalf("calibrate node: %v", err)
			}

			u := createTestUser(t, st, "guard-user", true)
			u.BillingResetDay = tc.resetDay
			if err := st.UpdateUser(ctx, u); err != nil {
				t.Fatalf("update user: %v", err)
			}
			if err := st.ResetUserTraffic(ctx, u.ID, prevEvening.UTC()); err != nil {
				t.Fatalf("set user LastResetAt: %v", err)
			}
			if _, err := st.ApplyTrafficDeltas(ctx, n.ID, 0, 0, []protocol.UserTrafficDelta{
				{UserID: u.ID, Username: u.Username, UpBytes: 250, DownBytes: 350},
			}, prevEvening.Format("2006-01-02")); err != nil {
				t.Fatalf("apply user traffic: %v", err)
			}

			// Running at effectiveDay - 1 23:30:00 must neither reset nor write last_*_reset_month.
			if err := sched.RunBillingResets(ctx, prevEvening); err != nil {
				t.Fatalf("RunBillingResets prevEvening: %v", err)
			}
			if _, err := st.GetSetting(ctx, fmt.Sprintf("last_node_reset_month:%d", n.ID)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expected node reset marker absent on effectiveDay-1, got err=%v", err)
			}
			if _, err := st.GetSetting(ctx, fmt.Sprintf("last_user_reset_month:%d", u.ID)); !errors.Is(err, store.ErrNotFound) {
				t.Fatalf("expected user reset marker absent on effectiveDay-1, got err=%v", err)
			}

			// Next day at effectiveDay 01:00:00: creation guard MUST NOT treat prevEvening (23:30) as >= effectiveDay!
			// Both node and user MUST reset.
			if err := sched.RunBillingResets(ctx, resetDay01); err != nil {
				t.Fatalf("RunBillingResets resetDay01: %v", err)
			}

			gotNode, _ := st.GetNodeByID(ctx, n.ID)
			if gotNode.CycleRxBytes != 0 || gotNode.CycleTxBytes != 0 {
				t.Fatalf("creation guard wrongly skipped effectiveDay reset for node: rx=%d tx=%d", gotNode.CycleRxBytes, gotNode.CycleTxBytes)
			}
			gotUser, _ := st.GetUserByID(ctx, u.ID)
			if gotUser.UsedUpBytes != 0 || gotUser.UsedDownBytes != 0 {
				t.Fatalf("creation guard wrongly skipped effectiveDay reset for user: up=%d down=%d", gotUser.UsedUpBytes, gotUser.UsedDownBytes)
			}

			// Also verify positive creation guard: entity created/calibrated ON effectiveDay (01:05:00)
			// must NOT be wiped when RunBillingResets runs at 01:10:00.
			nSameDay, _ := createTestNode(t, st, "same-day-node", true)
			nSameDay.BillingResetDay = tc.resetDay
			if err := st.UpdateNode(ctx, nSameDay); err != nil {
				t.Fatalf("update nSameDay: %v", err)
			}
			sameDay0105 := resetDay01.Add(5 * time.Minute)
			if err := st.ResetNodeCycleTraffic(ctx, nSameDay.ID, sameDay0105.UTC()); err != nil {
				t.Fatalf("set nSameDay LastResetAt: %v", err)
			}
			if err := st.CalibrateNodeTraffic(ctx, nSameDay.ID, 777, 888); err != nil {
				t.Fatalf("calibrate nSameDay: %v", err)
			}

			uSameDay := createTestUser(t, st, "same-day-user", true)
			uSameDay.BillingResetDay = tc.resetDay
			if err := st.UpdateUser(ctx, uSameDay); err != nil {
				t.Fatalf("update uSameDay: %v", err)
			}
			if err := st.ResetUserTraffic(ctx, uSameDay.ID, sameDay0105.UTC()); err != nil {
				t.Fatalf("set uSameDay LastResetAt: %v", err)
			}
			if _, err := st.ApplyTrafficDeltas(ctx, nSameDay.ID, 0, 0, []protocol.UserTrafficDelta{
				{UserID: uSameDay.ID, Username: uSameDay.Username, UpBytes: 111, DownBytes: 222},
			}, sameDay0105.Format("2006-01-02")); err != nil {
				t.Fatalf("apply uSameDay traffic: %v", err)
			}

			if err := sched.RunBillingResets(ctx, sameDay0105.Add(5*time.Minute)); err != nil {
				t.Fatalf("RunBillingResets sameDay0110: %v", err)
			}
			gotSameNode, _ := st.GetNodeByID(ctx, nSameDay.ID)
			if gotSameNode.CycleRxBytes != 777 || gotSameNode.CycleTxBytes != 888 {
				t.Fatalf("positive creation guard failed for node: rx=%d tx=%d", gotSameNode.CycleRxBytes, gotSameNode.CycleTxBytes)
			}
			gotSameUser, _ := st.GetUserByID(ctx, uSameDay.ID)
			if gotSameUser.UsedUpBytes != 111 || gotSameUser.UsedDownBytes != 222 {
				t.Fatalf("positive creation guard failed for user: up=%d down=%d", gotSameUser.UsedUpBytes, gotSameUser.UsedDownBytes)
			}
			if m, err := st.GetSetting(ctx, fmt.Sprintf("last_node_reset_month:%d", nSameDay.ID)); err != nil || m != tc.expectMonth {
				t.Fatalf("expected same-day node marker %q, got %q (err=%v)", tc.expectMonth, m, err)
			}
			if m, err := st.GetSetting(ctx, fmt.Sprintf("last_user_reset_month:%d", uSameDay.ID)); err != nil || m != tc.expectMonth {
				t.Fatalf("expected same-day user marker %q, got %q (err=%v)", tc.expectMonth, m, err)
			}
		})
	}
}

func TestTier5_RunBillingResets_NonUTCTimezonesAndDST(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	sched := scheduler.NewScheduler(st, nil, nil)

	shanghai, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatalf("load Asia/Shanghai: %v", err)
	}
	ny, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatalf("load America/New_York: %v", err)
	}

	// Node 1: reset day 10 in Asia/Shanghai (+08:00).
	nSH, _ := createTestNode(t, st, "shanghai-node", true)
	nSH.BillingResetDay = 10
	if err := st.UpdateNode(ctx, nSH); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetNodeCycleTraffic(ctx, nSH.ID, time.Date(2026, 2, 10, 0, 0, 0, 0, shanghai)); err != nil {
		t.Fatal(err)
	}
	if err := st.CalibrateNodeTraffic(ctx, nSH.ID, 500, 500); err != nil {
		t.Fatal(err)
	}

	// March 9 23:30 Shanghai (= March 9 15:30 UTC): must NOT reset yet.
	if err := sched.RunBillingResets(ctx, time.Date(2026, 3, 9, 23, 30, 0, 0, shanghai)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetNodeByID(ctx, nSH.ID); got.CycleRxBytes != 500 {
		t.Fatalf("expected no reset at 23:30 Shanghai day 9, got %d", got.CycleRxBytes)
	}

	// March 10 00:05 Shanghai (= March 9 16:05 UTC): MUST reset in Shanghai's local day 10!
	if err := sched.RunBillingResets(ctx, time.Date(2026, 3, 10, 0, 5, 0, 0, shanghai)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetNodeByID(ctx, nSH.ID); got.CycleRxBytes != 0 || got.CycleTxBytes != 0 {
		t.Fatalf("expected reset at 00:05 Shanghai day 10, got rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}

	// Node 2: DST spring-forward in America/New_York (2026-03-08 02:00 -> 03:00 EDT).
	nNY, _ := createTestNode(t, st, "ny-dst-node", true)
	nNY.BillingResetDay = 8
	if err := st.UpdateNode(ctx, nNY); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetNodeCycleTraffic(ctx, nNY.ID, time.Date(2026, 2, 8, 12, 0, 0, 0, ny)); err != nil {
		t.Fatal(err)
	}
	if err := st.CalibrateNodeTraffic(ctx, nNY.ID, 900, 100); err != nil {
		t.Fatal(err)
	}

	// 2026-03-08 03:05 EDT (right across spring-forward gap): must reset cleanly.
	if err := sched.RunBillingResets(ctx, time.Date(2026, 3, 8, 3, 5, 0, 0, ny)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetNodeByID(ctx, nNY.ID); got.CycleRxBytes != 0 || got.CycleTxBytes != 0 {
		t.Fatalf("expected NY DST spring-forward reset, got rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}

	// Node 3: Non-leap Feb 2025 clamping for billing_reset_day=30 -> resets on 2025-02-28.
	nFeb, _ := createTestNode(t, st, "feb-nonleap-node", true)
	nFeb.BillingResetDay = 30
	if err := st.UpdateNode(ctx, nFeb); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetNodeCycleTraffic(ctx, nFeb.ID, time.Date(2025, 1, 30, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := st.CalibrateNodeTraffic(ctx, nFeb.ID, 300, 400); err != nil {
		t.Fatal(err)
	}
	if err := sched.RunBillingResets(ctx, time.Date(2025, 2, 28, 1, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.GetNodeByID(ctx, nFeb.ID); got.CycleRxBytes != 0 || got.CycleTxBytes != 0 {
		t.Fatalf("expected non-leap Feb 28 reset for day=30, got rx=%d tx=%d", got.CycleRxBytes, got.CycleTxBytes)
	}
}

func TestTier5_RunBillingResets_UnpausesNodeEmitsResolvedAndSyncsWS(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier)
	defer h.Close()

	node, tok := createTestNode(t, st, "paused-reset-node", true)
	node.BillingResetDay = 15
	node.TrafficLimitBytes = 1000
	node.TrafficThresholdBytes = 1000
	if err := st.UpdateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := st.ResetNodeCycleTraffic(ctx, node.ID, time.Date(2026, 2, 15, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := st.CalibrateNodeTraffic(ctx, node.ID, 600, 600); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeTrafficPaused(ctx, node.ID, true, "traffic threshold reached"); err != nil {
		t.Fatal(err)
	}

	wsConn, wsCleanup := dialAgent(t, h, tok)
	defer wsCleanup()

	// Drain initial config sync (when TrafficPaused=true with stop_all, both Snell & SS are disabled).
	readCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, initFrameBytes, err := wsConn.Read(readCtx)
	if err != nil {
		t.Fatalf("read initial sync: %v", err)
	}
	var initEnv protocol.Envelope
	if err := json.Unmarshal(initFrameBytes, &initEnv); err != nil {
		t.Fatal(err)
	}
	var initSync protocol.ServerConfigSync
	if err := json.Unmarshal(initEnv.Payload, &initSync); err != nil {
		t.Fatal(err)
	}
	if initSync.Snell.Enabled || initSync.SS.Enabled {
		t.Fatalf("expected initial sync Snell & SS disabled while TrafficPaused=true, got snell=%v ss=%v", initSync.Snell.Enabled, initSync.SS.Enabled)
	}

	sched := scheduler.NewScheduler(st, h, notifier)
	if err := sched.RunBillingResets(ctx, time.Date(2026, 3, 15, 0, 1, 0, 0, time.UTC)); err != nil {
		t.Fatalf("RunBillingResets: %v", err)
	}

	gotNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotNode.IsTrafficPaused || gotNode.PausedReason != "" || gotNode.CycleRxBytes != 0 || gotNode.CycleTxBytes != 0 {
		t.Fatalf("expected node unpaused and traffic cleared after billing reset, got %+v", gotNode)
	}

	// Verify Resolved=true webhook fired.
	evts := notifier.Events()
	foundResolved := false
	for _, ev := range evts {
		if ev.Type == webhook.EventTrafficRecovered && ev.TargetID == node.ID && ev.Resolved {
			foundResolved = true
			break
		}
	}
	if !foundResolved {
		t.Fatalf("expected Resolved=true EventTrafficRecovered webhook on unpause, got %+v", evts)
	}

	// Verify agent WS receives server.config_sync re-enabling Snell & SS after unpause.
	_, syncBytes, err := wsConn.Read(readCtx)
	if err != nil {
		t.Fatalf("expected config_sync push after billing reset unpause: %v", err)
	}
	var env protocol.Envelope
	if err := json.Unmarshal(syncBytes, &env); err != nil {
		t.Fatal(err)
	}
	var syncPayload protocol.ServerConfigSync
	if err := json.Unmarshal(env.Payload, &syncPayload); err != nil {
		t.Fatal(err)
	}
	if !syncPayload.Snell.Enabled || !syncPayload.SS.Enabled {
		t.Fatalf("expected pushed syncPayload Snell & SS re-enabled after reset unpause, got snell=%v ss=%v", syncPayload.Snell.Enabled, syncPayload.SS.Enabled)
	}
}
