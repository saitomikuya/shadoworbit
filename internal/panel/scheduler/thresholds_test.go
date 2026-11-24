package scheduler_test

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

func TestCountedTraffic_AllModesAndOverflow(t *testing.T) {
	cases := []struct {
		name string
		rx   int64
		tx   int64
		mode string
		want int64
	}{
		{name: "both normal", rx: 300, tx: 700, mode: protocol.TrafficCountBoth, want: 1000},
		{name: "both negative clamped", rx: -10, tx: 250, mode: protocol.TrafficCountBoth, want: 250},
		{name: "both overflow clamped", rx: math.MaxInt64 - 5, tx: 100, mode: protocol.TrafficCountBoth, want: math.MaxInt64},
		{name: "tx_only", rx: 9999, tx: 420, mode: protocol.TrafficCountTxOnly, want: 420},
		{name: "rx_only", rx: 420, tx: 9999, mode: protocol.TrafficCountRxOnly, want: 420},
		{name: "max_dir rx larger", rx: 800, tx: 300, mode: protocol.TrafficCountMaxDir, want: 800},
		{name: "max_dir tx larger", rx: 300, tx: 950, mode: protocol.TrafficCountMaxDir, want: 950},
		{name: "unknown defaults to both", rx: 100, tx: 200, mode: "custom", want: 300},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := scheduler.CountedTraffic(tc.rx, tc.tx, tc.mode); got != tc.want {
				t.Fatalf("CountedTraffic(%d, %d, %q) = %d, want %d", tc.rx, tc.tx, tc.mode, got, tc.want)
			}
		})
	}
}

func TestEvaluateNodeThreshold_CountModesAndWarning85(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	sched := scheduler.NewScheduler(st, nil, notifier, scheduler.WithNow(clk.Now))

	// Test tx_only: rx=5000 should NOT trigger warning/pause if tx=849 < 850.
	n, _ := createTestNode(t, st, "tx-only-node", true)
	n.TrafficCountMode = protocol.TrafficCountTxOnly
	n.TrafficThresholdBytes = 1000
	if err := st.UpdateNode(ctx, n); err != nil {
		t.Fatalf("update node: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 5000, 849); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate below warning: %v", err)
	}
	if len(notifier.Events()) != 0 {
		t.Fatalf("expected 0 alerts at 849/1000 tx_only, got %+v", notifier.Events())
	}

	// Hit 850 (85%) -> emits EventTrafficWarning ONCE.
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 5000, 850); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate at 85%%: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("re-evaluate at 85%%: %v", err)
	}
	evts := notifier.Events()
	if len(evts) != 1 || evts[0].Type != webhook.EventTrafficWarning || evts[0].Resolved {
		t.Fatalf("expected exactly 1 unresolved traffic_warning, got %+v", evts)
	}

	// Hit 999 -> still unpaused.
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 5000, 999); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate at 999: %v", err)
	}
	fresh, _ := st.GetNodeByID(ctx, n.ID)
	if fresh.IsTrafficPaused {
		t.Fatalf("expected node unpaused at 999/1000")
	}

	// Hit 1000 -> pauses and emits EventTrafficPaused ONCE.
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 5000, 1000); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate at 1000: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("re-evaluate at 1000: %v", err)
	}
	fresh, _ = st.GetNodeByID(ctx, n.ID)
	if !fresh.IsTrafficPaused || fresh.Status != protocol.NodeStatusTrafficPaused {
		t.Fatalf("expected paused node, got paused=%v status=%s", fresh.IsTrafficPaused, fresh.Status)
	}
	evts = notifier.Events()
	if len(evts) != 2 || evts[1].Type != webhook.EventTrafficPaused || evts[1].Resolved {
		t.Fatalf("expected second alert to be traffic_paused, got %+v", evts)
	}
}

func TestEvaluateNodeThreshold_DisableWarningAndLargeThresholdOverflowSafe(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	notifier := newMockNotifier()
	sched := scheduler.NewScheduler(st, nil, notifier)

	if err := st.SetSetting(ctx, "warning_threshold_percent", "100"); err != nil {
		t.Fatalf("set warning pct: %v", err)
	}

	n, _ := createTestNode(t, st, "overflow-safe", true)
	n.TrafficThresholdBytes = math.MaxInt64
	if err := st.UpdateNode(ctx, n); err != nil {
		t.Fatalf("update node: %v", err)
	}
	if err := st.CalibrateNodeTraffic(ctx, n.ID, math.MaxInt64-10, 0); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(notifier.Events()) != 0 {
		t.Fatalf("expected 0 warning alerts when warning_threshold_percent=100, got %+v", notifier.Events())
	}

	// Re-enable warning at 85% with math.MaxInt64 threshold (must not overflow int64!).
	if err := st.SetSetting(ctx, "warning_threshold_percent", "85"); err != nil {
		t.Fatalf("set warning pct: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate with 85%% and MaxInt64: %v", err)
	}
	evts := notifier.Events()
	if len(evts) != 1 || evts[0].Type != webhook.EventTrafficWarning {
		t.Fatalf("expected 1 warning alert with MaxInt64 threshold, got %+v", evts)
	}
}

func TestEvaluateNodeThreshold_PauseActionsAndAutoRecovery(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	sched := scheduler.NewScheduler(st, h, notifier, scheduler.WithNow(clk.Now))

	// Create node with stop_ss_only and connect an online agent.
	n, tok := createTestNode(t, st, "stop-ss-only-node", true)
	n.ThresholdAction = protocol.ThresholdActionStopSSOnly
	n.TrafficThresholdBytes = 1000
	if err := st.UpdateNode(ctx, n); err != nil {
		t.Fatalf("update node: %v", err)
	}

	conn, _ := dialAgent(t, h, tok)
	_ = readEnvelope(t, conn, 3*time.Second) // initial config_sync

	// Set stale DB last_seen_at (>2 min old) while WS session IS still online,
	// so we verify auto-recovery reconciles using hub.IsOnline rather than nodes.go's 2-min heuristic!
	if err := st.SetNodeConnectionStatus(ctx, n.ID, true, clk.Now().Add(-10*time.Minute)); err != nil {
		t.Fatalf("set connection status: %v", err)
	}

	// Breach threshold -> pause -> pushes config_sync with snell=true, ss=false.
	if err := st.CalibrateNodeTraffic(ctx, n.ID, 600, 400); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate pause: %v", err)
	}

	env := readEnvelope(t, conn, 3*time.Second)
	if env.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected server.config_sync on pause, got %s", env.Type)
	}
	var cfg protocol.ServerConfigSync
	if err := json.Unmarshal(env.Payload, &cfg); err != nil {
		t.Fatalf("unmarshal config_sync: %v", err)
	}
	if !cfg.Snell.Enabled || cfg.SS.Enabled {
		t.Fatalf("stop_ss_only expected snell=true ss=false, got snell=%v ss=%v", cfg.Snell.Enabled, cfg.SS.Enabled)
	}

	// Raise threshold manually -> EvaluateNodeThreshold auto-recovers!
	fresh, _ := st.GetNodeByID(ctx, n.ID)
	fresh.TrafficThresholdBytes = 2000
	if err := st.UpdateNode(ctx, fresh); err != nil {
		t.Fatalf("raise threshold: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n.ID); err != nil {
		t.Fatalf("evaluate recovery: %v", err)
	}

	recovered, _ := st.GetNodeByID(ctx, n.ID)
	if recovered.IsTrafficPaused {
		t.Fatalf("expected IsTrafficPaused=false after threshold raise")
	}
	if recovered.Status != protocol.NodeStatusOnline {
		t.Fatalf("expected online status reconciled from hub.IsOnline, got %q", recovered.Status)
	}

	env2 := readEnvelope(t, conn, 3*time.Second)
	var cfg2 protocol.ServerConfigSync
	if err := json.Unmarshal(env2.Payload, &cfg2); err != nil {
		t.Fatalf("unmarshal recovered config_sync: %v", err)
	}
	if !cfg2.Snell.Enabled || !cfg2.SS.Enabled {
		t.Fatalf("expected both snell and ss enabled after recovery, got snell=%v ss=%v", cfg2.Snell.Enabled, cfg2.SS.Enabled)
	}

	evts := notifier.Events()
	last := evts[len(evts)-1]
	if last.Type != webhook.EventTrafficRecovered || !last.Resolved || last.Severity != webhook.SeverityInfo {
		t.Fatalf("expected resolved traffic_recovered info event, got %+v", last)
	}
}

type hookNotifier struct {
	onNotify func(ctx context.Context, evt webhook.AlertEvent)
}

func (h *hookNotifier) Notify(ctx context.Context, evt webhook.AlertEvent) {
	if h.onNotify != nil {
		h.onNotify(ctx, evt)
	}
}

func TestSweepNodeThresholds_SkipsDeletedNodeMidSweep(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	n1, _ := createTestNode(t, st, "sweep-node-1", true)
	n2, _ := createTestNode(t, st, "sweep-node-2", true)
	n3, _ := createTestNode(t, st, "sweep-node-3", true)

	for _, nid := range []int64{n1.ID, n2.ID, n3.ID} {
		if err := st.CalibrateNodeTraffic(ctx, nid, 600, 600); err != nil {
			t.Fatalf("calibrate node %d: %v", nid, err)
		}
	}

	var deleted bool
	notifier := &hookNotifier{
		onNotify: func(cbCtx context.Context, evt webhook.AlertEvent) {
			if !deleted && evt.TargetID == n1.ID {
				deleted = true
				_ = st.DeleteNode(cbCtx, n2.ID)
			}
		},
	}

	sched := scheduler.NewScheduler(st, nil, notifier)
	if err := sched.SweepNodeThresholds(ctx); err != nil {
		t.Fatalf("SweepNodeThresholds should skip deleted node cleanly, got %v", err)
	}

	fresh1, err := st.GetNodeByID(ctx, n1.ID)
	if err != nil || !fresh1.IsTrafficPaused {
		t.Fatalf("expected n1 paused, got node=%+v err=%v", fresh1, err)
	}
	fresh3, err := st.GetNodeByID(ctx, n3.ID)
	if err != nil || !fresh3.IsTrafficPaused {
		t.Fatalf("expected n3 evaluated and paused after n2 deletion, got node=%+v err=%v", fresh3, err)
	}
	if err := sched.EvaluateNodeThreshold(ctx, n2.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for deleted node n2, got %v", err)
	}
}
