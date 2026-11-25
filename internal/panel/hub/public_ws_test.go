package hub_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

func assertRedactedSnapshotJSON(t *testing.T, raw []byte) {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("unmarshal snapshot json: %v", err)
	}

	expectedTop := []string{"site_title", "announcement", "percentage_only", "nodes"}
	if len(top) != len(expectedTop) {
		t.Fatalf("expected %d top-level keys, got %d: %v", len(expectedTop), len(top), top)
	}
	for _, k := range expectedTop {
		if _, ok := top[k]; !ok {
			t.Fatalf("missing top-level key %q", k)
		}
	}

	forbidden := map[string]bool{
		"public_ip": true, "public_ipv6": true, "custom_entry_host": true, "custom_entry_port": true,
		"snell_config": true, "ss_config": true, "dns_unlock_server": true, "token": true,
		"token_hash": true, "psk": true, "ipsk": true, "upsk": true, "ss_upsk_16": true,
		"ss_upsk_32": true, "stls_password": true, "sub_token": true, "admin_sub_token": true,
		"username": true, "users": true,
	}
	var walk func(any, string)
	walk = func(v any, path string) {
		switch x := v.(type) {
		case map[string]any:
			for k, child := range x {
				if forbidden[strings.ToLower(k)] {
					t.Fatalf("forbidden key %q found at %s.%s", k, path, k)
				}
				walk(child, path+"."+k)
			}
		case []any:
			for i, child := range x {
				walk(child, fmt.Sprintf("%s[%d]", path, i))
			}
		}
	}
	walk(top, "snapshot")

	expectedNodeKeys := []string{
		"id", "name", "region_tag", "sort_order", "status", "paused_reason",
		"billing_reset_day", "cpu_percent", "mem_used_bytes", "mem_total_bytes",
		"uptime_seconds", "rx_bps", "tx_bps", "total_rx_bytes", "total_tx_bytes",
		"traffic_used_bytes", "traffic_limit_bytes", "traffic_percent", "percentage_only",
		"core_a_healthy", "core_b_healthy",
	}
	nodes, _ := top["nodes"].([]any)
	for i, item := range nodes {
		obj, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("nodes[%d] not object: %T", i, item)
		}
		if len(obj) != len(expectedNodeKeys) {
			t.Fatalf("nodes[%d] expected %d keys, got %d: %v", i, len(expectedNodeKeys), len(obj), obj)
		}
		for _, k := range expectedNodeKeys {
			if _, ok := obj[k]; !ok {
				t.Fatalf("nodes[%d] missing key %q", i, k)
			}
		}
	}
}

func TestBuildPublicSnapshot_RedactionAndModes(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	ctx := context.Background()

	_ = st.SetSetting(ctx, "site_title", "My Snell Status")
	_ = st.SetSetting(ctx, "announcement", "Maintenance tonight")

	// Disabled node must be excluded.
	_, _ = createTestNode(t, st, "hidden-disabled", false)

	// Create 4 enabled nodes with different traffic_count_mode values.
	modes := []struct {
		name      string
		mode      string
		limit     int64
		threshold int64
		rx        int64
		tx        int64
		wantUsed  int64
		wantPct   float64
	}{
		{"mode-both", protocol.TrafficCountBoth, 1000, 800, 300, 200, 500, 50},
		{"mode-tx", protocol.TrafficCountTxOnly, 1000, 800, 300, 200, 200, 20},
		{"mode-rx", protocol.TrafficCountRxOnly, 1000, 800, 300, 200, 300, 30},
		{"mode-max-thresh", protocol.TrafficCountMaxDir, 0, 800, 300, 600, 600, 75},
	}

	for _, m := range modes {
		n, _ := createTestNode(t, st, m.name, true)
		dbN, err := st.GetNodeByID(ctx, n.ID)
		if err != nil {
			t.Fatal(err)
		}
		dbN.TrafficCountMode = m.mode
		dbN.TrafficLimitBytes = m.limit
		dbN.TrafficThresholdBytes = m.threshold
		dbN.CustomEntryHost = "secret.entry.internal"
		dbN.DNSUnlockServer = "10.9.9.9:53"
		if err := st.UpdateNode(ctx, dbN); err != nil {
			t.Fatal(err)
		}
		if err := st.CalibrateNodeTraffic(ctx, n.ID, m.rx, m.tx); err != nil {
			t.Fatal(err)
		}
		// Seed DB telemetry on offline node to verify offline zeroes live gauges.
		_ = st.UpdateNodeTelemetry(ctx, n.ID, store.NodeTelemetryUpdate{
			CPUPercent:    88.8,
			MemUsedBytes:  1024,
			MemTotalBytes: 4096,
			UptimeSeconds: 500,
			RxBPS:         999,
			TxBPS:         888,
			CoreAHealthy:  true,
			CoreBHealthy:  true,
			LastSeenAt:    time.Now().UTC(),
		})
		_ = st.SetNodeConnectionStatus(ctx, n.ID, false, time.Time{})
	}

	snap, err := h.BuildPublicSnapshot(ctx)
	if err != nil {
		t.Fatalf("BuildPublicSnapshot: %v", err)
	}
	if snap.SiteTitle != "My Snell Status" || snap.Announcement != "Maintenance tonight" || snap.PercentageOnly {
		t.Fatalf("unexpected snapshot header: %+v", snap)
	}
	if len(snap.Nodes) != len(modes) {
		t.Fatalf("expected %d enabled nodes, got %d", len(modes), len(snap.Nodes))
	}

	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	assertRedactedSnapshotJSON(t, raw)
	for _, secret := range []string{"secret.entry.internal", "10.9.9.9:53", "203.0.113.1"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("secret %q leaked in public snapshot: %s", secret, string(raw))
		}
	}

	for i, m := range modes {
		v := snap.Nodes[i]
		if v.Status != protocol.NodeStatusOffline {
			t.Fatalf("node %s expected offline, got %q", m.name, v.Status)
		}
		if v.CoreAHealthy || v.CoreBHealthy || v.CPUPercent != 0 || v.RxBPS != 0 {
			t.Fatalf("offline node %s did not zero live gauges: %+v", m.name, v)
		}
		if v.TrafficUsedBytes != m.wantUsed || v.TrafficPercent != m.wantPct {
			t.Fatalf("node %s (%s): want used=%d pct=%.2f, got used=%d pct=%.2f",
				m.name, m.mode, m.wantUsed, m.wantPct, v.TrafficUsedBytes, v.TrafficPercent)
		}
	}

	// Enable public_percentage_only -> zeroes TrafficUsedBytes and TrafficLimitBytes while preserving TrafficPercent.
	if err := st.SetSetting(ctx, "public_percentage_only", "true"); err != nil {
		t.Fatal(err)
	}
	pctSnap, err := h.BuildPublicSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !pctSnap.PercentageOnly {
		t.Fatalf("expected PercentageOnly=true")
	}
	for _, v := range pctSnap.Nodes {
		if !v.PercentageOnly || v.TrafficUsedBytes != 0 || v.TrafficLimitBytes != 0 || v.TotalRxBytes != 0 || v.TotalTxBytes != 0 || v.TrafficPercent == 0 {
			t.Fatalf("unexpected percentage-only node view: %+v", v)
		}
	}
}

func TestServePublicWS_InitialAndSlowClientNonBlocking(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(15*time.Millisecond), hub.WithWriteTimeout(200*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	node, tok := createTestNode(t, st, "public-ws-node", true)
	wsPublicURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/public/ws"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connect slow client (never reads after handshake, overflowing publicSendQueueCap).
	slowConn, _, err := websocket.Dial(ctx, wsPublicURL, nil)
	if err != nil {
		t.Fatalf("dial slow public ws: %v", err)
	}
	defer slowConn.CloseNow()

	// Connect healthy fast client.
	fastConn, _, err := websocket.Dial(ctx, wsPublicURL, nil)
	if err != nil {
		t.Fatalf("dial fast public ws: %v", err)
	}
	defer fastConn.CloseNow()

	// Fast client receives initial snapshot immediately.
	_, initRaw, err := fastConn.Read(ctx)
	if err != nil {
		t.Fatalf("read initial public ws frame: %v", err)
	}
	assertRedactedSnapshotJSON(t, initRaw)
	var initSnap protocol.PublicStatusSnapshot
	if err := json.Unmarshal(initRaw, &initSnap); err != nil || len(initSnap.Nodes) != 1 || initSnap.Nodes[0].Status != protocol.NodeStatusOffline {
		t.Fatalf("unexpected initial public ws snapshot: %+v err=%v", initSnap, err)
	}

	// Connect agent and send multiple metrics bursts to trigger > publicSendQueueCap broadcasts.
	agentConn, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.CloseNow()
	_ = readEnvelope(t, agentConn, 3*time.Second)

	for i := 1; i <= 8; i++ {
		if err := sendAgentEnvelope(ctx, agentConn, protocol.MsgTypeAgentMetrics, fmt.Sprintf("m-%d", i), protocol.AgentMetrics{
			TS:         time.Now().Unix(),
			CPUPercent: float64(i * 10),
			RxBPS:      uint64(i * 1000),
			Health:     protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
		}); err != nil {
			t.Fatal(err)
		}
		time.Sleep(25 * time.Millisecond)
	}

	// Fast client must observe live online status and latest CPU without being blocked by slowConn.
	deadline := time.Now().Add(4 * time.Second)
	gotLatest := false
	for time.Now().Before(deadline) {
		rctx, rcancel := context.WithTimeout(ctx, 500*time.Millisecond)
		_, frame, readErr := fastConn.Read(rctx)
		rcancel()
		if readErr != nil {
			continue
		}
		assertRedactedSnapshotJSON(t, frame)
		var snap protocol.PublicStatusSnapshot
		if err := json.Unmarshal(frame, &snap); err == nil && len(snap.Nodes) == 1 {
			n := snap.Nodes[0]
			if n.ID == node.ID && n.Status == protocol.NodeStatusOnline && n.CoreAHealthy && n.CoreBHealthy && n.CPUPercent == 80 {
				gotLatest = true
				break
			}
		}
	}
	if !gotLatest {
		t.Fatalf("fast public WS client did not receive latest online snapshot while slow client existed")
	}

	// Closed hub rejects new public WS clients with 503 and cleanly closes existing ones.
	if err := h.Close(); err != nil {
		t.Fatalf("close hub: %v", err)
	}
	if _, resp, err := websocket.Dial(ctx, wsPublicURL, nil); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 on public WS after hub closed, got resp=%v err=%v", resp, err)
	}
}

func TestTier5_PublicSnapshot_BugB3_RedactsPausedReasonAndBroadcasts(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	node, _ := createTestNode(t, st, "Paused-Node", true)
	node.TrafficLimitBytes = 20000000
	node.TrafficThresholdBytes = 10000000
	node.TrafficCountMode = "both"
	if err := st.UpdateNode(ctx, node); err != nil {
		t.Fatal(err)
	}
	if err := st.CalibrateNodeTraffic(ctx, node.ID, 6000000, 6000000); err != nil {
		t.Fatal(err)
	}
	detailedReason := "traffic threshold reached: 12000000/10000000 (mode=both)"
	if err := st.SetNodeTrafficPaused(ctx, node.ID, true, detailedReason); err != nil {
		t.Fatal(err)
	}
	if err := st.SetSetting(ctx, "public_percentage_only", "true"); err != nil {
		t.Fatal(err)
	}

	h := hub.NewHub(st, nil, hub.WithPublicDebounce(15*time.Millisecond))
	defer h.Close()

	snap, err := h.BuildPublicSnapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(snap.Nodes))
	}
	got := snap.Nodes[0]
	if !snap.PercentageOnly || !got.PercentageOnly {
		t.Fatalf("expected percentage_only=true")
	}
	if got.TrafficUsedBytes != 0 || got.TrafficLimitBytes != 0 {
		t.Fatalf("expected zeroed byte fields in percentage_only mode, got used=%d limit=%d", got.TrafficUsedBytes, got.TrafficLimitBytes)
	}
	if got.PausedReason != "traffic threshold reached" {
		t.Fatalf("expected redacted paused_reason, got %q", got.PausedReason)
	}
	for _, secret := range []string{"12000000", "10000000", "mode=both"} {
		if strings.Contains(got.PausedReason, secret) {
			t.Fatalf("paused_reason leaked %q: %q", secret, got.PausedReason)
		}
	}

	// Verify BroadcastPublicStatus() pushes updated unredacted snapshot when setting flips to false.
	srv := newTestServer(t, h)
	wsPublicURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/public/ws"
	wctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(wctx, wsPublicURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	_, initRaw, err := conn.Read(wctx)
	if err != nil {
		t.Fatal(err)
	}
	assertRedactedSnapshotJSON(t, initRaw)
	if strings.Contains(string(initRaw), "12000000") || strings.Contains(string(initRaw), "mode=both") {
		t.Fatalf("initial public WS frame leaked paused_reason details: %s", string(initRaw))
	}

	if err := st.SetSetting(ctx, "public_percentage_only", "false"); err != nil {
		t.Fatal(err)
	}
	h.BroadcastPublicStatus()

	rctx, rcancel := context.WithTimeout(wctx, 2*time.Second)
	_, updatedRaw, err := conn.Read(rctx)
	rcancel()
	if err != nil {
		t.Fatalf("expected BroadcastPublicStatus frame: %v", err)
	}
	var updated protocol.PublicStatusSnapshot
	if err := json.Unmarshal(updatedRaw, &updated); err != nil {
		t.Fatal(err)
	}
	if updated.PercentageOnly || len(updated.Nodes) != 1 || updated.Nodes[0].PausedReason != detailedReason {
		t.Fatalf("expected full paused_reason when percentage_only=false, got %+v", updated)
	}
}

func TestTier5_PublicWS_BroadcastWithoutBlockingOnSlowPeer(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	_, _ = createTestNode(t, st, "Peer-Node", true)

	h := hub.NewHub(st, nil,
		hub.WithPublicDebounce(10*time.Millisecond),
		hub.WithWriteTimeout(50*time.Millisecond),
	)
	defer h.Close()

	srv := newTestServer(t, h)
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/public/ws"

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	slowConn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer slowConn.CloseNow()

	fastConn, _, err := websocket.Dial(dialCtx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer fastConn.CloseNow()

	// Drain initial frame on fastConn only; never read from slowConn.
	if _, _, err := fastConn.Read(dialCtx); err != nil {
		t.Fatal(err)
	}

	// Trigger >20 broadcasts rapidly to overflow slowConn sendCh and test non-blocking broadcast.
	for i := 0; i < 25; i++ {
		if err := st.SetSetting(ctx, "announcement", fmt.Sprintf("msg-%d", i)); err != nil {
			t.Fatal(err)
		}
		h.BroadcastPublicStatus()
		time.Sleep(15 * time.Millisecond)
	}

	deadline := time.Now().Add(3 * time.Second)
	gotFinal := false
	for time.Now().Before(deadline) {
		rctx, rcancel := context.WithTimeout(dialCtx, 500*time.Millisecond)
		_, frame, rerr := fastConn.Read(rctx)
		rcancel()
		if rerr != nil {
			continue
		}
		var snap protocol.PublicStatusSnapshot
		if err := json.Unmarshal(frame, &snap); err == nil && snap.Announcement == "msg-24" {
			gotFinal = true
			break
		}
	}
	if !gotFinal {
		t.Fatal("fast client failed to receive final BroadcastPublicStatus while slow client existed")
	}
}

func TestTier5_BugB4_EvictNodePurgesStateAndBroadcasts(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	node, tok := createTestNode(t, st, "Evictable-Node", true)

	h := hub.NewHub(st, nil, hub.WithPublicDebounce(15*time.Millisecond))
	defer h.Close()
	srv := newTestServer(t, h)

	agentURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/agent/ws"
	pubURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/public/ws"

	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	agentConn, _, err := websocket.Dial(dialCtx, agentURL, &websocket.DialOptions{
		HTTPHeader: http.Header{"Authorization": []string{"Bearer " + tok}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.CloseNow()

	// Consume initial config sync so handshake completes cleanly.
	if _, _, err := agentConn.Read(dialCtx); err != nil {
		t.Fatal(err)
	}

	// Send metrics + kernel update status to populate in-memory telemetry & kernelUpdates caches.
	if err := sendAgentEnvelope(dialCtx, agentConn, protocol.MsgTypeAgentMetrics, "m1", protocol.AgentMetrics{
		TS:         time.Now().Unix(),
		CPUPercent: 42.5,
		Health:     protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	if err := sendAgentEnvelope(dialCtx, agentConn, protocol.MsgTypeAgentEvent, "k1", protocol.AgentEvent{
		Event:   protocol.EventKernelUpdateResult,
		Kernel:  protocol.KernelSnellServer,
		Status:  protocol.EventStatusSuccess,
		Version: "v5.0.1",
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if _, ok := h.GetTelemetry(node.ID); ok {
			if _, ok2 := h.GetKernelUpdateStatus(node.ID); ok2 {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, ok := h.GetTelemetry(node.ID); !ok {
		t.Fatal("expected telemetry populated before eviction")
	}

	pubConn, _, err := websocket.Dial(dialCtx, pubURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pubConn.CloseNow()
	if _, _, err := pubConn.Read(dialCtx); err != nil {
		t.Fatal(err)
	}

	agentClosed := make(chan error, 1)
	go func() {
		for {
			if _, _, rerr := agentConn.Read(dialCtx); rerr != nil {
				agentClosed <- rerr
				return
			}
		}
	}()

	// EvictNode must clear session, telemetry, kernelUpdates, close WS, and broadcast public offline state.
	h.EvictNode(node.ID)

	if h.IsOnline(node.ID) {
		t.Fatal("expected IsOnline false immediately after EvictNode")
	}
	if _, ok := h.GetTelemetry(node.ID); ok {
		t.Fatal("expected telemetry purged after EvictNode")
	}
	if _, ok := h.GetKernelUpdateStatus(node.ID); ok {
		t.Fatal("expected kernel update status purged after EvictNode")
	}
	select {
	case <-agentClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for evicted agent WS connection to close")
	}

	// Public WS should observe node transition to offline.
	pubDeadline := time.Now().Add(2 * time.Second)
	sawOffline := false
	for time.Now().Before(pubDeadline) {
		rctx, rcancel := context.WithTimeout(dialCtx, 400*time.Millisecond)
		_, frame, rerr := pubConn.Read(rctx)
		rcancel()
		if rerr != nil {
			continue
		}
		var snap protocol.PublicStatusSnapshot
		if err := json.Unmarshal(frame, &snap); err == nil && len(snap.Nodes) == 1 && snap.Nodes[0].Status == protocol.NodeStatusOffline {
			sawOffline = true
			break
		}
	}
	if !sawOffline {
		t.Fatal("expected public WS to broadcast offline status after EvictNode")
	}
}

func TestServePublicWS_CachedPayloadInvalidatesOnStateTransitions(t *testing.T) {
	st := openTestStore(t)
	// Use a noticeable debounce window to verify immediate cache invalidation even before debounce fires.
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(200*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	node, tok := createTestNode(t, st, "cache-node", true)

	// 1. Two initial public WS dials share identical cached initial snapshot.
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/public/ws"
	p1, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p1.CloseNow()
	_, frame1, err := p1.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}

	p2, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p2.CloseNow()
	_, frame2, err := p2.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if string(frame1) != string(frame2) {
		t.Fatalf("expected identical cached initial snapshot, got:\n%s\nvs\n%s", frame1, frame2)
	}

	// 2. Store mutation + BroadcastPublicStatus immediately invalidates cache for a newly dialed WS
	//    even before publicDebounce expires.
	if err := st.SetSetting(ctx, "site_title", "Updated Cache Title"); err != nil {
		t.Fatal(err)
	}
	h.BroadcastPublicStatus()

	p3, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer p3.CloseNow()
	_, frame3, err := p3.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var snap3 protocol.PublicStatusSnapshot
	if err := json.Unmarshal(frame3, &snap3); err != nil {
		t.Fatal(err)
	}
	if snap3.SiteTitle != "Updated Cache Title" {
		t.Fatalf("expected immediate cache invalidation on BroadcastPublicStatus, got title=%q", snap3.SiteTitle)
	}

	// 3. Agent metrics update invalidates cached payload and updates node status/traffic.
	agentConn, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer agentConn.CloseNow()
	_ = readEnvelope(t, agentConn, 3*time.Second)

	if err := sendAgentEnvelope(ctx, agentConn, protocol.MsgTypeAgentMetrics, "m1", protocol.AgentMetrics{
		TS:         time.Now().Unix(),
		NicRxDelta: 1234,
		NicTxDelta: 5678,
		Health:     protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	// Wait until GetPublicSnapshotJSON reflects online + updated traffic.
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, err := h.GetPublicSnapshotJSON(ctx)
		if err == nil {
			var s protocol.PublicStatusSnapshot
			if json.Unmarshal(raw, &s) == nil && len(s.Nodes) == 1 &&
				s.Nodes[0].Status == protocol.NodeStatusOnline && s.Nodes[0].TrafficUsedBytes == 1234+5678 {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("public snapshot cache did not reflect agent.metrics transition")
		}
		time.Sleep(15 * time.Millisecond)
	}

	// 4. EvictNode immediately invalidates cached payload back to offline.
	h.EvictNode(node.ID)
	rawAfterEvict, err := h.GetPublicSnapshotJSON(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var snapAfterEvict protocol.PublicStatusSnapshot
	if err := json.Unmarshal(rawAfterEvict, &snapAfterEvict); err != nil {
		t.Fatal(err)
	}
	if len(snapAfterEvict.Nodes) != 1 || snapAfterEvict.Nodes[0].Status != protocol.NodeStatusOffline {
		t.Fatalf("expected EvictNode to invalidate cache to offline, got %+v", snapAfterEvict.Nodes)
	}
}
