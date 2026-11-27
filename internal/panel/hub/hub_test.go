package hub_test

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t.UTC()}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

type mockNotifier struct {
	mu     sync.Mutex
	events []webhook.AlertEvent
	ch     chan webhook.AlertEvent
}

func newMockNotifier() *mockNotifier {
	return &mockNotifier{
		ch: make(chan webhook.AlertEvent, 64),
	}
}

func (m *mockNotifier) Notify(_ context.Context, evt webhook.AlertEvent) {
	m.mu.Lock()
	m.events = append(m.events, evt)
	m.mu.Unlock()
	select {
	case m.ch <- evt:
	default:
	}
}

func (m *mockNotifier) Events() []webhook.AlertEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]webhook.AlertEvent, len(m.events))
	copy(out, m.events)
	return out
}

func (m *mockNotifier) WaitEvent(t *testing.T, timeout time.Duration) webhook.AlertEvent {
	t.Helper()
	select {
	case evt := <-m.ch:
		return evt
	case <-time.After(timeout):
		t.Fatalf("timed out waiting for webhook alert event")
		return webhook.AlertEvent{}
	}
}

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "hub_test.db")
	st, err := store.Open(ctx, dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SeedDefaults(ctx, store.SeedConfig{}); err != nil {
		t.Fatalf("seed defaults: %v", err)
	}
	return st
}

func createTestNode(t *testing.T, st *store.Store, name string, enabled bool) (*store.Node, string) {
	t.Helper()
	rawTok, tokHash, err := auth.GenerateNodeTokenPair()
	if err != nil {
		t.Fatalf("generate node token: %v", err)
	}
	ipsk, err := auth.GenerateIPSKForCipher(protocol.CipherAES128GCM)
	if err != nil {
		t.Fatalf("generate ipsk: %v", err)
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		t.Fatalf("generate stls password: %v", err)
	}
	snellPSK, err := auth.GenerateSnellPSK()
	if err != nil {
		t.Fatalf("generate snell psk: %v", err)
	}
	n := &store.Node{
		Name:                  name,
		RegionTag:             "US",
		TokenHash:             tokHash,
		PublicIP:              "203.0.113.1",
		Enabled:               enabled,
		Status:                protocol.NodeStatusOffline,
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 8500,
		TrafficCountMode:      protocol.TrafficCountBoth,
		ThresholdAction:       protocol.ThresholdActionStopAll,
		BillingResetDay:       1,
		SnellConfig: protocol.SnellConfig{
			Enabled:         true,
			Version:         protocol.SnellVersionV5,
			PublicPort:      443,
			InnerPort:       1443,
			PSK:             snellPSK,
			Obfs:            protocol.SnellObfsOff,
			TFO:             true,
			DNSIPPreference: protocol.DNSIPPrefPreferIPv4,
			STLSPassword:    stlsPwd,
			STLSSNI:         "apple.com",
		},
		SSConfig: protocol.SSConfig{
			Enabled: true,
			TCPPort: 8443,
			UDPPort: 8443,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    ipsk,
			STLSSNI: "icloud.com",
		},
	}
	if err := st.CreateNode(context.Background(), n); err != nil {
		t.Fatalf("create node: %v", err)
	}
	return n, rawTok
}

func createTestUser(t *testing.T, st *store.Store, username string, enabled bool) *store.User {
	t.Helper()
	subTok, err := auth.GenerateSubToken()
	if err != nil {
		t.Fatalf("generate sub token: %v", err)
	}
	upsk16, err := auth.GenerateUPSK16()
	if err != nil {
		t.Fatalf("generate upsk16: %v", err)
	}
	upsk32, err := auth.GenerateUPSK32()
	if err != nil {
		t.Fatalf("generate upsk32: %v", err)
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		t.Fatalf("generate stls pwd: %v", err)
	}
	u := &store.User{
		Username:     username,
		Enabled:      enabled,
		SubToken:     subTok,
		SSUPSK16:     upsk16,
		SSUPSK32:     upsk32,
		STLSPassword: stlsPwd,
	}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func newTestServer(t *testing.T, h *hub.Hub) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", h.ServeAgentWS)
	mux.HandleFunc("/api/v1/public/ws", h.ServePublicWS)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func dialAgentWS(ctx context.Context, baseURL, token string) (*websocket.Conn, *http.Response, error) {
	wsURL := "ws" + strings.TrimPrefix(baseURL, "http") + "/api/v1/agent/ws"
	hdr := make(http.Header)
	if token != "" {
		hdr.Set("Authorization", "Bearer "+token)
	}
	return websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: hdr})
}

func sendAgentEnvelope(ctx context.Context, conn *websocket.Conn, msgType, reqID string, payload any) error {
	b, err := protocol.MarshalEnvelope(msgType, reqID, payload)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, b)
}

func readEnvelope(t *testing.T, conn *websocket.Conn, timeout time.Duration) protocol.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read ws frame: %v", err)
	}
	env, err := protocol.ParseEnvelope(data)
	if err != nil {
		t.Fatalf("parse envelope: %v (raw=%s)", err, string(data))
	}
	return env
}

func TestAgentWS_AuthAndDisabledNode(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	_, tokEnabled := createTestNode(t, st, "enabled-node", true)
	_, tokDisabled := createTestNode(t, st, "disabled-node", false)

	// Uppercase hex hash node for legacy hash tolerance test.
	rawUpper, hashLower, err := auth.GenerateNodeTokenPair()
	if err != nil {
		t.Fatal(err)
	}
	upperNode := &store.Node{
		Name:      "upper-hash-node",
		TokenHash: strings.ToUpper(hashLower),
		Enabled:   true,
	}
	if err := st.CreateNode(context.Background(), upperNode); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Missing Authorization header -> 401
	if _, resp, err := dialAgentWS(ctx, srv.URL, ""); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for missing token, got resp=%v err=%v", resp, err)
	}

	// Wrong token -> 401
	if _, resp, err := dialAgentWS(ctx, srv.URL, "nd_live_wrong_token"); err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 for wrong token, got resp=%v err=%v", resp, err)
	}

	// Disabled node -> 403
	if _, resp, err := dialAgentWS(ctx, srv.URL, tokDisabled); err == nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for disabled node, got resp=%v err=%v", resp, err)
	}

	// Enabled node -> connects & receives initial config_sync
	c1, _, err := dialAgentWS(ctx, srv.URL, tokEnabled)
	if err != nil {
		t.Fatalf("dial enabled node: %v", err)
	}
	env := readEnvelope(t, c1, 3*time.Second)
	if env.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected initial server.config_sync, got %q", env.Type)
	}
	_ = c1.CloseNow()

	// Legacy uppercase hex token hash fallback -> connects cleanly
	c2, _, err := dialAgentWS(ctx, srv.URL, rawUpper)
	if err != nil {
		t.Fatalf("dial uppercase-hash node: %v", err)
	}
	_ = readEnvelope(t, c2, 3*time.Second)
	_ = c2.CloseNow()

	// Closed hub -> 503
	if err := h.Close(); err != nil {
		t.Fatalf("close hub: %v", err)
	}
	if _, resp, err := dialAgentWS(ctx, srv.URL, tokEnabled); err == nil || resp == nil || resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 after hub closed, got resp=%v err=%v", resp, err)
	}
}

func TestAgentWS_SessionReplacementZeroFalseOffline(t *testing.T) {
	st := openTestStore(t)
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	node, tok := createTestNode(t, st, "reconnect-node", true)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c1, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatalf("dial c1: %v", err)
	}
	defer c1.CloseNow()
	_ = readEnvelope(t, c1, 3*time.Second)

	// Reconnect while c1 is still open.
	c2, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatalf("dial c2: %v", err)
	}
	defer c2.CloseNow()
	_ = readEnvelope(t, c2, 3*time.Second)

	// c1 should be closed by hub replacement.
	rctx, rcancel := context.WithTimeout(ctx, 2*time.Second)
	defer rcancel()
	if _, _, err := c1.Read(rctx); err == nil {
		t.Fatalf("expected superseded c1 to be closed")
	}

	// Allow any async cleanup of c1 to finish, then assert node remains online in memory & DB.
	time.Sleep(50 * time.Millisecond)

	if !h.IsOnline(node.ID) {
		t.Fatalf("expected node %d to stay online after session replacement", node.ID)
	}
	ids := h.OnlineNodeIDs()
	if len(ids) != 1 || ids[0] != node.ID {
		t.Fatalf("expected OnlineNodeIDs [%d], got %v", node.ID, ids)
	}

	dbNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbNode.Status != protocol.NodeStatusOnline {
		t.Fatalf("expected DB status online (no offline flicker), got %q", dbNode.Status)
	}

	if evts := notifier.Events(); len(evts) != 0 {
		t.Fatalf("expected zero webhook alerts during reconnect replacement, got %+v", evts)
	}
}

func TestAgentWS_HelloUpdatesRecoveryAndNoDuplicateSync(t *testing.T) {
	st := openTestStore(t)
	notifier := newMockNotifier()
	clk := newFakeClock(time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC))
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now), hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	// 1. Fresh onboarding node (LastSeenAt == nil): should NOT emit node_online or duplicate config_sync.
	node1, tok1 := createTestNode(t, st, "fresh-node", true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c1, _, err := dialAgentWS(ctx, srv.URL, tok1)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.CloseNow()

	initSync := readEnvelope(t, c1, 3*time.Second)
	if initSync.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected initial server.config_sync, got %q", initSync.Type)
	}

	if err := sendAgentEnvelope(ctx, c1, protocol.MsgTypeAgentHello, "h1", protocol.AgentHello{
		OS:             "linux",
		Arch:           "amd64",
		CPUCores:       4,
		TotalRAMBytes:  8 << 30,
		PublicIPv4:     "", // Empty IP must preserve existing "203.0.113.1"
		PublicIPv6:     "2001:db8::1",
		Versions:       protocol.AgentVersions{SingBox: "1.11.4", SnellServer: "5.0.0", ShadowTLS: "0.2.25"},
		ConfigRevision: 0,
	}); err != nil {
		t.Fatal(err)
	}

	// Send service_ctl immediately after hello; next frame must be service_ctl (proving no duplicate config_sync).
	// Wait briefly for hello processing to complete on server side.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tel, ok := h.GetTelemetry(node1.ID)
		if ok && tel.OS == "linux" && tel.PublicIPv6 == "2001:db8::1" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := h.SendServiceCtl(ctx, node1.ID, protocol.ServerServiceCtl{Action: protocol.ServiceActionRestartSingBox}); err != nil {
		t.Fatalf("SendServiceCtl: %v", err)
	}
	nextFrame := readEnvelope(t, c1, 3*time.Second)
	if nextFrame.Type != protocol.MsgTypeServerServiceCtl {
		t.Fatalf("expected server.service_ctl (no duplicate config_sync), got %q", nextFrame.Type)
	}

	dbNode1, err := st.GetNodeByID(ctx, node1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbNode1.PublicIP != "203.0.113.1" || dbNode1.PublicIPv6 != "2001:db8::1" {
		t.Fatalf("unexpected IPs: ipv4=%q ipv6=%q", dbNode1.PublicIP, dbNode1.PublicIPv6)
	}
	if dbNode1.ReportedVersions.SingBox != "1.11.4" || dbNode1.AgentOS != "linux" || dbNode1.CPUCores != 4 {
		t.Fatalf("versions/host info not persisted: %+v", dbNode1)
	}
	if evts := notifier.Events(); len(evts) != 0 {
		t.Fatalf("expected zero node_online alert on first-ever onboarding, got %+v", evts)
	}

	// 2. Previously offline node (status=offline, LastSeenAt!=nil) recovering -> emits node_online (Resolved: true).
	node2, tok2 := createTestNode(t, st, "recovering-node", true)
	past := clk.Now().Add(-10 * time.Minute)
	if err := st.SetNodeConnectionStatus(ctx, node2.ID, true, past); err != nil {
		t.Fatal(err)
	}
	if err := st.SetNodeConnectionStatus(ctx, node2.ID, false, time.Time{}); err != nil {
		t.Fatal(err)
	}

	c2, _, err := dialAgentWS(ctx, srv.URL, tok2)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.CloseNow()
	_ = readEnvelope(t, c2, 3*time.Second) // drain initial config_sync

	// Bump revision between connect and hello to verify hello pushes new config_sync when revision changed.
	newRev, err := st.IncrementNodeConfigRevision(ctx, node2.ID)
	if err != nil {
		t.Fatal(err)
	}

	if err := sendAgentEnvelope(ctx, c2, protocol.MsgTypeAgentHello, "h2", protocol.AgentHello{
		OS:             "linux",
		Arch:           "arm64",
		CPUCores:       2,
		PublicIPv4:     "198.51.100.2",
		ConfigRevision: 1,
	}); err != nil {
		t.Fatal(err)
	}

	evt := notifier.WaitEvent(t, 3*time.Second)
	if evt.Type != webhook.EventNodeOnline || !evt.Resolved || evt.Severity != webhook.SeverityInfo || evt.TargetID != node2.ID {
		t.Fatalf("unexpected node_online alert: %+v", evt)
	}

	updatedSync := readEnvelope(t, c2, 3*time.Second)
	if updatedSync.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected updated server.config_sync after revision bump, got %q", updatedSync.Type)
	}
	var syncPayload protocol.ServerConfigSync
	if err := updatedSync.DecodePayload(&syncPayload); err != nil {
		t.Fatal(err)
	}
	if syncPayload.ConfigRevision != newRev {
		t.Fatalf("expected config_revision %d, got %d", newRev, syncPayload.ConfigRevision)
	}
}

func TestAgentWS_MalformedAndUnknownFramesTolerated(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	node, tok := createTestNode(t, st, "resilient-node", true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	_ = readEnvelope(t, c, 3*time.Second)

	// Send malformed JSON, missing type, invalid hello payload, and unknown message type.
	if err := c.Write(ctx, websocket.MessageText, []byte("{bad json")); err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"type":"","req_id":"r1","payload":{}}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"type":"agent.hello","req_id":"r2","payload":null}`)); err != nil {
		t.Fatal(err)
	}
	if err := sendAgentEnvelope(ctx, c, "agent.future_v99", "r3", map[string]string{"foo": "bar"}); err != nil {
		t.Fatal(err)
	}

	// Same session must stay open and process subsequent agent.metrics.
	if err := sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentMetrics, "m1", protocol.AgentMetrics{
		TS:         time.Now().Unix(),
		CPUPercent: 47.5,
		RxBPS:      1234,
		TxBPS:      5678,
		Health:     protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if tel, ok := h.GetTelemetry(node.ID); ok && tel.CPUPercent == 47.5 && tel.RxBPS == 1234 {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("metrics not processed on same session after malformed/unknown frames")
}

func TestAgentWS_MetricsDeltasCallbackAndTelemetry(t *testing.T) {
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 23, 14, 30, 0, 0, time.UTC))
	h := hub.NewHub(st, nil, hub.WithNow(clk.Now), hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })

	node, tok := createTestNode(t, st, "metrics-node", true)
	u1 := createTestUser(t, st, "alice", true)
	u2 := createTestUser(t, st, "bob", true)
	if err := st.SetUserNodes(context.Background(), u1.ID, []int64{node.ID}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetUserNodes(context.Background(), u2.ID, []int64{node.ID}); err != nil {
		t.Fatal(err)
	}

	type cbRecord struct {
		nodeID  int64
		userIDs []int64
	}
	cbCh := make(chan cbRecord, 4)
	h.SetOnTrafficUpdated(func(ctx context.Context, updatedNode *store.Node, updatedUserIDs []int64) {
		// Verify calling SyncNode inside OnTrafficUpdated does not deadlock.
		_ = h.SyncNode(ctx, updatedNode.ID)
		cbCh <- cbRecord{nodeID: updatedNode.ID, userIDs: updatedUserIDs}
	})

	srv := newTestServer(t, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	_ = readEnvelope(t, c, 3*time.Second) // initial config_sync

	if err := sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentMetrics, "m1", protocol.AgentMetrics{
		TS:              clk.Now().Unix(),
		CPUPercent:      33.3,
		MemUsedBytes:    512 << 20,
		MemTotalBytes:   2048 << 20,
		DiskUsedPercent: 45.0,
		UptimeSeconds:   7200,
		RxBPS:           10000,
		TxBPS:           20000,
		NicRxDelta:      1024,
		NicTxDelta:      2048,
		UserDeltas: []protocol.UserTrafficDelta{
			{UserID: u1.ID, Username: u1.Username, UpBytes: 100, DownBytes: 200},
			{UserID: u1.ID, Username: u1.Username, UpBytes: 50, DownBytes: 75}, // duplicate user ID from WAL flush
			{UserID: u2.ID, Username: u2.Username, UpBytes: 300, DownBytes: 400},
		},
		Health: protocol.AgentHealth{Snell: true, ShadowTLS: false, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case rec := <-cbCh:
		if rec.nodeID != node.ID {
			t.Fatalf("expected callback node %d, got %d", node.ID, rec.nodeID)
		}
		if len(rec.userIDs) != 2 || rec.userIDs[0] != u1.ID || rec.userIDs[1] != u2.ID {
			t.Fatalf("expected deduplicated userIDs [%d %d], got %v", u1.ID, u2.ID, rec.userIDs)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for OnTrafficUpdated callback")
	}

	// Callback triggered SyncNode -> agent should receive server.config_sync.
	syncEnv := readEnvelope(t, c, 3*time.Second)
	if syncEnv.Type != protocol.MsgTypeServerConfigSync {
		t.Fatalf("expected server.config_sync from callback SyncNode, got %q", syncEnv.Type)
	}

	dbNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbNode.CycleRxBytes != 1024 || dbNode.CycleTxBytes != 2048 {
		t.Fatalf("expected node cycle rx=1024 tx=2048, got rx=%d tx=%d", dbNode.CycleRxBytes, dbNode.CycleTxBytes)
	}
	if dbNode.CoreAHealthy || !dbNode.CoreBHealthy {
		t.Fatalf("expected CoreAHealthy=false (shadow_tls=false) and CoreBHealthy=true, got A=%v B=%v", dbNode.CoreAHealthy, dbNode.CoreBHealthy)
	}

	dbU1, err := st.GetUserByID(ctx, u1.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbU1.UsedUpBytes != 150 || dbU1.UsedDownBytes != 275 {
		t.Fatalf("expected u1 up=150 down=275, got up=%d down=%d", dbU1.UsedUpBytes, dbU1.UsedDownBytes)
	}

	// Verify uint64 > math.MaxInt64 clamping doesn't overflow/fail on a clean node.
	nodeMax, tokMax := createTestNode(t, st, "maxint-node", true)
	cMax, _, err := dialAgentWS(ctx, srv.URL, tokMax)
	if err != nil {
		t.Fatal(err)
	}
	defer cMax.CloseNow()
	_ = readEnvelope(t, cMax, 3*time.Second)
	if err := sendAgentEnvelope(ctx, cMax, protocol.MsgTypeAgentMetrics, "m-max", protocol.AgentMetrics{
		TS:         clk.Now().Unix(),
		NicRxDelta: math.MaxUint64,
		NicTxDelta: 5,
		Health:     protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
	}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		nMax, err := st.GetNodeByID(ctx, nodeMax.ID)
		if err == nil && nMax.CycleRxBytes == math.MaxInt64 && nMax.CycleTxBytes == 5 {
			break
		}
		time.Sleep(15 * time.Millisecond)
	}
	nMax, err := st.GetNodeByID(ctx, nodeMax.ID)
	if err != nil || nMax.CycleRxBytes != math.MaxInt64 || nMax.CycleTxBytes != 5 {
		t.Fatalf("expected clamped MaxInt64 rx and 5 tx, got rx=%d tx=%d err=%v", nMax.CycleRxBytes, nMax.CycleTxBytes, err)
	}
}

func TestAgentWS_AgentEvents(t *testing.T) {
	st := openTestStore(t)
	notifier := newMockNotifier()
	clk := newFakeClock(time.Date(2026, 11, 23, 15, 0, 0, 0, time.UTC))
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now), hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	node, tok := createTestNode(t, st, "events-node", true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()
	_ = readEnvelope(t, c, 3*time.Second)

	// 1. config_applied
	if err := sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentEvent, "ev1", protocol.AgentEvent{
		Event:          protocol.EventConfigApplied,
		ConfigRevision: 7,
		Status:         protocol.EventStatusSuccess,
		Message:        "applied",
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		tel, ok := h.GetTelemetry(node.ID)
		if ok && tel.ReportedConfigRevision == 7 && tel.LastEvent != nil && tel.LastEvent.Event == protocol.EventConfigApplied {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	dbNode, err := st.GetNodeByID(ctx, node.ID)
	if err != nil || dbNode.ReportedConfigRevision != 7 {
		t.Fatalf("expected ReportedConfigRevision=7, got %d err=%v", dbNode.ReportedConfigRevision, err)
	}

	// 2. config_error -> critical alert
	_ = sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentEvent, "ev2", protocol.AgentEvent{
		Event:   protocol.EventConfigError,
		Status:  protocol.EventStatusFailed,
		Message: "bad config",
		Detail:  "line 4",
	})
	evtErr := notifier.WaitEvent(t, 2*time.Second)
	if evtErr.Type != webhook.EventConfigError || evtErr.Severity != webhook.SeverityCritical || evtErr.Resolved {
		t.Fatalf("unexpected config_error alert: %+v", evtErr)
	}

	// 3. process_crashed -> critical alert
	_ = sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentEvent, "ev3", protocol.AgentEvent{
		Event:   protocol.EventProcessCrashed,
		Kernel:  protocol.KernelSingBox,
		Status:  protocol.EventStatusFailed,
		Message: "exit status 2",
	})
	evtCrash := notifier.WaitEvent(t, 2*time.Second)
	if evtCrash.Type != webhook.EventProcessCrashed || evtCrash.Severity != webhook.SeverityCritical || evtCrash.Resolved {
		t.Fatalf("unexpected process_crashed alert: %+v", evtCrash)
	}

	// 4. kernel_update_progress -> cached in GetKernelUpdateStatus
	_ = sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentEvent, "ev4", protocol.AgentEvent{
		Event:   protocol.EventKernelUpdateProgress,
		Kernel:  protocol.KernelSingBox,
		Version: "1.12.0",
		Status:  protocol.EventStatusInProgress,
		Message: "downloading",
	})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ks, ok := h.GetKernelUpdateStatus(node.ID)
		if ok && ks.Status == protocol.EventStatusInProgress && ks.Version == "1.12.0" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if ks, ok := h.GetKernelUpdateStatus(node.ID); !ok || ks.Status != protocol.EventStatusInProgress {
		t.Fatalf("expected kernel_update_progress cached, got ok=%v ks=%+v", ok, ks)
	}

	// 5. kernel_update_result with both "success" and "update_success", and both "failed" and "update_failed".
	cases := []struct {
		kernel   string
		version  string
		status   string
		resolved bool
		severity string
	}{
		{protocol.KernelSingBox, "1.12.0", protocol.EventStatusSuccess, true, webhook.SeverityInfo},
		{protocol.KernelShadowTLS, "0.2.26", "update_success", true, webhook.SeverityInfo},
		{protocol.KernelSnellServer, "5.0.1", protocol.EventStatusFailed, false, webhook.SeverityCritical},
		{protocol.KernelSnellServer, "5.0.2", "update_failed", false, webhook.SeverityCritical},
	}

	for i, tc := range cases {
		_ = sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentEvent, fmt.Sprintf("ku-%d", i), protocol.AgentEvent{
			Event:   protocol.EventKernelUpdateResult,
			Kernel:  tc.kernel,
			Version: tc.version,
			Status:  tc.status,
			Message: "kernel update " + tc.status,
		})
		ev := notifier.WaitEvent(t, 2*time.Second)
		if ev.Type != webhook.EventKernelUpdate || ev.Resolved != tc.resolved || ev.Severity != tc.severity {
			t.Fatalf("case %d (%s): unexpected alert %+v", i, tc.status, ev)
		}
	}

	// Verify DB ReportedVersions updated for SingBox & ShadowTLS (not failed SnellServer).
	dbNode, err = st.GetNodeByID(ctx, node.ID)
	if err != nil {
		t.Fatal(err)
	}
	if dbNode.ReportedVersions.SingBox != "1.12.0" || dbNode.ReportedVersions.ShadowTLS != "0.2.26" || dbNode.ReportedVersions.SnellServer != "" {
		t.Fatalf("unexpected ReportedVersions after kernel update results: %+v", dbNode.ReportedVersions)
	}
}

func TestHub_CheckHeartbeatsAndRealWebhookIntegration(t *testing.T) {
	st := openTestStore(t)
	ctx := context.Background()

	// Set up real *webhook.Engine backed by an httptest.Server.
	receivedPayloads := make(chan string, 16)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		receivedPayloads <- string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer hookSrv.Close()

	if err := st.CreateWebhookChannel(ctx, &store.WebhookChannel{
		Name:             "custom-hook",
		Provider:         protocol.WebhookProviderCustom,
		URL:              hookSrv.URL,
		SubscribedEvents: []string{webhook.EventNodeOffline},
		Enabled:          true,
	}); err != nil {
		t.Fatal(err)
	}

	clk := newFakeClock(time.Date(2026, 11, 23, 16, 0, 0, 0, time.UTC))
	eng := webhook.NewEngine(st, hookSrv.Client(), webhook.WithNow(clk.Now))
	defer eng.Close()

	h := hub.NewHub(st, eng, hub.WithNow(clk.Now), hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	if err := st.SetSetting(ctx, "offline_timeout_seconds", "30"); err != nil {
		t.Fatal(err)
	}

	nodeOnline, tokOnline := createTestNode(t, st, "hb-online", true)
	nodePaused, tokPaused := createTestNode(t, st, "hb-paused", true)

	// Connect both nodes.
	c1, _, err := dialAgentWS(ctx, srv.URL, tokOnline)
	if err != nil {
		t.Fatal(err)
	}
	_ = readEnvelope(t, c1, 3*time.Second)

	c2, _, err := dialAgentWS(ctx, srv.URL, tokPaused)
	if err != nil {
		t.Fatal(err)
	}
	_ = readEnvelope(t, c2, 3*time.Second)

	// Mark nodePaused as traffic_paused in DB.
	if err := st.SetNodeTrafficPaused(ctx, nodePaused.ID, true, "quota reached"); err != nil {
		t.Fatal(err)
	}

	// Disconnect nodePaused cleanly, keep nodeOnline's socket open silently (half-open stale session).
	_ = c2.Close(websocket.StatusNormalClosure, "bye")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.IsOnline(nodePaused.ID) {
		time.Sleep(10 * time.Millisecond)
	}
	if h.IsOnline(nodePaused.ID) {
		t.Fatalf("expected nodePaused to disconnect")
	}

	// CheckHeartbeats before timeout -> nothing alerted.
	clk.Advance(10 * time.Second)
	if err := h.CheckHeartbeats(ctx, 0); err != nil {
		t.Fatal(err)
	}
	eng.Wait()
	select {
	case p := <-receivedPayloads:
		t.Fatalf("unexpected alert before timeout: %s", p)
	default:
	}

	// Advance past 30s (offline_timeout_seconds from system_settings), still < 10m offline alert delay.
	clk.Advance(25 * time.Second)
	if err := h.CheckHeartbeats(ctx, 0); err != nil {
		t.Fatal(err)
	}
	eng.Wait()

	// Offline state & eviction must happen immediately, while node_offline webhook must NOT fire before 10 minutes.
	select {
	case p := <-receivedPayloads:
		t.Fatalf("unexpected node_offline alert before 10 minutes offline: %s", p)
	default:
	}

	if h.IsOnline(nodeOnline.ID) {
		t.Fatalf("expected stale live session to be evicted")
	}
	_ = c1.CloseNow()

	// Verify DB statuses: nodeOnline -> offline, nodePaused -> traffic_paused preserved!
	dbOnline, err := st.GetNodeByID(ctx, nodeOnline.ID)
	if err != nil || dbOnline.Status != protocol.NodeStatusOffline {
		t.Fatalf("expected nodeOnline status=offline, got %q err=%v", dbOnline.Status, err)
	}
	dbPaused, err := st.GetNodeByID(ctx, nodePaused.ID)
	if err != nil || dbPaused.Status != protocol.NodeStatusTrafficPaused {
		t.Fatalf("expected nodePaused status=traffic_paused preserved, got %q err=%v", dbPaused.Status, err)
	}

	// Advance past 10 minutes offline -> both nodeOnline and nodePaused now fire node_offline.
	clk.Advance(10 * time.Minute)
	if err := h.CheckHeartbeats(ctx, 0); err != nil {
		t.Fatal(err)
	}
	eng.Wait()

	var got []string
	for i := 0; i < 2; i++ {
		select {
		case p := <-receivedPayloads:
			got = append(got, p)
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for node_offline webhook #%d", i+1)
		}
	}
	joined := strings.Join(got, "\n")
	if !strings.Contains(joined, "hb-online") || !strings.Contains(joined, "hb-paused") {
		t.Fatalf("expected alerts for both nodes, got: %s", joined)
	}
	if !strings.Contains(joined, "节点离线") || !strings.Contains(joined, "已持续离线") {
		t.Fatalf("expected Chinese offline alert content, got: %s", joined)
	}

	// Subsequent CheckHeartbeats must NOT duplicate node_offline alerts.
	clk.Advance(60 * time.Second)
	if err := h.CheckHeartbeats(ctx, 0); err != nil {
		t.Fatal(err)
	}
	eng.Wait()
	select {
	case p := <-receivedPayloads:
		t.Fatalf("unexpected duplicate alert on second sweep: %s", p)
	default:
	}

	// Simulate panel restart with a fresh Hub -> must NOT re-alert previously offline nodes.
	h2 := hub.NewHub(st, eng, hub.WithNow(clk.Now), hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h2.Close() })
	if err := h2.CheckHeartbeats(ctx, 0); err != nil {
		t.Fatal(err)
	}
	eng.Wait()
	select {
	case p := <-receivedPayloads:
		t.Fatalf("unexpected re-alert after panel restart: %s", p)
	default:
	}

	// Reconnect nodeOnline on h2 and send agent.hello -> must deliver resolved node_online webhook!
	srv2 := newTestServer(t, h2)
	cRec, _, err := dialAgentWS(ctx, srv2.URL, tokOnline)
	if err != nil {
		t.Fatal(err)
	}
	defer cRec.CloseNow()
	_ = readEnvelope(t, cRec, 3*time.Second)
	if err := sendAgentEnvelope(ctx, cRec, protocol.MsgTypeAgentHello, "h-rec", protocol.AgentHello{
		OS: "linux", Arch: "amd64",
	}); err != nil {
		t.Fatal(err)
	}

	select {
	case p := <-receivedPayloads:
		if !strings.Contains(p, "node_online") || !strings.Contains(p, `"resolved":true`) {
			t.Fatalf("expected resolved node_online webhook, got: %s", p)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("timed out waiting for resolved node_online webhook")
	}
	eng.Wait()
}

func TestCheckHeartbeats_ReconnectWithin10MinutesSuppressesAlerts(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)

	receivedPayloads := make(chan string, 16)
	hookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		b, _ := json.Marshal(body)
		receivedPayloads <- string(b)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer hookSrv.Close()

	if err := st.CreateWebhookChannel(ctx, &store.WebhookChannel{
		Name:             "node-events",
		Provider:         protocol.WebhookProviderCustom,
		URL:              hookSrv.URL,
		SubscribedEvents: []string{webhook.EventNodeOffline, webhook.EventNodeOnline},
		Enabled:          true,
	}); err != nil {
		t.Fatal(err)
	}

	clk := newFakeClock(time.Date(2026, 11, 27, 10, 0, 0, 0, time.UTC))
	eng := webhook.NewEngine(st, hookSrv.Client(), webhook.WithNow(clk.Now))
	defer eng.Close()

	h := hub.NewHub(st, eng, hub.WithNow(clk.Now), hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	if err := st.SetSetting(ctx, "offline_timeout_seconds", "30"); err != nil {
		t.Fatal(err)
	}

	node, tok := createTestNode(t, st, "flapping-node", true)
	c1, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	_ = readEnvelope(t, c1, 3*time.Second)
	if err := sendAgentEnvelope(ctx, c1, protocol.MsgTypeAgentHello, "h1", protocol.AgentHello{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	_ = c1.Close(websocket.StatusNormalClosure, "reboot")

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && h.IsOnline(node.ID) {
		time.Sleep(10 * time.Millisecond)
	}

	// Advance 5 minutes (< 10m) and run CheckHeartbeats -> zero alerts.
	clk.Advance(5 * time.Minute)
	if err := h.CheckHeartbeats(ctx, 0); err != nil {
		t.Fatal(err)
	}
	eng.Wait()

	// Reconnect before 10 minutes -> zero node_offline AND zero node_online recovery alerts.
	c2, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.CloseNow()
	_ = readEnvelope(t, c2, 3*time.Second)
	if err := sendAgentEnvelope(ctx, c2, protocol.MsgTypeAgentHello, "h2", protocol.AgentHello{OS: "linux", Arch: "amd64"}); err != nil {
		t.Fatal(err)
	}
	eng.Wait()

	select {
	case p := <-receivedPayloads:
		t.Fatalf("expected zero offline/online alerts when reconnecting within 10m, got: %s", p)
	default:
	}
}

func TestAgentWS_DisconnectReconnectSQLiteContentionRace(t *testing.T) {
	st := openTestStore(t)
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithPublicDebounce(5*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	node, tok := createTestNode(t, st, "race-dc-node", true)
	noiseNode, _ := createTestNode(t, st, "race-dc-noise", true)
	noiseUser := createTestUser(t, st, "race-dc-user", true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start 3 background SQLite reader/writer goroutines to create realistic DB contention.
	bgCtx, bgCancel := context.WithCancel(ctx)
	var bgWg sync.WaitGroup
	for g := 0; g < 3; g++ {
		workerID := g
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			for {
				select {
				case <-bgCtx.Done():
					return
				default:
				}
				switch workerID {
				case 0:
					_, _ = st.ListNodes(bgCtx)
					_, _ = h.BuildPublicSnapshot(bgCtx)
				case 1:
					_, _ = st.ApplyTrafficDeltas(bgCtx, noiseNode.ID, 64, 128, []protocol.UserTrafficDelta{
						{UserID: noiseUser.ID, Username: noiseUser.Username, UpBytes: 16, DownBytes: 32},
					}, "2026-11-23")
				case 2:
					_, _ = st.GetNodeByID(bgCtx, noiseNode.ID)
					_ = st.SetNodeConnectionStatus(bgCtx, noiseNode.ID, true, time.Now().UTC())
				}
			}
		}()
	}
	t.Cleanup(func() {
		bgCancel()
		bgWg.Wait()
	})

	// Establish initial session and send agent.hello so LastSeenAt != nil (spurious node_online would fire if DB flickered offline).
	cCur, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	_ = readEnvelope(t, cCur, 3*time.Second)
	if err := sendAgentEnvelope(ctx, cCur, protocol.MsgTypeAgentHello, "init-hello", protocol.AgentHello{
		OS: "linux", Arch: "amd64", ConfigRevision: 1,
	}); err != nil {
		t.Fatalf("initial hello: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dbN, err := st.GetNodeByID(ctx, node.ID); err == nil && dbN.Status == protocol.NodeStatusOnline && dbN.LastSeenAt != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	const rounds = 65
	for round := 0; round < rounds; round++ {
		var cNew *websocket.Conn
		var dialErr error

		if round%2 == 0 {
			// Close right before dialing so cleanupAgentSession runs genuineDisconnect concurrently with ServeAgentWS.
			_ = cCur.Close(websocket.StatusNormalClosure, "reconnect")
			if jitter := time.Duration(round%5) * 150 * time.Microsecond; jitter > 0 {
				time.Sleep(jitter)
			}
			cNew, _, dialErr = dialAgentWS(ctx, srv.URL, tok)
		} else {
			// Concurrent close and dial behind a barrier.
			start := make(chan struct{})
			var wg sync.WaitGroup
			wg.Add(2)
			go func(prev *websocket.Conn) {
				defer wg.Done()
				<-start
				_ = prev.CloseNow()
			}(cCur)
			go func(r int) {
				defer wg.Done()
				<-start
				if jitter := time.Duration(r%4) * 100 * time.Microsecond; jitter > 0 {
					time.Sleep(jitter)
				}
				cNew, _, dialErr = dialAgentWS(ctx, srv.URL, tok)
			}(round)
			close(start)
			wg.Wait()
		}

		if dialErr != nil {
			t.Fatalf("round %d: dial failed: %v", round, dialErr)
		}
		env := readEnvelope(t, cNew, 3*time.Second)
		if env.Type != protocol.MsgTypeServerConfigSync {
			t.Fatalf("round %d: expected server.config_sync, got %q", round, env.Type)
		}

		if err := sendAgentEnvelope(ctx, cNew, protocol.MsgTypeAgentHello, fmt.Sprintf("h-%d", round), protocol.AgentHello{
			OS: "linux", Arch: "amd64", ConfigRevision: 1,
		}); err != nil {
			t.Fatalf("round %d: send hello: %v", round, err)
		}

		// Allow any concurrent cleanup goroutine and hello processing to settle.
		time.Sleep(10 * time.Millisecond)

		if !h.IsOnline(node.ID) {
			t.Fatalf("round %d: expected hub.IsOnline(%d)=true", round, node.ID)
		}
		dbNode, err := st.GetNodeByID(ctx, node.ID)
		if err != nil {
			t.Fatalf("round %d: GetNodeByID: %v", round, err)
		}
		if dbNode.Status != protocol.NodeStatusOnline {
			t.Fatalf("round %d: hub.IsOnline=true but DB status=%q!", round, dbNode.Status)
		}
		if evts := notifier.Events(); len(evts) != 0 {
			t.Fatalf("round %d: unexpected spurious webhook alerts: %+v", round, evts)
		}

		cCur = cNew
	}

	_ = cCur.CloseNow()
}

func TestHub_CheckHeartbeats_ReconnectSQLiteContentionRace(t *testing.T) {
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 23, 18, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now), hub.WithPublicDebounce(5*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	node, tok := createTestNode(t, st, "hb-race-node", true)
	noiseNode, _ := createTestNode(t, st, "hb-race-noise", true)
	noiseUser := createTestUser(t, st, "hb-race-user", true)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Start 3 background SQLite reader/writer goroutines to widen DB contention windows.
	bgCtx, bgCancel := context.WithCancel(ctx)
	var bgWg sync.WaitGroup
	for g := 0; g < 3; g++ {
		workerID := g
		bgWg.Add(1)
		go func() {
			defer bgWg.Done()
			for {
				select {
				case <-bgCtx.Done():
					return
				default:
				}
				switch workerID {
				case 0:
					_, _ = st.ListNodes(bgCtx)
					_, _ = h.BuildPublicSnapshot(bgCtx)
				case 1:
					_, _ = st.ApplyTrafficDeltas(bgCtx, noiseNode.ID, 64, 128, []protocol.UserTrafficDelta{
						{UserID: noiseUser.ID, Username: noiseUser.Username, UpBytes: 16, DownBytes: 32},
					}, "2026-11-23")
				case 2:
					_, _ = st.GetNodeByID(bgCtx, noiseNode.ID)
					_ = st.SetNodeConnectionStatus(bgCtx, noiseNode.ID, true, clk.Now())
				}
			}
		}()
	}
	t.Cleanup(func() {
		bgCancel()
		bgWg.Wait()
	})

	const rounds = 45
	for round := 0; round < rounds; round++ {
		var cStale *websocket.Conn
		if round%2 == 1 {
			// Half-open stale live session case.
			var err error
			cStale, _, err = dialAgentWS(ctx, srv.URL, tok)
			if err != nil {
				t.Fatalf("round %d: dial stale: %v", round, err)
			}
			_ = readEnvelope(t, cStale, 3*time.Second)
		} else {
			// Disconnected node still marked online with stale LastSeenAt.
			if err := st.SetNodeConnectionStatus(ctx, node.ID, true, clk.Now()); err != nil {
				t.Fatalf("round %d: seed online: %v", round, err)
			}
		}

		// Advance clock past offlineTimeout so CheckHeartbeats considers node expired.
		clk.Advance(2 * time.Minute)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var cNew *websocket.Conn
		var dialErr error
		var hbErr error

		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			hbErr = h.CheckHeartbeats(ctx, 30*time.Second)
		}()
		go func(r int) {
			defer wg.Done()
			<-start
			if jitter := time.Duration(r%4) * 150 * time.Microsecond; jitter > 0 {
				time.Sleep(jitter)
			}
			cNew, _, dialErr = dialAgentWS(ctx, srv.URL, tok)
			if dialErr == nil {
				env := readEnvelope(t, cNew, 3*time.Second)
				if env.Type != protocol.MsgTypeServerConfigSync {
					dialErr = fmt.Errorf("expected server.config_sync, got %q", env.Type)
				}
			}
		}(round)

		close(start)
		wg.Wait()

		if hbErr != nil {
			t.Fatalf("round %d: CheckHeartbeats failed: %v", round, hbErr)
		}
		if dialErr != nil {
			t.Fatalf("round %d: dial/sync failed: %v", round, dialErr)
		}

		if !h.IsOnline(node.ID) {
			t.Fatalf("round %d: expected hub.IsOnline(%d)=true after reconnect", round, node.ID)
		}
		dbNode, err := st.GetNodeByID(ctx, node.ID)
		if err != nil {
			t.Fatalf("round %d: GetNodeByID: %v", round, err)
		}
		if dbNode.Status != protocol.NodeStatusOnline {
			t.Fatalf("round %d: hub.IsOnline=true but DB status=%q after concurrent CheckHeartbeats!", round, dbNode.Status)
		}

		if cStale != nil {
			_ = cStale.CloseNow()
		}
		_ = cNew.Close(websocket.StatusNormalClosure, "round-done")
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) && h.IsOnline(node.ID) {
			time.Sleep(5 * time.Millisecond)
		}
		if h.IsOnline(node.ID) {
			t.Fatalf("round %d: expected node offline after closing cNew", round)
		}
	}
}

func TestAgentWS_CloseAbortsTeardownPromptly(t *testing.T) {
	st := openTestStore(t)
	h := hub.NewHub(st, nil, hub.WithPublicDebounce(10*time.Millisecond))
	t.Cleanup(func() { _ = h.Close() })
	srv := newTestServer(t, h)

	_, tok := createTestNode(t, st, "close-race-node", true)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := dialAgentWS(ctx, srv.URL, tok)
	if err != nil {
		t.Fatalf("dialAgentWS: %v", err)
	}
	defer c.CloseNow()
	_ = readEnvelope(t, c, 3*time.Second)

	if err := sendAgentEnvelope(ctx, c, protocol.MsgTypeAgentHello, "h-close", protocol.AgentHello{
		OS: "linux", Arch: "amd64", ConfigRevision: 0,
	}); err != nil {
		t.Fatalf("sendAgentEnvelope hello: %v", err)
	}

	// Race client disconnect with Hub.Close() and verify Hub.Close() finishes quickly (<1s).
	barrier := make(chan struct{})
	var closeErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-barrier
		_ = c.CloseNow()
	}()
	go func() {
		defer wg.Done()
		<-barrier
		closeErr = h.Close()
	}()

	start := time.Now()
	close(barrier)
	wg.Wait()
	elapsed := time.Since(start)

	if closeErr != nil {
		t.Fatalf("Hub.Close() failed: %v", closeErr)
	}
	if elapsed >= time.Second {
		t.Fatalf("expected Hub.Close() to abort promptly (<1s), took %s", elapsed)
	}
}
