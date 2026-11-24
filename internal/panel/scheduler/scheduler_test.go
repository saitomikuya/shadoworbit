package scheduler_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(t time.Time) *fakeClock {
	return &fakeClock{now: t}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Set(t time.Time) {
	c.mu.Lock()
	c.now = t
	c.mu.Unlock()
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
	dbPath := filepath.Join(t.TempDir(), "scheduler_test.db")
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
		PublicIP:              "203.0.113.10",
		Enabled:               enabled,
		Status:                protocol.NodeStatusOffline,
		TrafficLimitBytes:     10000,
		TrafficThresholdBytes: 1000,
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
	u16, err := auth.GenerateUPSK16()
	if err != nil {
		t.Fatalf("generate upsk16: %v", err)
	}
	u32, err := auth.GenerateUPSK32()
	if err != nil {
		t.Fatalf("generate upsk32: %v", err)
	}
	stlsPwd, err := auth.GenerateShadowTLSPassword()
	if err != nil {
		t.Fatalf("generate stls pwd: %v", err)
	}
	u := &store.User{
		Username:          username,
		Enabled:           enabled,
		SubToken:          subTok,
		SSUPSK16:          u16,
		SSUPSK32:          u32,
		STLSPassword:      stlsPwd,
		TrafficQuotaBytes: 10000,
		BillingResetDay:   1,
	}
	if err := st.CreateUser(context.Background(), u); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return u
}

func dialAgent(t *testing.T, h *hub.Hub, rawToken string) (*websocket.Conn, func()) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(h.ServeAgentWS))
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + rawToken},
		},
	})
	if err != nil {
		srv.Close()
		t.Fatalf("dial agent ws: %v", err)
	}

	cleanup := func() {
		_ = conn.CloseNow()
		srv.Close()
	}
	t.Cleanup(cleanup)
	return conn, cleanup
}

func readEnvelope(t *testing.T, conn *websocket.Conn, timeout time.Duration) protocol.Envelope {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, raw, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read ws envelope: %v", err)
	}
	var env protocol.Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

func sendEnvelope(t *testing.T, conn *websocket.Conn, msgType, reqID string, payload any) {
	t.Helper()
	raw, err := protocol.MarshalEnvelope(msgType, reqID, payload)
	if err != nil {
		t.Fatalf("marshal envelope: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := conn.Write(ctx, websocket.MessageText, raw); err != nil {
		t.Fatalf("write ws envelope: %v", err)
	}
}

func waitUntil(t *testing.T, timeout time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for condition: %s", msg)
}

func TestNewScheduler_TypedNilNotifierGuard(t *testing.T) {
	st := openTestStore(t)
	var nilEngine *webhook.Engine
	sched := scheduler.NewScheduler(st, nil, nilEngine)

	n, _ := createTestNode(t, st, "typed-nil-node", true)
	if err := st.CalibrateNodeTraffic(context.Background(), n.ID, 600, 500); err != nil {
		t.Fatalf("calibrate: %v", err)
	}
	if err := sched.EvaluateNodeThreshold(context.Background(), n.ID); err != nil {
		t.Fatalf("EvaluateNodeThreshold with typed-nil notifier failed: %v", err)
	}
	updated, err := st.GetNodeByID(context.Background(), n.ID)
	if err != nil {
		t.Fatalf("get node: %v", err)
	}
	if !updated.IsTrafficPaused {
		t.Fatalf("expected node to be paused even with typed-nil notifier")
	}
}

func TestScheduler_StartStopIdempotentAndNoUnsolicitedGitHubSync(t *testing.T) {
	var ghCalls atomic.Int32
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghCalls.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("[]"))
	}))
	defer ghSrv.Close()

	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	h := hub.NewHub(st, nil, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	sched := scheduler.NewScheduler(
		st,
		h,
		nil,
		scheduler.WithNow(clk.Now),
		scheduler.WithSweepInterval(15*time.Millisecond),
		scheduler.WithGitHubAPIBaseURL(ghSrv.URL),
	)

	// Double Start must be safe; Stop must be idempotent.
	sched.Start(context.Background())
	sched.Start(context.Background())
	time.Sleep(60 * time.Millisecond)
	sched.Stop()
	sched.Stop()

	if ghCalls.Load() != 0 {
		t.Fatalf("expected 0 GitHub HTTP calls when kernelSyncInterval == 0, got %d", ghCalls.Load())
	}
}

func TestScheduler_PeriodicKernelSyncAndHeartbeatCheck(t *testing.T) {
	var ghCalls atomic.Int32
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ghCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("[]"))
	}))
	defer ghSrv.Close()

	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	n, _ := createTestNode(t, st, "stale-node", true)
	if err := st.SetNodeConnectionStatus(context.Background(), n.ID, true, clk.Now().Add(-5*time.Minute)); err != nil {
		t.Fatalf("set online: %v", err)
	}

	sched := scheduler.NewScheduler(
		st,
		h,
		notifier,
		scheduler.WithNow(clk.Now),
		scheduler.WithSweepInterval(20*time.Millisecond),
		scheduler.WithKernelSyncInterval(25*time.Millisecond),
		scheduler.WithGitHubAPIBaseURL(ghSrv.URL),
	)
	sched.Start(context.Background())
	defer sched.Stop()

	waitUntil(t, 2*time.Second, func() bool {
		fresh, err := st.GetNodeByID(context.Background(), n.ID)
		return err == nil && fresh.Status == protocol.NodeStatusOffline
	}, "stale node marked offline by CheckHeartbeats")

	waitUntil(t, 2*time.Second, func() bool {
		return ghCalls.Load() >= 2
	}, "periodic kernel sync ticked")
}

func TestScheduler_OnTrafficUpdated_SessionCancelResilience(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	clk := newFakeClock(time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC))
	notifier := newMockNotifier()
	h := hub.NewHub(st, notifier, hub.WithNow(clk.Now))
	defer func() { _ = h.Close() }()

	n, tok := createTestNode(t, st, "ws-cancel-node", true)
	u := createTestUser(t, st, "ws-cancel-user", true)
	u.TrafficQuotaBytes = 500
	if err := st.UpdateUser(ctx, u); err != nil {
		t.Fatalf("update user: %v", err)
	}
	if err := st.SetUserNodes(ctx, u.ID, []int64{n.ID}); err != nil {
		t.Fatalf("set user nodes: %v", err)
	}

	sched := scheduler.NewScheduler(st, h, notifier, scheduler.WithNow(clk.Now))
	sched.WireHub()

	conn, _ := dialAgent(t, h, tok)
	_ = readEnvelope(t, conn, 3*time.Second) // initial server.config_sync

	sendEnvelope(t, conn, protocol.MsgTypeAgentHello, "h1", protocol.AgentHello{
		OS:   "linux",
		Arch: "amd64",
	})

	// Send metrics pushing BOTH node over threshold (1000) and user over quota (500),
	// then immediately terminate the WS connection so hub's session context cancels.
	sendEnvelope(t, conn, protocol.MsgTypeAgentMetrics, "m1", protocol.AgentMetrics{
		TS:         clk.Now().Unix(),
		NicRxDelta: 600,
		NicTxDelta: 500,
		UserDeltas: []protocol.UserTrafficDelta{
			{UserID: u.ID, Username: u.Username, UpBytes: 300, DownBytes: 250},
		},
		Health: protocol.AgentHealth{Snell: true, ShadowTLS: true, SingBox: true},
	})
	_ = conn.CloseNow()

	waitUntil(t, 3*time.Second, func() bool {
		fresh, err := st.GetNodeByID(ctx, n.ID)
		return err == nil && fresh.IsTrafficPaused && fresh.Status == protocol.NodeStatusTrafficPaused
	}, "node paused despite immediate WS session cancellation")

	waitUntil(t, 3*time.Second, func() bool {
		evts := notifier.Events()
		var hasPaused, hasQuota bool
		for _, e := range evts {
			if e.Type == webhook.EventTrafficPaused && e.TargetID == n.ID {
				hasPaused = true
			}
			if e.Type == webhook.EventUserQuotaExhausted && e.TargetID == u.ID {
				hasQuota = true
			}
		}
		return hasPaused && hasQuota
	}, "both traffic_paused and user_quota_exhausted alerts emitted")
}
