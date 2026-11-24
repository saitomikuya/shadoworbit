package wsclient

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/agent/collector"
	"snell-panel/internal/protocol"
)

func startTestClient(t *testing.T, client *Client) func() {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		runDone <- client.Run(ctx)
	}()

	var once sync.Once
	return func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-runDone:
				if err != nil {
					t.Errorf("client.Run returned error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Error("timed out waiting for client.Run shutdown")
			}
		})
	}
}

type syncLogBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestNormalizeWSURL(t *testing.T) {
	valid := []struct {
		in   string
		want string
	}{
		{"http://panel.example.com", "ws://panel.example.com/api/v1/agent/ws"},
		{"https://panel.example.com/", "wss://panel.example.com/api/v1/agent/ws"},
		{"ws://127.0.0.1:8080", "ws://127.0.0.1:8080/api/v1/agent/ws"},
		{"wss://panel.example.com:8443/api/v1/agent/ws", "wss://panel.example.com:8443/api/v1/agent/ws"},
		{"https://panel.example.com/api/v1/agent/ws/", "wss://panel.example.com/api/v1/agent/ws"},
		{"https://panel.example.com/sub/api/v1/agent/ws", "wss://panel.example.com/sub/api/v1/agent/ws"},
		{"wss://[::1]:8443", "wss://[::1]:8443/api/v1/agent/ws"},
		{"wss://[::1]", "wss://[::1]/api/v1/agent/ws"},
		{"https://[2001:db8::1]:443/api/v1/agent/ws/", "wss://[2001:db8::1]:443/api/v1/agent/ws"},
	}
	for _, tc := range valid {
		got, err := NormalizeWSURL(tc.in)
		if err != nil {
			t.Fatalf("NormalizeWSURL(%q) unexpected err: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeWSURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	invalid := []string{
		"",
		"ftp://panel.example.com",
		"wss://",
		"wss://:8443",
		"wss://panel.example.com:",
		"wss://panel.example.com:0",
		"wss://panel.example.com:70000",
		"wss://panel.example.com:abc",
		"wss://::1:8443",
		"wss://::1",
		"wss://[::1]:",
		"wss://[not-an-ip]:8443",
		"wss://[]",
	}
	for _, raw := range invalid {
		if got, err := NormalizeWSURL(raw); err == nil {
			t.Fatalf("NormalizeWSURL(%q) expected error, got %q", raw, got)
		}
	}
}

func TestComputeBackoffStrictlyCappedAt30s(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	for attempt := 0; attempt < 30; attempt++ {
		d := computeBackoff(attempt, time.Second, 60*time.Second, rng)
		if d > 30*time.Second {
			t.Fatalf("attempt %d backoff %s exceeded 30s cap", attempt, d)
		}
		if d <= 0 {
			t.Fatalf("attempt %d backoff %s must be > 0", attempt, d)
		}
	}
}

func TestClientAuthHelloTLSSkipVerifyAndNormalClosure(t *testing.T) {
	const token = "nd_live_test_secret_token_9988"

	type serverObservation struct {
		path  string
		auth  string
		hello protocol.AgentHello
		code  websocket.StatusCode
	}
	obsCh := make(chan serverObservation, 1)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		obs := serverObservation{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("websocket.Accept failed: %v", err)
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		_, data, err := conn.Read(ctx)
		if err != nil {
			t.Errorf("read hello failed: %v", err)
			return
		}
		env, err := protocol.ParseEnvelope(data)
		if err != nil {
			t.Errorf("parse hello envelope: %v", err)
			return
		}
		if env.Type != protocol.MsgTypeAgentHello {
			t.Errorf("expected %s, got %s", protocol.MsgTypeAgentHello, env.Type)
			return
		}
		if err := env.DecodePayload(&obs.hello); err != nil {
			t.Errorf("decode hello payload: %v", err)
			return
		}

		// Wait for client NormalClosure when ctx cancels.
		for {
			_, _, err := conn.Read(ctx)
			if err != nil {
				obs.code = websocket.CloseStatus(err)
				break
			}
		}
		obsCh <- obs
	}))
	defer srv.Close()

	client, err := New(Options{
		PanelURL:        srv.URL,
		NodeToken:       token,
		TLSSkipVerify:   true,
		MetricsInterval: 5 * time.Second,
		PingInterval:    -1,
		BuildHello: func(ctx context.Context) protocol.AgentHello {
			return protocol.AgentHello{
				OS:            "linux",
				Arch:          "amd64",
				CPUCores:      4,
				TotalRAMBytes: 8 << 30,
				PublicIPv4:    "203.0.113.10",
				PublicIPv6:    "2001:db8::10",
				Versions: protocol.AgentVersions{
					SingBox:     "1.11.0",
					SnellServer: "v5.0.0",
					ShadowTLS:   "v0.2.25",
				},
				ConfigRevision: 7,
			}
		},
	})
	if err != nil {
		t.Fatalf("wsclient.New failed: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx)
	}()

	// Wait until client connects before cancelling.
	deadline := time.Now().Add(3 * time.Second)
	for !client.Connected() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !client.Connected() {
		t.Fatal("client did not report Connected() == true")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("client.Run returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for client.Run shutdown")
	}

	select {
	case obs := <-obsCh:
		if obs.path != AgentWSPath {
			t.Fatalf("expected path %s, got %q", AgentWSPath, obs.path)
		}
		if obs.auth != "Bearer "+token {
			t.Fatalf("unexpected Authorization header: %q", obs.auth)
		}
		if obs.hello.ConfigRevision != 7 || obs.hello.PublicIPv4 != "203.0.113.10" || obs.hello.Versions.SingBox != "1.11.0" {
			t.Fatalf("unexpected hello payload: %+v", obs.hello)
		}
		if obs.code != websocket.StatusNormalClosure {
			t.Fatalf("expected NormalClosure (1000), got %v", obs.code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server observation")
	}
}

func TestClientReconnectBackoffAndResetAfterHealthySession(t *testing.T) {
	var attempts atomic.Int32
	var timestampsMu sync.Mutex
	var dialTimes []time.Time
	var healthyClosedAt time.Time
	reconnectedAfterReset := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timestampsMu.Lock()
		dialTimes = append(dialTimes, time.Now())
		timestampsMu.Unlock()

		n := attempts.Add(1)
		if n <= 3 {
			http.Error(w, "temporary unavailable", http.StatusServiceUnavailable)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		// Read hello.
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}

		// Send a valid frame so session counts as healthy, then drop on attempt 4 to test backoff reset.
		frame, _ := protocol.MarshalEnvelope(protocol.MsgTypeServerConfigSync, "srv-1", protocol.ServerConfigSync{ConfigRevision: 1})
		_ = conn.Write(ctx, websocket.MessageText, frame)
		time.Sleep(25 * time.Millisecond)
		if n == 4 {
			timestampsMu.Lock()
			healthyClosedAt = time.Now()
			timestampsMu.Unlock()
			_ = conn.Close(websocket.StatusGoingAway, "simulate restart")
			return
		}
		if n >= 5 {
			select {
			case <-reconnectedAfterReset:
			default:
				close(reconnectedAfterReset)
			}
			for {
				if _, _, err := conn.Read(r.Context()); err != nil {
					return
				}
			}
		}
	}))
	defer srv.Close()

	client, err := New(Options{
		PanelURL:             srv.URL,
		NodeToken:            "nd_live_backoff_token_0001",
		BackoffBase:          25 * time.Millisecond,
		BackoffMax:           200 * time.Millisecond,
		HealthyResetDuration: 20 * time.Millisecond,
		PingInterval:         -1,
	})
	if err != nil {
		t.Fatalf("wsclient.New failed: %v", err)
	}

	stop := startTestClient(t, client)
	defer stop()

	select {
	case <-reconnectedAfterReset:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for reconnect after healthy session (attempts=%d)", attempts.Load())
	}

	stop()

	timestampsMu.Lock()
	defer timestampsMu.Unlock()
	if len(dialTimes) < 5 {
		t.Fatalf("expected >=5 dial attempts, got %d", len(dialTimes))
	}
	if healthyClosedAt.IsZero() {
		t.Fatal("healthyClosedAt was not recorded")
	}
	// After attempt 4 (healthy), attempt 5 delay should reset to <= BackoffBase (25ms + scheduling slack),
	// well below unreset attempt=3 jitter floor (100ms..200ms).
	gap := dialTimes[4].Sub(healthyClosedAt)
	if gap > 95*time.Millisecond {
		t.Fatalf("expected reset backoff after healthy session, got gap %s", gap)
	}
}

func TestClientMetricsWALRetainedOnFailedWriteAndFlushedOnReconnect(t *testing.T) {
	dataDir := t.TempDir()
	procNetDev := filepath.Join(dataDir, "proc_net_dev")
	initialDev := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
	if err := os.WriteFile(procNetDev, []byte(initialDev), 0o600); err != nil {
		t.Fatal(err)
	}

	col, err := collector.New(collector.Options{
		DataDir:             dataDir,
		Interface:           "eth0",
		ProcNetDevPath:      procNetDev,
		PublicIPEndpointsV4: []string{},
		PublicIPEndpointsV6: []string{},
	})
	if err != nil {
		t.Fatalf("collector.New failed: %v", err)
	}
	col.SetStatsEnabled(false)

	// Baseline poll, then increment NIC counters so WAL contains rx=5000, tx=7000.
	if err := col.PollOnce(context.Background()); err != nil {
		t.Fatalf("baseline PollOnce failed: %v", err)
	}
	nextDev := "Inter-|   Receive                                                |  Transmit\n" +
		" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n" +
		"  eth0: 6000 20 0 0 0 0 0 0 9000 30 0 0 0 0 0 0\n"
	if err := os.WriteFile(procNetDev, []byte(nextDev), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := col.PollOnce(context.Background()); err != nil {
		t.Fatalf("delta PollOnce failed: %v", err)
	}

	// Verify StageMetrics -> failed write does NOT ack; simulate reconnect that succeeds.
	var metricsReceived atomic.Int32
	flushedCh := make(chan protocol.AgentMetrics, 4)

	var connCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := connCount.Add(1)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		// First connection: close immediately after reading hello so metrics write fails or races cleanly.
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		_, _, err = conn.Read(ctx)
		if err != nil {
			return
		}
		if n == 1 {
			// Immediately drop TCP without clean handshake so client's metrics write fails.
			conn.CloseNow()
			return
		}

		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			env, err := protocol.ParseEnvelope(data)
			if err != nil {
				continue
			}
			if env.Type == protocol.MsgTypeAgentMetrics {
				var m protocol.AgentMetrics
				if err := env.DecodePayload(&m); err == nil {
					metricsReceived.Add(1)
					flushedCh <- m
				}
			}
		}
	}))
	defer srv.Close()

	// Wrap StageMetrics to wait for session 1's EOF cancellation before writing so
	// session 1's write deterministically fails and WAL retention is exercised every run.
	var stageCalls atomic.Int32
	client, err := New(Options{
		PanelURL:        srv.URL,
		NodeToken:       "nd_live_wal_test_token_1234",
		MetricsInterval: 40 * time.Millisecond,
		BackoffBase:     20 * time.Millisecond,
		BackoffMax:      40 * time.Millisecond,
		PingInterval:    -1,
		StageMetrics: func(ctx context.Context) (protocol.AgentMetrics, func() error, error) {
			if stageCalls.Add(1) == 1 {
				select {
				case <-ctx.Done():
				case <-time.After(2 * time.Second):
				}
			}
			return col.StageMetrics(ctx, protocol.AgentHealth{SingBox: true})
		},
	})
	if err != nil {
		t.Fatalf("wsclient.New failed: %v", err)
	}

	stop := startTestClient(t, client)
	defer stop()

	// Wait for at least one metrics frame carrying the WAL delta on the healthy reconnect.
	var gotDelta protocol.AgentMetrics
	deadline := time.After(5 * time.Second)
	for {
		select {
		case m := <-flushedCh:
			if m.NicRxDelta == 5000 && m.NicTxDelta == 7000 {
				gotDelta = m
				goto verified
			}
		case <-deadline:
			t.Fatalf("timed out waiting for WAL flush (stageCalls=%d, metricsReceived=%d)", stageCalls.Load(), metricsReceived.Load())
		}
	}

verified:
	// Ensure Phase 1 client.Run has completely stopped (including completing ack())
	// before inspecting/mutating shared Collector and procNetDev in Phase 2.
	stop()

	if gotDelta.NicRxDelta != 5000 || gotDelta.NicTxDelta != 7000 {
		t.Fatalf("unexpected flushed WAL deltas: %+v", gotDelta)
	}

	// Next StageMetrics must now report 0 pending deltas because ack() ran after confirmed write.
	nextBatch, ack, err := col.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatalf("StageMetrics after flush failed: %v", err)
	}
	if ack != nil {
		_ = ack()
	}
	if nextBatch.NicRxDelta != 0 || nextBatch.NicTxDelta != 0 {
		t.Fatalf("expected WAL cleared after ack(), got rx=%d tx=%d", nextBatch.NicRxDelta, nextBatch.NicTxDelta)
	}

	// Also directly verify failed StageMetrics write never calls ack().
	if err := os.WriteFile(procNetDev, []byte(
		"Inter-|   Receive                                                |  Transmit\n"+
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
			"  eth0: 7500 25 0 0 0 0 0 0 11000 35 0 0 0 0 0 0\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := col.PollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	errClient, err := New(Options{
		PanelURL:        "ws://127.0.0.1:1/api/v1/agent/ws",
		NodeToken:       "nd_live_wal_test_token_1234",
		MetricsInterval: 20 * time.Millisecond,
		StageMetrics: func(ctx context.Context) (protocol.AgentMetrics, func() error, error) {
			return col.StageMetrics(ctx, protocol.AgentHealth{})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	errClient.runMetricsLoop(context.Background(), func(context.Context, []byte) error {
		return errors.New("simulated write failure")
	}, func() {})

	retained, _, err := col.StageMetrics(context.Background(), protocol.AgentHealth{})
	if err != nil {
		t.Fatal(err)
	}
	if retained.NicRxDelta != 1500 || retained.NicTxDelta != 2000 {
		t.Fatalf("expected WAL to retain 1500/2000 on failed write, got rx=%d tx=%d", retained.NicRxDelta, retained.NicTxDelta)
	}
}

func TestClientEventQueueNonBlockingOverflowAndReconnectDelivery(t *testing.T) {
	receivedCh := make(chan protocol.AgentEvent, 16)
	var allowServer atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowServer.Load() {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		ctx, cancel := context.WithTimeout(r.Context(), 4*time.Second)
		defer cancel()
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			env, err := protocol.ParseEnvelope(data)
			if err != nil {
				continue
			}
			if env.Type == protocol.MsgTypeAgentEvent {
				var ev protocol.AgentEvent
				if err := env.DecodePayload(&ev); err == nil {
					receivedCh <- ev
				}
			}
		}
	}))
	defer srv.Close()

	client, err := New(Options{
		PanelURL:        srv.URL,
		NodeToken:       "nd_live_event_queue_token_1234",
		EventQueueSize:  3,
		BackoffBase:     20 * time.Millisecond,
		BackoffMax:      40 * time.Millisecond,
		MetricsInterval: 5 * time.Second,
		PingInterval:    -1,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Queue 5 events while disconnected (non-blocking, cap=3 -> drops oldest 2, keeps rev 3,4,5).
	for i := 1; i <= 5; i++ {
		client.SendEvent(protocol.AgentEvent{
			Event:          protocol.EventConfigApplied,
			ConfigRevision: int64(i),
			Status:         protocol.EventStatusSuccess,
		})
	}

	stop := startTestClient(t, client)
	defer stop()

	time.Sleep(50 * time.Millisecond)
	allowServer.Store(true)

	var got []int64
	for len(got) < 3 {
		select {
		case ev := <-receivedCh:
			got = append(got, ev.ConfigRevision)
		case <-time.After(3 * time.Second):
			t.Fatalf("timed out waiting for queued events, got=%v", got)
		}
	}
	if got[0] != 3 || got[1] != 4 || got[2] != 5 {
		t.Fatalf("expected newest 3 events [3 4 5], got %v", got)
	}

	stop()
	// Safe after shutdown.
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 99})
}

func TestClientInboundOffReadLoopKeepaliveAndUpdateOverflow(t *testing.T) {
	updateStarted := make(chan struct{})
	releaseUpdate := make(chan struct{})
	appliedUpdatesCh := make(chan string, 4)
	configAppliedCh := make(chan int64, 4)
	serviceCtlCh := make(chan string, 4)
	updateResultCh := make(chan protocol.AgentEvent, 8)
	pingErrCh := make(chan error, 1)
	syncErrCh := make(chan string, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		// Read agent.hello
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}

		sendFrame := func(msgType string, payload any) {
			b, _ := protocol.MarshalEnvelope(msgType, "srv", payload)
			_ = conn.Write(ctx, websocket.MessageText, b)
		}

		// Start server read loop BEFORE calling conn.Ping so server can receive Pong and event frames.
		readDone := make(chan struct{})
		go func() {
			defer close(readDone)
			for {
				_, data, err := conn.Read(ctx)
				if err != nil {
					return
				}
				env, err := protocol.ParseEnvelope(data)
				if err != nil {
					continue
				}
				if env.Type == protocol.MsgTypeAgentEvent {
					var ev protocol.AgentEvent
					if err := env.DecodePayload(&ev); err == nil && ev.Event == protocol.EventKernelUpdateResult {
						updateResultCh <- ev
					}
				}
			}
		}()

		// Send v1 first and wait until runUpdateWorker has dequeued v1 and entered OnKernelUpdate
		// before sending v2 (fills UpdateQueueSize=1) and v3 (deterministically overflows).
		sendFrame(protocol.MsgTypeServerKernelUpdate, protocol.ServerKernelUpdate{
			Kernel: protocol.KernelSingBox, Version: "v1", DownloadURL: "https://example.com/1",
		})
		select {
		case <-updateStarted:
		case <-time.After(3 * time.Second):
			syncErrCh <- "timed out waiting for v1 OnKernelUpdate to start"
			return
		case <-ctx.Done():
			return
		}

		sendFrame(protocol.MsgTypeServerKernelUpdate, protocol.ServerKernelUpdate{
			Kernel: protocol.KernelSingBox, Version: "v2", DownloadURL: "https://example.com/2",
		})
		sendFrame(protocol.MsgTypeServerKernelUpdate, protocol.ServerKernelUpdate{
			Kernel: protocol.KernelSingBox, Version: "v3", DownloadURL: "https://example.com/3",
		})

		// Verify Ping + config_sync + service_ctl stay responsive while v1 OnKernelUpdate is blocked!
		sendFrame(protocol.MsgTypeServerConfigSync, protocol.ServerConfigSync{ConfigRevision: 42})
		sendFrame(protocol.MsgTypeServerServiceCtl, protocol.ServerServiceCtl{Action: protocol.ServiceActionRestartSingBox})

		pctx, pcancel := context.WithTimeout(ctx, 2*time.Second)
		pingErrCh <- conn.Ping(pctx)
		pcancel()

		<-readDone
	}))
	defer srv.Close()

	var once sync.Once
	var orderMu sync.Mutex
	var cmdOrder []string

	client, err := New(Options{
		PanelURL:        srv.URL,
		NodeToken:       "nd_live_dispatch_test_1234",
		UpdateQueueSize: 1,
		PingInterval:    -1,
		OnConfigSync: func(ctx context.Context, cfg protocol.ServerConfigSync) {
			orderMu.Lock()
			cmdOrder = append(cmdOrder, "config_sync")
			orderMu.Unlock()
			configAppliedCh <- cfg.ConfigRevision
		},
		OnServiceCtl: func(ctx context.Context, cmd protocol.ServerServiceCtl) {
			orderMu.Lock()
			cmdOrder = append(cmdOrder, "service_ctl")
			orderMu.Unlock()
			serviceCtlCh <- cmd.Action
		},
		OnKernelUpdate: func(ctx context.Context, req protocol.ServerKernelUpdate) {
			appliedUpdatesCh <- req.Version
			once.Do(func() {
				close(updateStarted)
				select {
				case <-releaseUpdate:
				case <-ctx.Done():
				}
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := startTestClient(t, client)
	defer stop()

	// Confirm v1 entered OnKernelUpdate first.
	select {
	case msg := <-syncErrCh:
		t.Fatal(msg)
	case ver := <-appliedUpdatesCh:
		if ver != "v1" {
			t.Fatalf("expected first applied update v1, got %q", ver)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for v1 OnKernelUpdate")
	}

	// Ping must succeed while OnKernelUpdate is blocked!
	select {
	case msg := <-syncErrCh:
		t.Fatal(msg)
	case err := <-pingErrCh:
		if err != nil {
			t.Fatalf("WS Ping failed while kernel update was running: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for WS Ping response during slow kernel update")
	}

	// config_sync & service_ctl must execute immediately without waiting for OnKernelUpdate!
	select {
	case rev := <-configAppliedCh:
		if rev != 42 {
			t.Fatalf("expected rev 42, got %d", rev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("config_sync blocked behind kernel update")
	}

	select {
	case act := <-serviceCtlCh:
		if act != protocol.ServiceActionRestartSingBox {
			t.Fatalf("unexpected service_ctl action: %q", act)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("service_ctl blocked behind kernel update")
	}

	// Overflow update_failed event must have been emitted for v3!
	select {
	case ev := <-updateResultCh:
		if ev.Status != "update_failed" || ev.Version != "v3" {
			t.Fatalf("unexpected overflow event: %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for kernel_update queue overflow event")
	}

	// Release v1 and verify queued v2 is applied before shutting down.
	close(releaseUpdate)
	select {
	case ver := <-appliedUpdatesCh:
		if ver != "v2" {
			t.Fatalf("expected queued update v2 after release, got %q", ver)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queued v2 OnKernelUpdate after release")
	}

	stop()

	select {
	case extra := <-appliedUpdatesCh:
		t.Fatalf("unexpected extra kernel update applied (v3 should have overflowed): %q", extra)
	default:
	}

	orderMu.Lock()
	if len(cmdOrder) != 2 || cmdOrder[0] != "config_sync" || cmdOrder[1] != "service_ctl" {
		t.Fatalf("expected ordered [config_sync service_ctl], got %v", cmdOrder)
	}
	orderMu.Unlock()
}

func TestClientPingKeepaliveDetectsDeadPeer(t *testing.T) {
	var dials atomic.Int32
	reconnected := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := dials.Add(1)
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if _, _, err := conn.Read(ctx); err != nil {
			return
		}
		if n == 1 {
			// Stop calling conn.Read so Pong is never sent back -> client's PingTimeout fires!
			time.Sleep(500 * time.Millisecond)
			return
		}
		select {
		case <-reconnected:
		default:
			close(reconnected)
		}
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	client, err := New(Options{
		PanelURL:        srv.URL,
		NodeToken:       "nd_live_ping_keepalive_1234",
		PingInterval:    25 * time.Millisecond,
		PingTimeout:     40 * time.Millisecond,
		BackoffBase:     15 * time.Millisecond,
		BackoffMax:      30 * time.Millisecond,
		MetricsInterval: 5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := startTestClient(t, client)
	defer stop()

	select {
	case <-reconnected:
	case <-time.After(3 * time.Second):
		t.Fatalf("expected client to detect dead peer via ping timeout and reconnect (dials=%d)", dials.Load())
	}
	stop()
}

func TestPrependEventFullQueueDropsOldestPreservesNewest(t *testing.T) {
	var logBuf bytes.Buffer
	client, err := New(Options{
		PanelURL:       "wss://panel.example.com",
		NodeToken:      "nd_live_prepend_test_1234",
		EventQueueSize: 2,
		Logger:         slog.New(slog.NewTextHandler(&logBuf, nil)),
	})
	if err != nil {
		t.Fatalf("wsclient.New failed: %v", err)
	}

	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 1, Status: protocol.EventStatusSuccess})
	popped, ok := client.popEvent()
	if !ok || popped.ConfigRevision != 1 {
		t.Fatalf("expected popped rev=1, got ok=%v ev=%+v", ok, popped)
	}

	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 2, Status: protocol.EventStatusSuccess})
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 3, Status: protocol.EventStatusSuccess})

	// Re-queueing rev=1 onto full queue (cap=2, holding [2, 3]) must drop rev=1 (oldest) and keep [2, 3].
	client.prependEvent(popped)

	var remaining []int64
	for {
		ev, ok := client.popEvent()
		if !ok {
			break
		}
		remaining = append(remaining, ev.ConfigRevision)
	}
	if len(remaining) != 2 || remaining[0] != 2 || remaining[1] != 3 {
		t.Fatalf("expected [2 3] preserved after prependEvent on full queue, got %v", remaining)
	}
	if !strings.Contains(logBuf.String(), "wsclient event queue full during re-queue, dropping oldest event") {
		t.Fatalf("expected warning log when dropping oldest event on re-queue, got %q", logBuf.String())
	}

	// Verify non-full prepend still preserves FIFO order [1, 2].
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 1})
	head, ok := client.popEvent()
	if !ok || head.ConfigRevision != 1 {
		t.Fatalf("expected head rev=1, got ok=%v ev=%+v", ok, head)
	}
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 2})
	client.prependEvent(head)

	ev1, ok1 := client.popEvent()
	ev2, ok2 := client.popEvent()
	if !ok1 || !ok2 || ev1.ConfigRevision != 1 || ev2.ConfigRevision != 2 {
		t.Fatalf("expected [1 2] after non-full prepend, got (%v,%d) (%v,%d)", ok1, ev1.ConfigRevision, ok2, ev2.ConfigRevision)
	}
}

func TestClientTLSSkipVerifyFalseRejectsUntrustedCert(t *testing.T) {
	var handlerCalled atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled.Store(true)
		http.Error(w, "should not reach handler", http.StatusInternalServerError)
	}))
	defer srv.Close()

	var logBuf syncLogBuffer
	client, err := New(Options{
		PanelURL:      srv.URL,
		NodeToken:     "nd_live_tls_strict_test_1234",
		TLSSkipVerify: false,
		DialTimeout:   500 * time.Millisecond,
		BackoffBase:   15 * time.Millisecond,
		BackoffMax:    30 * time.Millisecond,
		Logger:        slog.New(slog.NewTextHandler(&logBuf, nil)),
	})
	if err != nil {
		t.Fatalf("wsclient.New failed: %v", err)
	}

	stop := startTestClient(t, client)
	defer stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		logs := logBuf.String()
		if strings.Contains(logs, "panel websocket dial failed") &&
			(strings.Contains(logs, "x509:") || strings.Contains(strings.ToLower(logs), "certificate")) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	stop()

	logs := logBuf.String()
	if !strings.Contains(logs, "panel websocket dial failed") ||
		(!strings.Contains(logs, "x509:") && !strings.Contains(strings.ToLower(logs), "certificate")) {
		t.Fatalf("expected TLS certificate verification failure log, got %q", logs)
	}
	if client.Connected() {
		t.Fatal("expected client.Connected() == false when TLS certificate is untrusted")
	}
	if handlerCalled.Load() {
		t.Fatal("expected TLS handshake failure before reaching HTTP handler")
	}
}

func TestNormalizeWSURL_SubpathAndEndpointURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"https://example.com/panel", "wss://example.com/panel/api/v1/agent/ws"},
		{"https://example.com/panel/", "wss://example.com/panel/api/v1/agent/ws"},
		{"http://127.0.0.1:8080/a/b", "ws://127.0.0.1:8080/a/b/api/v1/agent/ws"},
		{"wss://example.com/panel/api/v1/agent/ws", "wss://example.com/panel/api/v1/agent/ws"},
		{"wss://example.com/panel/api/v1/agent/ws/", "wss://example.com/panel/api/v1/agent/ws"},
		{"https://example.com/panel?foo=bar", "wss://example.com/panel/api/v1/agent/ws?foo=bar"},
	}
	for _, tc := range cases {
		got, err := NormalizeWSURL(tc.in)
		if err != nil {
			t.Fatalf("NormalizeWSURL(%q) err: %v", tc.in, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeWSURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
		cl, err := New(Options{
			PanelURL:  tc.in,
			NodeToken: "nd_live_endpoint_url_test_1234",
		})
		if err != nil {
			t.Fatalf("New(%q) err: %v", tc.in, err)
		}
		if cl.EndpointURL() != tc.want {
			t.Fatalf("EndpointURL() = %q, want %q", cl.EndpointURL(), tc.want)
		}
	}
}

func TestWSClient_SlowDeadSocketWriteTimeoutAndBackoffReset(t *testing.T) {
	var dials atomic.Int32
	reconnectedHealthy := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := dials.Add(1)
		if n == 1 {
			// Accept handshake, then stall TCP connection without reading so client's WriteTimeout fires.
			hj, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "no hijack", http.StatusInternalServerError)
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			// Hold the raw TCP socket open without completing WS handshake or reading, or
			// better: accept WS and close underlying TCP read? No, raw stall after HTTP 101 works too:
			_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
			time.Sleep(500 * time.Millisecond)
			return
		}

		if n == 2 {
			// Second dial: accept WS, read hello, then sleep longer than HealthyResetDuration?
			// First verify fast fail/reconnect; for n == 2 accept and keep alive.
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			env, err := protocol.ParseEnvelope(data)
			if err == nil && env.Type == protocol.MsgTypeAgentHello {
				// Send a harmless server frame so receivedFrame=true & healthy session.
				syncBytes, _ := protocol.MarshalEnvelope(protocol.MsgTypeServerServiceCtl, "r1", protocol.ServerServiceCtl{Action: protocol.ServiceActionRestartSingBox})
				_ = conn.Write(r.Context(), websocket.MessageText, syncBytes)
				select {
				case <-reconnectedHealthy:
				default:
					close(reconnectedHealthy)
				}
			}
		}
	}))
	defer srv.Close()

	// Also test DialTimeout against a non-reading raw TCP listener (silent SYN/accept stall).
	stallLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer stallLn.Close()
	go func() {
		for {
			c, err := stallLn.Accept()
			if err != nil {
				return
			}
			time.Sleep(200 * time.Millisecond)
			_ = c.Close()
		}
	}()
	stallClient, err := New(Options{
		PanelURL:    "http://" + stallLn.Addr().String(),
		NodeToken:   "nd_live_stall_dial_1234",
		DialTimeout: 40 * time.Millisecond,
		BackoffBase: 10 * time.Millisecond,
		BackoffMax:  20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	stopStall := startTestClient(t, stallClient)
	time.Sleep(100 * time.Millisecond)
	stopStall()

	var logBuf syncLogBuffer
	var svcCount atomic.Int32
	client, err := New(Options{
		PanelURL:             srv.URL + "/panel",
		NodeToken:            "nd_live_write_timeout_test_1234",
		DialTimeout:          100 * time.Millisecond,
		WriteTimeout:         50 * time.Millisecond,
		HealthyResetDuration: 30 * time.Millisecond,
		BackoffBase:          15 * time.Millisecond,
		BackoffMax:           60 * time.Millisecond,
		PingInterval:         -1,
		Logger:               slog.New(slog.NewTextHandler(&logBuf, nil)),
		OnServiceCtl: func(ctx context.Context, cmd protocol.ServerServiceCtl) {
			svcCount.Add(1)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	stop := startTestClient(t, client)
	defer stop()

	select {
	case <-reconnectedHealthy:
	case <-time.After(4 * time.Second):
		t.Fatalf("expected recovery after stalled socket (dials=%d logs=%s)", dials.Load(), logBuf.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && svcCount.Load() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if svcCount.Load() < 1 {
		t.Fatalf("expected OnServiceCtl delivered on recovered session")
	}
	stop()
}

func TestWSClient_MalformedInboundAndEventQueueOverflow(t *testing.T) {
	var logBuf syncLogBuffer
	connected := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		// Read hello.
		if _, _, err := conn.Read(r.Context()); err != nil {
			return
		}
		// Send malformed JSON, bad config_sync payload, bad service_ctl payload, bad kernel_update payload, unknown msg type.
		_ = conn.Write(r.Context(), websocket.MessageText, []byte("{bad-json"))
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"server.config_sync","req_id":"1","payload":"not-an-object"}`))
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"server.service_ctl","req_id":"2","payload":123}`))
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"server.kernel_update","req_id":"3","payload":true}`))
		_ = conn.Write(r.Context(), websocket.MessageText, []byte(`{"type":"server.unknown_future","req_id":"4","payload":{}}`))
		// Valid service_ctl after malformed frames to prove session stayed alive.
		valid, _ := protocol.MarshalEnvelope(protocol.MsgTypeServerServiceCtl, "5", protocol.ServerServiceCtl{Action: protocol.ServiceActionRestartSnell})
		_ = conn.Write(r.Context(), websocket.MessageText, valid)

		close(connected)
		for {
			if _, _, err := conn.Read(r.Context()); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	var gotAction atomic.Value
	client, err := New(Options{
		PanelURL:       srv.URL,
		NodeToken:      "nd_live_malformed_inbound_1234",
		EventQueueSize: 2,
		PingInterval:   -1,
		Logger:         slog.New(slog.NewTextHandler(&logBuf, nil)),
		OnServiceCtl: func(ctx context.Context, cmd protocol.ServerServiceCtl) {
			gotAction.Store(cmd.Action)
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Overflow event queue while disconnected: oldest (rev=1) must be evicted, [2, 3] kept.
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 1})
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 2})
	client.SendEvent(protocol.AgentEvent{Event: protocol.EventConfigApplied, ConfigRevision: 3})

	stop := startTestClient(t, client)
	defer stop()

	select {
	case <-connected:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server handshake")
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && gotAction.Load() == nil {
		time.Sleep(10 * time.Millisecond)
	}
	if gotAction.Load() != protocol.ServiceActionRestartSnell {
		t.Fatalf("expected valid command processed after malformed frames, got %v", gotAction.Load())
	}
	stop()

	logs := logBuf.String()
	for _, want := range []string{
		"agent event queue full, dropped oldest event",
		"failed to parse server envelope",
		"invalid server.config_sync payload",
		"invalid server.service_ctl payload",
		"invalid server.kernel_update payload",
	} {
		if !strings.Contains(logs, want) {
			t.Fatalf("expected log substring %q in logs:\n%s", want, logs)
		}
	}
}
