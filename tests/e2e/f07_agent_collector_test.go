//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type f07_walFile struct {
	Version    int                            `json:"version"`
	NicRxDelta uint64                         `json:"nic_rx_delta"`
	NicTxDelta uint64                         `json:"nic_tx_delta"`
	UserDeltas map[string]UserTrafficDeltaDTO `json:"user_deltas"`
}

type f07_mockPanelWS struct {
	t    *testing.T
	addr string

	mu      sync.Mutex
	srv     *http.Server
	conns   map[*websocket.Conn]struct{}
	hellos  []AgentHelloPayload
	metrics []AgentMetricsPayload
	events  []AgentEventPayload
}

func f07_newMockPanelWS(t *testing.T) *f07_mockPanelWS {
	t.Helper()
	port := AllocFreePort(t)
	m := &f07_mockPanelWS{
		t:     t,
		addr:  fmt.Sprintf("127.0.0.1:%d", port),
		conns: make(map[*websocket.Conn]struct{}),
	}
	m.Start()
	t.Cleanup(func() { m.Stop() })
	return m
}

func (m *f07_mockPanelWS) WSBaseURL() string { return "ws://" + m.addr }

func (m *f07_mockPanelWS) Start() {
	m.t.Helper()
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		m.t.Fatalf("f07_mockPanelWS listen %s: %v", m.addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", m.handleWS)
	srv := &http.Server{Handler: mux}
	m.mu.Lock()
	m.srv = srv
	m.mu.Unlock()
	go func() { _ = srv.Serve(ln) }()
}

func (m *f07_mockPanelWS) Stop() {
	m.mu.Lock()
	srv := m.srv
	m.srv = nil
	conns := make([]*websocket.Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = make(map[*websocket.Conn]struct{})
	m.mu.Unlock()
	for _, c := range conns {
		_ = c.CloseNow()
	}
	if srv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = srv.Shutdown(ctx)
		cancel()
	}
}

func (m *f07_mockPanelWS) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.conns[conn] = struct{}{}
	m.mu.Unlock()
	defer func() {
		m.mu.Lock()
		delete(m.conns, conn)
		m.mu.Unlock()
		_ = conn.CloseNow()
	}()
	for {
		_, data, err := conn.Read(r.Context())
		if err != nil {
			return
		}
		var env WSEnvelope
		if json.Unmarshal(data, &env) != nil {
			continue
		}
		m.mu.Lock()
		switch env.Type {
		case "agent.hello":
			var p AgentHelloPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.hellos = append(m.hellos, p)
			}
		case "agent.metrics":
			var p AgentMetricsPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.metrics = append(m.metrics, p)
			}
		case "agent.event":
			var p AgentEventPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.events = append(m.events, p)
			}
		}
		m.mu.Unlock()
	}
}

func (m *f07_mockPanelWS) SendEnvelope(msgType, reqID string, payload any) error {
	m.mu.Lock()
	var target *websocket.Conn
	for c := range m.conns {
		target = c
	}
	m.mu.Unlock()
	if target == nil {
		return fmt.Errorf("no active ws connection")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	return SendWSEnvelope(ctx, target, msgType, reqID, payload)
}

func (m *f07_mockPanelWS) WaitForHelloCount(n int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		got := len(m.hellos)
		m.mu.Unlock()
		if got >= n {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func (m *f07_mockPanelWS) WaitForEvent(timeout time.Duration, match func(AgentEventPayload) bool) (AgentEventPayload, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		for _, ev := range m.events {
			if match(ev) {
				m.mu.Unlock()
				return ev, true
			}
		}
		m.mu.Unlock()
		time.Sleep(25 * time.Millisecond)
	}
	return AgentEventPayload{}, false
}

func (m *f07_mockPanelWS) WaitForMetricsCount(n int, timeout time.Duration) ([]AgentMetricsPayload, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		if len(m.metrics) >= n {
			out := append([]AgentMetricsPayload(nil), m.metrics...)
			m.mu.Unlock()
			return out, true
		}
		m.mu.Unlock()
		time.Sleep(50 * time.Millisecond)
	}
	m.mu.Lock()
	out := append([]AgentMetricsPayload(nil), m.metrics...)
	m.mu.Unlock()
	return out, false
}

func (m *f07_mockPanelWS) MetricsSince(idx int) []AgentMetricsPayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= len(m.metrics) {
		return nil
	}
	return append([]AgentMetricsPayload(nil), m.metrics[idx:]...)
}

func (m *f07_mockPanelWS) MetricsLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.metrics)
}

func f07_b64Key16(seed string) string {
	b := make([]byte, 16)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func f07_baseSyncPayload(t *testing.T, rev int64, dnsPort int, upstreamDNS string, ssEnabled bool) ServerConfigSyncPayload {
	t.Helper()
	return ServerConfigSyncPayload{
		ConfigRevision: rev,
		Snell: SnellConfigDTO{
			Enabled:      true,
			Version:      "v5",
			PublicPort:   AllocFreePort(t),
			InnerPort:    AllocFreePort(t),
			PSK:          "f07-snell-psk",
			Obfs:         "off",
			STLSPassword: "f07-stls-pwd",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: SSConfigDTO{
			Enabled: ssEnabled,
			TCPPort: AllocFreePort(t),
			UDPPort: AllocFreeUDPPort(t),
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    f07_b64Key16("f07-server-ipsk!"),
			STLSSNI: "swscan.apple.com",
			Users: []SSUserEntryDTO{
				{UserID: 101, Username: "alice", UPSK: f07_b64Key16("f07-alice-upsk!!"), STLSPassword: "p1"},
				{UserID: 102, Username: "bob", UPSK: f07_b64Key16("f07-bob-upsk!!!!"), STLSPassword: "p2"},
			},
		},
		DNS: DNSConfigDTO{
			UnlockEnabled: false,
			UpstreamDNS:   upstreamDNS,
			LocalPort:     dnsPort,
		},
	}
}

func f07_waitTCPReady(t *testing.T, addr string, timeout time.Duration) {
	t.Helper()
	dl := time.Now().Add(timeout)
	for time.Now().Before(dl) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("TCP addr %s not listening within %s", addr, timeout)
}

func f07_readWAL(walPath string) (f07_walFile, error) {
	b, err := os.ReadFile(walPath)
	if err != nil {
		return f07_walFile{}, err
	}
	var w f07_walFile
	if err := json.Unmarshal(b, &w); err != nil {
		return f07_walFile{}, err
	}
	return w, nil
}

func TestF07_Tier1_ProcNetDevIncrementalDeltaCollection(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 2000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_proc_net_dev",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), false)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatalf("expected initial baseline agent.metrics; logs:\n%s", ag.Logs())
	}

	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 6000, 10000)

	var rxSum, txSum uint64
	dl := time.Now().Add(25 * time.Second)
	for time.Now().Before(dl) {
		rxSum, txSum = 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
		}
		if rxSum >= 5000 && txSum >= 8000 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rxSum != 5000 || txSum != 8000 {
		t.Fatalf("expected nic_rx_delta=5000 nic_tx_delta=8000, got rx=%d tx=%d", rxSum, txSum)
	}

	// Steady fixture -> subsequent frame must report 0 delta
	steadyMark := srv.MetricsLen()
	dl2 := time.Now().Add(20 * time.Second)
	for time.Now().Before(dl2) {
		frames := srv.MetricsSince(steadyMark)
		if len(frames) >= 1 {
			if frames[0].NicRxDelta != 0 || frames[0].NicTxDelta != 0 {
				t.Fatalf("expected 0 delta on steady fixture, got rx=%d tx=%d", frames[0].NicRxDelta, frames[0].NicTxDelta)
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("expected subsequent steady agent.metrics frame")
}

func TestF07_Tier1_SingBoxGRPCUserStatsCollection(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_grpc_stats",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), true)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied; logs:\n%s", ag.Logs())
	}
	f07_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)

	mark := srv.MetricsLen()
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 1500},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 3500},
		{Name: "user>>>bob>>>traffic>>>uplink", Value: 200},
		{Name: "user>>>bob>>>traffic>>>downlink", Value: 800},
	})

	dl := time.Now().Add(25 * time.Second)
	var upMap, downMap map[string]uint64
	var idMap map[string]int64
	for time.Now().Before(dl) {
		upMap = map[string]uint64{}
		downMap = map[string]uint64{}
		idMap = map[string]int64{}
		for _, m := range srv.MetricsSince(mark) {
			for _, u := range m.UserDeltas {
				upMap[u.Username] += u.UpBytes
				downMap[u.Username] += u.DownBytes
				if u.UserID != 0 {
					idMap[u.Username] = u.UserID
				}
			}
		}
		if upMap["alice"] >= 1500 && downMap["alice"] >= 3500 && upMap["bob"] >= 200 && downMap["bob"] >= 800 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if upMap["alice"] != 1500 || downMap["alice"] != 3500 || upMap["bob"] != 200 || downMap["bob"] != 800 {
		t.Fatalf("unexpected user_deltas: up=%+v down=%+v", upMap, downMap)
	}
	if idMap["alice"] != 101 || idMap["bob"] != 102 {
		t.Fatalf("expected user IDs alice=101 bob=102, got %+v", idMap)
	}

	// Verify mock stats.json was reset by QueryStats(reset: true)
	for _, st := range kernels.ReadStats() {
		if st.Value != 0 {
			t.Fatalf("expected mock stats reset to 0, got %+v", st)
		}
	}
}

func TestF07_Tier1_WALPersistenceDuringDisconnectAndFlush(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 2000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_wal_flush",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), true)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied; logs:\n%s", ag.Logs())
	}
	f07_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatalf("expected baseline metrics")
	}

	// Stop mock WS server and accumulate traffic while disconnected
	srv.Stop()
	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 11000, 22000)
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 4000},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 6000},
	})

	walPath := filepath.Join(ag.DataDir, "pending_traffic.json")
	dl := time.Now().Add(25 * time.Second)
	var wal f07_walFile
	for time.Now().Before(dl) {
		if w, err := f07_readWAL(walPath); err == nil {
			wal = w
			if w.NicRxDelta >= 10000 && w.NicTxDelta >= 20000 && w.UserDeltas["alice"].UpBytes >= 4000 && w.UserDeltas["alice"].DownBytes >= 6000 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if wal.NicRxDelta != 10000 || wal.NicTxDelta != 20000 || wal.UserDeltas["alice"].UpBytes != 4000 || wal.UserDeltas["alice"].DownBytes != 6000 {
		t.Fatalf("expected WAL to persist offline deltas, got %+v", wal)
	}

	// Restart mock WS on same port and verify flush
	srv.Start()
	if !srv.WaitForHelloCount(2, 35*time.Second) {
		t.Fatalf("expected reconnect hello")
	}

	dlFlush := time.Now().Add(20 * time.Second)
	var rxSum, txSum, aUp, aDown uint64
	for time.Now().Before(dlFlush) {
		rxSum, txSum, aUp, aDown = 0, 0, 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
			for _, u := range m.UserDeltas {
				if u.Username == "alice" {
					aUp += u.UpBytes
					aDown += u.DownBytes
				}
			}
		}
		if rxSum >= 10000 && txSum >= 20000 && aUp >= 4000 && aDown >= 6000 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rxSum != 10000 || txSum != 20000 || aUp != 4000 || aDown != 6000 {
		t.Fatalf("WAL flush mismatch: rx=%d tx=%d aliceUp=%d aliceDown=%d", rxSum, txSum, aUp, aDown)
	}

	// WAL must be cleared after flush
	dlClear := time.Now().Add(5 * time.Second)
	for time.Now().Before(dlClear) {
		if w, err := f07_readWAL(walPath); err == nil && w.NicRxDelta == 0 && w.NicTxDelta == 0 && len(w.UserDeltas) == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	wAfter, _ := f07_readWAL(walPath)
	t.Fatalf("expected WAL cleared after flush, got %+v", wAfter)
}

func TestF07_Tier1_HostMetricsAndKernelHealthReporting(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_host_health",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	sync1 := f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), true)
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}

	var healthyFrame AgentMetricsPayload
	var gotHealthy bool
	dl := time.Now().Add(20 * time.Second)
	for time.Now().Before(dl) {
		for _, m := range srv.MetricsSince(0) {
			if m.Health.Snell && m.Health.ShadowTLS && m.Health.SingBox {
				healthyFrame = m
				gotHealthy = true
			}
		}
		if gotHealthy {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !gotHealthy {
		t.Fatalf("expected agent.metrics with all 3 kernels healthy")
	}
	if healthyFrame.TS <= 0 || healthyFrame.MemTotalBytes == 0 || healthyFrame.MemUsedBytes == 0 ||
		healthyFrame.DiskUsedPercent < 0 || healthyFrame.DiskUsedPercent > 100 || healthyFrame.CPUPercent < 0 {
		t.Fatalf("invalid host telemetry in agent.metrics: %+v", healthyFrame)
	}

	// Disable SS and confirm health reflects SingBox=false while Snell/ShadowTLS stay true
	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.Enabled = false
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("expected config_applied rev 2")
	}
	mark := srv.MetricsLen()
	dl2 := time.Now().Add(20 * time.Second)
	for time.Now().Before(dl2) {
		for _, m := range srv.MetricsSince(mark) {
			if m.Health.Snell && m.Health.ShadowTLS && !m.Health.SingBox {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected agent.metrics to report SingBox=false after SS disabled")
}

func TestF07_Tier1_WALSurvivesAgentProcessRestart(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 500, 500)
	dataDir := filepath.Join(env.RootDir, "wal-restart-data")
	dnsPort := AllocFreeDualPort(t)
	statsPort := AllocFreePort(t)

	ag1 := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_wal_restart",
		DataDir:        dataDir,
		LocalDNSPort:   dnsPort,
		StatsPort:      statsPort,
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent #1 hello; logs:\n%s", ag1.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, dnsPort, normalDNS.Addr(), true)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied")
	}
	f07_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", statsPort), 5*time.Second)
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatal("expected initial baseline metrics")
	}

	// Disconnect WS, update traffic & stats, wait for WAL persistence, then stop Agent #1
	srv.Stop()
	UpdateProcNetDevFixture(t, procPath, "eth0", 5500, 8500)
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 700},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 900},
	})

	walPath := filepath.Join(dataDir, "pending_traffic.json")
	dl := time.Now().Add(25 * time.Second)
	var wal f07_walFile
	for time.Now().Before(dl) {
		if w, err := f07_readWAL(walPath); err == nil {
			wal = w
			if w.NicRxDelta >= 5000 && w.NicTxDelta >= 8000 && w.UserDeltas["alice"].UpBytes >= 700 && w.UserDeltas["alice"].DownBytes >= 900 {
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	if wal.NicRxDelta < 5000 || wal.UserDeltas["alice"].UpBytes < 700 {
		t.Fatalf("expected WAL persisted before agent restart, got %+v", wal)
	}

	if err := ag1.Stop(); err != nil {
		t.Fatalf("ag1.Stop(): %v", err)
	}

	// Bring panel back up and start Agent #2 with same DataDir
	srv.Start()
	mark := srv.MetricsLen()
	ag2 := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_wal_restart",
		DataDir:        dataDir,
		LocalDNSPort:   dnsPort,
		StatsPort:      statsPort,
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})
	_ = ag2

	dlFlush := time.Now().Add(20 * time.Second)
	var rxSum, txSum, aUp, aDown uint64
	for time.Now().Before(dlFlush) {
		rxSum, txSum, aUp, aDown = 0, 0, 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
			for _, u := range m.UserDeltas {
				if u.Username == "alice" {
					aUp += u.UpBytes
					aDown += u.DownBytes
				}
			}
		}
		if rxSum >= 5000 && txSum >= 8000 && aUp >= 700 && aDown >= 900 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("pre-restart WAL deltas not flushed by ag2: rx=%d tx=%d aUp=%d aDown=%d", rxSum, txSum, aUp, aDown)
}

func TestF07_Tier2_RebootCounterResetNoUnderflow(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 50000, 80000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_reboot_reset",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), false)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatal("expected baseline metrics")
	}

	// Simulate host reboot counter reset (50000,80000) -> (1200,3400)
	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 1200, 3400)

	// Wait >= 8s so 5s NIC poll observes the reset with jitter margin
	time.Sleep(8 * time.Second)
	for _, m := range srv.MetricsSince(mark) {
		if m.NicRxDelta != 0 || m.NicTxDelta != 0 {
			t.Fatalf("expected 0 delta on reboot counter reset (no uint64 underflow!), got rx=%d tx=%d", m.NicRxDelta, m.NicTxDelta)
		}
	}

	// Now increment from new post-reboot baseline (1200, 3400) -> (2200, 5400)
	mark2 := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 2200, 5400)

	dl := time.Now().Add(20 * time.Second)
	var rxSum, txSum uint64
	for time.Now().Before(dl) {
		rxSum, txSum = 0, 0
		for _, m := range srv.MetricsSince(mark2) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
		}
		if rxSum >= 1000 && txSum >= 2000 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rxSum != 1000 || txSum != 2000 {
		t.Fatalf("expected post-reset increment rx=1000 tx=2000, got rx=%d tx=%d", rxSum, txSum)
	}
}

func TestF07_Tier2_CorruptOrMissingProcNetDevResilience(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	procPath := filepath.Join(t.TempDir(), "corrupt_proc_net_dev")
	if err := os.WriteFile(procPath, []byte("corrupt-content-without-eth0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_corrupt_proc",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), false)); err != nil {
		t.Fatal(err)
	}

	// Agent must keep sending metrics even while /proc/net/dev is corrupt
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatalf("expected agent.metrics heartbeat even with corrupt /proc/net/dev")
	}

	// Restore valid /proc/net/dev, wait for baseline poll, then increment
	UpdateProcNetDevFixture(t, procPath, "eth0", 1000, 2000)
	time.Sleep(8 * time.Second)
	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 3000, 6000)

	dl := time.Now().Add(20 * time.Second)
	var rxSum, txSum uint64
	for time.Now().Before(dl) {
		rxSum, txSum = 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
		}
		if rxSum >= 2000 && txSum >= 4000 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("collector failed to recover after valid /proc/net/dev restored: rx=%d tx=%d", rxSum, txSum)
}

func TestF07_Tier2_GRPCUnavailableFallbackStillBuffersNIC(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_grpc_fallback",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	// SS disabled -> sing-box not running -> gRPC StatsPort closed
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), false)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatal("expected baseline metrics")
	}

	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 4000, 5000)

	dl := time.Now().Add(20 * time.Second)
	var rxSum, txSum uint64
	for time.Now().Before(dl) {
		rxSum, txSum = 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
			if m.Health.SingBox {
				t.Fatalf("expected Health.SingBox=false when SS disabled")
			}
		}
		if rxSum >= 3000 && txSum >= 4000 {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("expected NIC deltas despite gRPC unavailable, got rx=%d tx=%d", rxSum, txSum)
}

func TestF07_Tier2_DuplicateWALReplayPrevention(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_no_dup_wal",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), false)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatal("expected baseline metrics")
	}

	srv.Stop()
	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 3500, 4500) // +2500 rx, +3500 tx

	walPath := filepath.Join(ag.DataDir, "pending_traffic.json")
	dl := time.Now().Add(20 * time.Second)
	for time.Now().Before(dl) {
		if w, err := f07_readWAL(walPath); err == nil && w.NicRxDelta >= 2500 && w.NicTxDelta >= 3500 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	srv.Start()
	if !srv.WaitForHelloCount(2, 35*time.Second) {
		t.Fatal("expected reconnect hello")
	}

	// Wait for flush
	dlFlush := time.Now().Add(20 * time.Second)
	var rxSum, txSum uint64
	for time.Now().Before(dlFlush) {
		rxSum, txSum = 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
		}
		if rxSum >= 2500 && txSum >= 3500 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rxSum != 2500 || txSum != 3500 {
		t.Fatalf("expected exact flush rx=2500 tx=3500, got rx=%d tx=%d", rxSum, txSum)
	}

	// Subsequent 2 metrics frames must NOT replay WAL deltas
	afterFlushMark := srv.MetricsLen()
	dlSteady := time.Now().Add(25 * time.Second)
	for time.Now().Before(dlSteady) {
		frames := srv.MetricsSince(afterFlushMark)
		if len(frames) >= 2 {
			for i, f := range frames[:2] {
				if f.NicRxDelta != 0 || f.NicTxDelta != 0 {
					t.Fatalf("duplicate WAL replay detected at frame %d: rx=%d tx=%d", i, f.NicRxDelta, f.NicTxDelta)
				}
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("expected 2 post-flush steady metrics frames")
}

func TestF07_Tier2_Large64BitCounterIncrements(t *testing.T) {
	env := NewTestEnv(t)
	srv := f07_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	procPath := WriteProcNetDevFixture(t, "eth0", 1000, 1000)

	ag := StartAgent(env, AgentConfig{
		PanelURL:       srv.WSBaseURL(),
		NodeToken:      "nd_live_f07_64bit_counters",
		Iface:          "eth0",
		ProcNetDevPath: procPath,
		SnellBin:       kernels.SnellBin,
		ShadowTLSBin:   kernels.ShadowTLSBin,
		SingBoxBin:     kernels.SingBoxBin,
	})

	if !srv.WaitForHelloCount(1, 8*time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", f07_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr(), true)); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatal("expected config_applied")
	}
	f07_waitTCPReady(t, fmt.Sprintf("127.0.0.1:%d", ag.StatsPort), 5*time.Second)
	if _, ok := srv.WaitForMetricsCount(1, 15*time.Second); !ok {
		t.Fatal("expected baseline metrics")
	}

	const eightGiB uint64 = 1 << 33
	const sixteenGiB uint64 = 1 << 34
	mark := srv.MetricsLen()
	UpdateProcNetDevFixture(t, procPath, "eth0", 1000+eightGiB, 1000+sixteenGiB)
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: int64(eightGiB)},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: int64(sixteenGiB)},
	})

	dl := time.Now().Add(25 * time.Second)
	var rxSum, txSum, aUp, aDown uint64
	for time.Now().Before(dl) {
		rxSum, txSum, aUp, aDown = 0, 0, 0, 0
		for _, m := range srv.MetricsSince(mark) {
			rxSum += m.NicRxDelta
			txSum += m.NicTxDelta
			for _, u := range m.UserDeltas {
				if u.Username == "alice" {
					aUp += u.UpBytes
					aDown += u.DownBytes
				}
			}
		}
		if rxSum >= eightGiB && txSum >= sixteenGiB && aUp >= eightGiB && aDown >= sixteenGiB {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if rxSum != eightGiB || txSum != sixteenGiB || aUp != eightGiB || aDown != sixteenGiB {
		t.Fatalf("64-bit counter truncation/mismatch: rx=%d tx=%d aUp=%d aDown=%d", rxSum, txSum, aUp, aDown)
	}
}
