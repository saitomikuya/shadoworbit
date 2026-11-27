//go:build e2e

package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/miekg/dns"
)

type f04_mockPanelWS struct {
	t    *testing.T
	addr string

	mu           sync.Mutex
	expectedTok  string
	rejectAuth   bool
	srv          *http.Server
	ln           net.Listener
	conns        map[*websocket.Conn]struct{}
	authHeaders  []string
	reqPaths     []string
	rejectedReqs int
	hellos       []AgentHelloPayload
	metrics      []AgentMetricsPayload
	events       []AgentEventPayload
	rawEnvs      []WSEnvelope
}

func f04_newMockPanelWS(t *testing.T, expectedToken string) *f04_mockPanelWS {
	t.Helper()
	port := AllocFreePort(t)
	m := &f04_mockPanelWS{
		t:           t,
		addr:        fmt.Sprintf("127.0.0.1:%d", port),
		expectedTok: expectedToken,
		conns:       make(map[*websocket.Conn]struct{}),
	}
	m.Start()
	t.Cleanup(func() {
		m.Stop()
	})
	return m
}

func (m *f04_mockPanelWS) HTTPBaseURL() string { return "http://" + m.addr }
func (m *f04_mockPanelWS) WSBaseURL() string   { return "ws://" + m.addr }

func (m *f04_mockPanelWS) SetRejectAuth(reject bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rejectAuth = reject
}

func (m *f04_mockPanelWS) Start() {
	m.t.Helper()
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		m.t.Fatalf("f04_mockPanelWS listen %s: %v", m.addr, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", m.handleWS)
	srv := &http.Server{Handler: mux}

	m.mu.Lock()
	m.ln = ln
	m.srv = srv
	m.mu.Unlock()

	go func() {
		_ = srv.Serve(ln)
	}()
}

func (m *f04_mockPanelWS) Stop() {
	m.mu.Lock()
	srv := m.srv
	m.srv = nil
	m.ln = nil
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

func (m *f04_mockPanelWS) CloseActiveConns() {
	m.mu.Lock()
	conns := make([]*websocket.Conn, 0, len(m.conns))
	for c := range m.conns {
		conns = append(conns, c)
	}
	m.conns = make(map[*websocket.Conn]struct{})
	m.mu.Unlock()

	for _, c := range conns {
		_ = c.CloseNow()
	}
}

func (m *f04_mockPanelWS) handleWS(w http.ResponseWriter, r *http.Request) {
	authHdr := r.Header.Get("Authorization")
	m.mu.Lock()
	m.authHeaders = append(m.authHeaders, authHdr)
	m.reqPaths = append(m.reqPaths, r.URL.Path)
	reject := m.rejectAuth
	expTok := m.expectedTok
	m.mu.Unlock()

	if reject || (expTok != "" && authHdr != "Bearer "+expTok) {
		m.mu.Lock()
		m.rejectedReqs++
		m.mu.Unlock()
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

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
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}
		m.mu.Lock()
		m.rawEnvs = append(m.rawEnvs, env)
		switch env.Type {
		case "agent.hello":
			var p AgentHelloPayload
			if err := json.Unmarshal(env.Payload, &p); err == nil {
				m.hellos = append(m.hellos, p)
			}
		case "agent.metrics":
			var p AgentMetricsPayload
			if err := json.Unmarshal(env.Payload, &p); err == nil {
				m.metrics = append(m.metrics, p)
			}
		case "agent.event":
			var p AgentEventPayload
			if err := json.Unmarshal(env.Payload, &p); err == nil {
				m.events = append(m.events, p)
			}
		}
		m.mu.Unlock()
	}
}

func (m *f04_mockPanelWS) SendEnvelope(msgType, reqID string, payload any) error {
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

func (m *f04_mockPanelWS) SendRawText(raw string) error {
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
	return target.Write(ctx, websocket.MessageText, []byte(raw))
}

func (m *f04_mockPanelWS) WaitForHelloCount(n int, timeout time.Duration) ([]AgentHelloPayload, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		out := append([]AgentHelloPayload(nil), m.hellos...)
		m.mu.Unlock()
		if len(out) >= n {
			return out, true
		}
		time.Sleep(25 * time.Millisecond)
	}
	m.mu.Lock()
	out := append([]AgentHelloPayload(nil), m.hellos...)
	m.mu.Unlock()
	return out, false
}

func (m *f04_mockPanelWS) WaitForEvent(timeout time.Duration, match func(AgentEventPayload) bool) (AgentEventPayload, bool) {
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

func (m *f04_mockPanelWS) SnapshotAuth() (headers []string, paths []string, rejected int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.authHeaders...), append([]string(nil), m.reqPaths...), m.rejectedReqs
}

func f04_baseSyncPayload(t *testing.T, rev int64, psk string, dnsPort int, unlockAddr, upstreamAddr string) ServerConfigSyncPayload {
	t.Helper()
	ipsk := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	upsk := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210"))
	return ServerConfigSyncPayload{
		ConfigRevision: rev,
		Snell: SnellConfigDTO{
			Enabled:         true,
			Version:         "v5",
			PublicPort:      AllocFreePort(t),
			InnerPort:       AllocFreePort(t),
			PSK:             psk,
			Obfs:            "off",
			TFO:             false,
			DNSIPPreference: "prefer-ipv4",
			STLSPassword:    "f04-stls-snell-pass",
			STLSSNI:         "gateway.icloud.com",
		},
		SS: SSConfigDTO{
			Enabled: true,
			TCPPort: AllocFreePort(t),
			UDPPort: AllocFreeUDPPort(t),
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    ipsk,
			STLSSNI: "swscan.apple.com",
			Users: []SSUserEntryDTO{
				{
					UserID:       101,
					Username:     "alice",
					UPSK:         upsk,
					STLSPassword: "f04-alice-stls-pass",
				},
			},
		},
		DNS: DNSConfigDTO{
			UnlockEnabled: unlockAddr != "",
			UnlockServer:  unlockAddr,
			Rules:         []string{"netflix.com"},
			UpstreamDNS:   upstreamAddr,
			LocalPort:     dnsPort,
		},
	}
}

func TestF04_Tier1_PersistentWSAuthAndHello(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_auth_token_12345"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.HTTPBaseURL(), // http:// must normalize to ws://
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	_ = ag

	hellos, ok := srv.WaitForHelloCount(1, 8*time.Second)
	if !ok {
		t.Fatalf("expected agent.hello over WS within 8s, got %d hellos; logs:\n%s", len(hellos), ag.Logs())
	}
	headers, paths, rejected := srv.SnapshotAuth()
	if rejected != 0 || len(headers) == 0 {
		t.Fatalf("unexpected auth state: headers=%v rejected=%d", headers, rejected)
	}
	if headers[0] != "Bearer "+token {
		t.Fatalf("expected Authorization %q, got %q", "Bearer "+token, headers[0])
	}
	if paths[0] != "/api/v1/agent/ws" {
		t.Fatalf("expected WS path /api/v1/agent/ws, got %q", paths[0])
	}

	h := hellos[0]
	if h.OS == "" || h.Arch == "" || h.CPUCores <= 0 || h.TotalRAMBytes == 0 {
		t.Fatalf("incomplete agent.hello host info: %+v", h)
	}
	if h.ConfigRevision != 0 {
		t.Fatalf("expected initial config_revision=0, got %d", h.ConfigRevision)
	}
	if !strings.Contains(h.Versions.SingBox, "1.11.4") || !strings.Contains(h.Versions.SnellServer, "5.0.0") || !strings.Contains(h.Versions.ShadowTLS, "0.2.25") {
		t.Fatalf("expected kernel versions populated in agent.hello, got %+v", h.Versions)
	}
}

func TestF04_Tier1_ConfigSyncApplicationAndRevisionPersistence(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_sync_persist"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if _, ok := srv.WaitForHelloCount(1, 8*time.Second); !ok {
		t.Fatalf("expected initial agent.hello; logs:\n%s", ag.Logs())
	}

	syncPayload := f04_baseSyncPayload(t, 7, "f04-rev7-psk", ag.LocalDNSPort, "", normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "sync-7", syncPayload); err != nil {
		t.Fatalf("SendEnvelope server.config_sync: %v", err)
	}

	ev, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 7
	})
	if !ok || ev.Status != "success" {
		t.Fatalf("expected config_applied event rev 7 success, got ok=%v ev=%+v", ok, ev)
	}

	cachePath := filepath.Join(ag.DataDir, "last_config.json")
	rawCache, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("expected persisted cache at %s: %v", cachePath, err)
	}
	var cached ServerConfigSyncPayload
	if err := json.Unmarshal(rawCache, &cached); err != nil {
		t.Fatalf("decode last_config.json: %v (raw=%s)", err, string(rawCache))
	}
	if cached.ConfigRevision != 7 || cached.Snell.PSK != "f04-rev7-psk" {
		t.Fatalf("unexpected last_config.json contents: %+v", cached)
	}

	// Force WS disconnect and confirm reconnecting hello reports config_revision == 7
	srv.CloseActiveConns()
	hellos, ok := srv.WaitForHelloCount(2, 10*time.Second)
	if !ok || len(hellos) < 2 {
		t.Fatalf("expected reconnect agent.hello after WS drop, got %d", len(hellos))
	}
	if hellos[len(hellos)-1].ConfigRevision != 7 {
		t.Fatalf("expected reconnect hello config_revision=7, got %d", hellos[len(hellos)-1].ConfigRevision)
	}
}

func TestF04_Tier1_ReconnectBackoffAfterPanelRestart(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_reconnect_backoff"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if _, ok := srv.WaitForHelloCount(1, 8*time.Second); !ok {
		t.Fatalf("expected initial agent.hello; logs:\n%s", ag.Logs())
	}

	// Shut down mock panel completely and confirm agent stays running
	srv.Stop()
	if err := ag.WaitExit(500 * time.Millisecond); !errors.Is(err, errWaitTimeout) {
		t.Fatalf("agent exited unexpectedly while panel was down: %v", err)
	}

	// Restart mock panel on the exact same port
	srv.Start()
	hellos, ok := srv.WaitForHelloCount(2, 12*time.Second)
	if !ok || len(hellos) < 2 {
		t.Fatalf("agent did not reconnect after panel restart; hellos=%d logs:\n%s", len(hellos), ag.Logs())
	}
}

func TestF04_Tier1_OfflineAutonomyFromCachedConfig(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_offline_autonomy"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"example.org": {"93.184.216.34"}},
	})
	unlockDNS := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{"netflix.com": {"203.0.113.99"}},
	})

	sharedDataDir := filepath.Join(env.RootDir, "agent-data")
	dnsPort := AllocFreeDualPort(t)
	statsPort := AllocFreePort(t)

	ag1 := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		DataDir:      sharedDataDir,
		LocalDNSPort: dnsPort,
		StatsPort:    statsPort,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if _, ok := srv.WaitForHelloCount(1, 8*time.Second); !ok {
		t.Fatalf("expected agent #1 hello; logs:\n%s", ag1.Logs())
	}

	syncPayload := f04_baseSyncPayload(t, 3, "f04-offline-psk", dnsPort, unlockDNS.Addr(), normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "sync-3", syncPayload); err != nil {
		t.Fatalf("SendEnvelope: %v", err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 3
	}); !ok {
		t.Fatalf("expected config_applied rev 3; logs:\n%s", ag1.Logs())
	}

	// Stop Agent #1 cleanly and shut down mock WS server completely (unreachable panel)
	if err := ag1.Stop(); err != nil {
		t.Fatalf("ag1.Stop(): %v", err)
	}
	srv.Stop()

	// Start Agent #2 with same DataDir while PanelURL is completely unreachable
	ag2 := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		DataDir:      sharedDataDir,
		LocalDNSPort: dnsPort,
		StatsPort:    statsPort,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})
	_ = ag2

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if kernels.LiveProcessCount("snell-server") != 1 || kernels.LiveProcessCount("shadow-tls") != 1 || kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected all 3 kernels booted offline from cache, got snell=%d stls=%d sb=%d; logs:\n%s",
			kernels.LiveProcessCount("snell-server"), kernels.LiveProcessCount("shadow-tls"), kernels.LiveProcessCount("sing-box"), ag2.Logs())
	}

	// Verify local DNS dispatcher also booted from cached config
	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	q := new(dns.Msg)
	q.SetQuestion("netflix.com.", dns.TypeA)
	resp, _, err := c.Exchange(q, fmt.Sprintf("127.0.0.1:%d", dnsPort))
	if err != nil || len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.99" {
		t.Fatalf("offline DNS dispatcher failed: err=%v resp=%+v", err, resp)
	}
}

func TestF04_Tier1_CLIFlagAndEnvBootstrapAndVersion(t *testing.T) {
	agentBin := BuildAgentBinary(t)

	// 1. -version prints version and exits 0
	out, err := exec.Command(agentBin, "-version").CombinedOutput()
	if err != nil {
		t.Fatalf("-version failed: err=%v out=%s", err, string(out))
	}
	if !strings.Contains(string(out), "node-agent") || !strings.Contains(string(out), "version=") {
		t.Fatalf("unexpected -version output: %q", string(out))
	}

	// 2. Missing -token exits 2
	cmdMissingTok := exec.Command(agentBin, "-panel-url", "ws://127.0.0.1:9999", "-data-dir", t.TempDir())
	cmdMissingTok.Env = []string{"PATH=" + os.Getenv("PATH")}
	err = cmdMissingTok.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
		t.Fatalf("expected exit code 2 for missing token, got err=%v", err)
	}

	// 3. Invalid -panel-url exits 2
	for _, badURL := range []string{"ftp://example.com", "http://", "not-a-url"} {
		cmdBadURL := exec.Command(agentBin, "-panel-url", badURL, "-token", "nd_live_tok_123456", "-data-dir", t.TempDir())
		cmdBadURL.Env = []string{"PATH=" + os.Getenv("PATH")}
		err = cmdBadURL.Run()
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 2 {
			t.Fatalf("expected exit code 2 for bad panel-url %q, got err=%v", badURL, err)
		}
	}

	// 4. CLI flags override env vars
	env := NewTestEnv(t)
	cliToken := "nd_live_cli_override_token_999"
	srv := f04_newMockPanelWS(t, cliToken)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	cliDataDir := filepath.Join(env.RootDir, "cli-wins-dir")
	envDataDir := filepath.Join(env.RootDir, "env-loses-dir")

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.HTTPBaseURL(),
		NodeToken:    cliToken,
		DataDir:      cliDataDir,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
		ExtraEnv: []string{
			"PANEL_URL=http://127.0.0.1:1",
			"NODE_TOKEN=nd_live_env_loses_token_111",
			"DATA_DIR=" + envDataDir,
			"LOCAL_DNS_PORT=65530",
			"STATS_PORT=65531",
		},
	})
	_ = ag

	hellos, ok := srv.WaitForHelloCount(1, 8*time.Second)
	if !ok || len(hellos) == 0 {
		t.Fatalf("expected CLI flags to override env vars and connect; logs:\n%s", ag.Logs())
	}
	if _, statErr := os.Stat(cliDataDir); statErr != nil {
		t.Fatalf("expected CLI data-dir %s to be created: %v", cliDataDir, statErr)
	}
	if _, statErr := os.Stat(envDataDir); !os.IsNotExist(statErr) {
		t.Fatalf("expected overridden env data-dir %s not to be used", envDataDir)
	}
}

func TestF04_Tier2_InvalidTokenRejectionAndRetry(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_eventually_valid"
	srv := f04_newMockPanelWS(t, token)
	srv.SetRejectAuth(true)
	kernels := BuildMockKernels(t, MockKernelOptions{})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, _, rejected := srv.SnapshotAuth()
		if rejected >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	_, _, rejected := srv.SnapshotAuth()
	if rejected < 2 {
		t.Fatalf("expected >=2 rejected 401 attempts, got %d; logs:\n%s", rejected, ag.Logs())
	}
	if err := ag.WaitExit(200 * time.Millisecond); !errors.Is(err, errWaitTimeout) {
		t.Fatalf("agent should survive 401 rejections and retry, exited: %v", err)
	}

	// Allow token and confirm recovery
	srv.SetRejectAuth(false)
	if _, ok := srv.WaitForHelloCount(1, 10*time.Second); !ok {
		t.Fatalf("agent did not recover after token accepted; logs:\n%s", ag.Logs())
	}
}

func TestF04_Tier2_MalformedWSFrameResilience(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_malformed_ws"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if _, ok := srv.WaitForHelloCount(1, 8*time.Second); !ok {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f04_baseSyncPayload(t, 1, "f04-malformed-psk-1", ag.LocalDNSPort, "", normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}

	// Send invalid JSON, empty-type envelope, and unknown message type
	_ = srv.SendRawText("{not-valid-json")
	_ = srv.SendEnvelope("", "empty-type", map[string]any{"x": 1})
	_ = srv.SendEnvelope("server.unknown_future_msg", "unk-1", map[string]any{"foo": "bar"})

	// Agent and kernels must stay alive and accept valid rev 2
	sync2 := f04_baseSyncPayload(t, 2, "f04-malformed-psk-2", ag.LocalDNSPort, "", normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatalf("SendEnvelope rev 2 after malformed frames: %v", err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("agent failed to process valid config_sync rev 2 after malformed frames; logs:\n%s", ag.Logs())
	}
}

func TestF04_Tier2_StaleLowerConfigRevisionIdempotency(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_stale_rev"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if _, ok := srv.WaitForHelloCount(1, 8*time.Second); !ok {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync10 := f04_baseSyncPayload(t, 10, "psk-revision-10", ag.LocalDNSPort, "", normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s10", sync10); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 10
	}); !ok {
		t.Fatalf("expected config_applied rev 10; logs:\n%s", ag.Logs())
	}

	snellPIDs := kernels.RunningPIDs("snell-server")
	sbPIDs := kernels.RunningPIDs("sing-box")
	if len(snellPIDs) != 1 || len(sbPIDs) != 1 {
		t.Fatalf("expected running kernels at rev 10, got snell=%v sb=%v", snellPIDs, sbPIDs)
	}

	// Send stale lower rev 5 and duplicate rev 10 with altered PSK
	sync5 := f04_baseSyncPayload(t, 5, "psk-stale-rev-5", ag.LocalDNSPort, "", normalDNS.Addr())
	_ = srv.SendEnvelope("server.config_sync", "s5", sync5)
	sync10Dup := f04_baseSyncPayload(t, 10, "psk-dup-rev-10", ag.LocalDNSPort, "", normalDNS.Addr())
	_ = srv.SendEnvelope("server.config_sync", "s10dup", sync10Dup)

	time.Sleep(800 * time.Millisecond)

	rawCache, err := os.ReadFile(filepath.Join(ag.DataDir, "last_config.json"))
	if err != nil {
		t.Fatalf("read last_config.json: %v", err)
	}
	var cached ServerConfigSyncPayload
	if err := json.Unmarshal(rawCache, &cached); err != nil {
		t.Fatal(err)
	}
	if cached.ConfigRevision != 10 || cached.Snell.PSK != "psk-revision-10" {
		t.Fatalf("stale/duplicate sync regressed last_config.json: %+v", cached)
	}

	confBytes, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "snell-server.conf"))
	if err != nil {
		t.Fatalf("read snell-server.conf: %v", err)
	}
	if !strings.Contains(string(confBytes), "psk-revision-10") || strings.Contains(string(confBytes), "psk-stale-rev-5") {
		t.Fatalf("snell-server.conf mutated by stale sync:\n%s", string(confBytes))
	}

	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPIDs[0] {
		t.Fatalf("snell-server PID changed on stale sync: before=%v after=%v", snellPIDs, got)
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPIDs[0] {
		t.Fatalf("sing-box PID changed on stale sync: before=%v after=%v", sbPIDs, got)
	}
}

func TestF04_Tier2_CorruptLocalCacheRecovery(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_corrupt_cache"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	dataDir := filepath.Join(env.RootDir, "corrupt-cache-dir")
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "last_config.json"), []byte("{not-valid-json!!!"), 0o600); err != nil {
		t.Fatal(err)
	}

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		DataDir:      dataDir,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	hellos, ok := srv.WaitForHelloCount(1, 8*time.Second)
	if !ok {
		t.Fatalf("agent failed to recover from corrupt last_config.json; logs:\n%s", ag.Logs())
	}
	if hellos[0].ConfigRevision != 0 {
		t.Fatalf("expected config_revision=0 after corrupt cache recovery, got %d", hellos[0].ConfigRevision)
	}

	sync1 := f04_baseSyncPayload(t, 1, "psk-recovered-1", ag.LocalDNSPort, "", normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected fresh config_sync rev 1 to apply after corrupt cache recovery; logs:\n%s", ag.Logs())
	}
}

func TestF04_Tier2_CleanSIGTERMShutdown(t *testing.T) {
	env := NewTestEnv(t)
	token := "nd_live_f04_sigterm_clean"
	srv := f04_newMockPanelWS(t, token)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    token,
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if _, ok := srv.WaitForHelloCount(1, 8*time.Second); !ok {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f04_baseSyncPayload(t, 1, "psk-sigterm-1", ag.LocalDNSPort, "", normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied; logs:\n%s", ag.Logs())
	}
	if kernels.LiveProcessCount("snell-server") != 1 || kernels.LiveProcessCount("shadow-tls") != 1 || kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected all 3 kernels running before SIGTERM")
	}

	if err := ag.Stop(); err != nil {
		t.Fatalf("expected clean exit code 0 on SIGTERM, got: %v\nLogs:\n%s", err, ag.Logs())
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if kernels.LiveProcessCount("snell-server") == 0 &&
			kernels.LiveProcessCount("shadow-tls") == 0 &&
			kernels.LiveProcessCount("sing-box") == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("orphaned child kernels left after SIGTERM: snell=%v stls=%v sb=%v",
		kernels.RunningPIDs("snell-server"), kernels.RunningPIDs("shadow-tls"), kernels.RunningPIDs("sing-box"))
}
