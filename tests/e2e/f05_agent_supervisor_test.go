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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type f05_mockPanelWS struct {
	t    *testing.T
	addr string

	mu     sync.Mutex
	srv    *http.Server
	conns  map[*websocket.Conn]struct{}
	hellos []AgentHelloPayload
	events []AgentEventPayload
}

func f05_newMockPanelWS(t *testing.T) *f05_mockPanelWS {
	t.Helper()
	port := AllocFreePort(t)
	m := &f05_mockPanelWS{
		t:     t,
		addr:  fmt.Sprintf("127.0.0.1:%d", port),
		conns: make(map[*websocket.Conn]struct{}),
	}
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		t.Fatalf("f05_mockPanelWS listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", m.handleWS)
	srv := &http.Server{Handler: mux}
	m.srv = srv
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { m.Stop() })
	return m
}

func (m *f05_mockPanelWS) WSBaseURL() string { return "ws://" + m.addr }

func (m *f05_mockPanelWS) Stop() {
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

func (m *f05_mockPanelWS) handleWS(w http.ResponseWriter, r *http.Request) {
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
		switch env.Type {
		case "agent.hello":
			var p AgentHelloPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.hellos = append(m.hellos, p)
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

func (m *f05_mockPanelWS) SendEnvelope(msgType, reqID string, payload any) error {
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

func (m *f05_mockPanelWS) WaitForHello(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		n := len(m.hellos)
		m.mu.Unlock()
		if n > 0 {
			return true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return false
}

func (m *f05_mockPanelWS) WaitForEvent(timeout time.Duration, match func(AgentEventPayload) bool) (AgentEventPayload, bool) {
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

func f05_b64Key16(seed string) string {
	b := make([]byte, 16)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func f05_baseSyncPayload(t *testing.T, rev int64, dnsPort int, upstreamDNS string) ServerConfigSyncPayload {
	t.Helper()
	return ServerConfigSyncPayload{
		ConfigRevision: rev,
		Snell: SnellConfigDTO{
			Enabled:         true,
			Version:         "v5",
			PublicPort:      AllocFreePort(t),
			InnerPort:       AllocFreePort(t),
			PSK:             "f05-snell-psk-secret",
			Obfs:            "http",
			TFO:             true,
			DNSIPPreference: "prefer-ipv4",
			STLSPassword:    "f05-snell-stls-pwd",
			STLSSNI:         "gateway.icloud.com",
		},
		SS: SSConfigDTO{
			Enabled: true,
			TCPPort: AllocFreePort(t),
			UDPPort: AllocFreeUDPPort(t),
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    f05_b64Key16("f05-server-ipsk!"),
			STLSSNI: "swscan.apple.com",
			Users: []SSUserEntryDTO{
				{
					UserID:       1,
					Username:     "alice",
					UPSK:         f05_b64Key16("f05-alice-upsk!!"),
					STLSPassword: "f05-alice-stls",
				},
			},
		},
		DNS: DNSConfigDTO{
			UnlockEnabled: false,
			UpstreamDNS:   upstreamDNS,
			LocalPort:     dnsPort,
		},
	}
}

func f05_countStartInvocations(kernels *MockKernelSet, role string) int {
	n := 0
	for _, inv := range kernels.Invocations(role) {
		if inv.Event == "start" {
			n++
		}
	}
	return n
}

func TestF05_Tier1_ThreeKernelIsolationLaunchAndConfigRender(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_three_kernels",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	ev, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	})
	if !ok || ev.Status != "success" {
		t.Fatalf("expected config_applied rev 1, got ok=%v ev=%+v", ok, ev)
	}

	if kernels.LiveProcessCount("snell-server") != 1 || kernels.LiveProcessCount("shadow-tls") != 1 || kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected 1 live PID each, got snell=%d stls=%d sb=%d",
			kernels.LiveProcessCount("snell-server"), kernels.LiveProcessCount("shadow-tls"), kernels.LiveProcessCount("sing-box"))
	}

	// Verify snell-server.conf
	snellConfBytes, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "snell-server.conf"))
	if err != nil {
		t.Fatalf("read snell-server.conf: %v", err)
	}
	snellConf := string(snellConfBytes)
	if !strings.Contains(snellConf, fmt.Sprintf("listen = 127.0.0.1:%d", sync1.Snell.InnerPort)) ||
		!strings.Contains(snellConf, "psk = f05-snell-psk-secret") {
		t.Fatalf("unexpected snell-server.conf:\n%s", snellConf)
	}
	if ag.LocalDNSPort == 53 {
		if !strings.Contains(snellConf, "dns = 127.0.0.1\n") {
			t.Fatalf("expected bare loopback dns = 127.0.0.1 in snell-server.conf:\n%s", snellConf)
		}
	} else if strings.Contains(snellConf, fmt.Sprintf("dns = 127.0.0.1:%d", ag.LocalDNSPort)) {
		t.Fatalf("snell-server.conf must not emit non-53 host:port dns line:\n%s", snellConf)
	}

	// Verify shadow-tls CLI arguments
	var stlsStart *MockKernelInvocation
	for _, inv := range kernels.Invocations("shadow-tls") {
		if inv.Event == "start" {
			invCopy := inv
			stlsStart = &invCopy
		}
	}
	if stlsStart == nil {
		t.Fatal("expected shadow-tls start invocation")
	}
	argLine := strings.Join(stlsStart.Args, " ")
	for _, want := range []string{
		"--v3", "--strict", "--fastopen", "server",
		fmt.Sprintf("--listen [::]:%d", sync1.Snell.PublicPort),
		fmt.Sprintf("--server 127.0.0.1:%d", sync1.Snell.InnerPort),
		"--tls gateway.icloud.com:443",
		"--password f05-snell-stls-pwd",
	} {
		if !strings.Contains(argLine, want) {
			t.Fatalf("shadow-tls args %q missing %q", argLine, want)
		}
	}

	// Verify sing-box.json
	sbBytes, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatalf("read sing-box.json: %v", err)
	}
	var sbDoc map[string]any
	if err := json.Unmarshal(sbBytes, &sbDoc); err != nil {
		t.Fatalf("parse sing-box.json: %v", err)
	}
	sbStr := string(sbBytes)
	for _, want := range []string{"stls-in", "ss-tcp-in", "ss-udp-in", "v2ray_api", fmt.Sprintf("127.0.0.1:%d", ag.StatsPort)} {
		if !strings.Contains(sbStr, want) {
			t.Fatalf("sing-box.json missing %q:\n%s", want, sbStr)
		}
	}
}

func TestF05_Tier1_UserUpdateReloadsOnlySingBoxZeroSnellInterruption(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_user_isolation",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}

	snellPID1 := kernels.RunningPIDs("snell-server")[0]
	stlsPID1 := kernels.RunningPIDs("shadow-tls")[0]
	sbPID1 := kernels.RunningPIDs("sing-box")[0]
	snellStarts1 := f05_countStartInvocations(kernels, "snell-server")
	stlsStarts1 := f05_countStartInvocations(kernels, "shadow-tls")

	// Update ONLY SS.Users (remove alice, add bob)
	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.Users = []SSUserEntryDTO{
		{
			UserID:       2,
			Username:     "bob",
			UPSK:         f05_b64Key16("f05-bob-upsk!!!!"),
			STLSPassword: "f05-bob-stls",
		},
	}
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("expected config_applied rev 2; logs:\n%s", ag.Logs())
	}

	sbPIDs2 := kernels.RunningPIDs("sing-box")
	if len(sbPIDs2) != 1 || sbPIDs2[0] == sbPID1 {
		t.Fatalf("expected sing-box PID to change on user update: before=%d after=%v", sbPID1, sbPIDs2)
	}
	snellPIDs2 := kernels.RunningPIDs("snell-server")
	stlsPIDs2 := kernels.RunningPIDs("shadow-tls")
	if len(snellPIDs2) != 1 || snellPIDs2[0] != snellPID1 {
		t.Fatalf("snell-server PID interrupted by SS user update: before=%d after=%v", snellPID1, snellPIDs2)
	}
	if len(stlsPIDs2) != 1 || stlsPIDs2[0] != stlsPID1 {
		t.Fatalf("shadow-tls PID interrupted by SS user update: before=%d after=%v", stlsPID1, stlsPIDs2)
	}
	if f05_countStartInvocations(kernels, "snell-server") != snellStarts1 || f05_countStartInvocations(kernels, "shadow-tls") != stlsStarts1 {
		t.Fatalf("expected zero extra snell-server/shadow-tls invocations on SS user update")
	}

	sbBytes, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sbBytes), `"bob"`) || strings.Contains(string(sbBytes), `"alice"`) {
		t.Fatalf("expected sing-box.json updated to bob without alice:\n%s", string(sbBytes))
	}
}

func TestF05_Tier1_PreApplyValidationAndBrokenConfigRollback(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{
		SingBoxSidecar: &MockKernelSidecar{
			Version:            "sing-box version 1.11.4",
			RejectConfigSubstr: "POISON_USER",
		},
	})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_preapply_rollback",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}

	snellPID1 := kernels.RunningPIDs("snell-server")[0]
	stlsPID1 := kernels.RunningPIDs("shadow-tls")[0]
	sbPID1 := kernels.RunningPIDs("sing-box")[0]

	// Push rev 2 with POISON_USER that fails `sing-box check -c`
	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.Users = append(sync2.SS.Users, SSUserEntryDTO{
		UserID:       99,
		Username:     "POISON_USER",
		UPSK:         f05_b64Key16("f05-poison-upsk!"),
		STLSPassword: "f05-poison-stls",
	})
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_error" && e.ConfigRevision == 2
	})
	if !ok || ev.Status != "failed" {
		t.Fatalf("expected config_error rev 2 failed, got ok=%v ev=%+v", ok, ev)
	}

	// Rev 1 must remain active and all 3 PIDs untouched
	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID1 {
		t.Fatalf("snell-server PID changed on broken config: %v vs %d", got, snellPID1)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID1 {
		t.Fatalf("shadow-tls PID changed on broken config: %v vs %d", got, stlsPID1)
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPID1 {
		t.Fatalf("sing-box PID changed on staged check failure: %v vs %d", got, sbPID1)
	}

	sbBytes, err := os.ReadFile(filepath.Join(ag.DataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(sbBytes), "POISON_USER") || !strings.Contains(string(sbBytes), `"alice"`) {
		t.Fatalf("live sing-box.json corrupted by failed rev 2:\n%s", string(sbBytes))
	}
}

func TestF05_Tier1_StopSSOnlyLeavesSnellRunning(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_stop_ss_only",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}
	snellPID1 := kernels.RunningPIDs("snell-server")[0]
	stlsPID1 := kernels.RunningPIDs("shadow-tls")[0]

	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.Enabled = false
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("expected config_applied rev 2; logs:\n%s", ag.Logs())
	}

	if kernels.LiveProcessCount("sing-box") != 0 {
		t.Fatalf("expected sing-box stopped, got PIDs %v", kernels.RunningPIDs("sing-box"))
	}
	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID1 {
		t.Fatalf("snell-server should stay running untouched: before=%d after=%v", snellPID1, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID1 {
		t.Fatalf("shadow-tls should stay running untouched: before=%d after=%v", stlsPID1, got)
	}
}

func TestF05_Tier1_StopAllStopsAllThreeKernels(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_stop_all",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}

	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.Snell.Enabled = false
	sync2.SS.Enabled = false
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("expected config_applied rev 2; logs:\n%s", ag.Logs())
	}

	if kernels.LiveProcessCount("snell-server") != 0 || kernels.LiveProcessCount("shadow-tls") != 0 || kernels.LiveProcessCount("sing-box") != 0 {
		t.Fatalf("expected all 3 kernels stopped, got snell=%d stls=%d sb=%d",
			kernels.LiveProcessCount("snell-server"), kernels.LiveProcessCount("shadow-tls"), kernels.LiveProcessCount("sing-box"))
	}
}

func TestF05_Tier2_PortConflictDetectionAndRollback(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_port_conflict",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}
	snellPIDs1 := kernels.RunningPIDs("snell-server")
	stlsPIDs1 := kernels.RunningPIDs("shadow-tls")
	sbPIDs1 := kernels.RunningPIDs("sing-box")
	if len(snellPIDs1) != 1 || len(stlsPIDs1) != 1 || len(sbPIDs1) != 1 {
		t.Fatalf("expected 1 PID each after rev 1, got snell=%v stls=%v sb=%v", snellPIDs1, stlsPIDs1, sbPIDs1)
	}
	snellPID1 := snellPIDs1[0]
	stlsPID1 := stlsPIDs1[0]
	sbPID1 := sbPIDs1[0]

	// Case A: Config-level TCP port conflict (SS.TCPPort == Snell.PublicPort)
	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.TCPPort = sync1.Snell.PublicPort
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	ev2, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_error" && e.ConfigRevision == 2
	})
	if !ok || ev2.Status != "failed" {
		t.Fatalf("expected config_error for intra-config port collision, got ok=%v ev=%+v", ok, ev2)
	}

	// Case B: External occupied TCP port causes bind failure during startup & rollback to rev 1
	sync3 := sync1
	sync3.ConfigRevision = 3
	targetedSS := false
	ln, err := net.Listen("tcp", "[::]:0")
	if err == nil {
		defer ln.Close()
		occupiedPort := ln.Addr().(*net.TCPAddr).Port
		sync3.SS.TCPPort = occupiedPort
		targetedSS = true
	} else {
		// IPv4-only host fallback: snell-server binds 127.0.0.1:<inner_port>
		ln, err = net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		occupiedPort := ln.Addr().(*net.TCPAddr).Port
		sync3.Snell.InnerPort = occupiedPort
	}

	if err := srv.SendEnvelope("server.config_sync", "s3", sync3); err != nil {
		t.Fatal(err)
	}
	ev3, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_error" && e.ConfigRevision == 3
	})
	if !ok || ev3.Status != "failed" {
		t.Fatalf("expected config_error + rollback for occupied external port, got ok=%v ev=%+v", ok, ev3)
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if kernels.LiveProcessCount("snell-server") == 1 &&
			kernels.LiveProcessCount("shadow-tls") == 1 &&
			kernels.LiveProcessCount("sing-box") == 1 {
			if targetedSS {
				if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID1 {
					t.Fatalf("snell-server PID changed on SS port conflict rollback: %v vs %d", got, snellPID1)
				}
				if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID1 {
					t.Fatalf("shadow-tls PID changed on SS port conflict rollback: %v vs %d", got, stlsPID1)
				}
				sbBytes, readErr := os.ReadFile(filepath.Join(ag.DataDir, "configs", "sing-box.json"))
				if readErr != nil {
					t.Fatalf("read sing-box.json after rollback: %v", readErr)
				}
				var sbDoc struct {
					Inbounds []struct {
						Tag        string `json:"tag"`
						ListenPort int    `json:"listen_port"`
					} `json:"inbounds"`
				}
				if err := json.Unmarshal(sbBytes, &sbDoc); err != nil {
					t.Fatalf("parse sing-box.json after rollback: %v", err)
				}
				foundSTLS := false
				for _, inb := range sbDoc.Inbounds {
					if inb.Tag == "stls-in" {
						foundSTLS = true
						if inb.ListenPort != sync1.SS.TCPPort {
							t.Fatalf("expected sing-box.json stls-in listen_port reverted to %d, got %d", sync1.SS.TCPPort, inb.ListenPort)
						}
					}
				}
				if !foundSTLS {
					t.Fatalf("sing-box.json missing stls-in inbound after rollback:\n%s", string(sbBytes))
				}
			} else {
				if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPID1 {
					t.Fatalf("sing-box PID changed on Snell inner_port conflict rollback: %v vs %d", got, sbPID1)
				}
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected rev 1 kernels running after port conflict rollback, got snell=%d stls=%d sb=%d",
		kernels.LiveProcessCount("snell-server"), kernels.LiveProcessCount("shadow-tls"), kernels.LiveProcessCount("sing-box"))
}

func TestF05_Tier2_CrashedChildAutoRestartAndEvent(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{
		SingBoxSidecar: &MockKernelSidecar{
			Version:      "sing-box version 1.11.4",
			CrashAfterMS: 1500, // Survives 350ms StartupGrace with >1s margin, then crashes
		},
	})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_crash_restart",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}

	snellPIDs1 := kernels.RunningPIDs("snell-server")
	if len(snellPIDs1) != 1 {
		t.Fatalf("expected 1 running snell-server PID, got %v", snellPIDs1)
	}
	snellPID1 := snellPIDs1[0]

	stlsPIDs1 := kernels.RunningPIDs("shadow-tls")
	if len(stlsPIDs1) != 1 {
		t.Fatalf("expected 1 running shadow-tls PID, got %v", stlsPIDs1)
	}
	stlsPID1 := stlsPIDs1[0]

	var sbPID1 int
	sbPIDs1 := kernels.RunningPIDs("sing-box")
	switch len(sbPIDs1) {
	case 1:
		sbPID1 = sbPIDs1[0]
	case 0:
		for _, inv := range kernels.Invocations("sing-box") {
			if inv.Event == "start" && inv.PID > 0 {
				sbPID1 = inv.PID
				break
			}
		}
		if sbPID1 == 0 {
			t.Fatalf("expected sing-box start PID in running PIDs or invocations, got none")
		}
	default:
		t.Fatalf("expected at most 1 running sing-box PID, got %v", sbPIDs1)
	}

	ev, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "process_crashed" && e.Kernel == "sing-box"
	})
	if !ok || ev.Status != "failed" {
		t.Fatalf("expected process_crashed event for sing-box, got ok=%v ev=%+v", ok, ev)
	}

	// Clear crash injection so auto-restarted sing-box stays alive
	kernels.UpdateSidecar("sing-box", MockKernelSidecar{
		Version: "sing-box version 1.11.4",
	})

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		pids := kernels.RunningPIDs("sing-box")
		if len(pids) == 1 && pids[0] != sbPID1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sbPIDs2 := kernels.RunningPIDs("sing-box")
	if len(sbPIDs2) != 1 || sbPIDs2[0] == sbPID1 {
		t.Fatalf("expected sing-box auto-restarted to new PID (old=%d), got %v", sbPID1, sbPIDs2)
	}
	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID1 {
		t.Fatalf("snell-server disturbed during sing-box crash recovery: before=%d after=%v", snellPID1, got)
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID1 {
		t.Fatalf("shadow-tls disturbed during sing-box crash recovery: before=%d after=%v", stlsPID1, got)
	}
}

func TestF05_Tier2_InvalidSnellOrSSCipherConfigRejection(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_invalid_cipher",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}
	snellPID1 := kernels.RunningPIDs("snell-server")[0]
	sbPID1 := kernels.RunningPIDs("sing-box")[0]

	badCases := []struct {
		rev    int64
		mutate func(*ServerConfigSyncPayload)
	}{
		{rev: 2, mutate: func(c *ServerConfigSyncPayload) { c.SS.Cipher = "rc4-md5" }},
		{rev: 3, mutate: func(c *ServerConfigSyncPayload) { c.SS.IPSK = "not-valid-base64!!!" }},
		{rev: 4, mutate: func(c *ServerConfigSyncPayload) { c.Snell.Version = "v99" }},
		{rev: 5, mutate: func(c *ServerConfigSyncPayload) { c.Snell.Obfs = "websocket" }},
	}

	for _, tc := range badCases {
		bad := sync1
		bad.ConfigRevision = tc.rev
		tc.mutate(&bad)
		if err := srv.SendEnvelope("server.config_sync", fmt.Sprintf("bad-%d", tc.rev), bad); err != nil {
			t.Fatal(err)
		}
		ev, ok := srv.WaitForEvent(8*time.Second, func(e AgentEventPayload) bool {
			return e.Event == "config_error" && e.ConfigRevision == tc.rev
		})
		if !ok || ev.Status != "failed" {
			t.Fatalf("expected config_error rev %d, got ok=%v ev=%+v", tc.rev, ok, ev)
		}
	}

	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID1 {
		t.Fatalf("snell-server PID changed on rejected configs: %v vs %d", got, snellPID1)
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPID1 {
		t.Fatalf("sing-box PID changed on rejected configs: %v vs %d", got, sbPID1)
	}
}

func TestF05_Tier2_ServiceCtlTargetedRestarts(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_service_ctl",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}

	snell1 := kernels.RunningPIDs("snell-server")[0]
	stls1 := kernels.RunningPIDs("shadow-tls")[0]
	sb1 := kernels.RunningPIDs("sing-box")[0]

	// 1. restart_snell: only snell-server + shadow-tls restart
	if err := srv.SendEnvelope("server.service_ctl", "ctl-1", ServerServiceCtlPayload{Action: "restart_snell"}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s := kernels.RunningPIDs("snell-server")
		tPids := kernels.RunningPIDs("shadow-tls")
		if len(s) == 1 && s[0] != snell1 && len(tPids) == 1 && tPids[0] != stls1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	snell2 := kernels.RunningPIDs("snell-server")
	stls2 := kernels.RunningPIDs("shadow-tls")
	if len(snell2) != 1 || snell2[0] == snell1 || len(stls2) != 1 || stls2[0] == stls1 {
		t.Fatalf("restart_snell did not restart both admin processes: snell=%v stls=%v", snell2, stls2)
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sb1 {
		t.Fatalf("restart_snell disturbed sing-box PID: %v vs %d", got, sb1)
	}

	// 2. restart_singbox: only sing-box restarts
	if err := srv.SendEnvelope("server.service_ctl", "ctl-2", ServerServiceCtlPayload{Action: "restart_singbox"}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		b := kernels.RunningPIDs("sing-box")
		if len(b) == 1 && b[0] != sb1 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	sb2 := kernels.RunningPIDs("sing-box")
	if len(sb2) != 1 || sb2[0] == sb1 {
		t.Fatalf("restart_singbox did not restart sing-box: %v", sb2)
	}
	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snell2[0] {
		t.Fatalf("restart_singbox disturbed snell-server PID: %v vs %d", got, snell2[0])
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stls2[0] {
		t.Fatalf("restart_singbox disturbed shadow-tls PID: %v vs %d", got, stls2[0])
	}

	// 3. restart_all: all 3 restart
	if err := srv.SendEnvelope("server.service_ctl", "ctl-3", ServerServiceCtlPayload{Action: "restart_all"}); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		s := kernels.RunningPIDs("snell-server")
		tPids := kernels.RunningPIDs("shadow-tls")
		b := kernels.RunningPIDs("sing-box")
		if len(s) == 1 && s[0] != snell2[0] && len(tPids) == 1 && tPids[0] != stls2[0] && len(b) == 1 && b[0] != sb2[0] {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("restart_all did not restart all 3 PIDs: snell=%v stls=%v sb=%v",
		kernels.RunningPIDs("snell-server"), kernels.RunningPIDs("shadow-tls"), kernels.RunningPIDs("sing-box"))
}

func TestF05_Tier2_MissingKernelBinaryHandling(t *testing.T) {
	env := NewTestEnv(t)
	srv := f05_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})
	missingSingBox := filepath.Join(t.TempDir(), "nonexistent-sing-box")

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f05_missing_bin",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   missingSingBox,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	// Rev 1 enables SS with missing sing-box -> must emit config_error without crashing agent
	sync1 := f05_baseSyncPayload(t, 1, ag.LocalDNSPort, normalDNS.Addr())
	if err := srv.SendEnvelope("server.config_sync", "s1", sync1); err != nil {
		t.Fatal(err)
	}
	ev1, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_error" && e.ConfigRevision == 1
	})
	if !ok || ev1.Status != "failed" {
		t.Fatalf("expected config_error rev 1 for missing sing-box binary, got ok=%v ev=%+v", ok, ev1)
	}

	// Rev 2 disables SS -> valid Snell + ShadowTLS channel must launch cleanly
	sync2 := sync1
	sync2.ConfigRevision = 2
	sync2.SS.Enabled = false
	if err := srv.SendEnvelope("server.config_sync", "s2", sync2); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 2
	}); !ok {
		t.Fatalf("expected config_applied rev 2 with SS disabled; logs:\n%s", ag.Logs())
	}
	if kernels.LiveProcessCount("snell-server") != 1 || kernels.LiveProcessCount("shadow-tls") != 1 {
		t.Fatalf("expected Snell channel running, got snell=%d stls=%d",
			kernels.LiveProcessCount("snell-server"), kernels.LiveProcessCount("shadow-tls"))
	}
}
