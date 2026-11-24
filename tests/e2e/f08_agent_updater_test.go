//go:build e2e

package e2e_test

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
)

type f08_mockPanelWS struct {
	t    *testing.T
	addr string

	mu     sync.Mutex
	srv    *http.Server
	conns  map[*websocket.Conn]struct{}
	hellos []AgentHelloPayload
	events []AgentEventPayload
}

func f08_newMockPanelWS(t *testing.T) *f08_mockPanelWS {
	t.Helper()
	port := AllocFreePort(t)
	m := &f08_mockPanelWS{
		t:     t,
		addr:  fmt.Sprintf("127.0.0.1:%d", port),
		conns: make(map[*websocket.Conn]struct{}),
	}
	ln, err := net.Listen("tcp", m.addr)
	if err != nil {
		t.Fatalf("f08_mockPanelWS listen: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/agent/ws", m.handleWS)
	srv := &http.Server{Handler: mux}
	m.srv = srv
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { m.Stop() })
	return m
}

func (m *f08_mockPanelWS) WSBaseURL() string { return "ws://" + m.addr }

func (m *f08_mockPanelWS) Stop() {
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

func (m *f08_mockPanelWS) handleWS(w http.ResponseWriter, r *http.Request) {
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
		case "agent.event":
			var p AgentEventPayload
			if json.Unmarshal(env.Payload, &p) == nil {
				m.events = append(m.events, p)
			}
		}
		m.mu.Unlock()
	}
}

func (m *f08_mockPanelWS) SendEnvelope(msgType, reqID string, payload any) error {
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

func (m *f08_mockPanelWS) WaitForHello(timeout time.Duration) bool {
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

func (m *f08_mockPanelWS) WaitForEvent(timeout time.Duration, match func(AgentEventPayload) bool) (AgentEventPayload, bool) {
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

func (m *f08_mockPanelWS) EventsSince(idx int) []AgentEventPayload {
	m.mu.Lock()
	defer m.mu.Unlock()
	if idx >= len(m.events) {
		return nil
	}
	return append([]AgentEventPayload(nil), m.events[idx:]...)
}

func (m *f08_mockPanelWS) EventsLen() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.events)
}

func f08_isUpdateSuccess(status string) bool {
	return status == "update_success" || status == "success"
}

func f08_isUpdateFailed(status string) bool {
	return status == "update_failed" || status == "failed"
}

func f08_b64Key16(seed string) string {
	b := make([]byte, 16)
	copy(b, []byte(seed))
	return base64.StdEncoding.EncodeToString(b)
}

func f08_fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s for sha256: %v", path, err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func f08_buildZipAsset(t *testing.T, entryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fh := &zip.FileHeader{
		Name:   entryName,
		Method: zip.Deflate,
	}
	fh.SetMode(0o755)
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("zip CreateHeader: %v", err)
	}
	if _, err := w.Write(content); err != nil {
		t.Fatalf("zip Write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

func f08_setupRunningAgent(t *testing.T) (*AgentProcess, *f08_mockPanelWS, *MockKernelSet, ServerConfigSyncPayload) {
	t.Helper()
	env := NewTestEnv(t)
	srv := f08_newMockPanelWS(t)
	kernels := BuildMockKernels(t, MockKernelOptions{})
	normalDNS := StartMockDNSServer(t, MockDNSOptions{Records: map[string][]string{"example.com": {"93.184.216.34"}}})

	ag := StartAgent(env, AgentConfig{
		PanelURL:     srv.WSBaseURL(),
		NodeToken:    "nd_live_f08_updater",
		SnellBin:     kernels.SnellBin,
		ShadowTLSBin: kernels.ShadowTLSBin,
		SingBoxBin:   kernels.SingBoxBin,
	})

	if !srv.WaitForHello(8 * time.Second) {
		t.Fatalf("expected agent.hello; logs:\n%s", ag.Logs())
	}

	syncPayload := ServerConfigSyncPayload{
		ConfigRevision: 1,
		Snell: SnellConfigDTO{
			Enabled:      true,
			Version:      "v5",
			PublicPort:   AllocFreePort(t),
			InnerPort:    AllocFreePort(t),
			PSK:          "f08-snell-psk",
			Obfs:         "off",
			STLSPassword: "f08-stls-pwd",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: SSConfigDTO{
			Enabled: true,
			TCPPort: AllocFreePort(t),
			UDPPort: AllocFreeUDPPort(t),
			Cipher:  "2022-blake3-aes-128-gcm",
			IPSK:    f08_b64Key16("f08-server-ipsk!"),
			STLSSNI: "swscan.apple.com",
			Users: []SSUserEntryDTO{
				{UserID: 1, Username: "alice", UPSK: f08_b64Key16("f08-alice-upsk!!"), STLSPassword: "p1"},
			},
		},
		DNS: DNSConfigDTO{
			UnlockEnabled: false,
			UpstreamDNS:   normalDNS.Addr(),
			LocalPort:     ag.LocalDNSPort,
		},
	}
	if err := srv.SendEnvelope("server.config_sync", "s1", syncPayload); err != nil {
		t.Fatal(err)
	}
	if _, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "config_applied" && e.ConfigRevision == 1
	}); !ok {
		t.Fatalf("expected config_applied rev 1; logs:\n%s", ag.Logs())
	}
	if kernels.LiveProcessCount("snell-server") != 1 || kernels.LiveProcessCount("shadow-tls") != 1 || kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected all 3 kernels running")
	}
	return ag, srv, kernels, syncPayload
}

func f08_assertTCPListening(t *testing.T, port int) {
	t.Helper()
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	dl := time.Now().Add(5 * time.Second)
	for time.Now().Before(dl) {
		c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("expected port %d to be listening", port)
}

func TestF08_Tier1_OnlineUpdateSingBoxTarGzSuccess(t *testing.T) {
	ag, srv, kernels, syncCfg := f08_setupRunningAgent(t)
	_ = ag

	updatedBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.0-updated", false)
	assetName := "sing-box-1.12.0.tar.gz"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.0",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: true, BinaryName: "sing-box-1.12.0/sing-box", Payload: updatedBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-sb-1", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.0-updated",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(15*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateSuccess(ev.Status) {
		t.Fatalf("expected kernel_update_result success for sing-box, got ok=%v ev=%+v", ok, ev)
	}

	if _, err := os.Stat(kernels.SingBoxBin + ".bak"); err != nil {
		t.Fatalf("expected backup %s.bak: %v", kernels.SingBoxBin, err)
	}
	verOut, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(verOut), "1.12.0-updated") {
		t.Fatalf("expected updated sing-box version, got err=%v out=%q", err, string(verOut))
	}
	if kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected updated sing-box running, got %v", kernels.RunningPIDs("sing-box"))
	}
	f08_assertTCPListening(t, syncCfg.SS.TCPPort)
	f08_assertTCPListening(t, ag.StatsPort)
}

func TestF08_Tier1_OnlineUpdateSnellServerRawBinarySuccess(t *testing.T) {
	_, srv, kernels, syncCfg := f08_setupRunningAgent(t)
	sbPIDBefore := kernels.RunningPIDs("sing-box")[0]

	updatedBytes := BuildMockKernelVariant(t, "snell-server", "snell-server v5.1.0", false)
	assetName := "snell-server-v5.1.0-linux-amd64"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "surge-networks", Repo: "snell", TagName: "v5.1.0",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: false, Payload: updatedBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-snell-1", ServerKernelUpdatePayload{
		Kernel:      "snell-server",
		Version:     "v5.1.0",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(15*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "snell-server"
	})
	if !ok || !f08_isUpdateSuccess(ev.Status) {
		t.Fatalf("expected kernel_update_result success for snell-server, got ok=%v ev=%+v", ok, ev)
	}

	if _, err := os.Stat(kernels.SnellBin + ".bak"); err != nil {
		t.Fatalf("expected backup %s.bak: %v", kernels.SnellBin, err)
	}
	verOut, err := exec.Command(kernels.SnellBin, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(verOut), "snell-server v5.1.0") {
		t.Fatalf("expected updated snell-server version, got err=%v out=%q", err, string(verOut))
	}
	f08_assertTCPListening(t, syncCfg.Snell.InnerPort)
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPIDBefore {
		t.Fatalf("snell-server update disturbed sing-box PID: before=%d after=%v", sbPIDBefore, got)
	}
}

func TestF08_Tier1_OnlineUpdateShadowTLSSuccess(t *testing.T) {
	_, srv, kernels, syncCfg := f08_setupRunningAgent(t)

	updatedBytes := BuildMockKernelVariant(t, "shadow-tls", "shadow-tls 0.3.0", false)
	assetName := "shadow-tls-0.3.0.tar.gz"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "ihciah", Repo: "shadow-tls", TagName: "v0.3.0",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: true, BinaryName: "shadow-tls", Payload: updatedBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-stls-1", ServerKernelUpdatePayload{
		Kernel:      "shadow-tls",
		Version:     "0.3.0",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(15*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "shadow-tls"
	})
	if !ok || !f08_isUpdateSuccess(ev.Status) {
		t.Fatalf("expected kernel_update_result success for shadow-tls, got ok=%v ev=%+v", ok, ev)
	}

	if _, err := os.Stat(kernels.ShadowTLSBin + ".bak"); err != nil {
		t.Fatalf("expected backup %s.bak: %v", kernels.ShadowTLSBin, err)
	}
	verOut, err := exec.Command(kernels.ShadowTLSBin, "--version").CombinedOutput()
	if err != nil || !strings.Contains(string(verOut), "shadow-tls 0.3.0") {
		t.Fatalf("expected updated shadow-tls version, got err=%v out=%q", err, string(verOut))
	}
	f08_assertTCPListening(t, syncCfg.Snell.PublicPort)
}

func TestF08_Tier1_OnlineUpdateZipArchiveSuccess(t *testing.T) {
	_, srv, kernels, _ := f08_setupRunningAgent(t)

	updatedBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.5-zip", false)
	zipBytes := f08_buildZipAsset(t, "sing-box-1.12.5/sing-box", updatedBytes)
	assetName := "sing-box-1.12.5.zip"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.5",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: false, Payload: zipBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-zip-1", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.5-zip",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(15*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateSuccess(ev.Status) {
		t.Fatalf("expected zip kernel_update_result success, got ok=%v ev=%+v", ok, ev)
	}

	verOut, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(verOut), "1.12.5-zip") {
		t.Fatalf("expected updated zip sing-box version, got err=%v out=%q", err, string(verOut))
	}
}

func TestF08_Tier1_ProgressStagesAndBackupIntegrity(t *testing.T) {
	_, srv, kernels, _ := f08_setupRunningAgent(t)
	origSHA := f08_fileSHA256(t, kernels.SingBoxBin)
	mark := srv.EventsLen()

	updatedBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.6-stages", false)
	assetName := "sing-box-1.12.6.tar.gz"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.6",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: true, BinaryName: "sing-box", Payload: updatedBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-stages", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.6-stages",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(15*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateSuccess(ev.Status) {
		t.Fatalf("expected update success, got ok=%v ev=%+v", ok, ev)
	}

	var stages []string
	for _, e := range srv.EventsSince(mark) {
		if e.Event == "kernel_update_progress" && e.Kernel == "sing-box" {
			stages = append(stages, e.Message)
		}
	}
	expectedOrder := []string{"downloading", "verifying", "extracting", "probing", "swapping", "restarting", "health_checking"}
	idx := 0
	for _, s := range stages {
		if idx < len(expectedOrder) && s == expectedOrder[idx] {
			idx++
		}
	}
	if idx != len(expectedOrder) {
		t.Fatalf("expected ordered progress stages %v, got %v", expectedOrder, stages)
	}

	bakSHA := f08_fileSHA256(t, kernels.SingBoxBin+".bak")
	if bakSHA != origSHA {
		t.Fatalf("backup SHA256 mismatch: bak=%s orig=%s", bakSHA, origSHA)
	}
}

func TestF08_Tier2_SHA256MismatchAbortsBeforeSwap(t *testing.T) {
	_, srv, kernels, _ := f08_setupRunningAgent(t)
	origSHA := f08_fileSHA256(t, kernels.SingBoxBin)
	sbPIDBefore := kernels.RunningPIDs("sing-box")[0]

	updatedBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.7-badsha", false)
	assetName := "sing-box-badsha.tar.gz"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.7",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: true, BinaryName: "sing-box", Payload: updatedBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-badsha", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.7",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      strings.Repeat("0", 64),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateFailed(ev.Status) {
		t.Fatalf("expected update failure on SHA256 mismatch, got ok=%v ev=%+v", ok, ev)
	}

	if gotSHA := f08_fileSHA256(t, kernels.SingBoxBin); gotSHA != origSHA {
		t.Fatalf("binary modified despite SHA256 mismatch")
	}
	if _, err := os.Stat(kernels.SingBoxBin + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("unexpected .bak created on SHA256 mismatch")
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPIDBefore {
		t.Fatalf("sing-box PID changed on SHA256 mismatch: before=%d after=%v", sbPIDBefore, got)
	}
}

func TestF08_Tier2_CorruptArchiveOrFailedVersionProbeAborts(t *testing.T) {
	_, srv, kernels, _ := f08_setupRunningAgent(t)
	origSHA := f08_fileSHA256(t, kernels.SingBoxBin)
	sbPIDBefore := kernels.RunningPIDs("sing-box")[0]

	badScript := []byte("#!/bin/sh\necho version-probe-error >&2\nexit 1\n")
	assetName := "sing-box-probe-fail.tar.gz"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		ServeCorruptBytes: true,
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v1.12.8",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: true, BinaryName: "sing-box", Payload: badScript,
			}},
		}},
	})

	// Part A: Corrupt archive bytes
	if err := srv.SendEnvelope("server.kernel_update", "upd-corrupt", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.8-corrupt",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      "",
	}); err != nil {
		t.Fatal(err)
	}
	ev1, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateFailed(ev1.Status) {
		t.Fatalf("expected failure on corrupt archive, got ok=%v ev=%+v", ok, ev1)
	}

	// Part B: Valid archive containing failing --version binary
	mark := srv.EventsLen()
	gh.SetCorruptArchive(false)
	if err := srv.SendEnvelope("server.kernel_update", "upd-badprobe", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.8-badprobe",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}
	dl := time.Now().Add(10 * time.Second)
	var ev2 AgentEventPayload
	var got2 bool
	for time.Now().Before(dl) {
		for _, e := range srv.EventsSince(mark) {
			if e.Event == "kernel_update_result" && e.Kernel == "sing-box" {
				ev2 = e
				got2 = true
				break
			}
		}
		if got2 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !got2 || !f08_isUpdateFailed(ev2.Status) {
		t.Fatalf("expected failure on failed version probe, got ok=%v ev=%+v", got2, ev2)
	}

	if gotSHA := f08_fileSHA256(t, kernels.SingBoxBin); gotSHA != origSHA {
		t.Fatalf("binary modified despite corrupt archive / probe failure")
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPIDBefore {
		t.Fatalf("sing-box PID changed on aborted update: before=%d after=%v", sbPIDBefore, got)
	}
}

func TestF08_Tier2_CrashWithin3sHealthWindowAutoRollback(t *testing.T) {
	_, srv, kernels, syncCfg := f08_setupRunningAgent(t)
	origSHA := f08_fileSHA256(t, kernels.SingBoxBin)
	mark := srv.EventsLen()

	// Variant passes --version, crashes immediately on run -> triggers 3s health rollback
	crashBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 9.9.9-crash", true)
	assetName := "sing-box-9.9.9-crash.tar.gz"
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		Releases: []MockGitHubRelease{{
			Owner: "SagerNet", Repo: "sing-box", TagName: "v9.9.9",
			Assets: []MockGitHubAsset{{
				Name: assetName, Archive: true, BinaryName: "sing-box", Payload: crashBytes,
			}},
		}},
	})

	if err := srv.SendEnvelope("server.kernel_update", "upd-rollback", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "9.9.9-crash",
		DownloadURL: gh.AssetURL(assetName),
		SHA256:      gh.AssetSHA256(assetName),
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(20*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateFailed(ev.Status) {
		t.Fatalf("expected kernel_update_result failure after crash rollback, got ok=%v ev=%+v", ok, ev)
	}

	sawRollingBack := false
	for _, e := range srv.EventsSince(mark) {
		if e.Event == "kernel_update_progress" && e.Message == "rolling_back" {
			sawRollingBack = true
			break
		}
	}
	if !sawRollingBack {
		t.Fatalf("expected kernel_update_progress rolling_back event, got %+v", srv.EventsSince(mark))
	}

	if gotSHA := f08_fileSHA256(t, kernels.SingBoxBin); gotSHA != origSHA {
		t.Fatalf("expected binary restored to original SHA %s, got %s", origSHA, gotSHA)
	}
	verOut, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(verOut), "1.11.4") {
		t.Fatalf("expected restored original version 1.11.4, got err=%v out=%q", err, string(verOut))
	}
	if kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected rolled-back sing-box restarted and running, got %v", kernels.RunningPIDs("sing-box"))
	}
	f08_assertTCPListening(t, syncCfg.SS.TCPPort)
}

func TestF08_Tier2_HTTP404DownloadFailureLeavesKernelUntouched(t *testing.T) {
	_, srv, kernels, _ := f08_setupRunningAgent(t)
	origSHA := f08_fileSHA256(t, kernels.SingBoxBin)
	sbPIDBefore := kernels.RunningPIDs("sing-box")[0]

	gh := StartMockGitHubServer(t, MockGitHubOptions{})
	if err := srv.SendEnvelope("server.kernel_update", "upd-404", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.12.9",
		DownloadURL: gh.URL() + "/download/does-not-exist.tar.gz",
		SHA256:      "",
	}); err != nil {
		t.Fatal(err)
	}

	ev, ok := srv.WaitForEvent(10*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateFailed(ev.Status) {
		t.Fatalf("expected update failure on HTTP 404, got ok=%v ev=%+v", ok, ev)
	}
	if gotSHA := f08_fileSHA256(t, kernels.SingBoxBin); gotSHA != origSHA {
		t.Fatalf("binary modified on HTTP 404")
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPIDBefore {
		t.Fatalf("sing-box PID changed on HTTP 404: before=%d after=%v", sbPIDBefore, got)
	}
}

func TestF08_Tier2_InvalidKernelNameRejected(t *testing.T) {
	_, srv, kernels, _ := f08_setupRunningAgent(t)
	snellPID := kernels.RunningPIDs("snell-server")[0]
	stlsPID := kernels.RunningPIDs("shadow-tls")[0]
	sbPID := kernels.RunningPIDs("sing-box")[0]

	gh := StartMockGitHubServer(t, MockGitHubOptions{})

	// 1. Unknown kernel name
	if err := srv.SendEnvelope("server.kernel_update", "upd-badkernel", ServerKernelUpdatePayload{
		Kernel:      "unknown-kernel",
		Version:     "1.0.0",
		DownloadURL: gh.URL() + "/download/foo.tar.gz",
		SHA256:      "",
	}); err != nil {
		t.Fatal(err)
	}
	ev1, ok := srv.WaitForEvent(8*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "unknown-kernel"
	})
	if !ok || !f08_isUpdateFailed(ev1.Status) {
		t.Fatalf("expected failure for unknown kernel name, got ok=%v ev=%+v", ok, ev1)
	}

	// 2. Non-HTTP download_url scheme
	if err := srv.SendEnvelope("server.kernel_update", "upd-badscheme", ServerKernelUpdatePayload{
		Kernel:      "sing-box",
		Version:     "1.0.0",
		DownloadURL: "ftp://invalid.example.com/sing-box.tar.gz",
		SHA256:      "",
	}); err != nil {
		t.Fatal(err)
	}
	ev2, ok := srv.WaitForEvent(8*time.Second, func(e AgentEventPayload) bool {
		return e.Event == "kernel_update_result" && e.Kernel == "sing-box"
	})
	if !ok || !f08_isUpdateFailed(ev2.Status) {
		t.Fatalf("expected failure for ftp:// download_url, got ok=%v ev=%+v", ok, ev2)
	}

	if got := kernels.RunningPIDs("snell-server"); len(got) != 1 || got[0] != snellPID {
		t.Fatalf("snell-server PID changed on rejected updates")
	}
	if got := kernels.RunningPIDs("shadow-tls"); len(got) != 1 || got[0] != stlsPID {
		t.Fatalf("shadow-tls PID changed on rejected updates")
	}
	if got := kernels.RunningPIDs("sing-box"); len(got) != 1 || got[0] != sbPID {
		t.Fatalf("sing-box PID changed on rejected updates")
	}
}
