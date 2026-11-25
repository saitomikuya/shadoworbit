package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/agent/dnsproxy"
	"snell-panel/internal/agent/supervisor"
	"snell-panel/internal/agent/updater"
	"snell-panel/internal/protocol"
)

func reserveFreePorts(t *testing.T, count int) []int {
	t.Helper()
	if count <= 0 {
		return nil
	}
	lns := make([]net.Listener, 0, count)
	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			for _, openLn := range lns {
				_ = openLn.Close()
			}
			t.Fatalf("reserve free tcp port: %v", err)
		}
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return ports
}

func reserveFreePort(t *testing.T) int {
	t.Helper()
	return reserveFreePorts(t, 1)[0]
}

func TestParseConfig(t *testing.T) {
	t.Run("env and scheme normalization", func(t *testing.T) {
		env := map[string]string{
			"PANEL_URL":           "https://panel.example.com",
			"NODE_TOKEN":          "nd_live_0123456789abcdef0123456789abcdef",
			"DATA_DIR":            "/tmp/agent-data",
			"IFACE":               "eth0",
			"LOCAL_DNS_PORT":      "15353",
			"STATS_PORT":          "10099",
			"TLS_SKIP_VERIFY":     "true",
			"PROC_NET_DEV_PATH":   "/tmp/proc/net/dev",
			"PROC_NET_ROUTE_PATH": "/tmp/proc/net/route",
		}
		cfg, err := ParseConfig(nil, func(k string) string { return env[k] })
		if err != nil {
			t.Fatalf("ParseConfig failed: %v", err)
		}
		if cfg.PanelURL != "wss://panel.example.com" {
			t.Fatalf("expected wss normalized URL, got %q", cfg.PanelURL)
		}
		if cfg.LocalDNSPort != 15353 || cfg.StatsPort != 10099 || !cfg.TLSSkipVerify || cfg.Iface != "eth0" {
			t.Fatalf("unexpected parsed config: %+v", cfg)
		}
		if cfg.ProcNetDevPath != "/tmp/proc/net/dev" || cfg.ProcNetRoutePath != "/tmp/proc/net/route" {
			t.Fatalf("unexpected proc paths: %+v", cfg)
		}
	})

	t.Run("flag overrides env", func(t *testing.T) {
		env := map[string]string{
			"PANEL_URL":  "http://old.example.com",
			"NODE_TOKEN": "nd_live_env",
		}
		cfg, err := ParseConfig([]string{
			"-panel-url", "wss://new.example.com:8443",
			"-token", "nd_live_flag_secret_token_1234",
			"-local-dns-port", "2053",
		}, func(k string) string { return env[k] })
		if err != nil {
			t.Fatalf("ParseConfig failed: %v", err)
		}
		if cfg.PanelURL != "wss://new.example.com:8443" || cfg.NodeToken != "nd_live_flag_secret_token_1234" || cfg.LocalDNSPort != 2053 {
			t.Fatalf("flag override failed: %+v", cfg)
		}
	})

	t.Run("bracketed IPv6 panel URLs accepted", func(t *testing.T) {
		for _, tc := range []struct {
			in   string
			want string
		}{
			{"wss://[::1]:8443", "wss://[::1]:8443"},
			{"wss://[::1]", "wss://[::1]"},
			{"https://[2001:db8::1]:443", "wss://[2001:db8::1]:443"},
		} {
			cfg, err := ParseConfig(nil, func(k string) string {
				switch k {
				case "PANEL_URL":
					return tc.in
				case "NODE_TOKEN":
					return "nd_live_ipv6_token_1234"
				default:
					return ""
				}
			})
			if err != nil {
				t.Fatalf("ParseConfig(%q) failed: %v", tc.in, err)
			}
			if cfg.PanelURL != tc.want {
				t.Fatalf("ParseConfig(%q) PanelURL = %q, want %q", tc.in, cfg.PanelURL, tc.want)
			}
		}
	})

	t.Run("validation errors including M1 §3.3 advisories", func(t *testing.T) {
		badCases := []struct {
			name string
			env  map[string]string
			args []string
		}{
			{name: "missing panel_url", env: map[string]string{"NODE_TOKEN": "nd_live_abc"}},
			{name: "bad scheme", env: map[string]string{"PANEL_URL": "ftp://a.com", "NODE_TOKEN": "nd_live_abc"}},
			{name: "missing host", env: map[string]string{"PANEL_URL": "wss://", "NODE_TOKEN": "nd_live_abc"}},
			{name: "empty hostname with port", env: map[string]string{"PANEL_URL": "wss://:8443", "NODE_TOKEN": "nd_live_abc"}},
			{name: "trailing colon empty port", env: map[string]string{"PANEL_URL": "wss://panel.example.com:", "NODE_TOKEN": "nd_live_abc"}},
			{name: "unbracketed ipv6 with port", env: map[string]string{"PANEL_URL": "wss://::1:8443", "NODE_TOKEN": "nd_live_abc"}},
			{name: "unbracketed ipv6 without port", env: map[string]string{"PANEL_URL": "wss://::1", "NODE_TOKEN": "nd_live_abc"}},
			{name: "bracketed ipv6 trailing colon", env: map[string]string{"PANEL_URL": "wss://[::1]:", "NODE_TOKEN": "nd_live_abc"}},
			{name: "invalid bracketed host", env: map[string]string{"PANEL_URL": "wss://[not-an-ip]:8443", "NODE_TOKEN": "nd_live_abc"}},
			{name: "port 0", env: map[string]string{"PANEL_URL": "wss://panel.example.com:0", "NODE_TOKEN": "nd_live_abc"}},
			{name: "port out of range", env: map[string]string{"PANEL_URL": "wss://panel.example.com:70000", "NODE_TOKEN": "nd_live_abc"}},
			{name: "non-numeric port", env: map[string]string{"PANEL_URL": "wss://panel.example.com:abc", "NODE_TOKEN": "nd_live_abc"}},
			{name: "missing token", env: map[string]string{"PANEL_URL": "wss://a.com"}},
			{name: "empty data dir", env: map[string]string{"PANEL_URL": "wss://a.com", "NODE_TOKEN": "tok"}, args: []string{"-data-dir", ""}},
			{name: "invalid local dns port", env: map[string]string{"PANEL_URL": "wss://a.com", "NODE_TOKEN": "tok", "LOCAL_DNS_PORT": "70000"}},
			{name: "invalid stats port", env: map[string]string{"PANEL_URL": "wss://a.com", "NODE_TOKEN": "tok", "STATS_PORT": "0"}},
			{name: "non-int port", env: map[string]string{"PANEL_URL": "wss://a.com", "NODE_TOKEN": "tok", "LOCAL_DNS_PORT": "abc"}},
			{name: "local dns port equals stats port", env: map[string]string{"PANEL_URL": "wss://a.com", "NODE_TOKEN": "tok", "LOCAL_DNS_PORT": "1053", "STATS_PORT": "1053"}},
		}
		for _, tc := range badCases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := ParseConfig(tc.args, func(k string) string { return tc.env[k] }); err == nil {
					t.Fatalf("expected validation error for %s", tc.name)
				}
			})
		}
	})

	t.Run("version flag", func(t *testing.T) {
		cfg, err := ParseConfig([]string{"-version"}, nil)
		if err != nil {
			t.Fatalf("ParseConfig -version failed: %v", err)
		}
		var out bytes.Buffer
		if err := run(context.Background(), cfg, &out); err != nil {
			t.Fatalf("run -version failed: %v", err)
		}
		if !strings.Contains(out.String(), "snell-agent version=") {
			t.Fatalf("unexpected version output: %q", out.String())
		}
	})
}

func TestRedactTokenAndPanelURL(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"short", "***"},
		{"123456789012", "***"},
		{"abcdefghijklm", "ab***lm"},         // 13 chars non-nd_live_
		{"0123456789abcdef", "01***ef"},      // 16 chars non-nd_live_
		{"0123456789abcdef0", "0123***def0"}, // 17 chars non-nd_live_
		{"nd_live_12345", "nd_live_***"},     // 13 chars nd_live_
		{"nd_live_12345678", "nd_live_***"},  // 16 chars nd_live_
		{"nd_live_123456789", "nd_live_***6789"},
		{"nd_live_super_secret_token_9876543210", "nd_live_***3210"},
	}
	for _, tc := range cases {
		if got := RedactToken(tc.in); got != tc.want {
			t.Fatalf("RedactToken(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}

	redacted := redactPanelURL("wss://admin:super_secret_pw@panel.example.com:8443/api/v1/agent/ws")
	if strings.Contains(redacted, "super_secret_pw") {
		t.Fatalf("redactPanelURL leaked password: %q", redacted)
	}
	if !strings.Contains(redacted, "panel.example.com:8443") {
		t.Fatalf("redactPanelURL lost host: %q", redacted)
	}
}

func TestRunRejectsPortCollisionAtRuntime(t *testing.T) {
	err := runWithReady(context.Background(), Config{
		PanelURL:     "wss://panel.example.com",
		NodeToken:    "nd_live_test_token_123456",
		DataDir:      t.TempDir(),
		LocalDNSPort: 15000,
		StatsPort:    15000,
	}, io.Discard, nil)
	if err == nil || !strings.Contains(err.Error(), "cannot equal") {
		t.Fatalf("expected runtime port collision error, got %v", err)
	}
}

func TestRunCreatesDirsRedactsTokenAndShutsDown(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "agent-state")
	secretToken := "nd_live_super_secret_token_9876543210"

	ports := reserveFreePorts(t, 2)
	cfg := Config{
		PanelURL:     "wss://user:secret_pass_xyz@panel.example.com",
		NodeToken:    secretToken,
		DataDir:      dataDir,
		LocalDNSPort: ports[0],
		StatsPort:    ports[1],
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	ready := make(chan struct{})
	errCh := make(chan error, 1)
	var out bytes.Buffer
	go func() {
		errCh <- runWithReady(ctx, cfg, &out, ready)
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent exited prematurely: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for agent ready")
	}

	for _, dir := range []string{dataDir, filepath.Join(dataDir, "tmp")} {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			t.Fatalf("expected directory %q to exist: err=%v", dir, err)
		}
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("expected clean exit, got %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for agent shutdown")
	}

	logged := out.String()
	if strings.Contains(logged, secretToken) {
		t.Fatalf("agent log leaked full NODE_TOKEN: %s", logged)
	}
	if strings.Contains(logged, "secret_pass_xyz") {
		t.Fatalf("agent log leaked URL password: %s", logged)
	}
	if !strings.Contains(logged, "nd_live_***3210") {
		t.Fatalf("expected redacted token in log output, got: %s", logged)
	}
}

// --- Coordinator Unit Tests ---

type fakeDNSManager struct {
	mu          sync.Mutex
	port        int
	applyCalls  []protocol.DNSConfig
	updateCalls []dnsproxy.Config
	applyErr    error
	onApply     func(protocol.DNSConfig)
}

func (f *fakeDNSManager) ApplyProtocolConfig(cfg protocol.DNSConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onApply != nil {
		f.onApply(cfg)
	}
	f.applyCalls = append(f.applyCalls, cfg)
	if f.applyErr != nil {
		return f.applyErr
	}
	if cfg.LocalPort > 0 {
		f.port = cfg.LocalPort
	}
	return nil
}

func (f *fakeDNSManager) UpdateConfig(cfg dnsproxy.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.updateCalls = append(f.updateCalls, cfg)
	if cfg.ListenPort > 0 {
		f.port = cfg.ListenPort
	}
	return nil
}

func (f *fakeDNSManager) Port() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.port
}

type fakeSupervisorManager struct {
	mu         sync.Mutex
	applyCalls []protocol.ServerConfigSync
	applyErr   error
	onApply    func(protocol.ServerConfigSync)
}

func (f *fakeSupervisorManager) ApplyConfig(ctx context.Context, cfg protocol.ServerConfigSync) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.onApply != nil {
		f.onApply(cfg)
	}
	f.applyCalls = append(f.applyCalls, cfg)
	return f.applyErr
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type fakeCollectorManager struct {
	mu           sync.Mutex
	usersCalls   [][]protocol.SSUserEntry
	statsEnabled []bool
}

func (f *fakeCollectorManager) SetActiveUsers(users []protocol.SSUserEntry) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.usersCalls = append(f.usersCalls, users)
}

func (f *fakeCollectorManager) SetStatsEnabled(enabled bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.statsEnabled = append(f.statsEnabled, enabled)
}

func TestConfigCoordinatorOrderingReconciliationRevisionsAndRollback(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("dnsproxy applied before supervisor, LocalDNSPort reconciled (1053 -> 15353 -> 0), and revision semantics", func(t *testing.T) {
		dataDir := t.TempDir()
		var seq []string
		var events []protocol.AgentEvent

		dns := &fakeDNSManager{
			port: 1053,
			onApply: func(protocol.DNSConfig) {
				seq = append(seq, "dnsproxy")
			},
		}
		sup := &fakeSupervisorManager{
			onApply: func(protocol.ServerConfigSync) {
				seq = append(seq, "supervisor")
			},
		}
		col := &fakeCollectorManager{}
		initialDNS := dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 1053, UpstreamDNS: dnsproxy.DefaultUpstreamDNS}

		coord := newConfigCoordinator(dns, sup, col, func(ev protocol.AgentEvent) {
			events = append(events, ev)
		}, logger, initialDNS, 1053, 10085, dataDir)

		// Rev 1: panel sets DNS.LocalPort = 15353.
		cfg1 := protocol.ServerConfigSync{
			ConfigRevision: 1,
			SS: protocol.SSConfig{
				Enabled: true,
				Users:   []protocol.SSUserEntry{{UserID: 10, Username: "alice"}},
			},
			DNS: protocol.DNSConfig{LocalPort: 15353, UnlockEnabled: true, Rules: []string{"netflix.com"}},
		}
		if err := coord.Apply(context.Background(), cfg1, true); err != nil {
			t.Fatalf("Apply rev 1 failed: %v", err)
		}
		if len(seq) != 2 || seq[0] != "dnsproxy" || seq[1] != "supervisor" {
			t.Fatalf("expected dnsproxy before supervisor, got %v", seq)
		}
		if sup.applyCalls[0].DNS.LocalPort != 15353 {
			t.Fatalf("expected supervisor to receive reconciled port 15353, got %d", sup.applyCalls[0].DNS.LocalPort)
		}
		if len(col.usersCalls) != 1 || len(col.usersCalls[0]) != 1 || !col.statsEnabled[0] {
			t.Fatalf("expected collector updated on success")
		}
		if coord.CurrentRevision() != 1 {
			t.Fatalf("expected currentRevision=1, got %d", coord.CurrentRevision())
		}
		if len(events) != 1 || events[0].Event != protocol.EventConfigApplied || events[0].ConfigRevision != 1 || events[0].Status != protocol.EventStatusSuccess {
			t.Fatalf("expected 1 config_applied event for rev 1, got %+v", events)
		}

		// Verify last_config.json persisted with 0600 permissions.
		lastPath := filepath.Join(dataDir, lastConfigFilename)
		info, err := os.Stat(lastPath)
		if err != nil {
			t.Fatalf("expected last_config.json: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("expected mode 0600, got %o", info.Mode().Perm())
		}

		// Stale rev 0 (< 1): ignored cleanly (no restarts, no new events, no overwrite).
		if err := coord.Apply(context.Background(), protocol.ServerConfigSync{ConfigRevision: 0}, true); err != nil {
			t.Fatalf("stale config_sync returned unexpected err: %v", err)
		}
		if len(dns.applyCalls) != 1 || len(sup.applyCalls) != 1 || len(events) != 1 {
			t.Fatalf("stale config_sync should not restart or emit events: dns=%d sup=%d events=%d", len(dns.applyCalls), len(sup.applyCalls), len(events))
		}

		// Equal rev 1 (== 1): skips redundant restarts AND emits config_applied!
		if err := coord.Apply(context.Background(), cfg1, true); err != nil {
			t.Fatalf("equal rev config_sync failed: %v", err)
		}
		if len(dns.applyCalls) != 1 || len(sup.applyCalls) != 1 {
			t.Fatalf("equal rev should skip restarts: dns=%d sup=%d", len(dns.applyCalls), len(sup.applyCalls))
		}
		if len(events) != 2 || events[1].Event != protocol.EventConfigApplied || events[1].ConfigRevision != 1 || events[1].Message != "configuration already applied" {
			t.Fatalf("unexpected equal-rev event: %+v", events)
		}

		// Rev 2 with DNS.LocalPort == 0 reconciles back to configuredDNSPort (1053).
		cfg2 := protocol.ServerConfigSync{
			ConfigRevision: 2,
			DNS:            protocol.DNSConfig{LocalPort: 0},
		}
		if err := coord.Apply(context.Background(), cfg2, true); err != nil {
			t.Fatalf("Apply rev 2 failed: %v", err)
		}
		if dns.Port() != 1053 || sup.applyCalls[1].DNS.LocalPort != 1053 {
			t.Fatalf("expected reconciliation back to 1053, dns=%d sup=%d", dns.Port(), sup.applyCalls[1].DNS.LocalPort)
		}
		if len(events) != 3 || events[2].Event != protocol.EventConfigApplied || events[2].ConfigRevision != 2 {
			t.Fatalf("expected config_applied event for rev 2, got %+v", events)
		}
	})

	t.Run("cold boot rejects config_revision <= 0 with config_error without writing last_config", func(t *testing.T) {
		for _, badRev := range []int64{0, -1} {
			dataDir := t.TempDir()
			var events []protocol.AgentEvent
			dns := &fakeDNSManager{port: 1053}
			sup := &fakeSupervisorManager{}
			col := &fakeCollectorManager{}
			initialDNS := dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 1053, UpstreamDNS: dnsproxy.DefaultUpstreamDNS}
			coord := newConfigCoordinator(dns, sup, col, func(ev protocol.AgentEvent) {
				events = append(events, ev)
			}, logger, initialDNS, 1053, 10085, dataDir)

			err := coord.Apply(context.Background(), protocol.ServerConfigSync{ConfigRevision: badRev}, true)
			if err == nil {
				t.Fatalf("expected error on cold boot with config_revision=%d", badRev)
			}
			if coord.CurrentRevision() != 0 || len(sup.applyCalls) != 0 || len(dns.applyCalls) != 0 {
				t.Fatalf("expected no apply side effects on bad rev %d: curRev=%d sup=%d dns=%d", badRev, coord.CurrentRevision(), len(sup.applyCalls), len(dns.applyCalls))
			}
			if len(events) != 1 || events[0].Event != protocol.EventConfigError || events[0].ConfigRevision != badRev || events[0].Status != protocol.EventStatusFailed {
				t.Fatalf("expected EventConfigError for bad rev %d, got %+v", badRev, events)
			}
			if _, statErr := os.Stat(filepath.Join(dataDir, lastConfigFilename)); !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("expected last_config.json not written, got err=%v", statErr)
			}
		}
	})

	t.Run("dnsproxy failure emits config_error and leaves supervisor/collector/last_config untouched", func(t *testing.T) {
		dataDir := t.TempDir()
		var events []protocol.AgentEvent
		dns := &fakeDNSManager{port: 1053, applyErr: errors.New("bind failed")}
		sup := &fakeSupervisorManager{}
		col := &fakeCollectorManager{}
		coord := newConfigCoordinator(dns, sup, col, func(ev protocol.AgentEvent) {
			events = append(events, ev)
		}, logger, dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 1053}, 1053, 10085, dataDir)

		err := coord.Apply(context.Background(), protocol.ServerConfigSync{
			ConfigRevision: 3,
			DNS:            protocol.DNSConfig{LocalPort: 15353},
		}, true)
		if err == nil {
			t.Fatal("expected error when dnsproxy fails")
		}
		if len(sup.applyCalls) != 0 || len(col.usersCalls) != 0 || coord.CurrentRevision() != 0 {
			t.Fatal("supervisor/collector/revision should remain untouched on dnsproxy failure")
		}
		if len(events) != 1 || events[0].Event != protocol.EventConfigError || events[0].Status != protocol.EventStatusFailed {
			t.Fatalf("expected config_error event, got %+v", events)
		}
		if _, err := os.Stat(filepath.Join(dataDir, lastConfigFilename)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("last_config.json should not exist after failure, err=%v", err)
		}
	})

	t.Run("supervisor failure rolls back dnsproxy (both !hasPrev and hasPrev) and preserves last_config.json", func(t *testing.T) {
		dataDir := t.TempDir()
		dns := &fakeDNSManager{port: 1053}
		sup := &fakeSupervisorManager{}
		col := &fakeCollectorManager{}
		initialDNS := dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 1053, UpstreamDNS: dnsproxy.DefaultUpstreamDNS}
		var events []protocol.AgentEvent

		coord := newConfigCoordinator(dns, sup, col, func(ev protocol.AgentEvent) {
			events = append(events, ev)
		}, logger, initialDNS, 1053, 10085, dataDir)

		// Failure when !hasPrev -> rolls back via UpdateConfig(initialDNS).
		sup.applyErr = errors.New("sing-box check failed")
		err := coord.Apply(context.Background(), protocol.ServerConfigSync{
			ConfigRevision: 1,
			DNS:            protocol.DNSConfig{LocalPort: 15353},
		}, true)
		if err == nil {
			t.Fatal("expected supervisor failure")
		}
		if dns.Port() != 1053 || len(dns.updateCalls) != 1 || dns.updateCalls[0].ListenPort != 1053 {
			t.Fatalf("expected dnsproxy rollback to initialDNS (1053), got port=%d updates=%+v", dns.Port(), dns.updateCalls)
		}
		if coord.CurrentRevision() != 0 || len(col.usersCalls) != 0 || len(events) != 0 {
			t.Fatalf("expected no collector/rev/duplicate-event changes on supervisor failure")
		}

		// Succeed rev 2 on 15353 -> persists last_config.json.
		sup.applyErr = nil
		rev2 := protocol.ServerConfigSync{
			ConfigRevision: 2,
			DNS:            protocol.DNSConfig{LocalPort: 15353, UnlockEnabled: true},
		}
		if err := coord.Apply(context.Background(), rev2, true); err != nil {
			t.Fatalf("Apply rev 2 failed: %v", err)
		}

		// Fail rev 3 on 16353 -> rolls back dnsproxy to rev 2 (15353) and preserves rev 2 in last_config.json.
		sup.applyErr = errors.New("snell failed")
		err = coord.Apply(context.Background(), protocol.ServerConfigSync{
			ConfigRevision: 3,
			DNS:            protocol.DNSConfig{LocalPort: 16353},
		}, true)
		if err == nil {
			t.Fatal("expected rev 3 failure")
		}
		if dns.Port() != 15353 {
			t.Fatalf("expected dnsproxy rolled back to 15353, got %d", dns.Port())
		}
		if coord.CurrentRevision() != 2 {
			t.Fatalf("expected revision preserved at 2, got %d", coord.CurrentRevision())
		}
		loaded, ok := loadLastConfig(filepath.Join(dataDir, lastConfigFilename), logger)
		if !ok || loaded.ConfigRevision != 2 {
			t.Fatalf("expected last_config.json preserved at rev 2, got ok=%v rev=%d", ok, loaded.ConfigRevision)
		}
	})

	t.Run("effective dns.local_port colliding with stats_port rejected pre-apply", func(t *testing.T) {
		dataDir := t.TempDir()
		dns := &fakeDNSManager{port: 1053}
		sup := &fakeSupervisorManager{}
		col := &fakeCollectorManager{}
		var events []protocol.AgentEvent
		coord := newConfigCoordinator(dns, sup, col, func(ev protocol.AgentEvent) {
			events = append(events, ev)
		}, logger, dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 1053}, 1053, 10085, dataDir)

		err := coord.Apply(context.Background(), protocol.ServerConfigSync{
			ConfigRevision: 4,
			DNS:            protocol.DNSConfig{LocalPort: 10085},
		}, true)
		if err == nil {
			t.Fatal("expected collision error")
		}
		if len(dns.applyCalls) != 0 || len(sup.applyCalls) != 0 {
			t.Fatal("expected pre-check to prevent touching dnsproxy or supervisor")
		}
		if len(events) != 1 || events[0].Event != protocol.EventConfigError {
			t.Fatalf("expected config_error event, got %+v", events)
		}
	})

	t.Run("initialDNS ListenPort 0 preserves initial bound port on !hasPrev rollback", func(t *testing.T) {
		dataDir := t.TempDir()
		dns := &fakeDNSManager{port: 1053}
		sup := &fakeSupervisorManager{applyErr: errors.New("sing-box failed")}
		col := &fakeCollectorManager{}
		initialDNS := dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 0, UpstreamDNS: dnsproxy.DefaultUpstreamDNS}
		coord := newConfigCoordinator(dns, sup, col, nil, logger, initialDNS, 1053, 10085, dataDir)

		err := coord.Apply(context.Background(), protocol.ServerConfigSync{
			ConfigRevision: 1,
			DNS:            protocol.DNSConfig{LocalPort: 15353},
		}, true)
		if err == nil {
			t.Fatal("expected supervisor failure")
		}
		if dns.Port() != 1053 || len(dns.updateCalls) != 1 || dns.updateCalls[0].ListenPort != 1053 {
			t.Fatalf("expected rollback to preserve initial bound port 1053, got port=%d updates=%+v", dns.Port(), dns.updateCalls)
		}
	})
}

func TestLoadLastConfigQuarantinesCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, lastConfigFilename)
	if err := os.WriteFile(path, []byte("{corrupt json"), 0o600); err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, ok := loadLastConfig(path, logger); ok {
		t.Fatal("expected loadLastConfig to reject corrupt file")
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected original corrupt file moved away, err=%v", err)
	}
	matches, err := filepath.Glob(path + ".corrupt.*")
	if err != nil || len(matches) != 1 {
		t.Fatalf("expected 1 quarantined corrupt file, got %v (err=%v)", matches, err)
	}
}

func writeFakeKernelScripts(t *testing.T) (snellBin, stlsBin, singBoxBin string) {
	t.Helper()
	binDir := t.TempDir()

	writeScript := func(name, body string) string {
		p := filepath.Join(binDir, name)
		if err := os.WriteFile(p, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// Minimal daemon scripts responding to --version/-v and staying alive until SIGTERM.
	snellBin = writeScript("snell-server", `#!/bin/sh
if [ "$1" = "-v" ] || [ "$1" = "--version" ]; then
  echo "snell-server v5.0.0"
  exit 0
fi
trap 'exit 0' TERM INT
while true; do sleep 1; done
`)
	stlsBin = writeScript("shadow-tls", `#!/bin/sh
if [ "$1" = "--version" ]; then
  echo "shadow-tls 0.2.25"
  exit 0
fi
trap 'exit 0' TERM INT
while true; do sleep 1; done
`)
	singBoxBin = writeScript("sing-box", `#!/bin/sh
if [ "$1" = "version" ] || [ "$1" = "--version" ]; then
  echo "sing-box version 1.11.0"
  exit 0
fi
if [ "$1" = "check" ]; then
  exit 0
fi
trap 'exit 0' TERM INT
while true; do sleep 1; done
`)
	return snellBin, stlsBin, singBoxBin
}

func TestAgentOfflineAutonomyProcNetDevAndCleanShutdown(t *testing.T) {
	snellBin, stlsBin, singBoxBin := writeFakeKernelScripts(t)
	dataDir := t.TempDir()
	ports := reserveFreePorts(t, 7)
	dnsPort1 := ports[0]
	dnsPort2 := ports[1]
	statsPort := ports[2]
	snellPubPort := ports[3]
	ssTCPPort := ports[4]
	ssUDPPort := ports[5]
	snellInnerPort := ports[6]

	// Prepare custom PROC_NET_DEV_PATH to verify env wiring into collector.
	procNetDev := filepath.Join(dataDir, "proc_net_dev")
	if err := os.WriteFile(procNetDev, []byte(
		"Inter-|   Receive                                                |  Transmit\n"+
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
			"  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}

	// Pre-seed last_config.json for offline autonomy test.
	cached := protocol.ServerConfigSync{
		ConfigRevision: 5,
		Snell: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   snellPubPort,
			InnerPort:    snellInnerPort,
			PSK:          "snell-secret-psk",
			Obfs:         protocol.SnellObfsOff,
			STLSPassword: "stls-admin-password",
			STLSSNI:      "example.com",
		},
		SS: protocol.SSConfig{
			Enabled: true,
			TCPPort: ssTCPPort,
			UDPPort: ssUDPPort,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "example.com",
			Users: []protocol.SSUserEntry{
				{UserID: 1, Username: "u1", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "p1"},
			},
		},
		DNS: protocol.DNSConfig{
			UnlockEnabled: true,
			UnlockServer:  "127.0.0.1:53",
			Rules:         []string{"example.com"},
			UpstreamDNS:   "127.0.0.1:53",
			LocalPort:     dnsPort2,
		},
	}
	if err := saveLastConfigAtomic(filepath.Join(dataDir, lastConfigFilename), cached); err != nil {
		t.Fatal(err)
	}

	// Phase 1: Boot with unreachable Panel -> must still apply last_config.json offline and bind dnsPort2!
	deadSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadSrv.URL
	deadSrv.Close()

	cfg := Config{
		PanelURL:       deadURL,
		NodeToken:      "nd_live_offline_autonomy_token_1234",
		DataDir:        dataDir,
		Iface:          "eth0",
		SnellBin:       snellBin,
		ShadowTLSBin:   stlsBin,
		SingBoxBin:     singBoxBin,
		LocalDNSPort:   dnsPort1,
		StatsPort:      statsPort,
		ProcNetDevPath: procNetDev,
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	ready1 := make(chan struct{})
	errCh1 := make(chan error, 1)
	var out1 syncBuffer
	go func() {
		errCh1 <- runWithOptions(ctx1, cfg, &out1, ready1, runtimeOptions{
			PublicIPEndpointsV4: []string{},
			PublicIPEndpointsV6: []string{},
			StartupGrace:        50 * time.Millisecond,
			BackoffBase:         25 * time.Millisecond,
			BackoffMax:          50 * time.Millisecond,
		})
	}()

	select {
	case <-ready1:
	case err := <-errCh1:
		t.Fatalf("offline boot failed: %v\nlogs:\n%s", err, out1.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for offline boot ready")
	}

	// Verify dnsproxy reconciled to dnsPort2 (from last_config.json) even while Panel is unreachable.
	udpConn, err := net.DialTimeout("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort2), time.Second)
	if err != nil {
		t.Fatalf("expected dnsproxy listening on reconciled port %d: %v", dnsPort2, err)
	}
	_ = udpConn.Close()

	// Verify sing-box.json rendered by supervisor uses dnsPort2.
	sbData, err := os.ReadFile(filepath.Join(dataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatalf("expected sing-box.json rendered offline: %v", err)
	}
	if !strings.Contains(string(sbData), fmt.Sprintf(":%d", dnsPort2)) && !strings.Contains(string(sbData), fmt.Sprintf(`"server_port": %d`, dnsPort2)) && !strings.Contains(string(sbData), fmt.Sprintf(`"server_port":%d`, dnsPort2)) {
		t.Fatalf("expected sing-box.json to reference reconciled DNS port %d:\n%s", dnsPort2, string(sbData))
	}

	cancel1()
	select {
	case err := <-errCh1:
		if err != nil {
			t.Fatalf("offline shutdown error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for offline shutdown")
	}

	// Phase 2: Connect to live httptest WS Panel -> verify agent.hello reports rev=5,
	// rev=5 config_sync skips restart & emits config_applied, and PROC_NET_DEV_PATH delta flows in agent.metrics!
	helloCh := make(chan protocol.AgentHello, 1)
	eventCh := make(chan protocol.AgentEvent, 8)
	metricsCh := make(chan protocol.AgentMetrics, 8)
	closeCodeCh := make(chan websocket.StatusCode, 1)

	liveSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		rctx, rcancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer rcancel()

		for {
			_, data, err := conn.Read(rctx)
			if err != nil {
				closeCodeCh <- websocket.CloseStatus(err)
				return
			}
			env, err := protocol.ParseEnvelope(data)
			if err != nil {
				continue
			}
			switch env.Type {
			case protocol.MsgTypeAgentHello:
				var h protocol.AgentHello
				if err := env.DecodePayload(&h); err == nil {
					helloCh <- h
					// Send same revision 5 back to verify config_applied fast-path!
					syncBytes, _ := protocol.MarshalEnvelope(protocol.MsgTypeServerConfigSync, "srv-1", cached)
					_ = conn.Write(rctx, websocket.MessageText, syncBytes)
				}
			case protocol.MsgTypeAgentEvent:
				var ev protocol.AgentEvent
				if err := env.DecodePayload(&ev); err == nil {
					eventCh <- ev
				}
			case protocol.MsgTypeAgentMetrics:
				var m protocol.AgentMetrics
				if err := env.DecodePayload(&m); err == nil {
					metricsCh <- m
				}
			}
		}
	}))
	defer liveSrv.Close()

	cfg.PanelURL = liveSrv.URL
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	ready2 := make(chan struct{})
	errCh2 := make(chan error, 1)
	var out2 syncBuffer
	go func() {
		errCh2 <- runWithOptions(ctx2, cfg, &out2, ready2, runtimeOptions{
			PublicIPEndpointsV4: []string{},
			PublicIPEndpointsV6: []string{},
			MetricsInterval:     50 * time.Millisecond,
			StartupGrace:        50 * time.Millisecond,
			BackoffBase:         25 * time.Millisecond,
			BackoffMax:          50 * time.Millisecond,
			PingInterval:        -1,
		})
	}()

	select {
	case <-ready2:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for live agent ready")
	}

	select {
	case h := <-helloCh:
		if h.ConfigRevision != 5 {
			t.Fatalf("expected agent.hello config_revision=5 from last_config.json, got %d", h.ConfigRevision)
		}
		if h.Versions.SingBox == "" || h.Versions.SnellServer == "" || h.Versions.ShadowTLS == "" {
			t.Fatalf("expected probed versions in agent.hello, got %+v", h.Versions)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for agent.hello")
	}

	// Expect config_applied for rev 5 fast-path.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-eventCh:
			if ev.Event == protocol.EventConfigApplied && ev.ConfigRevision == 5 && ev.Status == protocol.EventStatusSuccess {
				goto checkedApplied
			}
		case <-deadline:
			t.Fatal("timed out waiting for config_applied event on rev 5")
		}
	}

checkedApplied:
	// Update custom PROC_NET_DEV_PATH and confirm delta arrives in agent.metrics!
	if err := os.WriteFile(procNetDev, []byte(
		"Inter-|   Receive                                                |  Transmit\n"+
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
			"  eth0: 5500 20 0 0 0 0 0 0 8500 30 0 0 0 0 0 0\n",
	), 0o600); err != nil {
		t.Fatal(err)
	}
	// Trigger NIC poll on next 5s collector tick? Wait: default NICInterval is 5s, let's check within 7s.
	metricsDeadline := time.After(7 * time.Second)
	for {
		select {
		case m := <-metricsCh:
			if m.NicRxDelta == 4500 && m.NicTxDelta == 6500 {
				goto checkedMetrics
			}
		case <-metricsDeadline:
			t.Fatal("timed out waiting for PROC_NET_DEV_PATH delta (4500/6500) in agent.metrics")
		}
	}

checkedMetrics:
	cancel2()
	select {
	case err := <-errCh2:
		if err != nil {
			t.Fatalf("live shutdown error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for live shutdown")
	}

	select {
	case code := <-closeCodeCh:
		if code != websocket.StatusNormalClosure {
			t.Fatalf("expected NormalClosure (1000) on shutdown, got %v", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for server close status")
	}

	// Verify last_config.json still parses cleanly.
	raw, err := os.ReadFile(filepath.Join(dataDir, lastConfigFilename))
	if err != nil {
		t.Fatal(err)
	}
	var persisted protocol.ServerConfigSync
	if err := json.Unmarshal(raw, &persisted); err != nil || persisted.ConfigRevision != 5 {
		t.Fatalf("unexpected persisted last_config.json: err=%v cfg=%+v", err, persisted)
	}
}

func TestAgentBinarySIGTERMSignalShutdown(t *testing.T) {
	binPath := filepath.Join(t.TempDir(), "snell-agent-test")
	buildCmd := exec.Command("go", "build", "-o", binPath, ".")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		t.Fatalf("go build cmd/agent failed: %v\n%s", err, string(out))
	}

	dataDir := t.TempDir()
	ports := reserveFreePorts(t, 2)
	dnsPort := ports[0]
	statsPort := ports[1]

	wsConnected := make(chan struct{})
	wsClosedNormal := make(chan websocket.StatusCode, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				wsClosedNormal <- websocket.CloseStatus(err)
				return
			}
			if env, perr := protocol.ParseEnvelope(data); perr == nil && env.Type == protocol.MsgTypeAgentHello {
				select {
				case <-wsConnected:
				default:
					close(wsConnected)
				}
			}
		}
	}))
	defer srv.Close()

	cmd := exec.Command(binPath,
		"-panel-url", srv.URL,
		"-token", "nd_live_sigterm_test_token_1234",
		"-data-dir", dataDir,
		"-local-dns-port", fmt.Sprintf("%d", dnsPort),
		"-stats-port", fmt.Sprintf("%d", statsPort),
	)
	var stdout, stderr syncBuffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start agent binary: %v", err)
	}
	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	waitReaped := func() {
		select {
		case <-waitDone:
		case <-time.After(3 * time.Second):
		}
	}

	select {
	case <-wsConnected:
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		waitReaped()
		t.Fatalf("agent binary failed to connect to WS; stdout=%s stderr=%s", stdout.String(), stderr.String())
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		_ = cmd.Process.Kill()
		waitReaped()
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case err := <-waitDone:
		if err != nil {
			t.Fatalf("expected exit 0 on SIGTERM, got %v\nstdout=%s\nstderr=%s", err, stdout.String(), stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		waitReaped()
		t.Fatalf("timed out waiting for agent binary SIGTERM exit; stdout=%s stderr=%s", stdout.String(), stderr.String())
	}

	select {
	case code := <-wsClosedNormal:
		if code != websocket.StatusNormalClosure {
			t.Fatalf("expected NormalClosure (1000) on SIGTERM, got %v", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for WS NormalClosure on SIGTERM")
	}
}

func TestCoordinator_LastConfigNullZeroRevAndStaleRevision(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	for _, tc := range []struct {
		name    string
		payload string
	}{
		{"literal_null", "null\n"},
		{"empty_object_zero_rev", "{}"},
		{"explicit_zero_revision", `{"config_revision":0}`},
		{"negative_revision", `{"config_revision":-3}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, lastConfigFilename)
			if err := os.WriteFile(path, []byte(tc.payload), 0o600); err != nil {
				t.Fatal(err)
			}
			if cfg, ok := loadLastConfig(path, logger); ok {
				t.Fatalf("expected loadLastConfig to reject/quarantine %s, got %+v", tc.name, cfg)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("expected %s moved away, err=%v", path, err)
			}
			matches, err := filepath.Glob(path + ".corrupt.*")
			if err != nil || len(matches) != 1 {
				t.Fatalf("expected 1 quarantined file for %s, got %v (err=%v)", tc.name, matches, err)
			}
		})
	}
}

func makeSingleFileTarGz(t *testing.T, name string, content []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func TestSingBoxHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_CROSS_MAJOR_HELPER") != "1" {
		return
	}
	var args []string
	for i, a := range os.Args {
		if a == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	mode := os.Getenv("HELPER_MODE")
	ver := os.Getenv("HELPER_VERSION")

	if len(args) > 0 && (args[0] == "version" || args[0] == "--version") {
		fmt.Println(ver)
		os.Exit(0)
	}

	var cfgPath string
	if len(args) >= 3 && args[1] == "-c" {
		cfgPath = args[2]
	}
	var cfgContent string
	if cfgPath != "" {
		b, err := os.ReadFile(cfgPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		cfgContent = string(b)
	}

	switch mode {
	case "legacy":
		if strings.Contains(cfgContent, `"type": "udp"`) {
			fmt.Fprintln(os.Stderr, "legacy 1.11 rejects typed dns")
			os.Exit(1)
		}
	case "typed":
		if strings.Contains(cfgContent, `"address": "udp://"`) {
			fmt.Fprintln(os.Stderr, "1.14 removed legacy dns address")
			os.Exit(1)
		}
	}

	if len(args) > 0 && args[0] == "check" {
		os.Exit(0)
	}

	// Parse sing-box.json TCP listen ports and bind them so Updater.observeHealth succeeds genuinely.
	var doc struct {
		Inbounds []struct {
			ListenPort int    `json:"listen_port"`
			Network    string `json:"network"`
		} `json:"inbounds"`
		Experimental struct {
			V2RayAPI struct {
				Listen string `json:"listen"`
			} `json:"v2ray_api"`
		} `json:"experimental"`
	}
	if err := json.Unmarshal([]byte(cfgContent), &doc); err == nil {
		var addrs []string
		for _, inb := range doc.Inbounds {
			if inb.ListenPort > 0 && !strings.EqualFold(inb.Network, "udp") {
				addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", inb.ListenPort))
			}
		}
		if doc.Experimental.V2RayAPI.Listen != "" {
			addrs = append(addrs, doc.Experimental.V2RayAPI.Listen)
		}
		for _, addr := range addrs {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "listen %s: %v\n", addr, err)
				os.Exit(1)
			}
			defer ln.Close()
			go func(l net.Listener) {
				for {
					c, err := l.Accept()
					if err != nil {
						return
					}
					_ = c.Close()
				}
			}(ln)
		}
	}

	if mode == "crash_300ms" {
		time.Sleep(300 * time.Millisecond)
		fmt.Fprintln(os.Stderr, "boom at 300ms")
		os.Exit(1)
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh
	os.Exit(0)
}

func makeCrossMajorSingBoxScript(t *testing.T, versionOut string, mode string) []byte {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return []byte(fmt.Sprintf(`#!/bin/sh
export GO_WANT_CROSS_MAJOR_HELPER=1
export HELPER_VERSION=%q
export HELPER_MODE=%q
exec %q -test.run=^TestSingBoxHelperProcess$ -- "$@"
`, versionOut, mode, exe))
}

func testFullSupervisorSyncConfig(t *testing.T, ssEnabled bool, ports []int) protocol.ServerConfigSync {
	t.Helper()
	if len(ports) != 5 {
		ports = reserveFreePorts(t, 5)
	}
	return protocol.ServerConfigSync{
		ConfigRevision: 1,
		Snell: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   ports[0],
			InnerPort:    ports[1],
			PSK:          "tier5-snell-psk",
			Obfs:         protocol.SnellObfsOff,
			STLSPassword: "tier5-stls-password",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: protocol.SSConfig{
			Enabled: ssEnabled,
			TCPPort: ports[2],
			UDPPort: ports[3],
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "swscan.apple.com",
			Users: []protocol.SSUserEntry{
				{UserID: 1, Username: "alice", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "p1"},
			},
		},
		DNS: protocol.DNSConfig{
			UnlockEnabled: false,
			UpstreamDNS:   "127.0.0.1:53",
			LocalPort:     ports[4],
		},
	}
}

func TestUpdaterSupervisor_CrossMajorSingBoxUpdateAndRollback(t *testing.T) {
	snellBin, stlsBin, _ := writeFakeKernelScripts(t)
	binDir := t.TempDir()
	sbBin := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(sbBin, makeCrossMajorSingBoxScript(t, "sing-box version 1.11.4", "legacy"), 0o755); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	var eventsMu sync.Mutex
	var events []protocol.AgentEvent
	recordEv := func(ev protocol.AgentEvent) {
		eventsMu.Lock()
		events = append(events, ev)
		eventsMu.Unlock()
	}

	ports := reserveFreePorts(t, 8)
	sup, err := supervisor.New(supervisor.Options{
		DataDir:        dataDir,
		SnellBin:       snellBin,
		ShadowTLSBin:   stlsBin,
		SingBoxBin:     sbBin,
		StatsPort:      ports[0],
		LocalDNSPort:   ports[1],
		SSInnerTCPPort: ports[2],
		StartupGrace:   120 * time.Millisecond,
		StopTimeout:    300 * time.Millisecond,
		OnEvent:        recordEv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Stop(context.Background()) })

	cfg := testFullSupervisorSyncConfig(t, true, ports[3:])
	if err := sup.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}
	sbJSONPath := filepath.Join(dataDir, "configs", "sing-box.json")
	b1, err := os.ReadFile(sbJSONPath)
	if err != nil || !strings.Contains(string(b1), `"address": "udp://127.0.0.1:`) {
		t.Fatalf("expected legacy DNS format for 1.11.4, got err=%v:\n%s", err, string(b1))
	}

	upd, err := updater.New(updater.Options{
		DataDir:               dataDir,
		Controller:            sup,
		HealthObserveDuration: 300 * time.Millisecond,
		HealthPollInterval:    40 * time.Millisecond,
		OnEvent:               recordEv,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 1. Cross-major upgrade 1.11.4 -> 1.14.4 (must re-render sing-box.json to typed DNS!).
	tg14, sha14 := makeSingleFileTarGz(t, "sing-box-1.14.4/sing-box", makeCrossMajorSingBoxScript(t, "sing-box version 1.14.4", "typed"))
	tg11, sha11 := makeSingleFileTarGz(t, "sing-box-1.11.4/sing-box", makeCrossMajorSingBoxScript(t, "sing-box version 1.11.4", "legacy"))
	tgCrash, shaCrash := makeSingleFileTarGz(t, "sing-box-1.15.0-bad/sing-box", makeCrossMajorSingBoxScript(t, "sing-box version 1.15.0-bad", "crash_300ms"))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sb-1.14.4.tar.gz":
			_, _ = w.Write(tg14)
		case "/sb-1.11.4.tar.gz":
			_, _ = w.Write(tg11)
		case "/sb-crash.tar.gz":
			_, _ = w.Write(tgCrash)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	if err := upd.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "1.14.4",
		DownloadURL: srv.URL + "/sb-1.14.4.tar.gz",
		SHA256:      sha14,
	}); err != nil {
		t.Fatalf("1.11.4 -> 1.14.4 cross-major update failed: %v", err)
	}
	b2, err := os.ReadFile(sbJSONPath)
	if err != nil || !strings.Contains(string(b2), `"type": "udp"`) || !strings.Contains(string(b2), `"default_domain_resolver": "local-dns"`) {
		t.Fatalf("expected typed DNS format after 1.14.4 upgrade, got err=%v:\n%s", err, string(b2))
	}
	if !sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected sing-box 1.14.4 healthy")
	}

	// 2. Cross-major downgrade 1.14.4 -> 1.11.4 (must re-render sing-box.json back to legacy DNS!).
	if err := upd.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "1.11.4",
		DownloadURL: srv.URL + "/sb-1.11.4.tar.gz",
		SHA256:      sha11,
	}); err != nil {
		t.Fatalf("1.14.4 -> 1.11.4 cross-major downgrade failed: %v", err)
	}
	b3, err := os.ReadFile(sbJSONPath)
	if err != nil || !strings.Contains(string(b3), `"address": "udp://127.0.0.1:`) {
		t.Fatalf("expected legacy DNS format after 1.11.4 downgrade, got err=%v:\n%s", err, string(b3))
	}

	// 3. Upgrade back to 1.14.4, then attempt broken 1.15.0-bad (crashes at 300ms during 900ms health window):
	//    must roll back to 1.14.4 cleanly AND emit ZERO spurious process_crashed events (BUG-A3)!
	if err := upd.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "1.14.4",
		DownloadURL: srv.URL + "/sb-1.14.4.tar.gz",
		SHA256:      sha14,
	}); err != nil {
		t.Fatalf("re-upgrade to 1.14.4 failed: %v", err)
	}

	updLong, err := updater.New(updater.Options{
		DataDir:               dataDir,
		Controller:            sup,
		HealthObserveDuration: 900 * time.Millisecond,
		HealthPollInterval:    40 * time.Millisecond,
		OnEvent:               recordEv,
	})
	if err != nil {
		t.Fatal(err)
	}

	eventsMu.Lock()
	evStartIdx := len(events)
	eventsMu.Unlock()

	err = updLong.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "1.15.0-bad",
		DownloadURL: srv.URL + "/sb-crash.tar.gz",
		SHA256:      shaCrash,
	})
	if err == nil {
		t.Fatal("expected broken 1.15.0-bad update to fail and roll back")
	}

	// Give any stray goroutines a brief moment to verify no delayed process_crashed fires.
	time.Sleep(150 * time.Millisecond)

	eventsMu.Lock()
	recentEvents := append([]protocol.AgentEvent(nil), events[evStartIdx:]...)
	eventsMu.Unlock()

	var crashCount, failedResultCount int
	for _, ev := range recentEvents {
		if ev.Event == protocol.EventProcessCrashed {
			crashCount++
		}
		if ev.Event == protocol.EventKernelUpdateResult && ev.Status == updater.StatusUpdateFailed {
			failedResultCount++
		}
	}
	if crashCount != 0 {
		t.Fatalf("expected 0 spurious process_crashed events during update observation window, got %d: %+v", crashCount, recentEvents)
	}
	if failedResultCount != 1 {
		t.Fatalf("expected 1 update_failed result event, got %d: %+v", failedResultCount, recentEvents)
	}

	probedVer, err := sup.ProbeVersion(context.Background(), protocol.KernelSingBox, "")
	if err != nil || !strings.Contains(probedVer, "1.14.4") {
		t.Fatalf("expected sing-box rolled back to 1.14.4, got %q (err=%v)", probedVer, err)
	}
	if !sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected rolled-back 1.14.4 sing-box healthy")
	}
}

func TestUpdaterSupervisor_DisabledAndUnconfiguredKernelUpdate(t *testing.T) {
	snellBin, stlsBin, _ := writeFakeKernelScripts(t)
	binDir := t.TempDir()
	sbBin := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(sbBin, makeCrossMajorSingBoxScript(t, "sing-box version 1.11.4", "legacy"), 0o755); err != nil {
		t.Fatal(err)
	}

	dataDir := t.TempDir()
	var eventsMu sync.Mutex
	var events []protocol.AgentEvent
	recordEv := func(ev protocol.AgentEvent) {
		eventsMu.Lock()
		events = append(events, ev)
		eventsMu.Unlock()
	}

	ports := reserveFreePorts(t, 8)
	sup, err := supervisor.New(supervisor.Options{
		DataDir:        dataDir,
		SnellBin:       snellBin,
		ShadowTLSBin:   stlsBin,
		SingBoxBin:     sbBin,
		StatsPort:      ports[0],
		LocalDNSPort:   ports[1],
		SSInnerTCPPort: ports[2],
		StartupGrace:   100 * time.Millisecond,
		StopTimeout:    300 * time.Millisecond,
		OnEvent:        recordEv,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sup.Stop(context.Background()) })

	upd, err := updater.New(updater.Options{
		DataDir:               dataDir,
		Controller:            sup,
		HealthObserveDuration: 2 * time.Second,
		HealthPollInterval:    40 * time.Millisecond,
		OnEvent:               recordEv,
	})
	if err != nil {
		t.Fatal(err)
	}

	tg12, sha12 := makeSingleFileTarGz(t, "sing-box", makeCrossMajorSingBoxScript(t, "sing-box version 1.12.0", "typed"))
	tg14, sha14 := makeSingleFileTarGz(t, "sing-box", makeCrossMajorSingBoxScript(t, "sing-box version 1.14.4", "typed"))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/1.12.0.tar.gz" {
			_, _ = w.Write(tg12)
			return
		}
		_, _ = w.Write(tg14)
	}))
	defer srv.Close()

	// 1. Unconfigured agent (no ApplyConfig yet): update must succeed cleanly without rollback!
	if err := upd.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "1.12.0",
		DownloadURL: srv.URL + "/1.12.0.tar.gz",
		SHA256:      sha12,
	}); err != nil {
		t.Fatalf("unconfigured sing-box update failed: %v", err)
	}
	if v, err := sup.ProbeVersion(context.Background(), protocol.KernelSingBox, ""); err != nil || !strings.Contains(v, "1.12.0") {
		t.Fatalf("expected unconfigured sing-box updated to 1.12.0, got %q (err=%v)", v, err)
	}

	// 2. Apply stop_ss_only config (Snell.Enabled=true, SS.Enabled=false): update must succeed cleanly
	//    without starting sing-box or disturbing Snell/ShadowTLS!
	cfg := testFullSupervisorSyncConfig(t, false, ports[3:])
	if err := sup.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatalf("ApplyConfig stop_ss_only failed: %v", err)
	}

	eventsMu.Lock()
	mark := len(events)
	eventsMu.Unlock()

	if err := upd.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "1.14.4",
		DownloadURL: srv.URL + "/1.14.4.tar.gz",
		SHA256:      sha14,
	}); err != nil {
		t.Fatalf("disabled sing-box (stop_ss_only) update failed: %v", err)
	}
	if v, err := sup.ProbeVersion(context.Background(), protocol.KernelSingBox, ""); err != nil || !strings.Contains(v, "1.14.4") {
		t.Fatalf("expected disabled sing-box updated to 1.14.4, got %q (err=%v)", v, err)
	}
	h := sup.Health()
	if !h.Snell || !h.ShadowTLS || h.SingBox {
		t.Fatalf("expected Snell+ShadowTLS healthy and SingBox stopped, got %+v", h)
	}

	eventsMu.Lock()
	evSlice := append([]protocol.AgentEvent(nil), events[mark:]...)
	eventsMu.Unlock()
	last := evSlice[len(evSlice)-1]
	if last.Event != protocol.EventKernelUpdateResult || last.Status != protocol.EventStatusSuccess {
		t.Fatalf("expected kernel_update_result success, got %+v", last)
	}
	if !strings.Contains(last.Detail, "disabled") {
		t.Fatalf("expected detail mentioning disabled, got %q", last.Detail)
	}

	// 3. Re-enable SS and verify the newly updated 1.14.4 binary starts cleanly!
	cfg.ConfigRevision = 2
	cfg.SS.Enabled = true
	if err := sup.ApplyConfig(context.Background(), cfg); err != nil {
		t.Fatalf("ApplyConfig re-enable SS failed: %v", err)
	}
	if !sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected updated 1.14.4 sing-box to start cleanly when SS re-enabled")
	}
}

func TestConcurrentConfigSyncDuringKernelUpdateHealthWindow(t *testing.T) {
	snellBin, stlsBin, _ := writeFakeKernelScripts(t)
	binDir := t.TempDir()
	sbBin := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(sbBin, makeCrossMajorSingBoxScript(t, "sing-box version 1.14.5", "typed"), 0o755); err != nil {
		t.Fatal(err)
	}

	tg14, sha14 := makeSingleFileTarGz(t, "sing-box-1.14.4/sing-box", makeCrossMajorSingBoxScript(t, "sing-box version 1.14.4", "typed"))
	artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/sb-1.14.4.tar.gz" {
			_, _ = w.Write(tg14)
			return
		}
		http.NotFound(w, r)
	}))
	defer artifactSrv.Close()

	ports := reserveFreePorts(t, 7)
	localDNSPort := ports[0]
	statsPort := ports[1]
	snellPubPort := ports[2]
	snellInnerPort := ports[3]
	ssTCPPort := ports[4]
	ssUDPPort := ports[5]
	cfgDNSPort := ports[6]

	cfgRev1 := protocol.ServerConfigSync{
		ConfigRevision: 1,
		Snell: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   snellPubPort,
			InnerPort:    snellInnerPort,
			PSK:          "bug-a8-snell-psk",
			Obfs:         protocol.SnellObfsOff,
			STLSPassword: "bug-a8-stls-password",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: protocol.SSConfig{
			Enabled: true,
			TCPPort: ssTCPPort,
			UDPPort: ssUDPPort,
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "swscan.apple.com",
			Users: []protocol.SSUserEntry{
				{UserID: 1, Username: "alice", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "p1"},
			},
		},
		DNS: protocol.DNSConfig{
			UnlockEnabled: false,
			UpstreamDNS:   "127.0.0.1:53",
			LocalPort:     cfgDNSPort,
		},
	}

	cfgRev2 := cfgRev1
	cfgRev2.ConfigRevision = 2
	cfgRev2.SS.Users = []protocol.SSUserEntry{
		{UserID: 1, Username: "alice", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "p1"},
		{UserID: 2, Username: "bob", UPSK: "CCCCCCCCCCCCCCCCCCCCCC==", STLSPassword: "p2"},
	}

	var eventsMu sync.Mutex
	var events []protocol.AgentEvent
	doneSignal := make(chan struct{})
	var doneOnce sync.Once

	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()

		var writeMu sync.Mutex
		sendEnvelope := func(msgType, reqID string, payload any) {
			b, merr := protocol.MarshalEnvelope(msgType, reqID, payload)
			if merr != nil {
				return
			}
			writeMu.Lock()
			defer writeMu.Unlock()
			wctx, wcancel := context.WithTimeout(r.Context(), 5*time.Second)
			_ = conn.Write(wctx, websocket.MessageText, b)
			wcancel()
		}

		updateSent := false
		rev2Sent := false
		sawUpdateSuccess := false
		sawRev2Applied := false

		for {
			_, data, err := conn.Read(r.Context())
			if err != nil {
				return
			}
			env, perr := protocol.ParseEnvelope(data)
			if perr != nil {
				continue
			}
			switch env.Type {
			case protocol.MsgTypeAgentHello:
				sendEnvelope(protocol.MsgTypeServerConfigSync, "sync-1", cfgRev1)
			case protocol.MsgTypeAgentEvent:
				var ev protocol.AgentEvent
				if err := env.DecodePayload(&ev); err != nil {
					continue
				}
				eventsMu.Lock()
				events = append(events, ev)
				eventsMu.Unlock()

				if ev.Event == protocol.EventConfigApplied && ev.ConfigRevision == 1 && ev.Status == protocol.EventStatusSuccess && !updateSent {
					updateSent = true
					sendEnvelope(protocol.MsgTypeServerKernelUpdate, "upd-1", protocol.ServerKernelUpdate{
						Kernel:      protocol.KernelSingBox,
						Version:     "1.14.4",
						DownloadURL: artifactSrv.URL + "/sb-1.14.4.tar.gz",
						SHA256:      sha14,
					})
				}
				if ev.Event == protocol.EventKernelUpdateProgress && ev.Message == "health_checking" && !rev2Sent {
					rev2Sent = true
					// Trigger concurrent config_sync (config_revision: 2, adding user bob) right inside the 3s health_checking window.
					sendEnvelope(protocol.MsgTypeServerConfigSync, "sync-2", cfgRev2)
				}
				if ev.Event == protocol.EventKernelUpdateResult && ev.Status == updater.StatusUpdateSuccess {
					sawUpdateSuccess = true
				}
				if ev.Event == protocol.EventConfigApplied && ev.ConfigRevision == 2 && ev.Status == protocol.EventStatusSuccess {
					sawRev2Applied = true
				}
				if sawUpdateSuccess && sawRev2Applied {
					doneOnce.Do(func() { close(doneSignal) })
				}
			}
		}
	}))
	defer wsSrv.Close()

	dataDir := t.TempDir()
	agentCfg := Config{
		PanelURL:     wsSrv.URL,
		NodeToken:    "nd_live_bug_a8_test_token_1234",
		DataDir:      dataDir,
		SnellBin:     snellBin,
		ShadowTLSBin: stlsBin,
		SingBoxBin:   sbBin,
		LocalDNSPort: localDNSPort,
		StatsPort:    statsPort,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	var out syncBuffer
	go func() {
		errCh <- runWithOptions(ctx, agentCfg, &out, ready, runtimeOptions{
			PublicIPEndpointsV4: []string{},
			PublicIPEndpointsV6: []string{},
			MetricsInterval:     200 * time.Millisecond,
			StartupGrace:        80 * time.Millisecond,
			BackoffBase:         25 * time.Millisecond,
			BackoffMax:          50 * time.Millisecond,
			PingInterval:        -1,
		})
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent exited prematurely: %v\nlogs:\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for agent ready")
	}

	select {
	case <-doneSignal:
	case err := <-errCh:
		t.Fatalf("agent exited before update+sync completed: %v\nlogs:\n%s", err, out.String())
	case <-time.After(20 * time.Second):
		eventsMu.Lock()
		snap := append([]protocol.AgentEvent(nil), events...)
		eventsMu.Unlock()
		t.Fatalf("timed out waiting for update_success and config_revision=2 applied; events=%+v\nlogs:\n%s", snap, out.String())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("agent shutdown error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for agent shutdown")
	}

	eventsMu.Lock()
	snap := append([]protocol.AgentEvent(nil), events...)
	eventsMu.Unlock()

	updateResultIdx := -1
	rev2AppliedIdx := -1
	for i, ev := range snap {
		switch ev.Event {
		case protocol.EventProcessCrashed:
			t.Fatalf("unexpected process_crashed event during update/sync: %+v", ev)
		case protocol.EventConfigError:
			t.Fatalf("unexpected config_error event during update/sync: %+v", ev)
		case protocol.EventKernelUpdateResult:
			if ev.Status != updater.StatusUpdateSuccess {
				t.Fatalf("expected kernel_update_result status=%q, got %+v", updater.StatusUpdateSuccess, ev)
			}
			updateResultIdx = i
		case protocol.EventConfigApplied:
			if ev.ConfigRevision == 2 && ev.Status == protocol.EventStatusSuccess {
				rev2AppliedIdx = i
			}
		}
	}
	if updateResultIdx < 0 {
		t.Fatalf("missing kernel_update_result update_success in events: %+v", snap)
	}
	if rev2AppliedIdx < 0 {
		t.Fatalf("missing config_applied revision=2 in events: %+v", snap)
	}
	if rev2AppliedIdx <= updateResultIdx {
		t.Fatalf("expected config_revision=2 applied after kernel_update_result (updateResultIdx=%d, rev2AppliedIdx=%d): %+v", updateResultIdx, rev2AppliedIdx, snap)
	}

	// (b) Assert the new 1.14.4 binary remains on disk (no false rollback to 1.14.5).
	verOut, err := exec.Command(sbBin, "version").CombinedOutput()
	if err != nil {
		t.Fatalf("exec %s version failed: %v\n%s", sbBin, err, string(verOut))
	}
	if !strings.Contains(string(verOut), "1.14.4") {
		t.Fatalf("expected new binary version 1.14.4 on disk, got %q", string(verOut))
	}

	// (c) Assert config_revision 2 (adding user bob) is applied cleanly in sing-box.json and last_config.json.
	sbJSON, err := os.ReadFile(filepath.Join(dataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatalf("read sing-box.json: %v", err)
	}
	if !strings.Contains(string(sbJSON), `"alice"`) || !strings.Contains(string(sbJSON), `"bob"`) {
		t.Fatalf("expected sing-box.json to contain alice and bob:\n%s", string(sbJSON))
	}
	persisted, ok := loadLastConfig(filepath.Join(dataDir, lastConfigFilename), slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !ok || persisted.ConfigRevision != 2 || len(persisted.SS.Users) != 2 {
		t.Fatalf("expected persisted last_config.json at rev 2 with 2 users, got ok=%v cfg=%+v", ok, persisted)
	}
}

func TestConcurrentServiceCtlAndContextCancellationDuringKernelUpdate(t *testing.T) {
	t.Run("service_ctl_during_health_checking_waits_and_restarts_settled_binary", func(t *testing.T) {
		snellBin, stlsBin, _ := writeFakeKernelScripts(t)
		binDir := t.TempDir()
		sbBin := filepath.Join(binDir, "sing-box")
		if err := os.WriteFile(sbBin, makeCrossMajorSingBoxScript(t, "sing-box version 1.14.5", "typed"), 0o755); err != nil {
			t.Fatal(err)
		}

		exe, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		startLog := filepath.Join(t.TempDir(), "sb-1.14.4-starts.log")
		sb14Script := []byte(fmt.Sprintf(`#!/bin/sh
if [ "$1" = "run" ]; then
  echo "started" >> %q
fi
export GO_WANT_CROSS_MAJOR_HELPER=1
export HELPER_VERSION="sing-box version 1.14.4"
export HELPER_MODE="typed"
exec %q -test.run=^TestSingBoxHelperProcess$ -- "$@"
`, startLog, exe))
		tg14, sha14 := makeSingleFileTarGz(t, "sing-box-1.14.4/sing-box", sb14Script)

		artifactSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/sb-1.14.4.tar.gz" {
				_, _ = w.Write(tg14)
				return
			}
			http.NotFound(w, r)
		}))
		defer artifactSrv.Close()

		ports := reserveFreePorts(t, 7)
		cfgRev1 := protocol.ServerConfigSync{
			ConfigRevision: 1,
			Snell: protocol.SnellConfig{
				Enabled:      true,
				Version:      protocol.SnellVersionV5,
				PublicPort:   ports[2],
				InnerPort:    ports[3],
				PSK:          "svcctl-snell-psk",
				Obfs:         protocol.SnellObfsOff,
				STLSPassword: "svcctl-stls-password",
				STLSSNI:      "gateway.icloud.com",
			},
			SS: protocol.SSConfig{
				Enabled: true,
				TCPPort: ports[4],
				UDPPort: ports[5],
				Cipher:  protocol.CipherAES128GCM,
				IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
				STLSSNI: "swscan.apple.com",
				Users: []protocol.SSUserEntry{
					{UserID: 1, Username: "alice", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "p1"},
				},
			},
			DNS: protocol.DNSConfig{
				UnlockEnabled: false,
				UpstreamDNS:   "127.0.0.1:53",
				LocalPort:     ports[6],
			},
		}

		var eventsMu sync.Mutex
		var events []protocol.AgentEvent
		updateSuccessCh := make(chan struct{})
		var successOnce sync.Once

		wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			conn, err := websocket.Accept(w, r, nil)
			if err != nil {
				return
			}
			defer conn.CloseNow()

			var writeMu sync.Mutex
			sendEnvelope := func(msgType, reqID string, payload any) {
				b, merr := protocol.MarshalEnvelope(msgType, reqID, payload)
				if merr != nil {
					return
				}
				writeMu.Lock()
				defer writeMu.Unlock()
				wctx, wcancel := context.WithTimeout(r.Context(), 5*time.Second)
				_ = conn.Write(wctx, websocket.MessageText, b)
				wcancel()
			}

			updateSent := false
			svcCtlSent := false

			for {
				_, data, err := conn.Read(r.Context())
				if err != nil {
					return
				}
				env, perr := protocol.ParseEnvelope(data)
				if perr != nil {
					continue
				}
				switch env.Type {
				case protocol.MsgTypeAgentHello:
					sendEnvelope(protocol.MsgTypeServerConfigSync, "sync-1", cfgRev1)
				case protocol.MsgTypeAgentEvent:
					var ev protocol.AgentEvent
					if err := env.DecodePayload(&ev); err != nil {
						continue
					}
					eventsMu.Lock()
					events = append(events, ev)
					eventsMu.Unlock()

					if ev.Event == protocol.EventConfigApplied && ev.ConfigRevision == 1 && !updateSent {
						updateSent = true
						sendEnvelope(protocol.MsgTypeServerKernelUpdate, "upd-1", protocol.ServerKernelUpdate{
							Kernel:      protocol.KernelSingBox,
							Version:     "1.14.4",
							DownloadURL: artifactSrv.URL + "/sb-1.14.4.tar.gz",
							SHA256:      sha14,
						})
					}
					if ev.Event == protocol.EventKernelUpdateProgress && ev.Message == "health_checking" && !svcCtlSent {
						svcCtlSent = true
						sendEnvelope(protocol.MsgTypeServerServiceCtl, "ctl-1", protocol.ServerServiceCtl{
							Action: protocol.ServiceActionRestartSingBox,
						})
					}
					if ev.Event == protocol.EventKernelUpdateResult && ev.Status == updater.StatusUpdateSuccess {
						successOnce.Do(func() { close(updateSuccessCh) })
					}
				}
			}
		}))
		defer wsSrv.Close()

		dataDir := t.TempDir()
		agentCfg := Config{
			PanelURL:     wsSrv.URL,
			NodeToken:    "nd_live_svcctl_test_token_1234",
			DataDir:      dataDir,
			SnellBin:     snellBin,
			ShadowTLSBin: stlsBin,
			SingBoxBin:   sbBin,
			LocalDNSPort: ports[0],
			StatsPort:    ports[1],
		}

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		ready := make(chan struct{})
		errCh := make(chan error, 1)
		var out syncBuffer
		go func() {
			errCh <- runWithOptions(ctx, agentCfg, &out, ready, runtimeOptions{
				PublicIPEndpointsV4: []string{},
				PublicIPEndpointsV6: []string{},
				MetricsInterval:     200 * time.Millisecond,
				StartupGrace:        80 * time.Millisecond,
				BackoffBase:         25 * time.Millisecond,
				BackoffMax:          50 * time.Millisecond,
				PingInterval:        -1,
			})
		}()

		select {
		case <-ready:
		case err := <-errCh:
			t.Fatalf("agent exited prematurely: %v\nlogs:\n%s", err, out.String())
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for agent ready")
		}

		select {
		case <-updateSuccessCh:
		case <-time.After(20 * time.Second):
			eventsMu.Lock()
			snap := append([]protocol.AgentEvent(nil), events...)
			eventsMu.Unlock()
			t.Fatalf("timed out waiting for update_success; events=%+v\nlogs:\n%s", snap, out.String())
		}

		// Wait for queued OnServiceCtl (restart_singbox) to execute a 2nd start of 1.14.4 cleanly after update_success.
		deadline := time.Now().Add(5 * time.Second)
		for {
			b, _ := os.ReadFile(startLog)
			lines := strings.Fields(string(b))
			if len(lines) >= 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("expected 2 starts of 1.14.4 (update + queued service_ctl restart_singbox), got %d lines (%q)", len(lines), string(b))
			}
			time.Sleep(25 * time.Millisecond)
		}

		cancel()
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("agent shutdown error: %v", err)
			}
		case <-time.After(10 * time.Second):
			t.Fatal("timed out waiting for agent shutdown")
		}

		eventsMu.Lock()
		snap := append([]protocol.AgentEvent(nil), events...)
		eventsMu.Unlock()
		for _, ev := range snap {
			if ev.Event == protocol.EventProcessCrashed {
				t.Fatalf("unexpected process_crashed event: %+v", ev)
			}
			if ev.Event == protocol.EventKernelUpdateResult && ev.Status != updater.StatusUpdateSuccess {
				t.Fatalf("expected update_success, got %+v", ev)
			}
		}

		verOut, err := exec.Command(sbBin, "version").CombinedOutput()
		if err != nil || !strings.Contains(string(verOut), "1.14.4") {
			t.Fatalf("expected 1.14.4 binary preserved on disk, got %q (err=%v)", string(verOut), err)
		}
	})

	t.Run("ctx_timeout_and_cancellation_while_waiting_on_opLock", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		dataDir := t.TempDir()
		dns := &fakeDNSManager{port: 1053}
		sup := &fakeSupervisorManager{}
		col := &fakeCollectorManager{}
		coord := newConfigCoordinator(dns, sup, col, nil, logger, dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: 1053}, 1053, 10085, dataDir)

		unlock, err := coord.AcquireOpLock(context.Background())
		if err != nil {
			t.Fatalf("AcquireOpLock failed: %v", err)
		}

		timeoutCtx, timeoutCancel := context.WithTimeout(context.Background(), 35*time.Millisecond)
		defer timeoutCancel()
		start := time.Now()
		err = coord.Apply(timeoutCtx, protocol.ServerConfigSync{ConfigRevision: 1}, true)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded waiting on opLock, got %v", err)
		}
		if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
			t.Fatalf("Apply took too long to respect timeout (%v)", elapsed)
		}
		if len(dns.applyCalls) != 0 || len(sup.applyCalls) != 0 || coord.CurrentRevision() != 0 {
			t.Fatal("expected dns/supervisor/revision untouched after lock timeout")
		}

		cancelledCtx, cancelFn := context.WithCancel(context.Background())
		cancelFn()
		if _, err := coord.AcquireOpLock(cancelledCtx); !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled from AcquireOpLock, got %v", err)
		}

		unlock()

		if err := coord.Apply(context.Background(), protocol.ServerConfigSync{ConfigRevision: 1}, true); err != nil {
			t.Fatalf("expected Apply to succeed after opLock released, got %v", err)
		}
		if coord.CurrentRevision() != 1 {
			t.Fatalf("expected revision=1, got %d", coord.CurrentRevision())
		}
	})
}

func TestConfigCoordinatorEventConfigAppliedStrictlyAfterPersistAndRevisionCommit(t *testing.T) {
	snellBin, stlsBin, singBoxBin := writeFakeKernelScripts(t)
	dataDir := t.TempDir()
	ports := reserveFreePorts(t, 7)

	var (
		coord          *configCoordinator
		eventsMu       sync.Mutex
		events         []protocol.AgentEvent
		eventCheckErrs []string
	)

	emitEvent := func(ev protocol.AgentEvent) {
		eventsMu.Lock()
		events = append(events, ev)
		if ev.Event == protocol.EventConfigApplied {
			gotRev := coord.CurrentRevision()
			if gotRev != ev.ConfigRevision {
				eventCheckErrs = append(eventCheckErrs, fmt.Sprintf("at EventConfigApplied(rev=%d): CurrentRevision()=%d, want %d", ev.ConfigRevision, gotRev, ev.ConfigRevision))
			}
			raw, err := os.ReadFile(filepath.Join(dataDir, lastConfigFilename))
			if err != nil {
				eventCheckErrs = append(eventCheckErrs, fmt.Sprintf("at EventConfigApplied(rev=%d): read last_config.json: %v", ev.ConfigRevision, err))
			} else {
				var persisted protocol.ServerConfigSync
				if err := json.Unmarshal(raw, &persisted); err != nil {
					eventCheckErrs = append(eventCheckErrs, fmt.Sprintf("at EventConfigApplied(rev=%d): unmarshal last_config.json: %v", ev.ConfigRevision, err))
				} else if persisted.ConfigRevision != ev.ConfigRevision {
					eventCheckErrs = append(eventCheckErrs, fmt.Sprintf("at EventConfigApplied(rev=%d): last_config.json revision=%d, want %d", ev.ConfigRevision, persisted.ConfigRevision, ev.ConfigRevision))
				}
			}
		}
		eventsMu.Unlock()
	}

	sup, err := supervisor.New(supervisor.Options{
		DataDir:        dataDir,
		SnellBin:       snellBin,
		ShadowTLSBin:   stlsBin,
		SingBoxBin:     singBoxBin,
		StatsPort:      ports[0],
		LocalDNSPort:   ports[1],
		SSInnerTCPPort: ports[2],
		StartupGrace:   60 * time.Millisecond,
		StopTimeout:    300 * time.Millisecond,
		OnEvent:        supervisorEventHandler(emitEvent),
	})
	if err != nil {
		t.Fatalf("supervisor.New: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("sup.Start: %v", err)
	}
	t.Cleanup(func() { _ = sup.Stop(context.Background()) })

	dns := &fakeDNSManager{port: ports[1]}
	col := &fakeCollectorManager{}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	initialDNS := dnsproxy.Config{ListenHost: "127.0.0.1", ListenPort: ports[1], UpstreamDNS: dnsproxy.DefaultUpstreamDNS}
	coord = newConfigCoordinator(dns, sup, col, emitEvent, logger, initialDNS, ports[1], ports[0], dataDir)

	// 1. Inject a slow/blocked saveLastConfigAtomic to prove EventConfigApplied is NOT emitted
	//    until saveLastConfigAtomic and currentRevision.Store have both completed.
	persistStarted := make(chan struct{})
	allowPersist := make(chan struct{})
	coord.saveLastConfig = func(path string, cfg protocol.ServerConfigSync) error {
		close(persistStarted)
		<-allowPersist
		return saveLastConfigAtomic(path, cfg)
	}

	cfg1 := testFullSupervisorSyncConfig(t, true, []int{ports[3], ports[4], ports[5], ports[6], ports[1]})
	cfg1.ConfigRevision = 1

	applyDone := make(chan error, 1)
	go func() {
		applyDone <- coord.Apply(context.Background(), cfg1, true)
	}()

	select {
	case <-persistStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for saveLastConfig to start")
	}

	// While saveLastConfig is blocked (after sup.ApplyConfig already returned!),
	// EventConfigApplied MUST NOT have fired and CurrentRevision() MUST still be 0.
	time.Sleep(30 * time.Millisecond)
	eventsMu.Lock()
	prematureCount := len(events)
	eventsMu.Unlock()
	if prematureCount != 0 {
		t.Fatalf("EventConfigApplied emitted prematurely before saveLastConfig finished: %+v", events)
	}
	if got := coord.CurrentRevision(); got != 0 {
		t.Fatalf("expected CurrentRevision() == 0 before saveLastConfig finishes, got %d", got)
	}
	if _, err := os.Stat(filepath.Join(dataDir, lastConfigFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected last_config.json absent before saveLastConfig finishes, got err=%v", err)
	}

	close(allowPersist)
	select {
	case err := <-applyDone:
		if err != nil {
			t.Fatalf("coord.Apply rev 1 failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for coord.Apply rev 1")
	}

	eventsMu.Lock()
	if len(eventCheckErrs) > 0 {
		t.Fatalf("ordering assertions failed at EventConfigApplied delivery: %v", eventCheckErrs)
	}
	if len(events) != 1 || events[0].Event != protocol.EventConfigApplied || events[0].ConfigRevision != 1 {
		t.Fatalf("expected 1 config_applied event for rev 1, got %+v", events)
	}
	eventsMu.Unlock()

	// 2. Unchanged kernel config with higher ConfigRevision (rev 2): supervisor hits !adminChanged && !ssChanged,
	//    and coordinator MUST still emit EventConfigApplied strictly after persisting rev 2.
	coord.saveLastConfig = saveLastConfigAtomic
	cfg2 := cfg1
	cfg2.ConfigRevision = 2
	if err := coord.Apply(context.Background(), cfg2, true); err != nil {
		t.Fatalf("coord.Apply rev 2 (unchanged kernels) failed: %v", err)
	}
	eventsMu.Lock()
	if len(eventCheckErrs) > 0 {
		t.Fatalf("ordering assertions failed at rev 2 EventConfigApplied delivery: %v", eventCheckErrs)
	}
	if len(events) != 2 || events[1].Event != protocol.EventConfigApplied || events[1].ConfigRevision != 2 {
		t.Fatalf("expected config_applied event for unchanged-kernel rev 2, got %+v", events)
	}
	eventsMu.Unlock()

	// 3. Persistence failure when persist == true MUST emit EventConfigError (never EventConfigApplied),
	//    leave CurrentRevision() at 2, and allow a subsequent retry of rev 3 to succeed.
	coord.saveLastConfig = func(string, protocol.ServerConfigSync) error {
		return errors.New("simulated disk full")
	}
	cfg3 := cfg1
	cfg3.ConfigRevision = 3
	if err := coord.Apply(context.Background(), cfg3, true); err == nil {
		t.Fatal("expected coord.Apply rev 3 to fail when saveLastConfig fails")
	}
	if got := coord.CurrentRevision(); got != 2 {
		t.Fatalf("expected CurrentRevision() to remain 2 on persist failure, got %d", got)
	}
	eventsMu.Lock()
	if len(events) != 3 || events[2].Event != protocol.EventConfigError || events[2].ConfigRevision != 3 || events[2].Status != protocol.EventStatusFailed {
		t.Fatalf("expected config_error event for rev 3 persist failure, got %+v", events)
	}
	eventsMu.Unlock()

	// Retry rev 3 with working persistence.
	coord.saveLastConfig = saveLastConfigAtomic
	if err := coord.Apply(context.Background(), cfg3, true); err != nil {
		t.Fatalf("retry coord.Apply rev 3 failed: %v", err)
	}
	eventsMu.Lock()
	if len(eventCheckErrs) > 0 {
		t.Fatalf("ordering assertions failed at rev 3 retry EventConfigApplied delivery: %v", eventCheckErrs)
	}
	if len(events) != 4 || events[3].Event != protocol.EventConfigApplied || events[3].ConfigRevision != 3 {
		t.Fatalf("expected config_applied event for rev 3 retry, got %+v", events)
	}
	eventsMu.Unlock()
}

func TestRunWithOptionsEventConfigAppliedOrderingAndReconnect(t *testing.T) {
	snellBin, stlsBin, singBoxBin := writeFakeKernelScripts(t)
	dataDir := t.TempDir()
	ports := reserveFreePorts(t, 7)

	syncRev7 := protocol.ServerConfigSync{
		ConfigRevision: 7,
		Snell: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   ports[2],
			InnerPort:    ports[3],
			PSK:          "ws-order-snell-psk",
			Obfs:         protocol.SnellObfsOff,
			STLSPassword: "ws-order-stls-pass",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: protocol.SSConfig{
			Enabled: true,
			TCPPort: ports[4],
			UDPPort: ports[5],
			Cipher:  protocol.CipherAES128GCM,
			IPSK:    "AAAAAAAAAAAAAAAAAAAAAA==",
			STLSSNI: "swscan.apple.com",
			Users: []protocol.SSUserEntry{
				{UserID: 1, Username: "alice", UPSK: "BBBBBBBBBBBBBBBBBBBBBB==", STLSPassword: "p1"},
			},
		},
		DNS: protocol.DNSConfig{
			UnlockEnabled: false,
			UpstreamDNS:   "127.0.0.1:53",
			LocalPort:     ports[0],
		},
	}

	var (
		mu             sync.Mutex
		hellos         []protocol.AgentHello
		diskCheckErr   string
		doneSignal     = make(chan struct{})
		doneOnce       sync.Once
		syncSent       bool
		reconnectReady bool
	)

	wsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			env, perr := protocol.ParseEnvelope(data)
			if perr != nil {
				continue
			}
			switch env.Type {
			case protocol.MsgTypeAgentHello:
				var h protocol.AgentHello
				if err := env.DecodePayload(&h); err == nil {
					mu.Lock()
					hellos = append(hellos, h)
					shouldSendSync := !syncSent
					syncSent = true
					shouldClose := reconnectReady && len(hellos) >= 2
					mu.Unlock()
					if shouldSendSync {
						b, _ := protocol.MarshalEnvelope(protocol.MsgTypeServerConfigSync, "sync-7", syncRev7)
						_ = conn.Write(r.Context(), websocket.MessageText, b)
					}
					if shouldClose {
						doneOnce.Do(func() { close(doneSignal) })
					}
				}
			case protocol.MsgTypeAgentEvent:
				var ev protocol.AgentEvent
				if err := env.DecodePayload(&ev); err != nil {
					continue
				}
				if ev.Event == protocol.EventConfigApplied && ev.ConfigRevision == 7 && ev.Status == protocol.EventStatusSuccess {
					raw, rerr := os.ReadFile(filepath.Join(dataDir, lastConfigFilename))
					if rerr != nil {
						mu.Lock()
						diskCheckErr = fmt.Sprintf("read last_config.json immediately on WS config_applied: %v", rerr)
						mu.Unlock()
					} else {
						var cached protocol.ServerConfigSync
						if uerr := json.Unmarshal(raw, &cached); uerr != nil || cached.ConfigRevision != 7 {
							mu.Lock()
							diskCheckErr = fmt.Sprintf("invalid last_config.json immediately on WS config_applied: err=%v rev=%d", uerr, cached.ConfigRevision)
							mu.Unlock()
						}
					}
					mu.Lock()
					reconnectReady = true
					mu.Unlock()
					// Force immediate disconnect to confirm reconnecting agent.hello reports revision 7.
					_ = conn.CloseNow()
					return
				}
			}
		}
	}))
	defer wsSrv.Close()

	cfg := Config{
		PanelURL:     wsSrv.URL,
		NodeToken:    "nd_live_ws_order_test_token_1234",
		DataDir:      dataDir,
		SnellBin:     snellBin,
		ShadowTLSBin: stlsBin,
		SingBoxBin:   singBoxBin,
		LocalDNSPort: ports[0],
		StatsPort:    ports[1],
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	var out syncBuffer
	go func() {
		errCh <- runWithOptions(ctx, cfg, &out, ready, runtimeOptions{
			PublicIPEndpointsV4: []string{},
			PublicIPEndpointsV6: []string{},
			MetricsInterval:     500 * time.Millisecond,
			StartupGrace:        50 * time.Millisecond,
			BackoffBase:         25 * time.Millisecond,
			BackoffMax:          50 * time.Millisecond,
			PingInterval:        -1,
		})
	}()

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("agent exited prematurely: %v\nlogs:\n%s", err, out.String())
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for agent ready")
	}

	select {
	case <-doneSignal:
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for config_applied + reconnect hello; logs:\n%s", out.String())
	}

	cancel()
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("agent shutdown error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for agent shutdown")
	}

	mu.Lock()
	defer mu.Unlock()
	if diskCheckErr != "" {
		t.Fatal(diskCheckErr)
	}
	if len(hellos) < 2 {
		t.Fatalf("expected >=2 hellos, got %d", len(hellos))
	}
	if hellos[len(hellos)-1].ConfigRevision != 7 {
		t.Fatalf("expected reconnect hello ConfigRevision=7, got %d", hellos[len(hellos)-1].ConfigRevision)
	}
}
