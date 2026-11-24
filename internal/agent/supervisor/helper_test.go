package supervisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"snell-panel/internal/protocol"
)

const helperEnvFlag = "SNELL_SUPERVISOR_HELPER"

type helperInvocation struct {
	Event   string   `json:"event"`
	Kernel  string   `json:"kernel"`
	PID     int      `json:"pid"`
	Args    []string `json:"args"`
	Config  string   `json:"config,omitempty"`
	ExitSig string   `json:"exit_sig,omitempty"`
}

type helperBehavior struct {
	VersionOut                string `json:"version_out,omitempty"`
	VersionFail               bool   `json:"version_fail,omitempty"`
	SnellUsageOnVersion       bool   `json:"snell_usage_on_version,omitempty"`
	SnellUsageOnFirstFlagOnly bool   `json:"snell_usage_on_first_flag_only,omitempty"`
	CheckRejectSubstr         string `json:"check_reject_substr,omitempty"`
	CrashOnStart              bool   `json:"crash_on_start,omitempty"`
	CrashOnConfigSubstr       string `json:"crash_on_config_substr,omitempty"`
	CrashStderr               string `json:"crash_stderr,omitempty"`
	ExitCode                  int    `json:"exit_code,omitempty"`
	IgnoreSIGTERM             bool   `json:"ignore_sigterm,omitempty"`
	BindPorts                 bool   `json:"bind_ports,omitempty"`
}

// TestHelperProcess acts as a real subprocess stand-in for snell-server, shadow-tls, and sing-box.
func TestHelperProcess(t *testing.T) {
	if os.Getenv(helperEnvFlag) != "1" {
		return
	}

	idx := -1
	for i, a := range os.Args {
		if a == "--" {
			idx = i
			break
		}
	}
	if idx < 0 || len(os.Args) <= idx+2 {
		fmt.Fprintln(os.Stderr, "missing helper args")
		os.Exit(2)
	}

	kernel := os.Args[idx+1]
	controlDir := os.Args[idx+2]
	args := os.Args[idx+3:]

	behPath := filepath.Join(controlDir, kernel+".behavior.json")
	var beh helperBehavior
	if b, err := os.ReadFile(behPath); err == nil {
		_ = json.Unmarshal(b, &beh)
	}

	record := func(ev helperInvocation) {
		ev.Kernel = kernel
		ev.PID = os.Getpid()
		ev.Args = args
		b, _ := json.Marshal(ev)
		invPath := filepath.Join(controlDir, kernel+".invocations.jsonl")
		f, err := os.OpenFile(invPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err == nil {
			_, _ = f.Write(append(b, '\n'))
			_ = f.Close()
		}
	}

	isVersion := false
	isCheck := false
	var cfgPath string
	var listenArg string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "version", "--version", "-v", "-V":
			isVersion = true
		case "check":
			isCheck = true
		case "-c", "--config":
			if i+1 < len(args) {
				cfgPath = args[i+1]
			}
		case "--listen":
			if i+1 < len(args) {
				listenArg = args[i+1]
			}
		}
	}

	var cfgContent string
	if cfgPath != "" {
		if b, err := os.ReadFile(cfgPath); err == nil {
			cfgContent = string(b)
		}
	}

	if isVersion {
		record(helperInvocation{Event: "version"})
		if beh.SnellUsageOnFirstFlagOnly {
			for _, a := range args {
				if a == "--version" {
					fmt.Fprintln(os.Stderr, "Usage: snell-server v5.0.1 -c <config>")
					os.Exit(1)
				}
			}
			os.Exit(1)
		}
		if beh.SnellUsageOnVersion {
			fmt.Fprintln(os.Stderr, "Usage: snell-server -c <config>")
			os.Exit(1)
		}
		if beh.VersionFail {
			fmt.Fprintln(os.Stderr, "mock version failure")
			os.Exit(1)
		}
		if beh.VersionOut != "" {
			fmt.Println(beh.VersionOut)
		} else {
			fmt.Println(kernel + " 1.0.0")
		}
		os.Exit(0)
	}

	if isCheck {
		record(helperInvocation{Event: "check", Config: cfgContent})
		if cfgPath == "" || cfgContent == "" {
			fmt.Fprintln(os.Stderr, "missing config file")
			os.Exit(1)
		}
		if kernel == protocol.KernelSingBox && !json.Valid([]byte(cfgContent)) {
			fmt.Fprintln(os.Stderr, "invalid sing-box json")
			os.Exit(1)
		}
		if beh.CheckRejectSubstr != "" && strings.Contains(cfgContent, beh.CheckRejectSubstr) {
			fmt.Fprintf(os.Stderr, "check rejected substring %q\n", beh.CheckRejectSubstr)
			os.Exit(1)
		}
		os.Exit(0)
	}

	record(helperInvocation{Event: "start", Config: cfgContent})

	if beh.CrashOnStart || (beh.CrashOnConfigSubstr != "" && strings.Contains(cfgContent, beh.CrashOnConfigSubstr)) {
		if beh.CrashStderr != "" {
			fmt.Fprintln(os.Stderr, beh.CrashStderr)
		} else {
			fmt.Fprintln(os.Stderr, "simulated startup crash")
		}
		code := beh.ExitCode
		if code == 0 {
			code = 1
		}
		os.Exit(code)
	}

	var listeners []net.Listener
	closeListeners := func() {
		for _, ln := range listeners {
			_ = ln.Close()
		}
	}
	defer closeListeners()

	if beh.BindPorts {
		var addrs []string
		switch kernel {
		case protocol.KernelSnellServer:
			for _, line := range strings.Split(cfgContent, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "listen") {
					if parts := strings.SplitN(line, "=", 2); len(parts) == 2 {
						addrs = append(addrs, strings.TrimSpace(parts[1]))
					}
				}
			}
		case protocol.KernelShadowTLS:
			if listenArg != "" {
				if _, port, err := net.SplitHostPort(listenArg); err == nil {
					addrs = append(addrs, net.JoinHostPort("127.0.0.1", port))
				}
			}
		case protocol.KernelSingBox:
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
			if json.Unmarshal([]byte(cfgContent), &doc) == nil {
				for _, inb := range doc.Inbounds {
					if inb.ListenPort > 0 && !strings.EqualFold(inb.Network, "udp") {
						addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", inb.ListenPort))
					}
				}
				if doc.Experimental.V2RayAPI.Listen != "" {
					addrs = append(addrs, doc.Experimental.V2RayAPI.Listen)
				}
			}
		}

		for _, addr := range addrs {
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "bind %s failed: %v\n", addr, err)
				os.Exit(1)
			}
			listeners = append(listeners, ln)
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

	pidFile := filepath.Join(controlDir, fmt.Sprintf("%s.%d.pid", kernel, os.Getpid()))
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
	defer os.Remove(pidFile)

	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)

	for sig := range sigCh {
		if beh.IgnoreSIGTERM && sig == syscall.SIGTERM {
			continue
		}
		record(helperInvocation{Event: "stop", ExitSig: sig.String()})
		os.Exit(0)
	}
}

type helperEnv struct {
	t          *testing.T
	dataDir    string
	controlDir string
	bins       map[string]string
}

func newHelperEnv(t *testing.T) *helperEnv {
	t.Helper()
	t.Setenv(helperEnvFlag, "1")

	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	controlDir := filepath.Join(root, "ctrl")
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(controlDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatal(err)
	}

	selfExe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	bins := make(map[string]string, 3)
	for _, kernel := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		scriptPath := filepath.Join(binDir, kernel)
		script := fmt.Sprintf("#!/bin/sh\nexec %q -test.run=^TestHelperProcess$ -- %q %q \"$@\"\n", selfExe, kernel, controlDir)
		if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
		bins[kernel] = scriptPath
	}

	env := &helperEnv{
		t:          t,
		dataDir:    dataDir,
		controlDir: controlDir,
		bins:       bins,
	}

	env.setBehavior(protocol.KernelSnellServer, helperBehavior{VersionOut: "snell-server v5.0.0"})
	env.setBehavior(protocol.KernelShadowTLS, helperBehavior{VersionOut: "shadow-tls 0.2.25"})
	env.setBehavior(protocol.KernelSingBox, helperBehavior{VersionOut: "sing-box version 1.11.4"})

	return env
}

func (e *helperEnv) setBehavior(kernel string, beh helperBehavior) {
	e.t.Helper()
	b, err := json.Marshal(beh)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(e.controlDir, kernel+".behavior.json"), b, 0o644); err != nil {
		e.t.Fatal(err)
	}
}

func (e *helperEnv) invocations(kernel string) []helperInvocation {
	e.t.Helper()
	b, err := os.ReadFile(filepath.Join(e.controlDir, kernel+".invocations.jsonl"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		e.t.Fatal(err)
	}
	var out []helperInvocation
	for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if line == "" {
			continue
		}
		var inv helperInvocation
		if err := json.Unmarshal([]byte(line), &inv); err != nil {
			e.t.Fatal(err)
		}
		out = append(out, inv)
	}
	return out
}

func (e *helperEnv) startEvents(kernel string) []helperInvocation {
	var out []helperInvocation
	for _, inv := range e.invocations(kernel) {
		if inv.Event == "start" {
			out = append(out, inv)
		}
	}
	return out
}

type eventRecorder struct {
	mu     sync.Mutex
	events []protocol.AgentEvent
}

func (r *eventRecorder) handle(ev protocol.AgentEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
}

func (r *eventRecorder) snapshot() []protocol.AgentEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]protocol.AgentEvent, len(r.events))
	copy(out, r.events)
	return out
}

func (r *eventRecorder) countEvent(evType string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, ev := range r.events {
		if ev.Event == evType {
			n++
		}
	}
	return n
}

func freeTCPPorts(t *testing.T, count int) []int {
	t.Helper()
	var lns []net.Listener
	ports := make([]int, 0, count)
	for i := 0; i < count; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		lns = append(lns, ln)
		ports = append(ports, ln.Addr().(*net.TCPAddr).Port)
	}
	for _, ln := range lns {
		_ = ln.Close()
	}
	return ports
}

func testSyncConfig(t *testing.T) protocol.ServerConfigSync {
	t.Helper()
	ports := freeTCPPorts(t, 6)
	return protocol.ServerConfigSync{
		ConfigRevision: 1,
		Snell: protocol.SnellConfig{
			Enabled:      true,
			Version:      protocol.SnellVersionV5,
			PublicPort:   ports[0],
			InnerPort:    ports[1],
			PSK:          "snell-psk-1",
			Obfs:         protocol.SnellObfsOff,
			TFO:          true,
			STLSPassword: "snell-stls-1",
			STLSSNI:      "gateway.icloud.com",
		},
		SS: protocol.SSConfig{
			Enabled: true,
			TCPPort: ports[2],
			UDPPort: ports[2],
			Cipher:  protocol.CipherAES256GCM,
			IPSK:    b64Key(32, 1),
			STLSSNI: "swscan.apple.com",
			Users: []protocol.SSUserEntry{
				{
					UserID:       1,
					Username:     "user1",
					UPSK:         b64Key(32, 10),
					STLSPassword: "user1-stls",
				},
			},
		},
		DNS: protocol.DNSConfig{
			UnlockEnabled: true,
			UnlockServer:  "1.2.3.4:3535",
			Rules:         []string{"netflix.com"},
			UpstreamDNS:   "1.1.1.1:53",
			LocalPort:     ports[3],
		},
	}
}

func newTestSupervisor(t *testing.T, env *helperEnv, rec *eventRecorder, mutate func(*Options)) *Supervisor {
	t.Helper()
	reserved := freeTCPPorts(t, 3)
	opts := Options{
		DataDir:          env.dataDir,
		SnellBin:         env.bins[protocol.KernelSnellServer],
		ShadowTLSBin:     env.bins[protocol.KernelShadowTLS],
		SingBoxBin:       env.bins[protocol.KernelSingBox],
		StatsPort:        reserved[0],
		LocalDNSPort:     reserved[1],
		SSInnerTCPPort:   reserved[2],
		StartupGrace:     900 * time.Millisecond,
		StopTimeout:      500 * time.Millisecond,
		CrashBackoffBase: 50 * time.Millisecond,
		CrashBackoffMax:  200 * time.Millisecond,
		StabilityWindow:  1 * time.Second,
	}
	if rec != nil {
		opts.OnEvent = rec.handle
	}
	if mutate != nil {
		mutate(&opts)
	}
	sup, err := New(opts)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if err := sup.Start(context.Background()); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() {
		_ = sup.Stop(context.Background())
	})
	return sup
}

func waitUntil(t *testing.T, timeout time.Duration, desc string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(15 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", desc)
}
