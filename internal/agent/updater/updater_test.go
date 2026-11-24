package updater_test

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"snell-panel/internal/agent/updater"
	"snell-panel/internal/protocol"
)

var (
	helperBinOnce sync.Once
	helperBinDir  string
	helperBinPath string
)

func TestMain(m *testing.M) {
	code := m.Run()
	if helperBinDir != "" {
		_ = os.RemoveAll(helperBinDir)
	}
	os.Exit(code)
}

func sanitizeGoBuildEnv(environ []string) []string {
	out := make([]string, 0, len(environ)+1)
	hasGOWORK := false
	for _, kv := range environ {
		if strings.HasPrefix(kv, "GOWORK=") {
			out = append(out, "GOWORK=off")
			hasGOWORK = true
			continue
		}
		if strings.HasPrefix(kv, "GOFLAGS=") {
			raw := strings.TrimPrefix(kv, "GOFLAGS=")
			fields := strings.Fields(raw)
			filtered := make([]string, 0, len(fields))
			for _, f := range fields {
				if f == "-race" || f == "--race" || strings.HasPrefix(f, "-race=") {
					continue
				}
				filtered = append(filtered, f)
			}
			out = append(out, "GOFLAGS="+strings.Join(filtered, " "))
			continue
		}
		out = append(out, kv)
	}
	if !hasGOWORK {
		out = append(out, "GOWORK=off")
	}
	return out
}

func compiledHelperBinaryPath() string {
	helperBinOnce.Do(func() {
		goBin, err := exec.LookPath("go")
		if err != nil {
			return
		}
		dir, err := os.MkdirTemp("", "updater-helper-*")
		if err != nil {
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module updater-helper\n\ngo 1.21\n"), 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(standaloneHelperSource), 0o600); err != nil {
			_ = os.RemoveAll(dir)
			return
		}
		outBin := filepath.Join(dir, "helper")
		cmd := exec.Command(goBin, "build", "-o", outBin, ".")
		cmd.Dir = dir
		cmd.Env = sanitizeGoBuildEnv(os.Environ())
		if err := cmd.Run(); err != nil {
			_ = os.RemoveAll(dir)
			return
		}
		helperBinDir = dir
		helperBinPath = outBin
	})
	return helperBinPath
}

const standaloneHelperSource = `package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func main() {
	args := os.Args[1:]
	mode := os.Getenv("HELPER_MODE")
	ver := os.Getenv("HELPER_VERSION")

	if len(args) > 0 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version") {
		if mode == "probe_fail" {
			_, _ = fmt.Fprintln(os.Stderr, "simulated version probe failure")
			os.Exit(2)
		}
		fmt.Println(ver)
		os.Exit(0)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if mode == "no_listen" {
		<-sigCh
		os.Exit(0)
	}

	listenAddr := os.Getenv("HELPER_LISTEN_ADDR")
	var ln net.Listener
	if listenAddr != "" {
		var err error
		ln, err = net.Listen("tcp", listenAddr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "helper listen %q: %v\n", listenAddr, err)
			os.Exit(3)
		}
		defer ln.Close()

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	if mode == "crash_after_ms" {
		ms := 150
		if raw := os.Getenv("HELPER_CRASH_MS"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				ms = parsed
			}
		}
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
			if ln != nil {
				_ = ln.Close()
			}
			os.Exit(1)
		case <-sigCh:
			os.Exit(0)
		}
	}

	<-sigCh
	os.Exit(0)
}
`

// TestHelperProcess acts as a real OS subprocess when invoked via shell-wrapped test binaries.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
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

	if len(args) > 0 && (args[0] == "--version" || args[0] == "-v" || args[0] == "version") {
		if mode == "probe_fail" {
			_, _ = fmt.Fprintln(os.Stderr, "simulated version probe failure")
			os.Exit(2)
		}
		fmt.Println(ver)
		os.Exit(0)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	if mode == "no_listen" {
		<-sigCh
		os.Exit(0)
	}

	listenAddr := os.Getenv("HELPER_LISTEN_ADDR")
	var ln net.Listener
	if listenAddr != "" {
		var err error
		ln, err = net.Listen("tcp", listenAddr)
		if err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "helper listen %q: %v\n", listenAddr, err)
			os.Exit(3)
		}
		defer ln.Close()

		go func() {
			for {
				conn, err := ln.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	if mode == "crash_after_ms" {
		ms := 150
		if raw := os.Getenv("HELPER_CRASH_MS"); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
				ms = parsed
			}
		}
		select {
		case <-time.After(time.Duration(ms) * time.Millisecond):
			if ln != nil {
				_ = ln.Close()
			}
			os.Exit(1)
		case <-sigCh:
			os.Exit(0)
		}
	}

	<-sigCh
	os.Exit(0)
}

func makeHelperBinaryPayload(t *testing.T, version string, mode string, crashMS int) []byte {
	t.Helper()
	if bin := compiledHelperBinaryPath(); bin != "" {
		script := fmt.Sprintf(`#!/bin/sh
export HELPER_VERSION=%q
export HELPER_MODE=%q
export HELPER_CRASH_MS=%q
exec %q "$@"
`, version, mode, strconv.Itoa(crashMS), bin)
		return []byte(script)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	script := fmt.Sprintf(`#!/bin/sh
export GO_WANT_HELPER_PROCESS=1
export HELPER_VERSION=%q
export HELPER_MODE=%q
export HELPER_CRASH_MS=%q
exec %q -test.run=^TestHelperProcess$ -- "$@"
`, version, mode, strconv.Itoa(crashMS), exe)
	return []byte(script)
}

type testController struct {
	mu            sync.Mutex
	paths         map[string]string
	listenAddrs   map[string][]string
	dialOverride  map[string]string
	procs         map[string]*managedProc
	restartErr    error
	restartHook   func(ctx context.Context, kernel string) error
	forceHealth   map[string]*bool
	restartCount  atomic.Int64
	activeUpdates atomic.Int32
	maxConcurrent atomic.Int32
}

type managedProc struct {
	cmd  *exec.Cmd
	done chan struct{}
}

func newTestController() *testController {
	return &testController{
		paths:        make(map[string]string),
		listenAddrs:  make(map[string][]string),
		dialOverride: make(map[string]string),
		procs:        make(map[string]*managedProc),
		forceHealth:  make(map[string]*bool),
	}
}

func (c *testController) setKernel(kernel, binPath string, listenAddrs []string, bindAddr string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.paths[kernel] = binPath
	c.listenAddrs[kernel] = append([]string(nil), listenAddrs...)
	c.dialOverride[kernel] = bindAddr
}

func (c *testController) setRestartHook(fn func(ctx context.Context, kernel string) error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.restartHook = fn
}

func (c *testController) BinaryPath(kernel string) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, ok := c.paths[kernel]
	if !ok {
		return "", fmt.Errorf("unknown kernel %q", kernel)
	}
	return p, nil
}

func (c *testController) RestartKernel(ctx context.Context, kernel string) error {
	c.restartCount.Add(1)

	if err := ctx.Err(); err != nil {
		return err
	}

	c.mu.Lock()
	hook := c.restartHook
	forcedErr := c.restartErr
	c.mu.Unlock()

	if hook != nil {
		if err := hook(ctx, kernel); err != nil {
			return err
		}
	}
	if forcedErr != nil {
		return forcedErr
	}

	c.stopLockedKernel(kernel)

	c.mu.Lock()
	binPath := c.paths[kernel]
	bindAddr := c.dialOverride[kernel]
	c.mu.Unlock()

	if _, err := os.Stat(binPath); err != nil {
		return err
	}

	cmd := exec.Command(binPath)
	if bindAddr != "" {
		cmd.Env = append(os.Environ(), "HELPER_LISTEN_ADDR="+bindAddr)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %s: %w", binPath, err)
	}

	proc := &managedProc{
		cmd:  cmd,
		done: make(chan struct{}),
	}
	go func() {
		_ = cmd.Wait()
		close(proc.done)
	}()

	c.mu.Lock()
	c.procs[kernel] = proc
	c.mu.Unlock()
	return nil
}

func (c *testController) stopLockedKernel(kernel string) {
	c.mu.Lock()
	proc := c.procs[kernel]
	delete(c.procs, kernel)
	c.mu.Unlock()

	if proc == nil {
		return
	}
	if proc.cmd.Process != nil {
		_ = proc.cmd.Process.Signal(syscall.SIGTERM)
	}
	select {
	case <-proc.done:
	case <-time.After(2 * time.Second):
		if proc.cmd.Process != nil {
			_ = proc.cmd.Process.Kill()
		}
		<-proc.done
	}
}

func (c *testController) stopAll() {
	c.mu.Lock()
	kernels := make([]string, 0, len(c.procs))
	for k := range c.procs {
		kernels = append(kernels, k)
	}
	c.mu.Unlock()
	for _, k := range kernels {
		c.stopLockedKernel(k)
	}
}

func (c *testController) IsKernelHealthy(kernel string) bool {
	c.mu.Lock()
	if ov, ok := c.forceHealth[kernel]; ok && ov != nil {
		val := *ov
		c.mu.Unlock()
		return val
	}
	proc := c.procs[kernel]
	c.mu.Unlock()

	if proc == nil {
		return false
	}
	select {
	case <-proc.done:
		return false
	default:
		return true
	}
}

func (c *testController) ListenAddrs(kernel string) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.listenAddrs[kernel]...)
}

func (c *testController) ProbeVersion(ctx context.Context, kernel string, binPath string) (string, error) {
	flag := "--version"
	if kernel == protocol.KernelSnellServer {
		flag = "-v"
	}
	cmd := exec.CommandContext(ctx, binPath, flag)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("probe %s %s: %w (%s)", binPath, flag, err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func reserveTCPPort(t *testing.T) (string, int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserveTCPPort: %v", err)
	}
	addr := ln.Addr().String()
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return addr, port
}

type tarEntrySpec struct {
	name     string
	typeflag byte
	body     []byte
	mode     int64
	linkname string
}

func buildTarGz(t *testing.T, entries []tarEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		mode := e.mode
		if mode == 0 {
			if e.typeflag == tar.TypeDir {
				mode = 0o755
			} else {
				mode = 0o755
			}
		}
		hdr := &tar.Header{
			Name:     e.name,
			Typeflag: e.typeflag,
			Mode:     mode,
			Size:     int64(len(e.body)),
			Linkname: e.linkname,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("tar WriteHeader %q: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("tar Write %q: %v", e.name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip Close: %v", err)
	}
	return buf.Bytes()
}

type zipEntrySpec struct {
	name string
	body []byte
	mode os.FileMode
}

func buildZip(t *testing.T, entries []zipEntrySpec) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		hdr := &zip.FileHeader{
			Name:   e.name,
			Method: zip.Deflate,
		}
		if e.mode != 0 {
			hdr.SetMode(e.mode)
		} else if strings.HasSuffix(e.name, "/") {
			hdr.SetMode(os.ModeDir | 0o755)
		} else {
			hdr.SetMode(0o755)
		}
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			t.Fatalf("zip CreateHeader %q: %v", e.name, err)
		}
		if len(e.body) > 0 {
			if _, err := w.Write(e.body); err != nil {
				t.Fatalf("zip Write %q: %v", e.name, err)
			}
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip Close: %v", err)
	}
	return buf.Bytes()
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

type eventCollector struct {
	mu     sync.Mutex
	events []protocol.AgentEvent
}

func (ec *eventCollector) record(ev protocol.AgentEvent) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.events = append(ec.events, ev)
}

func (ec *eventCollector) snapshot() []protocol.AgentEvent {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	return append([]protocol.AgentEvent(nil), ec.events...)
}

func newTestUpdater(t *testing.T, dataDir string, ctrl updater.KernelController, ec *eventCollector, optsMod func(*updater.Options)) *updater.Updater {
	t.Helper()
	opts := updater.Options{
		DataDir:               dataDir,
		Controller:            ctrl,
		HealthObserveDuration: 1500 * time.Millisecond,
		HealthPollInterval:    50 * time.Millisecond,
		PortDialTimeout:       500 * time.Millisecond,
		DownloadTimeout:       15 * time.Second,
		ProbeTimeout:          15 * time.Second,
		RollbackTimeout:       15 * time.Second,
	}
	if ec != nil {
		opts.OnEvent = ec.record
	}
	if optsMod != nil {
		optsMod(&opts)
	}
	u, err := updater.New(opts)
	if err != nil {
		t.Fatalf("updater.New: %v", err)
	}
	return u
}

func assertTmpClean(t *testing.T, dataDir string) {
	t.Helper()
	tmpDir := filepath.Join(dataDir, "tmp")
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("ReadDir %q: %v", tmpDir, err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "update-") {
			t.Fatalf("expected %q to have no leftover update-* dirs, found %q", tmpDir, e.Name())
		}
	}
}

func TestNewValidationAndStaleTempCleanup(t *testing.T) {
	ctrl := newTestController()
	if _, err := updater.New(updater.Options{Controller: ctrl}); err == nil {
		t.Fatal("expected error for empty DataDir")
	}
	if _, err := updater.New(updater.Options{DataDir: t.TempDir()}); err == nil {
		t.Fatal("expected error for nil Controller")
	}

	dataDir := t.TempDir()
	tmpDir := filepath.Join(dataDir, "tmp")
	staleDir := filepath.Join(tmpDir, "update-sing-box-stale")
	if err := os.MkdirAll(staleDir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(staleDir, "artifact.dl"), []byte("junk"), 0o600); err != nil {
		t.Fatal(err)
	}
	bakFile := filepath.Join(tmpDir, "keep.bak")
	if err := os.WriteFile(bakFile, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := updater.New(updater.Options{DataDir: dataDir, Controller: ctrl}); err != nil {
		t.Fatalf("updater.New: %v", err)
	}

	if _, err := os.Stat(staleDir); !os.IsNotExist(err) {
		t.Fatalf("expected stale dir %q to be swept", staleDir)
	}
	if _, err := os.Stat(bakFile); err != nil {
		t.Fatalf("expected .bak file %q to remain untouched: %v", bakFile, err)
	}
}

func TestApplyUpdate_PreFlightValidation(t *testing.T) {
	dataDir := t.TempDir()
	ctrl := newTestController()
	ec := &eventCollector{}
	u := newTestUpdater(t, dataDir, ctrl, ec, nil)

	cases := []struct {
		name string
		req  protocol.ServerKernelUpdate
	}{
		{
			name: "invalid_kernel",
			req:  protocol.ServerKernelUpdate{Kernel: "unknown-kernel", DownloadURL: "https://example.com/bin"},
		},
		{
			name: "empty_url",
			req:  protocol.ServerKernelUpdate{Kernel: protocol.KernelSingBox, DownloadURL: "   "},
		},
		{
			name: "file_scheme_rejected",
			req:  protocol.ServerKernelUpdate{Kernel: protocol.KernelSingBox, DownloadURL: "file:///etc/passwd"},
		},
		{
			name: "missing_host",
			req:  protocol.ServerKernelUpdate{Kernel: protocol.KernelSingBox, DownloadURL: "https:///sing-box"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := u.ApplyUpdate(context.Background(), tc.req)
			if err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}

	events := ec.snapshot()
	if len(events) != len(cases) {
		t.Fatalf("expected %d terminal events, got %d", len(cases), len(events))
	}
	for _, ev := range events {
		if ev.Event != protocol.EventKernelUpdateResult || ev.Status != updater.StatusUpdateFailed {
			t.Fatalf("unexpected event: %+v", ev)
		}
	}
}

func TestApplyUpdate_TarGz_Zip_Raw_Redirect_SeparateFS(t *testing.T) {
	cases := []struct {
		name        string
		kernel      string
		urlPath     string
		redirectTo  string
		contentDisp string
		initMissing bool
		buildBody   func(t *testing.T, payload []byte) []byte
	}{
		{
			name:    "targz_nested_separate_dirs",
			kernel:  protocol.KernelSingBox,
			urlPath: "/releases/sing-box-v2.0.0.tar.gz",
			buildBody: func(t *testing.T, payload []byte) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "sing-box-2.0.0-linux-amd64/", typeflag: tar.TypeDir},
					{name: "sing-box-2.0.0-linux-amd64/LICENSE", typeflag: tar.TypeReg, body: []byte("MIT")},
					{name: "sing-box-2.0.0-linux-amd64/sing-box", typeflag: tar.TypeReg, body: payload},
				})
			},
		},
		{
			name:    "zip_nested",
			kernel:  protocol.KernelSnellServer,
			urlPath: "/downloads/snell-server-v5.0.0.zip",
			buildBody: func(t *testing.T, payload []byte) []byte {
				return buildZip(t, []zipEntrySpec{
					{name: "snell-v5/", mode: os.ModeDir | 0o755},
					{name: "snell-v5/README.md", body: []byte("docs")},
					{name: "snell-v5/snell-server", body: payload},
				})
			},
		},
		{
			name:    "raw_binary_extensionless",
			kernel:  protocol.KernelShadowTLS,
			urlPath: "/releases/shadow-tls-x86_64-unknown-linux-musl",
			buildBody: func(t *testing.T, payload []byte) []byte {
				return payload
			},
		},
		{
			name:        "extensionless_magic_targz_and_redirect",
			kernel:      protocol.KernelSingBox,
			urlPath:     "/latest",
			redirectTo:  "/cdn/blob-without-ext?sig=123",
			contentDisp: `attachment; filename="sing-box.tgz"`,
			buildBody: func(t *testing.T, payload []byte) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "sing-box", typeflag: tar.TypeReg, body: payload},
				})
			},
		},
		{
			name:    "targz_fallback_prefixed_binary",
			kernel:  protocol.KernelShadowTLS,
			urlPath: "/releases/shadow-tls.tar.gz",
			buildBody: func(t *testing.T, payload []byte) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "shadow-tls-README.md", typeflag: tar.TypeReg, body: []byte("doc")},
					{name: "shadow-tls-x86_64-unknown-linux-musl", typeflag: tar.TypeReg, body: payload},
				})
			},
		},
		{
			name:        "missing_initial_binary",
			kernel:      protocol.KernelSingBox,
			urlPath:     "/releases/sing-box.tar.gz",
			initMissing: true,
			buildBody: func(t *testing.T, payload []byte) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "sing-box", typeflag: tar.TypeReg, body: payload},
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			binDir := t.TempDir()
			targetBin := filepath.Join(binDir, tc.kernel)

			ctrl := newTestController()
			t.Cleanup(ctrl.stopAll)

			addr, _ := reserveTCPPort(t)
			ctrl.setKernel(tc.kernel, targetBin, []string{addr}, addr)

			if !tc.initMissing {
				v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
				if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := ctrl.RestartKernel(context.Background(), tc.kernel); err != nil {
					t.Fatal(err)
				}
			}

			v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
			artifact := tc.buildBody(t, v2)
			digest := "  " + strings.ToUpper(sha256Hex(artifact)) + " \n"

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.redirectTo != "" && r.URL.Path == tc.urlPath {
					http.Redirect(w, r, tc.redirectTo, http.StatusFound)
					return
				}
				if tc.contentDisp != "" {
					w.Header().Set("Content-Disposition", tc.contentDisp)
				}
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(artifact)
			}))
			defer srv.Close()

			ec := &eventCollector{}
			u := newTestUpdater(t, dataDir, ctrl, ec, nil)

			err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
				Kernel:      tc.kernel,
				Version:     "v2.0.0",
				DownloadURL: srv.URL + tc.urlPath,
				SHA256:      digest,
			})
			if err != nil {
				t.Fatalf("ApplyUpdate failed: %v", err)
			}

			probed, err := ctrl.ProbeVersion(context.Background(), tc.kernel, targetBin)
			if err != nil || probed != "v2.0.0" {
				t.Fatalf("expected v2.0.0 on disk, got %q (err=%v)", probed, err)
			}

			if !tc.initMissing {
				bakProbed, err := ctrl.ProbeVersion(context.Background(), tc.kernel, targetBin+".bak")
				if err != nil || bakProbed != "v1.0.0" {
					t.Fatalf("expected .bak to contain v1.0.0, got %q (err=%v)", bakProbed, err)
				}
			}

			if !ctrl.IsKernelHealthy(tc.kernel) {
				t.Fatal("expected updated kernel to be healthy")
			}

			events := ec.snapshot()
			if len(events) < 2 {
				t.Fatalf("expected progress + result events, got %d", len(events))
			}
			last := events[len(events)-1]
			if last.Event != protocol.EventKernelUpdateResult || last.Status != updater.StatusUpdateSuccess || last.Version != "v2.0.0" {
				t.Fatalf("unexpected terminal event: %+v", last)
			}
			var stages []string
			for _, ev := range events[:len(events)-1] {
				if ev.Event != protocol.EventKernelUpdateProgress || ev.Status != protocol.EventStatusInProgress {
					t.Fatalf("unexpected progress event: %+v", ev)
				}
				stages = append(stages, ev.Message)
			}
			wantStages := []string{"downloading", "verifying", "extracting", "probing", "swapping", "restarting", "health_checking"}
			if strings.Join(stages, ",") != strings.Join(wantStages, ",") {
				t.Fatalf("stage sequence = %v, want %v", stages, wantStages)
			}

			assertTmpClean(t, dataDir)
		})
	}
}

func TestApplyUpdate_SHA256AndDownloadErrors(t *testing.T) {
	setup := func(t *testing.T) (string, string, *testController, *eventCollector) {
		t.Helper()
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}
		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)
		return dataDir, targetBin, ctrl, &eventCollector{}
	}

	t.Run("malformed_sha256_skips_http", func(t *testing.T) {
		dataDir, targetBin, ctrl, ec := setup(t)
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, ec, nil)
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
			SHA256:      "deadbeef",
		})
		if err == nil {
			t.Fatal("expected error for malformed sha256")
		}
		if hits.Load() != 0 {
			t.Fatalf("expected 0 HTTP requests on malformed sha256, got %d", hits.Load())
		}
		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("original binary modified: %q", ver)
		}
		events := ec.snapshot()
		if len(events) != 1 || events[0].Status != updater.StatusUpdateFailed {
			t.Fatalf("expected single update_failed event, got %+v", events)
		}
	})

	t.Run("sha256_mismatch", func(t *testing.T) {
		dataDir, targetBin, ctrl, ec := setup(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0))
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, ec, nil)
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
			SHA256:      strings.Repeat("a", 64),
		})
		if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
			t.Fatalf("expected sha256 mismatch error, got %v", err)
		}
		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("original binary modified: %q", ver)
		}
		assertTmpClean(t, dataDir)
	})

	t.Run("http_404_and_500", func(t *testing.T) {
		for _, code := range []int{http.StatusNotFound, http.StatusInternalServerError} {
			dataDir, targetBin, ctrl, ec := setup(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				_, _ = w.Write([]byte("upstream error detail"))
			}))
			u := newTestUpdater(t, dataDir, ctrl, ec, nil)
			err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
				Kernel:      protocol.KernelSingBox,
				Version:     "v2.0.0",
				DownloadURL: srv.URL + "/sing-box",
			})
			srv.Close()
			if err == nil || !strings.Contains(err.Error(), strconv.Itoa(code)) {
				t.Fatalf("expected HTTP %d error, got %v", code, err)
			}
			ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
			if ver != "v1.0.0" {
				t.Fatalf("original binary modified: %q", ver)
			}
			events := ec.snapshot()
			last := events[len(events)-1]
			if last.Status != updater.StatusUpdateFailed || !strings.Contains(last.Detail, "upstream error detail") {
				t.Fatalf("expected update_failed with snippet detail, got %+v", last)
			}
		}
	})

	t.Run("empty_and_oversized_download", func(t *testing.T) {
		dataDir, _, ctrl, ec := setup(t)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/empty":
				w.WriteHeader(http.StatusOK)
			case "/big-chunked":
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(bytes.Repeat([]byte("A"), 2048))
			}
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
			o.MaxDownloadBytes = 512
		})
		if err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			DownloadURL: srv.URL + "/empty",
		}); err == nil {
			t.Fatal("expected error for 0-byte download")
		}
		if err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			DownloadURL: srv.URL + "/big-chunked",
		}); err == nil || !strings.Contains(err.Error(), "exceeds max") {
			t.Fatalf("expected oversized download error, got %v", err)
		}
		assertTmpClean(t, dataDir)
	})
}

func TestApplyUpdate_ArchiveSecurityAndCorrupt(t *testing.T) {
	validBin := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)

	cases := []struct {
		name    string
		urlPath string
		body    func(t *testing.T) []byte
	}{
		{
			name:    "corrupt_targz_bytes",
			urlPath: "/sing-box.tar.gz",
			body:    func(t *testing.T) []byte { return []byte("corrupted-non-archive-bytes") },
		},
		{
			name:    "corrupt_zip_bytes",
			urlPath: "/sing-box.zip",
			body:    func(t *testing.T) []byte { return []byte("corrupted-non-zip-bytes") },
		},
		{
			name:    "unsupported_tar_xz",
			urlPath: "/sing-box.tar.xz",
			body:    func(t *testing.T) []byte { return []byte("dummy") },
		},
		{
			name:    "targz_zip_slip",
			urlPath: "/sing-box.tar.gz",
			body: func(t *testing.T) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "../../evil", typeflag: tar.TypeReg, body: validBin},
				})
			},
		},
		{
			name:    "zip_zip_slip",
			urlPath: "/sing-box.zip",
			body: func(t *testing.T) []byte {
				return buildZip(t, []zipEntrySpec{
					{name: "../evil", body: validBin},
				})
			},
		},
		{
			name:    "targz_trailing_symlink",
			urlPath: "/sing-box.tar.gz",
			body: func(t *testing.T) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "sing-box", typeflag: tar.TypeReg, body: validBin},
					{name: "escape", typeflag: tar.TypeSymlink, linkname: "/etc/passwd"},
				})
			},
		},
		{
			name:    "targz_hardlink",
			urlPath: "/sing-box.tar.gz",
			body: func(t *testing.T) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "link", typeflag: tar.TypeLink, linkname: "/etc/passwd"},
				})
			},
		},
		{
			name:    "zip_symlink",
			urlPath: "/sing-box.zip",
			body: func(t *testing.T) []byte {
				return buildZip(t, []zipEntrySpec{
					{name: "sing-box", body: validBin},
					{name: "badlink", body: []byte("/etc/passwd"), mode: os.ModeSymlink | 0o777},
				})
			},
		},
		{
			name:    "targz_extract_bomb",
			urlPath: "/sing-box.tar.gz",
			body: func(t *testing.T) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "sing-box", typeflag: tar.TypeReg, body: bytes.Repeat([]byte("X"), 4096)},
				})
			},
		},
		{
			name:    "zip_extract_bomb",
			urlPath: "/sing-box.zip",
			body: func(t *testing.T) []byte {
				return buildZip(t, []zipEntrySpec{
					{name: "sing-box", body: bytes.Repeat([]byte("X"), 4096)},
				})
			},
		},
		{
			name:    "targz_missing_binary",
			urlPath: "/sing-box.tar.gz",
			body: func(t *testing.T) []byte {
				return buildTarGz(t, []tarEntrySpec{
					{name: "LICENSE", typeflag: tar.TypeReg, body: []byte("MIT")},
				})
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			binDir := t.TempDir()
			targetBin := filepath.Join(binDir, protocol.KernelSingBox)
			v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
			if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
				t.Fatal(err)
			}

			ctrl := newTestController()
			t.Cleanup(ctrl.stopAll)
			addr, _ := reserveTCPPort(t)
			ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

			payload := tc.body(t)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(payload)
			}))
			defer srv.Close()

			ec := &eventCollector{}
			u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
				o.MaxExtractBytes = 1024
			})

			err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
				Kernel:      protocol.KernelSingBox,
				Version:     "v2.0.0",
				DownloadURL: srv.URL + tc.urlPath,
			})
			if err == nil {
				t.Fatalf("expected error for %s", tc.name)
			}
			ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
			if ver != "v1.0.0" {
				t.Fatalf("original binary modified: %q", ver)
			}
			if ctrl.restartCount.Load() != 0 {
				t.Fatalf("expected 0 restarts on pre-swap failure, got %d", ctrl.restartCount.Load())
			}
			assertTmpClean(t, dataDir)
		})
	}
}

func TestApplyUpdate_ProbeFailureLeavesOriginalUntouched(t *testing.T) {
	dataDir := t.TempDir()
	binDir := t.TempDir()
	targetBin := filepath.Join(binDir, protocol.KernelSingBox)
	v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
	if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
		t.Fatal(err)
	}

	ctrl := newTestController()
	t.Cleanup(ctrl.stopAll)
	addr, _ := reserveTCPPort(t)
	ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)
	if err := ctrl.RestartKernel(context.Background(), protocol.KernelSingBox); err != nil {
		t.Fatal(err)
	}
	initialRestarts := ctrl.restartCount.Load()

	badBin := makeHelperBinaryPayload(t, "v2.0.0", "probe_fail", 0)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(badBin)
	}))
	defer srv.Close()

	ec := &eventCollector{}
	u := newTestUpdater(t, dataDir, ctrl, ec, nil)
	err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
		Kernel:      protocol.KernelSingBox,
		Version:     "v2.0.0",
		DownloadURL: srv.URL + "/sing-box",
	})
	if err == nil {
		t.Fatal("expected probe error")
	}
	if ctrl.restartCount.Load() != initialRestarts {
		t.Fatalf("expected no restart on probe failure, got restarts=%d", ctrl.restartCount.Load()-initialRestarts)
	}
	if _, err := os.Stat(targetBin + ".bak"); !os.IsNotExist(err) {
		t.Fatalf("expected no .bak created when probe fails")
	}
	ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
	if ver != "v1.0.0" {
		t.Fatalf("expected v1.0.0 untouched, got %q", ver)
	}
	if entries, err := os.ReadDir(binDir); err != nil || len(entries) != 1 {
		t.Fatalf("expected no leftover staging files in %q, got %v (err=%v)", binDir, entries, err)
	}
	assertTmpClean(t, dataDir)
}

func TestApplyUpdate_PostSwapRollbacks(t *testing.T) {
	t.Run("restart_failure_rollback", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

		var calls atomic.Int32
		ctrl.setRestartHook(func(ctx context.Context, kernel string) error {
			if calls.Add(1) == 1 {
				return errors.New("simulated restart failure")
			}
			return nil
		})

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		ec := &eventCollector{}
		u := newTestUpdater(t, dataDir, ctrl, ec, nil)
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil {
			t.Fatal("expected RestartKernel failure")
		}
		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("expected rollback to v1.0.0, got %q", ver)
		}
		if !ctrl.IsKernelHealthy(protocol.KernelSingBox) {
			t.Fatal("expected rolled-back kernel to be running and healthy")
		}
		events := ec.snapshot()
		last := events[len(events)-1]
		if last.Status != updater.StatusUpdateFailed {
			t.Fatalf("expected update_failed, got %+v", last)
		}
	})

	t.Run("mid_window_crash_rollback", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)
		if err := ctrl.RestartKernel(context.Background(), protocol.KernelSingBox); err != nil {
			t.Fatal(err)
		}

		// New binary binds TCP port initially (passes probe and initial polls), then crashes at 180ms.
		v2 := makeHelperBinaryPayload(t, "v2.0.0", "crash_after_ms", 180)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		ec := &eventCollector{}
		u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
			o.HealthObserveDuration = 2 * time.Second
			o.HealthPollInterval = 40 * time.Millisecond
		})

		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil {
			t.Fatal("expected rollback error on mid-window crash")
		}

		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("expected rollback to v1.0.0, got %q", ver)
		}
		if !ctrl.IsKernelHealthy(protocol.KernelSingBox) {
			t.Fatal("expected old binary running after rollback")
		}
		dialDeadline := time.Now().Add(3 * time.Second)
		var dialErr error
		for {
			var conn net.Conn
			conn, dialErr = net.DialTimeout("tcp", addr, 200*time.Millisecond)
			if dialErr == nil {
				_ = conn.Close()
				break
			}
			if !time.Now().Before(dialDeadline) {
				t.Fatalf("expected rolled-back binary to listen on %s: %v", addr, dialErr)
			}
			time.Sleep(25 * time.Millisecond)
		}

		events := ec.snapshot()
		hasRollingBack := false
		for _, ev := range events {
			if ev.Event == protocol.EventKernelUpdateProgress && ev.Message == "rolling_back" {
				hasRollingBack = true
			}
		}
		if !hasRollingBack {
			t.Fatalf("expected rolling_back progress event, got %+v", events)
		}
		if events[len(events)-1].Status != updater.StatusUpdateFailed {
			t.Fatalf("expected terminal update_failed event, got %+v", events[len(events)-1])
		}
	})

	t.Run("port_never_ready_rollback", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

		// Process stays alive, but never binds listening TCP port.
		v2 := makeHelperBinaryPayload(t, "v2.0.0", "no_listen", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		ec := &eventCollector{}
		u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
			o.HealthObserveDuration = 250 * time.Millisecond
			o.HealthPollInterval = 40 * time.Millisecond
		})

		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil {
			t.Fatal("expected port-never-ready rollback error")
		}
		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("expected rollback to v1.0.0, got %q", ver)
		}
		if !ctrl.IsKernelHealthy(protocol.KernelSingBox) {
			t.Fatal("expected old binary running after rollback")
		}
	})

	t.Run("parent_ctx_cancel_during_observation_still_rolls_back", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		var sawRollbackCtxAlive atomic.Bool
		var restarts atomic.Int32
		ctrl.setRestartHook(func(rCtx context.Context, kernel string) error {
			if restarts.Add(1) == 2 {
				// Second restart is rollback; verify context was NOT cancelled!
				sawRollbackCtxAlive.Store(rCtx.Err() == nil)
			}
			return nil
		})

		ec := &eventCollector{}
		var cancelOnce sync.Once
		u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
			o.HealthObserveDuration = 2 * time.Second
			o.HealthPollInterval = 40 * time.Millisecond
			o.OnEvent = func(ev protocol.AgentEvent) {
				ec.record(ev)
				if ev.Event == protocol.EventKernelUpdateProgress && ev.Message == "health_checking" {
					cancelOnce.Do(func() {
						go func() {
							time.Sleep(100 * time.Millisecond)
							cancel()
						}()
					})
				}
			}
		})

		err := u.ApplyUpdate(ctx, protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if !sawRollbackCtxAlive.Load() {
			t.Fatal("expected rollback RestartKernel to receive non-cancelled context")
		}
		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("expected rollback to v1.0.0, got %q", ver)
		}
		if !ctrl.IsKernelHealthy(protocol.KernelSingBox) {
			t.Fatal("expected old binary running after cancellation rollback")
		}
	})

	t.Run("missing_initial_binary_removes_broken_binary_on_rollback", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "no_listen", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, nil, func(o *updater.Options) {
			o.HealthObserveDuration = 200 * time.Millisecond
			o.HealthPollInterval = 40 * time.Millisecond
		})
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil {
			t.Fatal("expected rollback error")
		}
		if _, statErr := os.Stat(targetBin); !os.IsNotExist(statErr) {
			t.Fatalf("expected targetBin %q to be removed on rollback when !hadOriginal", targetBin)
		}
	})
}

func TestApplyUpdate_ListenAddrVariantsAndEmptyAddrs(t *testing.T) {
	t.Run("wildcard_and_scheme_variants", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}

		bindAddr, port := reserveTCPPort(t)
		listenVariants := []string{
			fmt.Sprintf("0.0.0.0:%d", port),
			fmt.Sprintf("[::]:%d", port),
			fmt.Sprintf(":%d", port),
			fmt.Sprintf("tcp://127.0.0.1:%d", port),
			fmt.Sprintf("udp://127.0.0.1:%d", port),
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, listenVariants, bindAddr)

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, nil, nil)
		if err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		}); err != nil {
			t.Fatalf("expected wildcard & scheme variants to succeed, got %v", err)
		}
	})

	t.Run("empty_listen_addrs_enforces_IsKernelHealthy", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		v1 := makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0)
		if err := os.WriteFile(targetBin, v1, 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, nil, "")

		// Binary crashes at 120ms; with empty ListenAddrs, IsKernelHealthy must catch it!
		v2 := makeHelperBinaryPayload(t, "v2.0.0", "crash_after_ms", 120)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, nil, func(o *updater.Options) {
			o.HealthObserveDuration = 2 * time.Second
			o.HealthPollInterval = 30 * time.Millisecond
		})
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil {
			t.Fatal("expected rollback when empty ListenAddrs kernel crashes")
		}
		ver, _ := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if ver != "v1.0.0" {
			t.Fatalf("expected rollback to v1.0.0, got %q", ver)
		}
	})
}

func TestApplyUpdate_ConcurrencyAndLockCancellation(t *testing.T) {
	dataDir := t.TempDir()
	binDir := t.TempDir()

	ctrl := newTestController()
	t.Cleanup(ctrl.stopAll)

	for _, k := range []string{protocol.KernelSingBox, protocol.KernelSnellServer, protocol.KernelShadowTLS} {
		p := filepath.Join(binDir, k)
		if err := os.WriteFile(p, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(k, p, []string{addr}, addr)
	}

	ctrl.setRestartHook(func(ctx context.Context, kernel string) error {
		cur := ctrl.activeUpdates.Add(1)
		defer ctrl.activeUpdates.Add(-1)
		for {
			prev := ctrl.maxConcurrent.Load()
			if cur <= prev || ctrl.maxConcurrent.CompareAndSwap(prev, cur) {
				break
			}
		}
		time.Sleep(40 * time.Millisecond)
		return nil
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sing-box":
			_, _ = w.Write(makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0))
		case "/snell-server":
			_, _ = w.Write(makeHelperBinaryPayload(t, "v2.1.0", "healthy", 0))
		case "/shadow-tls":
			_, _ = w.Write(makeHelperBinaryPayload(t, "v2.2.0", "healthy", 0))
		}
	}))
	defer srv.Close()

	ec := &eventCollector{}
	u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
		o.HealthObserveDuration = 1500 * time.Millisecond
		o.HealthPollInterval = 40 * time.Millisecond
	})

	reqs := []protocol.ServerKernelUpdate{
		{Kernel: protocol.KernelSingBox, Version: "v2.0.0", DownloadURL: srv.URL + "/sing-box"},
		{Kernel: protocol.KernelSnellServer, Version: "v2.1.0", DownloadURL: srv.URL + "/snell-server"},
		{Kernel: protocol.KernelShadowTLS, Version: "v2.2.0", DownloadURL: srv.URL + "/shadow-tls"},
	}

	var wg sync.WaitGroup
	errs := make([]error, len(reqs))
	for i, req := range reqs {
		wg.Add(1)
		go func(idx int, r protocol.ServerKernelUpdate) {
			defer wg.Done()
			errs[idx] = u.ApplyUpdate(context.Background(), r)
		}(i, req)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent update %d failed: %v", i, err)
		}
	}
	if ctrl.maxConcurrent.Load() != 1 {
		t.Fatalf("expected max concurrency 1, got %d", ctrl.maxConcurrent.Load())
	}

	// Verify events did not interleave between kernels (each kernel's sequence finishes with update_success before next starts).
	events := ec.snapshot()
	var currentKernel string
	resultCount := 0
	for _, ev := range events {
		if currentKernel == "" {
			currentKernel = ev.Kernel
		}
		if ev.Kernel != currentKernel {
			t.Fatalf("interleaved event for %q while %q was active: %+v", ev.Kernel, currentKernel, events)
		}
		if ev.Event == protocol.EventKernelUpdateResult {
			resultCount++
			currentKernel = ""
		}
	}
	if resultCount != 3 {
		t.Fatalf("expected 3 terminal result events, got %d", resultCount)
	}

	// Verify queued caller context cancellation while another update holds lock.
	holdCh := make(chan struct{})
	releasedCh := make(chan struct{})
	var holdOnce sync.Once
	var releaseOnce sync.Once
	releaseHold := func() {
		releaseOnce.Do(func() { close(releasedCh) })
	}
	t.Cleanup(releaseHold)

	var hookCalls atomic.Int32
	ctrl.setRestartHook(func(ctx context.Context, kernel string) error {
		if hookCalls.Add(1) == 1 {
			holdOnce.Do(func() { close(holdCh) })
			<-releasedCh
		}
		return nil
	})
	defer ctrl.setRestartHook(nil)

	firstDone := make(chan error, 1)
	go func() {
		firstDone <- u.ApplyUpdate(context.Background(), reqs[0])
	}()

	select {
	case <-holdCh:
	case err := <-firstDone:
		t.Fatalf("first update exited before restartHook: %v", err)
	}
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer waitCancel()
	waitErr := u.ApplyUpdate(waitCtx, reqs[1])
	if !errors.Is(waitErr, context.DeadlineExceeded) {
		releaseHold()
		<-firstDone
		t.Fatalf("expected context.DeadlineExceeded for queued caller, got %v", waitErr)
	}

	releaseHold()
	if err := <-firstDone; err != nil {
		t.Fatalf("first update failed: %v", err)
	}

	assertTmpClean(t, dataDir)
}

func makeMultiTarGz(t *testing.T, fn func(*tar.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	fn(tw)
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

func makeMultiZip(t *testing.T, fn func(*zip.Writer)) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fn(zw)
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

func addTarFile(t *testing.T, tw *tar.Writer, name string, data []byte, mode int64) {
	t.Helper()
	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     mode,
		Size:     int64(len(data)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("tar header %s: %v", name, err)
	}
	if _, err := tw.Write(data); err != nil {
		t.Fatalf("tar write %s: %v", name, err)
	}
}

func addZipFile(t *testing.T, zw *zip.Writer, name string, data []byte, mode os.FileMode) {
	t.Helper()
	fh := &zip.FileHeader{Name: name, Method: zip.Deflate}
	fh.SetMode(mode)
	w, err := zw.CreateHeader(fh)
	if err != nil {
		t.Fatalf("zip header %s: %v", name, err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatalf("zip write %s: %v", name, err)
	}
}

func TestExtractTarGzAndZip_MultiCandidateAndEmptyDecoy(t *testing.T) {
	runArchiveCase := func(t *testing.T, ext string, payload []byte) string {
		t.Helper()
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}
		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, nil, func(o *updater.Options) {
			o.HealthObserveDuration = 120 * time.Millisecond
			o.HealthPollInterval = 25 * time.Millisecond
		})
		if err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box." + ext,
		}); err != nil {
			t.Fatalf("ApplyUpdate (%s) failed: %v", ext, err)
		}
		probed, err := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if err != nil {
			t.Fatalf("ProbeVersion failed: %v", err)
		}
		return probed
	}

	t.Run("zip_zero_byte_root_decoy_skipped_for_nested_binary", func(t *testing.T) {
		valid := makeHelperBinaryPayload(t, "v2.0.0-nested", "healthy", 0)
		z := makeMultiZip(t, func(zw *zip.Writer) {
			addZipFile(t, zw, "sing-box", nil, 0o755)
			addZipFile(t, zw, "sing-box-1.14.4-linux-amd64/sing-box", valid, 0o755)
		})
		if got := runArchiveCase(t, "zip", z); got != "v2.0.0-nested" {
			t.Fatalf("got %q, want v2.0.0-nested", got)
		}
	})

	t.Run("tar_zero_byte_root_decoy_skipped_for_nested_binary", func(t *testing.T) {
		valid := makeHelperBinaryPayload(t, "v2.0.0-tar-nested", "healthy", 0)
		tg := makeMultiTarGz(t, func(tw *tar.Writer) {
			addTarFile(t, tw, "sing-box", nil, 0o755)
			addTarFile(t, tw, "sing-box-1.14.4-linux-amd64/sing-box", valid, 0o755)
		})
		if got := runArchiveCase(t, "tar.gz", tg); got != "v2.0.0-tar-nested" {
			t.Fatalf("got %q, want v2.0.0-tar-nested", got)
		}
	})

	t.Run("depth_and_lexicographic_tie_break_and_exact_over_fallback", func(t *testing.T) {
		deep := makeHelperBinaryPayload(t, "v-deep", "healthy", 0)
		shallowB := makeHelperBinaryPayload(t, "v-shallow-b", "healthy", 0)
		shallowA := makeHelperBinaryPayload(t, "v-shallow-a", "healthy", 0)
		fallback := makeHelperBinaryPayload(t, "v-fallback", "healthy", 0)
		readme := []byte("ignore me")

		z := makeMultiZip(t, func(zw *zip.Writer) {
			addZipFile(t, zw, "sing-box-README.md", readme, 0o644)
			addZipFile(t, zw, "sing-box-linux-amd64", fallback, 0o755)
			addZipFile(t, zw, "sub/deep/sing-box", deep, 0o755)
			addZipFile(t, zw, "dirb/sing-box", shallowB, 0o755)
			addZipFile(t, zw, "dira/sing-box", shallowA, 0o755)
		})
		if got := runArchiveCase(t, "zip", z); got != "v-shallow-a" {
			t.Fatalf("zip candidate selection got %q, want v-shallow-a", got)
		}

		tg := makeMultiTarGz(t, func(tw *tar.Writer) {
			addTarFile(t, tw, "sing-box-checksum.sha256", readme, 0o644)
			addTarFile(t, tw, "sing-box-linux-amd64", fallback, 0o755)
			addTarFile(t, tw, "sub/deep/sing-box", deep, 0o755)
			addTarFile(t, tw, "dirb/sing-box", shallowB, 0o755)
			addTarFile(t, tw, "dira/sing-box", shallowA, 0o755)
		})
		if got := runArchiveCase(t, "tar.gz", tg); got != "v-shallow-a" {
			t.Fatalf("tar.gz candidate selection got %q, want v-shallow-a", got)
		}
	})
}

func TestExtractArchive_TraversalSymlinkAndSizeBomb(t *testing.T) {
	runExpectFail := func(t *testing.T, ext string, payload []byte, maxExtract int64, wantSubstr string) {
		t.Helper()
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}
		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, nil, "")

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(payload)
		}))
		defer srv.Close()

		u := newTestUpdater(t, dataDir, ctrl, nil, func(o *updater.Options) {
			if maxExtract > 0 {
				o.MaxExtractBytes = maxExtract
			}
		})
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/bad." + ext,
		})
		if err == nil || !strings.Contains(err.Error(), wantSubstr) {
			t.Fatalf("expected error containing %q, got %v", wantSubstr, err)
		}
		assertTmpClean(t, dataDir)
	}

	valid := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)

	t.Run("tar_traversal_and_links", func(t *testing.T) {
		for _, tc := range []struct {
			name string
			hdr  tar.Header
			want string
		}{
			{"dotdot", tar.Header{Name: "../../etc/passwd", Mode: 0o644, Size: int64(len(valid)), Typeflag: tar.TypeReg}, ".."},
			{"abs", tar.Header{Name: "/etc/sing-box", Mode: 0o755, Size: int64(len(valid)), Typeflag: tar.TypeReg}, "absolute path"},
			{"backslash", tar.Header{Name: `dir\sing-box`, Mode: 0o755, Size: int64(len(valid)), Typeflag: tar.TypeReg}, "backslash"},
			{"symlink", tar.Header{Name: "sing-box", Mode: 0o777, Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}, "forbidden link"},
			{"hardlink", tar.Header{Name: "sing-box", Mode: 0o777, Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}, "forbidden link"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				tg := makeMultiTarGz(t, func(tw *tar.Writer) {
					_ = tw.WriteHeader(&tc.hdr)
					if tc.hdr.Size > 0 {
						_, _ = tw.Write(valid)
					}
				})
				runExpectFail(t, "tar.gz", tg, 0, tc.want)
			})
		}
	})

	t.Run("zip_traversal_symlink_and_size_bomb", func(t *testing.T) {
		zTrav := makeMultiZip(t, func(zw *zip.Writer) {
			addZipFile(t, zw, "../sing-box", valid, 0o755)
		})
		runExpectFail(t, "zip", zTrav, 0, "..")

		zSym := makeMultiZip(t, func(zw *zip.Writer) {
			addZipFile(t, zw, "sing-box", []byte("/etc/passwd"), os.ModeSymlink|0o777)
		})
		runExpectFail(t, "zip", zSym, 0, "symlink")

		zDrive := makeMultiZip(t, func(zw *zip.Writer) {
			addZipFile(t, zw, "C:sing-box", valid, 0o755)
		})
		runExpectFail(t, "zip", zDrive, 0, "drive prefix")

		big := bytes.Repeat([]byte("A"), 4096)
		zBomb := makeMultiZip(t, func(zw *zip.Writer) {
			addZipFile(t, zw, "sing-box", big, 0o755)
		})
		runExpectFail(t, "zip", zBomb, 1024, "max extract limit")

		tgBomb := makeMultiTarGz(t, func(tw *tar.Writer) {
			addTarFile(t, tw, "sing-box", big, 0o755)
		})
		runExpectFail(t, "tar.gz", tgBomb, 1024, "max extract limit")
	})
}

func TestUpdater_UpdateDisabledOrUnconfiguredKernel(t *testing.T) {
	for _, tc := range []struct {
		name       string
		errFactory func() error
		wantMsg    string
	}{
		{
			name:       "sentinel_ErrKernelInactive",
			errFactory: func() error { return updater.ErrKernelInactive },
			wantMsg:    "kernel updated while stopped",
		},
		{
			name: "wrapped_inactive_unconfigured",
			errFactory: func() error {
				return &inactiveStubErr{msg: "no active config", reason: "unconfigured"}
			},
			wantMsg: "kernel updated while unconfigured",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dataDir := t.TempDir()
			binDir := t.TempDir()
			targetBin := filepath.Join(binDir, protocol.KernelSingBox)
			if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
				t.Fatal(err)
			}

			ctrl := newTestController()
			t.Cleanup(ctrl.stopAll)
			ctrl.setKernel(protocol.KernelSingBox, targetBin, nil, "")
			ctrl.setRestartHook(func(ctx context.Context, kernel string) error {
				return tc.errFactory()
			})

			v2 := makeHelperBinaryPayload(t, "v2.1.0", "healthy", 0)
			sum := sha256.Sum256(v2)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write(v2)
			}))
			defer srv.Close()

			ec := &eventCollector{}
			u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
				o.HealthObserveDuration = 3 * time.Second // Must NOT sleep 3s when kernel is inactive!
			})

			start := time.Now()
			err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
				Kernel:      protocol.KernelSingBox,
				Version:     "v2.1.0",
				DownloadURL: srv.URL + "/sing-box",
				SHA256:      hex.EncodeToString(sum[:]),
			})
			if err != nil {
				t.Fatalf("expected inactive kernel update to succeed cleanly, got: %v", err)
			}
			if elapsed := time.Since(start); elapsed >= 1500*time.Millisecond {
				t.Fatalf("inactive update unexpectedly waited for live observation window (%v)", elapsed)
			}

			probed, err := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
			if err != nil || probed != "v2.1.0" {
				t.Fatalf("expected binary updated to v2.1.0 without false rollback, got %q (err=%v)", probed, err)
			}
			bakProbed, err := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin+".bak")
			if err != nil || bakProbed != "v1.0.0" {
				t.Fatalf("expected .bak preserved at v1.0.0, got %q (err=%v)", bakProbed, err)
			}

			events := ec.snapshot()
			last := events[len(events)-1]
			if last.Event != protocol.EventKernelUpdateResult || last.Status != protocol.EventStatusSuccess {
				t.Fatalf("expected terminal success event, got %+v", last)
			}
			if last.Message != tc.wantMsg {
				t.Fatalf("message = %q, want %q", last.Message, tc.wantMsg)
			}
		})
	}
}

type inactiveStubErr struct {
	msg    string
	reason string
}

func (e *inactiveStubErr) Error() string          { return e.msg }
func (e *inactiveStubErr) KernelInactive() bool   { return true }
func (e *inactiveStubErr) InactiveReason() string { return e.reason }

func TestUpdater_RollbackFailureAndSwapPermissions(t *testing.T) {
	t.Run("stage_fails_on_unwritable_target_dir", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("chmod 0555 does not block root")
		}
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, nil, "")

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		if err := os.Chmod(binDir, 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(binDir, 0o755) })

		ec := &eventCollector{}
		u := newTestUpdater(t, dataDir, ctrl, ec, nil)
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil {
			t.Fatal("expected staging failure on read-only binDir")
		}
		events := ec.snapshot()
		if events[len(events)-1].Status != updater.StatusUpdateFailed {
			t.Fatalf("expected update_failed event, got %+v", events[len(events)-1])
		}
	})

	t.Run("rollback_failure_when_backup_removed_before_restore", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, nil, "")
		ctrl.setRestartHook(func(ctx context.Context, kernel string) error {
			// Delete .bak right when RestartKernel is called to simulate restoreBackup failure!
			_ = os.Remove(targetBin + ".bak")
			return errors.New("simulated restart boom")
		})

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		ec := &eventCollector{}
		u := newTestUpdater(t, dataDir, ctrl, ec, nil)
		err := u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if err == nil || !strings.Contains(err.Error(), "rollback errors:") || !strings.Contains(err.Error(), "restore backup") {
			t.Fatalf("expected combined rollback error, got %v", err)
		}
		events := ec.snapshot()
		last := events[len(events)-1]
		if last.Status != updater.StatusUpdateFailed || !strings.Contains(last.Message, "rollback encountered errors") {
			t.Fatalf("unexpected terminal event: %+v", last)
		}
	})
}

func TestUpdater_AcquireApplyLock_SerializationAndCancellation(t *testing.T) {
	t.Run("download_non_blocking_while_swap_restart_health_serialized", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		addr, _ := reserveTCPPort(t)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, []string{addr}, addr)

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		downloadStarted := make(chan struct{})
		releaseDownload := make(chan struct{})
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			close(downloadStarted)
			<-releaseDownload
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		lockCh := make(chan struct{}, 1)
		acquireLock := func(ctx context.Context) (func(), error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			select {
			case lockCh <- struct{}{}:
				var once sync.Once
				return func() { once.Do(func() { <-lockCh }) }, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		healthChecking := make(chan struct{})
		var hcOnce sync.Once
		ec := &eventCollector{}
		u, err := updater.New(updater.Options{
			DataDir:               dataDir,
			Controller:            ctrl,
			HealthObserveDuration: 350 * time.Millisecond,
			HealthPollInterval:    25 * time.Millisecond,
			AcquireApplyLock:      acquireLock,
			OnEvent: func(ev protocol.AgentEvent) {
				ec.record(ev)
				if ev.Event == protocol.EventKernelUpdateProgress && ev.Message == "health_checking" {
					hcOnce.Do(func() { close(healthChecking) })
				}
			},
		})
		if err != nil {
			t.Fatal(err)
		}

		doneCh := make(chan error, 1)
		go func() {
			doneCh <- u.ApplyUpdate(context.Background(), protocol.ServerKernelUpdate{
				Kernel:      protocol.KernelSingBox,
				Version:     "v2.0.0",
				DownloadURL: srv.URL + "/sing-box",
			})
		}()

		select {
		case <-downloadStarted:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for download to start")
		}

		// While download is blocked, lockCh must NOT be held!
		unlockDuringDL, err := acquireLock(context.Background())
		if err != nil {
			t.Fatalf("expected apply lock free during download, got %v", err)
		}
		unlockDuringDL()

		close(releaseDownload)

		select {
		case <-healthChecking:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for health_checking")
		}

		// During health_checking, acquireLock with short timeout must block and fail with DeadlineExceeded.
		waitCtx, waitCancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
		_, lockErr := acquireLock(waitCtx)
		waitCancel()
		if !errors.Is(lockErr, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded while health_checking holds apply lock, got %v", lockErr)
		}

		select {
		case err := <-doneCh:
			if err != nil {
				t.Fatalf("ApplyUpdate failed: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for ApplyUpdate")
		}

		// After ApplyUpdate finishes, lock must be released.
		unlockAfter, err := acquireLock(context.Background())
		if err != nil {
			t.Fatalf("expected apply lock released after ApplyUpdate, got %v", err)
		}
		unlockAfter()
	})

	t.Run("ctx_cancelled_while_waiting_for_apply_lock_aborts_before_swap", func(t *testing.T) {
		dataDir := t.TempDir()
		binDir := t.TempDir()
		targetBin := filepath.Join(binDir, protocol.KernelSingBox)
		if err := os.WriteFile(targetBin, makeHelperBinaryPayload(t, "v1.0.0", "healthy", 0), 0o755); err != nil {
			t.Fatal(err)
		}

		ctrl := newTestController()
		t.Cleanup(ctrl.stopAll)
		ctrl.setKernel(protocol.KernelSingBox, targetBin, nil, "")

		v2 := makeHelperBinaryPayload(t, "v2.0.0", "healthy", 0)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(v2)
		}))
		defer srv.Close()

		lockCh := make(chan struct{}, 1)
		lockCh <- struct{}{} // Externally held!
		defer func() { <-lockCh }()

		enteredApplyLock := make(chan struct{})
		var enteredOnce sync.Once
		ec := &eventCollector{}
		u := newTestUpdater(t, dataDir, ctrl, ec, func(o *updater.Options) {
			o.AcquireApplyLock = func(ctx context.Context) (func(), error) {
				enteredOnce.Do(func() { close(enteredApplyLock) })
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				select {
				case lockCh <- struct{}{}:
					return func() { <-lockCh }, nil
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		go func() {
			<-enteredApplyLock
			time.Sleep(25 * time.Millisecond)
			cancel()
		}()

		err := u.ApplyUpdate(ctx, protocol.ServerKernelUpdate{
			Kernel:      protocol.KernelSingBox,
			Version:     "v2.0.0",
			DownloadURL: srv.URL + "/sing-box",
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}

		// Original v1.0.0 binary must remain untouched and no .bak should exist.
		probed, probeErr := ctrl.ProbeVersion(context.Background(), protocol.KernelSingBox, targetBin)
		if probeErr != nil || probed != "v1.0.0" {
			t.Fatalf("expected original v1.0.0 binary untouched, got %q (err=%v)", probed, probeErr)
		}
		if _, err := os.Stat(targetBin + ".bak"); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("expected no .bak created when cancelled before swap, got err=%v", err)
		}
		events := ec.snapshot()
		last := events[len(events)-1]
		if last.Event != protocol.EventKernelUpdateResult || last.Status != updater.StatusUpdateFailed ||
			!strings.Contains(last.Message, "cancelled while waiting to apply") {
			t.Fatalf("expected update_failed cancellation event, got %+v", last)
		}
	})
}
