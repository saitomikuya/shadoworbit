//go:build e2e

package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/coder/websocket"
)

var (
	sharedBinMu  sync.Mutex
	sharedBinDir string

	panelBuildOnce sync.Once
	panelBinPath   string
	panelBuildErr  error

	agentBuildOnce sync.Once
	agentBinPath   string
	agentBuildErr  error
)

func TestMain(m *testing.M) {
	code := m.Run()
	sharedBinMu.Lock()
	dir := sharedBinDir
	sharedBinDir = ""
	sharedBinMu.Unlock()
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

func ensureSharedBinDir() (string, error) {
	sharedBinMu.Lock()
	defer sharedBinMu.Unlock()
	if sharedBinDir != "" {
		return sharedBinDir, nil
	}
	dir, err := os.MkdirTemp("", "snell-e2e-bins-*")
	if err != nil {
		return "", fmt.Errorf("create shared bin dir: %w", err)
	}
	sharedBinDir = dir
	return sharedBinDir, nil
}

const (
	primaryPortStart   = 32000
	primaryPortEnd     = 32767
	primaryPortCount   = primaryPortEnd - primaryPortStart + 1
	secondaryPortStart = 30000
	secondaryPortEnd   = 30999
	secondaryPortCount = secondaryPortEnd - secondaryPortStart + 1
)

var (
	portAllocMu         sync.Mutex
	primaryPortCursor   = os.Getpid() % primaryPortCount
	secondaryPortCursor = os.Getpid() % secondaryPortCount
)

func allocPortFromRanges(probe func(int) bool) (int, bool) {
	portAllocMu.Lock()
	defer portAllocMu.Unlock()

	for i := 0; i < primaryPortCount; i++ {
		port := primaryPortStart + primaryPortCursor
		primaryPortCursor = (primaryPortCursor + 1) % primaryPortCount
		if probe(port) {
			return port, true
		}
	}
	for i := 0; i < secondaryPortCount; i++ {
		port := secondaryPortStart + secondaryPortCursor
		secondaryPortCursor = (secondaryPortCursor + 1) % secondaryPortCount
		if probe(port) {
			return port, true
		}
	}
	return 0, false
}

func probeTCPPortBindable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = ln.Close()
	ln4, err4 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err4 != nil {
		return false
	}
	_ = ln4.Close()
	return true
}

func probeUDPPortBindable(port int) bool {
	pc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	_ = pc.Close()
	pc4, err4 := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err4 != nil {
		return false
	}
	_ = pc4.Close()
	return true
}

func probeDualPortBindable(port int) bool {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return false
	}
	pc, udpErr := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
	if udpErr != nil {
		_ = ln.Close()
		return false
	}
	_ = pc.Close()
	_ = ln.Close()

	ln4, err4 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err4 != nil {
		return false
	}
	pc4, udpErr4 := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if udpErr4 != nil {
		_ = ln4.Close()
		return false
	}
	_ = pc4.Close()
	_ = ln4.Close()
	return true
}

// AllocFreePort finds an available TCP port free on both wildcard and 127.0.0.1.
func AllocFreePort(t *testing.T) int {
	t.Helper()
	if port, ok := allocPortFromRanges(probeTCPPortBindable); ok {
		return port
	}
	for i := 0; i < 32; i++ {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		_ = ln.Close()
		if probeTCPPortBindable(port) {
			return port
		}
	}
	t.Fatal("AllocFreePort: failed to allocate TCP port on wildcard and 127.0.0.1")
	return 0
}

// AllocFreeUDPPort finds an available UDP port free on both wildcard and 127.0.0.1.
func AllocFreeUDPPort(t *testing.T) int {
	t.Helper()
	if port, ok := allocPortFromRanges(probeUDPPortBindable); ok {
		return port
	}
	for i := 0; i < 32; i++ {
		pc, err := net.ListenPacket("udp", ":0")
		if err != nil {
			continue
		}
		port := pc.LocalAddr().(*net.UDPAddr).Port
		_ = pc.Close()
		if probeUDPPortBindable(port) {
			return port
		}
	}
	t.Fatal("AllocFreeUDPPort: failed to allocate UDP port on wildcard and 127.0.0.1")
	return 0
}

// AllocFreeDualPort finds a port free for both TCP and UDP on wildcard and 127.0.0.1.
func AllocFreeDualPort(t *testing.T) int {
	t.Helper()
	if port, ok := allocPortFromRanges(probeDualPortBindable); ok {
		return port
	}
	for i := 0; i < 32; i++ {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			continue
		}
		port := ln.Addr().(*net.TCPAddr).Port
		pc, udpErr := net.ListenPacket("udp", fmt.Sprintf(":%d", port))
		if udpErr == nil {
			_ = pc.Close()
			_ = ln.Close()
			ln4, err4 := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
			if err4 == nil {
				pc4, udpErr4 := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", port))
				if udpErr4 == nil {
					_ = pc4.Close()
					_ = ln4.Close()
					return port
				}
				_ = ln4.Close()
			}
			continue
		}
		_ = ln.Close()
	}
	t.Fatal("AllocFreeDualPort: failed to allocate dual TCP+UDP port after exhausting ranges and 32 OS attempts")
	return 0
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("findRepoRoot: could not locate go.mod from %s", dir)
		}
		dir = parent
	}
}

// BuildPanelBinary compiles ./cmd/panel once per test run (or returns SNELL_E2E_PANEL_BIN).
func BuildPanelBinary(t *testing.T) string {
	t.Helper()
	if override := strings.TrimSpace(os.Getenv("SNELL_E2E_PANEL_BIN")); override != "" {
		return override
	}
	repoRoot := findRepoRoot(t)
	panelBuildOnce.Do(func() {
		binDir, err := ensureSharedBinDir()
		if err != nil {
			panelBuildErr = err
			return
		}
		out := filepath.Join(binDir, "panel")
		cmd := exec.Command("go", "build", "-race", "-o", out, "./cmd/panel")
		cmd.Dir = repoRoot
		if raw, err := cmd.CombinedOutput(); err != nil {
			panelBuildErr = fmt.Errorf("go build ./cmd/panel failed: %w\n%s", err, string(raw))
			return
		}
		panelBinPath = out
	})
	if panelBuildErr != nil {
		t.Fatalf("BuildPanelBinary: %v", panelBuildErr)
	}
	return panelBinPath
}

// BuildAgentBinary compiles ./cmd/agent once per test run (or returns SNELL_E2E_AGENT_BIN).
func BuildAgentBinary(t *testing.T) string {
	t.Helper()
	if override := strings.TrimSpace(os.Getenv("SNELL_E2E_AGENT_BIN")); override != "" {
		return override
	}
	repoRoot := findRepoRoot(t)
	agentBuildOnce.Do(func() {
		binDir, err := ensureSharedBinDir()
		if err != nil {
			agentBuildErr = err
			return
		}
		out := filepath.Join(binDir, "agent")
		cmd := exec.Command("go", "build", "-race", "-o", out, "./cmd/agent")
		cmd.Dir = repoRoot
		if raw, err := cmd.CombinedOutput(); err != nil {
			agentBuildErr = fmt.Errorf("go build ./cmd/agent failed: %w\n%s", err, string(raw))
			return
		}
		agentBinPath = out
	})
	if agentBuildErr != nil {
		t.Fatalf("BuildAgentBinary: %v", agentBuildErr)
	}
	return agentBinPath
}

type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func mergeEnv(base []string, overrides map[string]string, extras []string) []string {
	kv := make(map[string]string, len(base)+len(overrides)+len(extras))
	order := make([]string, 0, len(base)+len(overrides)+len(extras))
	put := func(k, v string) {
		if _, exists := kv[k]; !exists {
			order = append(order, k)
		}
		kv[k] = v
	}
	for _, entry := range base {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			put(entry[:idx], entry[idx+1:])
		}
	}
	for k, v := range overrides {
		put(k, v)
	}
	for _, entry := range extras {
		if idx := strings.IndexByte(entry, '='); idx > 0 {
			put(entry[:idx], entry[idx+1:])
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+kv[k])
	}
	return out
}

// TestEnv isolates filesystem state and subprocess lifecycles per test.
type TestEnv struct {
	T        *testing.T
	RootDir  string
	RepoRoot string
}

// NewTestEnv constructs an isolated TestEnv backed by t.TempDir().
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()
	return &TestEnv{
		T:        t,
		RootDir:  t.TempDir(),
		RepoRoot: findRepoRoot(t),
	}
}

// PanelConfig configures a black-box cmd/panel subprocess.
type PanelConfig struct {
	ListenAddr   string
	DBPath       string
	AdminUser    string
	AdminPass    string
	JWTSecret    string
	TZ           string
	ExtraEnv     []string
	ExtraArgs    []string
	StartTimeout time.Duration
}

// PanelProcess manages a running cmd/panel subprocess.
type PanelProcess struct {
	t          *testing.T
	ListenAddr string
	DBPath     string
	cmd        *exec.Cmd
	logs       *safeBuffer
	done       chan error

	mu                  sync.Mutex
	exited              bool
	exitEr              error
	intentionallyKilled bool
	clients             []*PanelClient
}

// StartPanel builds and launches cmd/panel, waiting until HTTP readiness or timeout.
func StartPanel(env *TestEnv, cfg PanelConfig) *PanelProcess {
	env.T.Helper()
	bin := BuildPanelBinary(env.T)

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf("127.0.0.1:%d", AllocFreePort(env.T))
	}
	if cfg.DBPath == "" {
		cfg.DBPath = filepath.Join(env.RootDir, "data", "panel.db")
	}
	if cfg.AdminUser == "" {
		cfg.AdminUser = "admin"
	}
	if cfg.AdminPass == "" {
		cfg.AdminPass = "change_me_on_first_login"
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 15 * time.Second
	}

	args := []string{
		"-listen", cfg.ListenAddr,
		"-db", cfg.DBPath,
		"-admin-user", cfg.AdminUser,
		"-admin-pass", cfg.AdminPass,
	}
	envOverrides := map[string]string{
		"LISTEN_ADDR":        cfg.ListenAddr,
		"DB_PATH":            cfg.DBPath,
		"ADMIN_USER":         cfg.AdminUser,
		"ADMIN_INITIAL_PASS": cfg.AdminPass,
	}
	if cfg.JWTSecret != "" {
		args = append(args, "-jwt-secret", cfg.JWTSecret)
		envOverrides["JWT_SECRET"] = cfg.JWTSecret
	}
	if cfg.TZ != "" {
		envOverrides["TZ"] = cfg.TZ
	}
	args = append(args, cfg.ExtraArgs...)

	logs := &safeBuffer{}
	cmd := exec.Command(bin, args...)
	cmd.Dir = env.RootDir
	cmd.Env = mergeEnv(os.Environ(), envOverrides, cfg.ExtraEnv)
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond

	if err := cmd.Start(); err != nil {
		env.T.Fatalf("StartPanel: cmd.Start failed: %v", err)
	}

	p := &PanelProcess{
		t:          env.T,
		ListenAddr: cfg.ListenAddr,
		DBPath:     cfg.DBPath,
		cmd:        cmd,
		logs:       logs,
		done:       make(chan error, 1),
	}
	go func() {
		err := cmd.Wait()
		p.mu.Lock()
		p.exited = true
		p.exitEr = err
		p.mu.Unlock()
		p.done <- err
		close(p.done)
	}()

	env.T.Cleanup(func() {
		if p.wasIntentionallyKilled() && p.cmd != nil && p.cmd.Process != nil && p.cmd.Process.Pid > 0 {
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		}
		stopErr := p.Stop()
		captured := p.Logs()
		if strings.Contains(captured, "WARNING: DATA RACE") {
			env.T.Errorf("Panel (%s) detected DATA RACE in logs:\n%s", p.ListenAddr, captured)
		}
		if stopErr != nil {
			var exitErr *exec.ExitError
			if errors.As(stopErr, &exitErr) && exitErr.ExitCode() == 66 {
				env.T.Errorf("Panel (%s) exited with -race status 66:\n%s", p.ListenAddr, captured)
			} else if !p.wasIntentionallyKilled() {
				env.T.Errorf("Panel (%s) non-graceful Stop(): %v\nLogs:\n%s", p.ListenAddr, stopErr, captured)
			}
		}
		if env.T.Failed() {
			env.T.Logf("Panel (%s) logs:\n%s", p.ListenAddr, captured)
		}
	})

	client := &http.Client{
		Timeout:   1 * time.Second,
		Transport: &http.Transport{DisableKeepAlives: true},
	}
	deadline := time.Now().Add(cfg.StartTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-p.done:
			env.T.Fatalf("StartPanel: panel exited early (%v)\nLogs:\n%s", err, p.Logs())
		default:
		}
		if probeHTTPReady(client, p.BaseURL()+"/healthz") || probeHTTPReady(client, p.BaseURL()+"/api/v1/public/status") {
			return p
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = p.Stop()
	env.T.Fatalf("StartPanel: panel at %s did not become ready within %s\nLogs:\n%s", p.ListenAddr, cfg.StartTimeout, p.Logs())
	return nil
}

// StartPanelExpectFail launches cmd/panel expecting it to exit non-zero before timeout.
func StartPanelExpectFail(env *TestEnv, cfg PanelConfig, timeout time.Duration) (int, string, error) {
	env.T.Helper()
	bin := BuildPanelBinary(env.T)
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = fmt.Sprintf("127.0.0.1:%d", AllocFreePort(env.T))
	}
	if cfg.AdminUser == "" {
		cfg.AdminUser = "admin"
	}
	if cfg.AdminPass == "" {
		cfg.AdminPass = "change_me_on_first_login"
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	args := []string{
		"-listen", cfg.ListenAddr,
		"-db", cfg.DBPath,
		"-admin-user", cfg.AdminUser,
		"-admin-pass", cfg.AdminPass,
	}
	envOverrides := map[string]string{
		"LISTEN_ADDR":        cfg.ListenAddr,
		"DB_PATH":            cfg.DBPath,
		"ADMIN_USER":         cfg.AdminUser,
		"ADMIN_INITIAL_PASS": cfg.AdminPass,
	}
	if cfg.JWTSecret != "" {
		args = append(args, "-jwt-secret", cfg.JWTSecret)
		envOverrides["JWT_SECRET"] = cfg.JWTSecret
	}
	args = append(args, cfg.ExtraArgs...)

	logs := &safeBuffer{}
	cmd := exec.Command(bin, args...)
	cmd.Dir = env.RootDir
	cmd.Env = mergeEnv(os.Environ(), envOverrides, cfg.ExtraEnv)
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond

	if err := cmd.Start(); err != nil {
		return -1, logs.String(), err
	}
	done := make(chan error, 1)
	go func() {
		done <- cmd.Wait()
	}()

	select {
	case err := <-done:
		exitCode := 0
		if err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				exitCode = exitErr.ExitCode()
			} else {
				exitCode = -1
			}
		}
		return exitCode, logs.String(), err
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
		<-done
		return -1, logs.String(), fmt.Errorf("panel did not exit within %s", timeout)
	}
}

func probeHTTPReady(client *http.Client, url string) bool {
	if client == nil {
		client = &http.Client{
			Timeout:   1 * time.Second,
			Transport: &http.Transport{DisableKeepAlives: true},
		}
	}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func probeTCPReady(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (p *PanelProcess) BaseURL() string {
	return "http://" + p.ListenAddr
}

func (p *PanelProcess) WSBaseURL() string {
	return "ws://" + p.ListenAddr
}

func (p *PanelProcess) Logs() string {
	if p == nil || p.logs == nil {
		return ""
	}
	return p.logs.String()
}

func (p *PanelProcess) isExited() (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.exited, p.exitEr
}

func (p *PanelProcess) wasIntentionallyKilled() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.intentionallyKilled
}

// Stop sends SIGTERM and waits up to 5s before falling back to process-group SIGKILL.
func (p *PanelProcess) Stop() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	p.mu.Lock()
	clients := append([]*PanelClient(nil), p.clients...)
	p.mu.Unlock()
	for _, c := range clients {
		c.Close()
	}
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
		dt.CloseIdleConnections()
	}
	if exited, err := p.isExited(); exited {
		return err
	}
	pid := p.cmd.Process.Pid
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	if err := p.WaitExit(5 * time.Second); err == nil || !errors.Is(err, errWaitTimeout) {
		return err
	}
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	} else {
		_ = p.cmd.Process.Kill()
	}
	if waitErr := p.WaitExit(5 * time.Second); waitErr != nil {
		return fmt.Errorf("panel did not exit gracefully on SIGTERM (killed pgid %d): %w", pid, waitErr)
	}
	return fmt.Errorf("panel did not exit gracefully on SIGTERM (killed pgid %d)", pid)
}

// Kill sends SIGKILL and waits for process termination.
func (p *PanelProcess) Kill() error {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil
	}
	p.mu.Lock()
	p.intentionallyKilled = true
	p.mu.Unlock()
	if exited, err := p.isExited(); exited {
		if errors.Is(err, exec.ErrWaitDelay) {
			return nil
		}
		return err
	}
	_ = p.cmd.Process.Kill()
	err := p.WaitExit(5 * time.Second)
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

var errWaitTimeout = errors.New("wait timeout")

// WaitExit waits for the subprocess to exit within timeout.
func (p *PanelProcess) WaitExit(timeout time.Duration) error {
	if exited, err := p.isExited(); exited {
		return err
	}
	select {
	case err, ok := <-p.done:
		if !ok {
			_, err = p.isExited()
		}
		return err
	case <-time.After(timeout):
		return errWaitTimeout
	}
}

func (p *PanelProcess) NewClient() *PanelClient {
	c := NewPanelClient(p.BaseURL())
	if p != nil {
		p.mu.Lock()
		p.clients = append(p.clients, c)
		p.mu.Unlock()
		if p.t != nil {
			p.t.Cleanup(c.Close)
		}
	}
	return c
}

// AgentConfig configures a black-box cmd/agent subprocess.
type AgentConfig struct {
	PanelURL       string
	NodeToken      string
	DataDir        string
	Iface          string
	SnellBin       string
	ShadowTLSBin   string
	SingBoxBin     string
	LocalDNSPort   int
	StatsPort      int
	TLSSkipVerify  bool
	ProcNetDevPath string
	ExtraEnv       []string
	ExtraArgs      []string
	StartTimeout   time.Duration
}

// AgentProcess manages a running cmd/agent subprocess.
type AgentProcess struct {
	t            *testing.T
	DataDir      string
	LocalDNSPort int
	StatsPort    int
	cmd          *exec.Cmd
	logs         *safeBuffer
	done         chan error

	mu                  sync.Mutex
	exited              bool
	exitEr              error
	intentionallyKilled bool
}

// StartAgent builds and launches cmd/agent with isolated data dir and ports.
func StartAgent(env *TestEnv, cfg AgentConfig) *AgentProcess {
	env.T.Helper()
	bin := BuildAgentBinary(env.T)

	if cfg.LocalDNSPort == 0 {
		cfg.LocalDNSPort = AllocFreeDualPort(env.T)
	}
	if cfg.StatsPort == 0 {
		cfg.StatsPort = AllocFreePort(env.T)
	}
	if cfg.DataDir == "" {
		cfg.DataDir = env.T.TempDir()
	}
	if cfg.StartTimeout <= 0 {
		cfg.StartTimeout = 15 * time.Second
	}

	args := []string{
		"-panel-url", cfg.PanelURL,
		"-token", cfg.NodeToken,
		"-data-dir", cfg.DataDir,
		"-local-dns-port", strconv.Itoa(cfg.LocalDNSPort),
		"-stats-port", strconv.Itoa(cfg.StatsPort),
	}
	envOverrides := map[string]string{
		"PANEL_URL":      cfg.PanelURL,
		"NODE_TOKEN":     cfg.NodeToken,
		"DATA_DIR":       cfg.DataDir,
		"LOCAL_DNS_PORT": strconv.Itoa(cfg.LocalDNSPort),
		"STATS_PORT":     strconv.Itoa(cfg.StatsPort),
	}
	if cfg.Iface != "" {
		args = append(args, "-iface", cfg.Iface)
		envOverrides["IFACE"] = cfg.Iface
	}
	if cfg.SnellBin != "" {
		args = append(args, "-snell-bin", cfg.SnellBin)
		envOverrides["SNELL_BIN"] = cfg.SnellBin
	}
	if cfg.ShadowTLSBin != "" {
		args = append(args, "-shadow-tls-bin", cfg.ShadowTLSBin)
		envOverrides["SHADOW_TLS_BIN"] = cfg.ShadowTLSBin
	}
	if cfg.SingBoxBin != "" {
		args = append(args, "-sing-box-bin", cfg.SingBoxBin)
		envOverrides["SING_BOX_BIN"] = cfg.SingBoxBin
	}
	if cfg.TLSSkipVerify {
		args = append(args, "-tls-skip-verify")
		envOverrides["TLS_SKIP_VERIFY"] = "true"
	}
	if cfg.ProcNetDevPath != "" {
		envOverrides["PROC_NET_DEV_PATH"] = cfg.ProcNetDevPath
	}
	args = append(args, cfg.ExtraArgs...)

	logs := &safeBuffer{}
	cmd := exec.Command(bin, args...)
	cmd.Dir = env.RootDir
	cmd.Env = mergeEnv(os.Environ(), envOverrides, cfg.ExtraEnv)
	cmd.Stdout = logs
	cmd.Stderr = logs
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = 250 * time.Millisecond

	if err := cmd.Start(); err != nil {
		env.T.Fatalf("StartAgent: cmd.Start failed: %v", err)
	}

	a := &AgentProcess{
		t:            env.T,
		DataDir:      cfg.DataDir,
		LocalDNSPort: cfg.LocalDNSPort,
		StatsPort:    cfg.StatsPort,
		cmd:          cmd,
		logs:         logs,
		done:         make(chan error, 1),
	}
	go func() {
		err := cmd.Wait()
		a.mu.Lock()
		a.exited = true
		a.exitEr = err
		a.mu.Unlock()
		a.done <- err
		close(a.done)
	}()

	env.T.Cleanup(func() {
		if a.wasIntentionallyKilled() && a.cmd != nil && a.cmd.Process != nil && a.cmd.Process.Pid > 0 {
			_ = syscall.Kill(-a.cmd.Process.Pid, syscall.SIGKILL)
		}
		stopErr := a.Stop()
		captured := a.Logs()
		if strings.Contains(captured, "WARNING: DATA RACE") {
			env.T.Errorf("Agent (%s) detected DATA RACE in logs:\n%s", a.DataDir, captured)
		}
		if stopErr != nil {
			var exitErr *exec.ExitError
			if errors.As(stopErr, &exitErr) && exitErr.ExitCode() == 66 {
				env.T.Errorf("Agent (%s) exited with -race status 66:\n%s", a.DataDir, captured)
			} else if !a.wasIntentionallyKilled() {
				env.T.Errorf("Agent (%s) non-graceful Stop(): %v\nLogs:\n%s", a.DataDir, stopErr, captured)
			}
		}
		if env.T.Failed() {
			env.T.Logf("Agent (%s) logs:\n%s", a.DataDir, captured)
		}
	})

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", a.LocalDNSPort)
	configsDir := filepath.Join(a.DataDir, "configs")
	tmpDir := filepath.Join(a.DataDir, "tmp")

	deadline := time.Now().Add(cfg.StartTimeout)
	for time.Now().Before(deadline) {
		select {
		case err := <-a.done:
			env.T.Fatalf("StartAgent: agent exited early (%v)\nLogs:\n%s", err, a.Logs())
		default:
		}
		logsNow := a.Logs()
		if strings.Contains(logsNow, "node agent initialized") && (probeTCPReady(dnsAddr) || strings.Contains(logsNow, "reconciled local_dns_port")) {
			if _, err1 := os.Stat(configsDir); err1 == nil {
				if _, err2 := os.Stat(tmpDir); err2 == nil {
					// Allow sup.Start(ctx) (immediately following supervisor.New) to pass its ctx.Err() check.
					time.Sleep(50 * time.Millisecond)
					select {
					case err := <-a.done:
						env.T.Fatalf("StartAgent: agent exited early (%v)\nLogs:\n%s", err, a.Logs())
					default:
					}
					return a
				}
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = a.Stop()
	env.T.Fatalf("StartAgent: agent (%s) did not become ready within %s\nLogs:\n%s", a.DataDir, cfg.StartTimeout, a.Logs())
	return nil
}

func (a *AgentProcess) Logs() string {
	if a == nil || a.logs == nil {
		return ""
	}
	return a.logs.String()
}

func (a *AgentProcess) isExited() (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.exited, a.exitEr
}

func (a *AgentProcess) wasIntentionallyKilled() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.intentionallyKilled
}

func (a *AgentProcess) Stop() error {
	if a == nil || a.cmd == nil || a.cmd.Process == nil {
		return nil
	}
	if exited, err := a.isExited(); exited {
		return err
	}
	pid := a.cmd.Process.Pid
	_ = a.cmd.Process.Signal(syscall.SIGTERM)
	if err := a.WaitExit(5 * time.Second); err == nil || !errors.Is(err, errWaitTimeout) {
		return err
	}
	if pid > 0 {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	} else {
		_ = a.cmd.Process.Kill()
	}
	if waitErr := a.WaitExit(5 * time.Second); waitErr != nil {
		return fmt.Errorf("agent did not exit gracefully on SIGTERM (killed pgid %d): %w", pid, waitErr)
	}
	return fmt.Errorf("agent did not exit gracefully on SIGTERM (killed pgid %d)", pid)
}

func (a *AgentProcess) Kill() error {
	if a == nil || a.cmd == nil || a.cmd.Process == nil {
		return nil
	}
	a.mu.Lock()
	a.intentionallyKilled = true
	a.mu.Unlock()
	if exited, err := a.isExited(); exited {
		if errors.Is(err, exec.ErrWaitDelay) {
			return nil
		}
		return err
	}
	_ = a.cmd.Process.Kill()
	err := a.WaitExit(5 * time.Second)
	if errors.Is(err, exec.ErrWaitDelay) {
		return nil
	}
	return err
}

func (a *AgentProcess) WaitExit(timeout time.Duration) error {
	if exited, err := a.isExited(); exited {
		return err
	}
	select {
	case err, ok := <-a.done:
		if !ok {
			_, err = a.isExited()
		}
		return err
	case <-time.After(timeout):
		return errWaitTimeout
	}
}

// --- Opaque-box Wire & REST DTOs (defined locally without internal/* imports) ---

type WSEnvelope struct {
	Type    string          `json:"type"`
	ReqID   string          `json:"req_id"`
	Payload json.RawMessage `json:"payload"`
}

type AgentVersionsDTO struct {
	SingBox     string `json:"sing_box"`
	SnellServer string `json:"snell_server"`
	ShadowTLS   string `json:"shadow_tls"`
}

type AgentHelloPayload struct {
	OS             string           `json:"os"`
	Arch           string           `json:"arch"`
	CPUCores       int              `json:"cpu_cores"`
	TotalRAMBytes  uint64           `json:"total_ram_bytes"`
	PublicIPv4     string           `json:"public_ipv4"`
	PublicIPv6     string           `json:"public_ipv6"`
	Versions       AgentVersionsDTO `json:"versions"`
	ConfigRevision int64            `json:"config_revision"`
}

type UserTrafficDeltaDTO struct {
	Username  string `json:"username"`
	UserID    int64  `json:"user_id"`
	UpBytes   uint64 `json:"up_bytes"`
	DownBytes uint64 `json:"down_bytes"`
}

type AgentHealthDTO struct {
	Snell     bool `json:"snell"`
	ShadowTLS bool `json:"shadow_tls"`
	SingBox   bool `json:"sing_box"`
}

type AgentMetricsPayload struct {
	TS              int64                 `json:"ts"`
	CPUPercent      float64               `json:"cpu_percent"`
	MemUsedBytes    uint64                `json:"mem_used_bytes"`
	MemTotalBytes   uint64                `json:"mem_total_bytes"`
	DiskUsedPercent float64               `json:"disk_used_percent"`
	UptimeSeconds   uint64                `json:"uptime_seconds"`
	RxBPS           uint64                `json:"rx_bps"`
	TxBPS           uint64                `json:"tx_bps"`
	NicRxDelta      uint64                `json:"nic_rx_delta"`
	NicTxDelta      uint64                `json:"nic_tx_delta"`
	UserDeltas      []UserTrafficDeltaDTO `json:"user_deltas"`
	Health          AgentHealthDTO        `json:"health"`
}

type AgentEventPayload struct {
	Event          string `json:"event"`
	ConfigRevision int64  `json:"config_revision"`
	Kernel         string `json:"kernel"`
	Status         string `json:"status"`
	Version        string `json:"version"`
	Message        string `json:"message"`
	Detail         string `json:"detail"`
}

type SnellConfigDTO struct {
	Enabled         bool   `json:"enabled"`
	Version         string `json:"version"`
	PublicPort      int    `json:"public_port"`
	InnerPort       int    `json:"inner_port"`
	PSK             string `json:"psk"`
	Obfs            string `json:"obfs"`
	TFO             bool   `json:"tfo"`
	DNSIPPreference string `json:"dns_ip_preference"`
	STLSPassword    string `json:"stls_password"`
	STLSSNI         string `json:"stls_sni"`
}

type SSUserEntryDTO struct {
	UserID       int64  `json:"user_id"`
	Username     string `json:"username"`
	UPSK         string `json:"upsk"`
	STLSPassword string `json:"stls_password"`
}

type SSConfigDTO struct {
	Enabled bool             `json:"enabled"`
	TCPPort int              `json:"tcp_port"`
	UDPPort int              `json:"udp_port"`
	Cipher  string           `json:"cipher"`
	IPSK    string           `json:"ipsk"`
	STLSSNI string           `json:"stls_sni"`
	Users   []SSUserEntryDTO `json:"users"`
}

type DNSConfigDTO struct {
	UnlockEnabled bool     `json:"unlock_enabled"`
	UnlockServer  string   `json:"unlock_server"`
	Rules         []string `json:"rules"`
	UpstreamDNS   string   `json:"upstream_dns"`
	LocalPort     int      `json:"local_port"`
}

type ServerConfigSyncPayload struct {
	ConfigRevision int64          `json:"config_revision"`
	Snell          SnellConfigDTO `json:"snell"`
	SS             SSConfigDTO    `json:"ss"`
	DNS            DNSConfigDTO   `json:"dns"`
}

type ServerKernelUpdatePayload struct {
	Kernel      string `json:"kernel"`
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
}

type ServerServiceCtlPayload struct {
	Action string `json:"action"`
}

type PublicNodeViewDTO struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	RegionTag         string  `json:"region_tag"`
	SortOrder         int     `json:"sort_order"`
	Status            string  `json:"status"`
	PausedReason      string  `json:"paused_reason"`
	BillingResetDay   int     `json:"billing_reset_day"`
	CPUPercent        float64 `json:"cpu_percent"`
	MemUsedBytes      uint64  `json:"mem_used_bytes"`
	MemTotalBytes     uint64  `json:"mem_total_bytes"`
	UptimeSeconds     uint64  `json:"uptime_seconds"`
	RxBPS             uint64  `json:"rx_bps"`
	TxBPS             uint64  `json:"tx_bps"`
	TrafficUsedBytes  int64   `json:"traffic_used_bytes"`
	TrafficLimitBytes int64   `json:"traffic_limit_bytes"`
	TrafficPercent    float64 `json:"traffic_percent"`
	PercentageOnly    bool    `json:"percentage_only"`
	CoreAHealthy      bool    `json:"core_a_healthy"`
	CoreBHealthy      bool    `json:"core_b_healthy"`
}

type PublicStatusSnapshotDTO struct {
	SiteTitle      string              `json:"site_title"`
	Announcement   string              `json:"announcement"`
	PercentageOnly bool                `json:"percentage_only"`
	Nodes          []PublicNodeViewDTO `json:"nodes"`
}

type LoginResponseDTO struct {
	Token    string `json:"token"`
	Username string `json:"username"`
}

type AuthMeResponseDTO struct {
	Username string `json:"username"`
}

type NodeDTO struct {
	ID                    int64           `json:"id"`
	Name                  string          `json:"name"`
	RegionTag             string          `json:"region_tag"`
	NodeToken             string          `json:"node_token,omitempty"`
	Token                 string          `json:"token,omitempty"`
	PublicIP              string          `json:"public_ip"`
	CustomEntryHost       string          `json:"custom_entry_host"`
	CustomEntryPort       int             `json:"custom_entry_port"`
	SortOrder             int             `json:"sort_order"`
	Enabled               bool            `json:"enabled"`
	Status                string          `json:"status"`
	SnellConfig           *SnellConfigDTO `json:"snell_config,omitempty"`
	SSConfig              *SSConfigDTO    `json:"ss_config,omitempty"`
	DNSUnlockEnabled      bool            `json:"dns_unlock_enabled"`
	DNSUnlockServer       string          `json:"dns_unlock_server"`
	DNSRuleGroupID        *int64          `json:"dns_rule_group_id"`
	ExtraDNSRules         []string        `json:"dns_extra_rules,omitempty"`
	TrafficLimitBytes     int64           `json:"traffic_limit_bytes"`
	TrafficThresholdBytes int64           `json:"traffic_threshold_bytes"`
	TrafficCountMode      string          `json:"traffic_count_mode"`
	ThresholdAction       string          `json:"threshold_action"`
	BillingResetDay       int             `json:"billing_reset_day"`
	CycleRxBytes          int64           `json:"cycle_rx_bytes"`
	CycleTxBytes          int64           `json:"cycle_tx_bytes"`
	IsTrafficPaused       bool            `json:"is_traffic_paused"`
	ConfigRevision        int64           `json:"config_revision"`
}

// EffectiveToken returns whichever plaintext onboarding token field the server populated.
func (n NodeDTO) EffectiveToken() string {
	if n.NodeToken != "" {
		return n.NodeToken
	}
	return n.Token
}

type CreateNodeReq struct {
	Name                  string          `json:"name"`
	RegionTag             string          `json:"region_tag,omitempty"`
	PublicIP              string          `json:"public_ip,omitempty"`
	CustomEntryHost       string          `json:"custom_entry_host,omitempty"`
	CustomEntryPort       int             `json:"custom_entry_port,omitempty"`
	SortOrder             int             `json:"sort_order,omitempty"`
	Enabled               *bool           `json:"enabled,omitempty"`
	SnellConfig           *SnellConfigDTO `json:"snell_config,omitempty"`
	SSConfig              *SSConfigDTO    `json:"ss_config,omitempty"`
	DNSUnlockEnabled      bool            `json:"dns_unlock_enabled,omitempty"`
	DNSUnlockServer       string          `json:"dns_unlock_server,omitempty"`
	DNSRuleGroupID        *int64          `json:"dns_rule_group_id,omitempty"`
	ExtraDNSRules         []string        `json:"dns_extra_rules,omitempty"`
	TrafficLimitBytes     int64           `json:"traffic_limit_bytes,omitempty"`
	TrafficThresholdBytes int64           `json:"traffic_threshold_bytes,omitempty"`
	TrafficCountMode      string          `json:"traffic_count_mode,omitempty"`
	ThresholdAction       string          `json:"threshold_action,omitempty"`
	BillingResetDay       int             `json:"billing_reset_day,omitempty"`
}

type UserDTO struct {
	ID                int64   `json:"id"`
	Username          string  `json:"username"`
	Enabled           bool    `json:"enabled"`
	SubToken          string  `json:"sub_token"`
	SSUPSK16          string  `json:"ss_upsk_16"`
	SSUPSK32          string  `json:"ss_upsk_32"`
	STLSPassword      string  `json:"stls_password"`
	TrafficQuotaBytes int64   `json:"traffic_quota_bytes"`
	BillingResetDay   int     `json:"billing_reset_day"`
	UsedUpBytes       int64   `json:"used_up_bytes"`
	UsedDownBytes     int64   `json:"used_down_bytes"`
	ExpireAt          *string `json:"expire_at"`
	NodeIDs           []int64 `json:"node_ids,omitempty"`
}

type CreateUserReq struct {
	Username          string  `json:"username"`
	Enabled           *bool   `json:"enabled,omitempty"`
	TrafficQuotaBytes int64   `json:"traffic_quota_bytes,omitempty"`
	BillingResetDay   int     `json:"billing_reset_day,omitempty"`
	ExpireAt          *string `json:"expire_at,omitempty"`
	NodeIDs           []int64 `json:"node_ids,omitempty"`
}

type DNSRuleGroupDTO struct {
	ID    int64    `json:"id"`
	Name  string   `json:"name"`
	Rules []string `json:"rules"`
}

type SubTemplateDTO struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	ClientType string `json:"client_type"`
	Content    string `json:"content"`
	IsDefault  bool   `json:"is_default"`
}

type WebhookChannelDTO struct {
	ID               int64    `json:"id"`
	Name             string   `json:"name"`
	Provider         string   `json:"provider"`
	URL              string   `json:"url"`
	Secret           string   `json:"secret"`
	SubscribedEvents []string `json:"subscribed_events"`
	Enabled          bool     `json:"enabled"`
}

type DailyTrafficDTO struct {
	Date    string `json:"date"`
	NodeID  int64  `json:"node_id"`
	UserID  int64  `json:"user_id"`
	RxBytes int64  `json:"rx_bytes"`
	TxBytes int64  `json:"tx_bytes"`
}

type SystemSettingsDTO struct {
	SiteTitle          string `json:"site_title"`
	Announcement       string `json:"announcement"`
	PercentageOnly     bool   `json:"percentage_only"`
	AdminSubToken      string `json:"admin_sub_token"`
	AlertCooldownMins  int    `json:"alert_cooldown_minutes"`
	AlertCooldownShort int    `json:"alert_cooldown_mins,omitempty"`
}

// --- Typed Panel HTTP & WS Client ---

type PanelClient struct {
	BaseURL    string
	WSBaseURL  string
	HTTPClient *http.Client
}

func NewPanelClient(baseURL string) *PanelClient {
	wsURL := strings.Replace(baseURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	var tr http.RoundTripper
	if dt, ok := http.DefaultTransport.(*http.Transport); ok && dt != nil {
		tr = dt.Clone()
	} else {
		tr = &http.Transport{}
	}
	return &PanelClient{
		BaseURL:   strings.TrimRight(baseURL, "/"),
		WSBaseURL: strings.TrimRight(wsURL, "/"),
		HTTPClient: &http.Client{
			Timeout:   15 * time.Second,
			Transport: tr,
		},
	}
}

func (c *PanelClient) Close() {
	if c == nil || c.HTTPClient == nil {
		return
	}
	c.HTTPClient.CloseIdleConnections()
}

func (c *PanelClient) DoRaw(ctx context.Context, method, path string, headers map[string]string, body []byte) (int, http.Header, []byte, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.BaseURL+path, reader)
	if err != nil {
		return 0, nil, nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, resp.Header, nil, err
	}
	return resp.StatusCode, resp.Header, raw, nil
}

func (c *PanelClient) DoJSON(ctx context.Context, method, path, bearerToken string, reqBody any, respBody any) (int, []byte, error) {
	var bodyBytes []byte
	headers := map[string]string{}
	if reqBody != nil {
		var err error
		bodyBytes, err = json.Marshal(reqBody)
		if err != nil {
			return 0, nil, err
		}
		headers["Content-Type"] = "application/json"
	}
	if bearerToken != "" {
		headers["Authorization"] = "Bearer " + bearerToken
	}
	status, _, raw, err := c.DoRaw(ctx, method, path, headers, bodyBytes)
	if err != nil {
		return status, raw, err
	}
	if respBody != nil && status >= 200 && status < 300 && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, respBody); err != nil {
			return status, raw, fmt.Errorf("decode %s %s response: %w (body=%s)", method, path, err, string(raw))
		}
	}
	return status, raw, nil
}

func (c *PanelClient) Login(username, password string) (int, LoginResponseDTO, []byte, error) {
	var out LoginResponseDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, "/api/v1/auth/login", "", map[string]string{
		"username": username,
		"password": password,
	}, &out)
	return status, out, raw, err
}

func (c *PanelClient) MustLogin(t *testing.T, username, password string) string {
	t.Helper()
	status, out, raw, err := c.Login(username, password)
	if err != nil || status != http.StatusOK || out.Token == "" {
		t.Fatalf("MustLogin(%s) failed: status=%d err=%v body=%s", username, status, err, string(raw))
	}
	return out.Token
}

func (c *PanelClient) GetMe(token string) (int, AuthMeResponseDTO, []byte, error) {
	var out AuthMeResponseDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/auth/me", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) UpdatePassword(token, oldPass, newPass string) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPut, "/api/v1/auth/password", token, map[string]string{
		"old_password": oldPass,
		"new_password": newPass,
	}, nil)
}

func (c *PanelClient) GetPublicStatus() (int, PublicStatusSnapshotDTO, []byte, error) {
	var out PublicStatusSnapshotDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/public/status", "", nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) DialPublicWS(ctx context.Context) (*websocket.Conn, int, error) {
	conn, resp, err := websocket.Dial(ctx, c.WSBaseURL+"/api/v1/public/ws", &websocket.DialOptions{
		HTTPClient: c.HTTPClient,
	})
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return conn, status, err
}

func (c *PanelClient) DialAgentWS(ctx context.Context, nodeToken string) (*websocket.Conn, int, error) {
	headers := http.Header{}
	if nodeToken != "" {
		headers.Set("Authorization", "Bearer "+nodeToken)
	}
	conn, resp, err := websocket.Dial(ctx, c.WSBaseURL+"/api/v1/agent/ws", &websocket.DialOptions{
		HTTPClient: c.HTTPClient,
		HTTPHeader: headers,
	})
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return conn, status, err
}

func (c *PanelClient) DialAgentWSWithHeaders(ctx context.Context, headers http.Header) (*websocket.Conn, int, error) {
	conn, resp, err := websocket.Dial(ctx, c.WSBaseURL+"/api/v1/agent/ws", &websocket.DialOptions{
		HTTPClient: c.HTTPClient,
		HTTPHeader: headers,
	})
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return conn, status, err
}

func SendWSEnvelope(ctx context.Context, conn *websocket.Conn, msgType, reqID string, payload any) error {
	var raw json.RawMessage
	if payload == nil {
		raw = json.RawMessage("{}")
	} else {
		b, err := json.Marshal(payload)
		if err != nil {
			return err
		}
		raw = b
	}
	env := WSEnvelope{
		Type:    msgType,
		ReqID:   reqID,
		Payload: raw,
	}
	b, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return conn.Write(ctx, websocket.MessageText, b)
}

func ReadWSEnvelope(ctx context.Context, conn *websocket.Conn, timeout time.Duration) (WSEnvelope, []byte, error) {
	rctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	_, data, err := conn.Read(rctx)
	if err != nil {
		return WSEnvelope{}, nil, err
	}
	var env WSEnvelope
	if err := json.Unmarshal(data, &env); err != nil {
		return WSEnvelope{}, data, err
	}
	return env, data, nil
}

// --- Admin Nodes ---

func (c *PanelClient) CreateNode(token string, req CreateNodeReq) (int, NodeDTO, []byte, error) {
	var out NodeDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/nodes", token, req, &out)
	return status, out, raw, err
}

func (c *PanelClient) ListNodes(token string) (int, []NodeDTO, []byte, error) {
	var out []NodeDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/nodes", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) GetNode(token string, id int64) (int, NodeDTO, []byte, error) {
	var out NodeDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/nodes/%d", id), token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) UpdateNode(token string, id int64, body any) (int, NodeDTO, []byte, error) {
	var out NodeDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPut, fmt.Sprintf("/api/v1/admin/nodes/%d", id), token, body, &out)
	return status, out, raw, err
}

func (c *PanelClient) DeleteNode(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodDelete, fmt.Sprintf("/api/v1/admin/nodes/%d", id), token, nil, nil)
}

func (c *PanelClient) ResetNodeTraffic(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/reset-traffic", id), token, nil, nil)
}

func (c *PanelClient) CalibrateNodeTraffic(token string, id int64, rxBytes, txBytes int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/calibrate-traffic", id), token, map[string]int64{
		"cycle_rx_bytes": rxBytes,
		"cycle_tx_bytes": txBytes,
	}, nil)
}

func (c *PanelClient) ServiceCtlNode(token string, id int64, action string) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/service-ctl", id), token, map[string]string{
		"action": action,
	}, nil)
}

func (c *PanelClient) SyncNode(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/nodes/%d/sync", id), token, nil, nil)
}

func (c *PanelClient) GetInstallCmd(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/nodes/%d/install-cmd", id), token, nil, nil)
}

func (c *PanelClient) ReorderNodes(token string, ids []int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPut, "/api/v1/admin/nodes/reorder", token, map[string][]int64{
		"ids": ids,
	}, nil)
}

// --- Admin Users ---

func (c *PanelClient) CreateUser(token string, req CreateUserReq) (int, UserDTO, []byte, error) {
	var out UserDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/users", token, req, &out)
	return status, out, raw, err
}

func (c *PanelClient) ListUsers(token string) (int, []UserDTO, []byte, error) {
	var out []UserDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/users", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) GetUser(token string, id int64) (int, UserDTO, []byte, error) {
	var out UserDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, fmt.Sprintf("/api/v1/admin/users/%d", id), token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) UpdateUser(token string, id int64, body any) (int, UserDTO, []byte, error) {
	var out UserDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d", id), token, body, &out)
	return status, out, raw, err
}

func (c *PanelClient) DeleteUser(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodDelete, fmt.Sprintf("/api/v1/admin/users/%d", id), token, nil, nil)
}

func (c *PanelClient) ResetUserKeys(token string, id int64, body any) (int, UserDTO, []byte, error) {
	var out UserDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-keys", id), token, body, &out)
	return status, out, raw, err
}

func (c *PanelClient) ResetUserTraffic(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/users/%d/reset-traffic", id), token, nil, nil)
}

func (c *PanelClient) SetUserNodes(token string, id int64, nodeIDs []int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPut, fmt.Sprintf("/api/v1/admin/users/%d/nodes", id), token, map[string][]int64{
		"node_ids": nodeIDs,
	}, nil)
}

// --- Admin DNS Rules, Templates, Webhooks, Kernels, Traffic, Settings ---

func (c *PanelClient) CreateDNSRuleGroup(token string, name string, rules []string) (int, DNSRuleGroupDTO, []byte, error) {
	var out DNSRuleGroupDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/dns-rules", token, map[string]any{
		"name":  name,
		"rules": rules,
	}, &out)
	return status, out, raw, err
}

func (c *PanelClient) ListDNSRuleGroups(token string) (int, []DNSRuleGroupDTO, []byte, error) {
	var out []DNSRuleGroupDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/dns-rules", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) CreateTemplate(token string, req SubTemplateDTO) (int, SubTemplateDTO, []byte, error) {
	var out SubTemplateDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/templates", token, req, &out)
	return status, out, raw, err
}

func (c *PanelClient) ListTemplates(token string) (int, []SubTemplateDTO, []byte, error) {
	var out []SubTemplateDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/templates", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) CreateWebhook(token string, req WebhookChannelDTO) (int, WebhookChannelDTO, []byte, error) {
	var out WebhookChannelDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/webhooks", token, req, &out)
	return status, out, raw, err
}

func (c *PanelClient) ListWebhooks(token string) (int, []WebhookChannelDTO, []byte, error) {
	var out []WebhookChannelDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/webhooks", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) TestWebhook(token string, id int64) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, fmt.Sprintf("/api/v1/admin/webhooks/%d/test", id), token, nil, nil)
}

func (c *PanelClient) ListDailyTraffic(token string, query string) (int, []DailyTrafficDTO, []byte, error) {
	var out []DailyTrafficDTO
	path := "/api/v1/admin/traffic/daily"
	if query != "" {
		path += "?" + strings.TrimPrefix(query, "?")
	}
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, path, token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) GetSettings(token string) (int, SystemSettingsDTO, []byte, error) {
	var out SystemSettingsDTO
	status, raw, err := c.DoJSON(context.Background(), http.MethodGet, "/api/v1/admin/settings", token, nil, &out)
	return status, out, raw, err
}

func (c *PanelClient) UpdateSettings(token string, req any) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPut, "/api/v1/admin/settings", token, req, nil)
}

func (c *PanelClient) TriggerKernelUpdate(token string, nodeIDs []int64, kernel, version, downloadURL, sha256 string) (int, []byte, error) {
	return c.DoJSON(context.Background(), http.MethodPost, "/api/v1/admin/kernels/update", token, map[string]any{
		"node_ids":     nodeIDs,
		"kernel":       kernel,
		"version":      version,
		"download_url": downloadURL,
		"sha256":       sha256,
	}, nil)
}

// --- Subscriptions ---

func (c *PanelClient) GetAdminSub(adminSubToken, query string) (int, http.Header, string, error) {
	path := "/s/admin/" + adminSubToken
	if query != "" {
		path += "?" + strings.TrimPrefix(query, "?")
	}
	status, hdr, raw, err := c.DoRaw(context.Background(), http.MethodGet, path, nil, nil)
	return status, hdr, string(raw), err
}

func (c *PanelClient) GetUserSub(userSubToken, query, userAgent string) (int, http.Header, string, error) {
	path := "/s/u/" + userSubToken
	if query != "" {
		path += "?" + strings.TrimPrefix(query, "?")
	}
	headers := map[string]string{}
	if userAgent != "" {
		headers["User-Agent"] = userAgent
	}
	status, hdr, raw, err := c.DoRaw(context.Background(), http.MethodGet, path, headers, nil)
	return status, hdr, string(raw), err
}

// --- Harness Self-Tests ---

func TestHarness_PortAllocators(t *testing.T) {
	tcpPort := AllocFreePort(t)
	if tcpPort <= 0 || tcpPort > 65535 {
		t.Fatalf("invalid TCP port: %d", tcpPort)
	}
	wln, err := net.Listen("tcp", fmt.Sprintf(":%d", tcpPort))
	if err != nil {
		t.Fatalf("failed to bind allocated wildcard TCP port %d: %v", tcpPort, err)
	}
	_ = wln.Close()
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", tcpPort))
	if err != nil {
		t.Fatalf("failed to bind allocated TCP port %d: %v", tcpPort, err)
	}
	_ = ln.Close()

	udpPort := AllocFreeUDPPort(t)
	if udpPort <= 0 || udpPort > 65535 {
		t.Fatalf("invalid UDP port: %d", udpPort)
	}
	if udpPort == tcpPort {
		t.Fatalf("expected monotonic allocator to avoid reusing port %d back-to-back", tcpPort)
	}
	wpc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", udpPort))
	if err != nil {
		t.Fatalf("failed to bind allocated wildcard UDP port %d: %v", udpPort, err)
	}
	_ = wpc.Close()
	pc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", udpPort))
	if err != nil {
		t.Fatalf("failed to bind allocated UDP port %d: %v", udpPort, err)
	}
	_ = pc.Close()

	dualPort := AllocFreeDualPort(t)
	if dualPort <= 0 || dualPort > 65535 {
		t.Fatalf("invalid dual port: %d", dualPort)
	}
	if dualPort == tcpPort || dualPort == udpPort {
		t.Fatalf("expected monotonic allocator to return distinct dual port, got %d (tcp=%d udp=%d)", dualPort, tcpPort, udpPort)
	}
	wdln, err := net.Listen("tcp", fmt.Sprintf(":%d", dualPort))
	if err != nil {
		t.Fatalf("failed to bind dual wildcard TCP port %d: %v", dualPort, err)
	}
	wdpc, err := net.ListenPacket("udp", fmt.Sprintf(":%d", dualPort))
	if err != nil {
		_ = wdln.Close()
		t.Fatalf("failed to bind dual wildcard UDP port %d: %v", dualPort, err)
	}
	_ = wdpc.Close()
	_ = wdln.Close()

	dln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", dualPort))
	if err != nil {
		t.Fatalf("failed to bind dual TCP port %d: %v", dualPort, err)
	}
	defer dln.Close()
	dpc, err := net.ListenPacket("udp", fmt.Sprintf("127.0.0.1:%d", dualPort))
	if err != nil {
		t.Fatalf("failed to bind dual UDP port %d: %v", dualPort, err)
	}
	defer dpc.Close()
}

func TestHarness_ProcessLifecycleAndSetpgid(t *testing.T) {
	env := NewTestEnv(t)

	// 1. StartPanel + Setpgid + graceful Stop()
	p1 := StartPanel(env, PanelConfig{JWTSecret: "harness-lifecycle-secret-32-bytes!!"})
	pgid1, err := syscall.Getpgid(p1.cmd.Process.Pid)
	if err != nil || pgid1 != p1.cmd.Process.Pid {
		t.Fatalf("expected panel pgid == pid (%d), got pgid=%d err=%v", p1.cmd.Process.Pid, pgid1, err)
	}
	if err := p1.Stop(); err != nil {
		t.Fatalf("panel graceful Stop() failed: %v", err)
	}

	// 2. StartPanel + intentional Kill() should not cause t.Cleanup failure
	p2 := StartPanel(env, PanelConfig{JWTSecret: "harness-lifecycle-secret-32-bytes!!"})
	_ = p2.Kill()

	// 3. StartAgent + Setpgid + immediate graceful Stop() (no manual log polling)
	ag := StartAgent(env, AgentConfig{
		PanelURL:  p1.WSBaseURL(),
		NodeToken: "nd_live_harness_lifecycle_test",
	})
	agPgid, err := syscall.Getpgid(ag.cmd.Process.Pid)
	if err != nil || agPgid != ag.cmd.Process.Pid {
		t.Fatalf("expected agent pgid == pid (%d), got pgid=%d err=%v", ag.cmd.Process.Pid, agPgid, err)
	}
	if err := ag.Stop(); err != nil {
		t.Fatalf("agent graceful Stop() failed: %v", err)
	}

	// 4. StartAgent + immediate return (t.Cleanup calls Stop() with zero manual sleep/poll)
	t.Run("StartAgent_ImmediateReturn_CleanupStop", func(t *testing.T) {
		subEnv := NewTestEnv(t)
		_ = StartAgent(subEnv, AgentConfig{
			PanelURL:  p1.WSBaseURL(),
			NodeToken: "nd_live_harness_immediate_cleanup",
		})
	})

	// 5. StartAgent + intentional Kill() should reap pgid cleanly without t.Cleanup failure
	t.Run("StartAgent_Kill_CleanupReap", func(t *testing.T) {
		subEnv := NewTestEnv(t)
		ag2 := StartAgent(subEnv, AgentConfig{
			PanelURL:  p1.WSBaseURL(),
			NodeToken: "nd_live_harness_kill_cleanup",
		})
		if err := ag2.Kill(); errors.Is(err, errWaitTimeout) {
			t.Fatalf("agent Kill() timed out: %v", err)
		}
		if exited, _ := ag2.isExited(); !exited {
			t.Fatalf("expected agent to have exited after Kill()")
		}
	})
}
