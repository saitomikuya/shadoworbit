//go:build e2e

package e2e_test

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// --- 1. Mock DNS Server (UDP + TCP on identical ephemeral port) ---

type MockDNSOptions struct {
	Records        map[string][]string
	AAAARecords    map[string][]string
	TXTRecords     map[string][]string
	CNAMERecords   map[string]string
	HTTPSRecords   map[string]bool
	SVCBRecords    map[string]bool
	PerDomainRcode map[string]int
	DefaultRcode   int
	Delay          time.Duration
}

type RecordedDNSQuery struct {
	Name      string
	QType     uint16
	Proto     string
	Timestamp time.Time
}

type MockDNSServer struct {
	port    int
	addr    string
	opts    MockDNSOptions
	udpSrv  *dns.Server
	tcpSrv  *dns.Server
	mu      sync.Mutex
	queries []RecordedDNSQuery
}

func normalizeFQDNMap[V any](in map[string]V) map[string]V {
	out := make(map[string]V, len(in))
	for k, v := range in {
		out[dns.Fqdn(strings.ToLower(strings.TrimSpace(k)))] = v
	}
	return out
}

// StartMockDNSServer starts a miekg/dns server listening on both UDP and TCP on the same 127.0.0.1 port.
func StartMockDNSServer(t *testing.T, opts MockDNSOptions) *MockDNSServer {
	t.Helper()

	normOpts := MockDNSOptions{
		Records:        normalizeFQDNMap(opts.Records),
		AAAARecords:    normalizeFQDNMap(opts.AAAARecords),
		TXTRecords:     normalizeFQDNMap(opts.TXTRecords),
		CNAMERecords:   normalizeFQDNMap(opts.CNAMERecords),
		HTTPSRecords:   normalizeFQDNMap(opts.HTTPSRecords),
		SVCBRecords:    normalizeFQDNMap(opts.SVCBRecords),
		PerDomainRcode: normalizeFQDNMap(opts.PerDomainRcode),
		DefaultRcode:   opts.DefaultRcode,
		Delay:          opts.Delay,
	}

	var pc net.PacketConn
	var ln net.Listener
	var port int
	var bindErr error

	for i := 0; i < 16; i++ {
		pConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			bindErr = err
			continue
		}
		p := pConn.LocalAddr().(*net.UDPAddr).Port
		tLn, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			_ = pConn.Close()
			bindErr = err
			continue
		}
		pc = pConn
		ln = tLn
		port = p
		break
	}
	if pc == nil || ln == nil {
		t.Fatalf("StartMockDNSServer: failed to bind dual UDP+TCP port: %v", bindErr)
	}

	srv := &MockDNSServer{
		port: port,
		addr: fmt.Sprintf("127.0.0.1:%d", port),
		opts: normOpts,
	}

	makeHandler := func(protoName string) dns.HandlerFunc {
		return func(w dns.ResponseWriter, r *dns.Msg) {
			if srv.opts.Delay > 0 {
				time.Sleep(srv.opts.Delay)
			}
			msg := new(dns.Msg)
			msg.SetReply(r)
			msg.Authoritative = true

			if len(r.Question) == 0 {
				_ = w.WriteMsg(msg)
				return
			}
			q := r.Question[0]
			fqdn := dns.Fqdn(strings.ToLower(q.Name))

			srv.mu.Lock()
			srv.queries = append(srv.queries, RecordedDNSQuery{
				Name:      fqdn,
				QType:     q.Qtype,
				Proto:     protoName,
				Timestamp: time.Now(),
			})
			srv.mu.Unlock()

			if rcode, ok := srv.opts.PerDomainRcode[fqdn]; ok {
				msg.Rcode = rcode
				_ = w.WriteMsg(msg)
				return
			}

			matched := false
			switch q.Qtype {
			case dns.TypeA:
				if ips, ok := srv.opts.Records[fqdn]; ok {
					matched = true
					for _, ipStr := range ips {
						if ip := net.ParseIP(ipStr).To4(); ip != nil {
							msg.Answer = append(msg.Answer, &dns.A{
								Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
								A:   ip,
							})
						}
					}
				}
			case dns.TypeAAAA:
				if ips, ok := srv.opts.AAAARecords[fqdn]; ok {
					matched = true
					for _, ipStr := range ips {
						if ip := net.ParseIP(ipStr).To16(); ip != nil {
							msg.Answer = append(msg.Answer, &dns.AAAA{
								Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
								AAAA: ip,
							})
						}
					}
				}
			case dns.TypeTXT:
				if txts, ok := srv.opts.TXTRecords[fqdn]; ok {
					matched = true
					msg.Answer = append(msg.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
						Txt: txts,
					})
				}
			case dns.TypeCNAME:
				if target, ok := srv.opts.CNAMERecords[fqdn]; ok {
					matched = true
					msg.Answer = append(msg.Answer, &dns.CNAME{
						Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
						Target: dns.Fqdn(target),
					})
				}
			case dns.TypeHTTPS:
				if srv.opts.HTTPSRecords[fqdn] {
					matched = true
					msg.Answer = append(msg.Answer, &dns.HTTPS{
						SVCB: dns.SVCB{
							Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeHTTPS, Class: dns.ClassINET, Ttl: 60},
							Priority: 1,
							Target:   ".",
						},
					})
				}
			case dns.TypeSVCB:
				if srv.opts.SVCBRecords[fqdn] {
					matched = true
					msg.Answer = append(msg.Answer, &dns.SVCB{
						Hdr:      dns.RR_Header{Name: q.Name, Rrtype: dns.TypeSVCB, Class: dns.ClassINET, Ttl: 60},
						Priority: 1,
						Target:   ".",
					})
				}
			case dns.TypeANY:
				if ips, ok := srv.opts.Records[fqdn]; ok {
					matched = true
					for _, ipStr := range ips {
						if ip := net.ParseIP(ipStr).To4(); ip != nil {
							msg.Answer = append(msg.Answer, &dns.A{
								Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
								A:   ip,
							})
						}
					}
				}
			}

			if !matched && !srv.domainKnown(fqdn) && srv.opts.DefaultRcode != 0 {
				msg.Rcode = srv.opts.DefaultRcode
			}
			_ = w.WriteMsg(msg)
		}
	}

	udpStarted := make(chan struct{})
	tcpStarted := make(chan struct{})

	srv.udpSrv = &dns.Server{
		PacketConn:        pc,
		Handler:           makeHandler("udp"),
		NotifyStartedFunc: func() { close(udpStarted) },
	}
	srv.tcpSrv = &dns.Server{
		Listener:          ln,
		Handler:           makeHandler("tcp"),
		NotifyStartedFunc: func() { close(tcpStarted) },
	}

	go func() { _ = srv.udpSrv.ActivateAndServe() }()
	go func() { _ = srv.tcpSrv.ActivateAndServe() }()

	select {
	case <-udpStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("StartMockDNSServer: UDP server startup timeout")
	}
	select {
	case <-tcpStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("StartMockDNSServer: TCP server startup timeout")
	}

	t.Cleanup(func() {
		_ = srv.udpSrv.Shutdown()
		_ = srv.tcpSrv.Shutdown()
	})

	return srv
}

func (s *MockDNSServer) domainKnown(fqdn string) bool {
	if _, ok := s.opts.Records[fqdn]; ok {
		return true
	}
	if _, ok := s.opts.AAAARecords[fqdn]; ok {
		return true
	}
	if _, ok := s.opts.TXTRecords[fqdn]; ok {
		return true
	}
	if _, ok := s.opts.CNAMERecords[fqdn]; ok {
		return true
	}
	if s.opts.HTTPSRecords[fqdn] || s.opts.SVCBRecords[fqdn] {
		return true
	}
	return false
}

func (s *MockDNSServer) Addr() string { return s.addr }
func (s *MockDNSServer) Port() int    { return s.port }

func (s *MockDNSServer) Queries() []RecordedDNSQuery {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RecordedDNSQuery, len(s.queries))
	copy(out, s.queries)
	return out
}

func (s *MockDNSServer) ResetQueries() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queries = nil
}

// --- 2. Universal Mock Kernels (snell-server, shadow-tls, sing-box + gRPC StatsService) ---

var (
	mockKernelCompileOnce sync.Once
	mockKernelBasePath    string
	mockKernelCompileErr  error
)

type MockKernelSidecar struct {
	Role               string `json:"role"`
	Version            string `json:"version"`
	VersionFail        bool   `json:"version_fail"`
	LogDir             string `json:"log_dir"`
	StatsFile          string `json:"stats_file"`
	RejectConfigSubstr string `json:"reject_config_substr"`
	CrashOnStart       bool   `json:"crash_on_start"`
	CrashAfterMS       int    `json:"crash_after_ms"`
	FailPortBind       bool   `json:"fail_port_bind"`
	ExitCode           int    `json:"exit_code"`
}

type MockKernelOptions struct {
	SnellVersion     string
	ShadowTLSVersion string
	SingBoxVersion   string
	SnellSidecar     *MockKernelSidecar
	ShadowTLSSidecar *MockKernelSidecar
	SingBoxSidecar   *MockKernelSidecar
}

type MockUserStat struct {
	Name  string `json:"name"`
	Value int64  `json:"value"`
}

type MockKernelInvocation struct {
	Event         string   `json:"event"`
	Role          string   `json:"role"`
	PID           int      `json:"pid"`
	Args          []string `json:"args"`
	Subcommand    string   `json:"subcommand,omitempty"`
	ConfigPath    string   `json:"config_path,omitempty"`
	ConfigContent string   `json:"config_content,omitempty"`
	ExitCode      int      `json:"exit_code,omitempty"`
	TimestampNano int64    `json:"timestamp_nano"`
}

type MockKernelSet struct {
	t            *testing.T
	BinDir       string
	LogDir       string
	StatsFile    string
	SnellBin     string
	ShadowTLSBin string
	SingBoxBin   string
}

func compileMockKernelBase(t *testing.T) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	mockKernelCompileOnce.Do(func() {
		binDir, err := ensureSharedBinDir()
		if err != nil {
			mockKernelCompileErr = err
			return
		}
		srcDir, err := os.MkdirTemp("", "snell-mockkernel-src-*")
		if err != nil {
			mockKernelCompileErr = err
			return
		}
		defer os.RemoveAll(srcDir)

		srcFile := filepath.Join(srcDir, "main.go")
		if err := os.WriteFile(srcFile, []byte(mockKernelSource), 0o600); err != nil {
			mockKernelCompileErr = err
			return
		}
		outBin := filepath.Join(binDir, "mockkernel-base")
		cmd := exec.Command("go", "build", "-o", outBin, srcFile)
		cmd.Dir = repoRoot
		if raw, err := cmd.CombinedOutput(); err != nil {
			mockKernelCompileErr = fmt.Errorf("compile mockkernel failed: %w\n%s", err, string(raw))
			return
		}
		mockKernelBasePath = outBin
	})
	if mockKernelCompileErr != nil {
		t.Fatalf("compileMockKernelBase: %v", mockKernelCompileErr)
	}
	return mockKernelBasePath
}

// BuildMockKernelVariant compiles a standalone kernel executable with -ldflags baked metadata (for updater/rollback E2E).
func BuildMockKernelVariant(t *testing.T, roleName, version string, crashOnStart bool) []byte {
	t.Helper()
	repoRoot := findRepoRoot(t)
	srcDir := t.TempDir()
	srcFile := filepath.Join(srcDir, "main.go")
	if err := os.WriteFile(srcFile, []byte(mockKernelSource), 0o600); err != nil {
		t.Fatalf("BuildMockKernelVariant write src: %v", err)
	}
	outBin := filepath.Join(srcDir, roleName)
	ldflags := fmt.Sprintf("-X 'main.bakedRole=%s' -X 'main.bakedVersion=%s' -X 'main.bakedCrashOnStart=%t' -X 'main.bakedExitCode=2'",
		roleName, version, crashOnStart)
	cmd := exec.Command("go", "build", "-ldflags", ldflags, "-o", outBin, srcFile)
	cmd.Dir = repoRoot
	if raw, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("BuildMockKernelVariant build failed: %v\n%s", err, string(raw))
	}
	data, err := os.ReadFile(outBin)
	if err != nil {
		t.Fatalf("BuildMockKernelVariant read binary: %v", err)
	}
	return data
}

// BuildMockKernels creates isolated executable copies of mockkernel for snell-server, shadow-tls, and sing-box.
func BuildMockKernels(t *testing.T, opts MockKernelOptions) *MockKernelSet {
	t.Helper()
	base := compileMockKernelBase(t)
	baseBytes, err := os.ReadFile(base)
	if err != nil {
		t.Fatalf("BuildMockKernels read base: %v", err)
	}

	binDir := t.TempDir()
	logDir := t.TempDir()
	statsFile := filepath.Join(logDir, "stats.json")
	if err := os.WriteFile(statsFile, []byte("[]"), 0o644); err != nil {
		t.Fatalf("BuildMockKernels init stats file: %v", err)
	}

	snellVer := opts.SnellVersion
	if snellVer == "" {
		snellVer = "snell-server v5.0.0"
	}
	stlsVer := opts.ShadowTLSVersion
	if stlsVer == "" {
		stlsVer = "shadow-tls 0.2.25"
	}
	sbVer := opts.SingBoxVersion
	if sbVer == "" {
		sbVer = "sing-box version 1.11.4"
	}

	set := &MockKernelSet{
		t:            t,
		BinDir:       binDir,
		LogDir:       logDir,
		StatsFile:    statsFile,
		SnellBin:     filepath.Join(binDir, "snell-server"),
		ShadowTLSBin: filepath.Join(binDir, "shadow-tls"),
		SingBoxBin:   filepath.Join(binDir, "sing-box"),
	}

	writeKernel := func(binPath, role, defaultVer string, override *MockKernelSidecar) {
		if err := os.WriteFile(binPath, baseBytes, 0o755); err != nil {
			t.Fatalf("BuildMockKernels write %s: %v", binPath, err)
		}
		sc := MockKernelSidecar{
			Role:      role,
			Version:   defaultVer,
			LogDir:    logDir,
			StatsFile: statsFile,
			ExitCode:  1,
		}
		if override != nil {
			sc = *override
			if sc.Role == "" {
				sc.Role = role
			}
			if sc.Version == "" {
				sc.Version = defaultVer
			}
			if sc.LogDir == "" {
				sc.LogDir = logDir
			}
			if sc.StatsFile == "" {
				sc.StatsFile = statsFile
			}
			if sc.ExitCode == 0 && (sc.CrashOnStart || sc.CrashAfterMS > 0) {
				sc.ExitCode = 1
			}
		}
		set.UpdateSidecar(role, sc)
	}

	writeKernel(set.SnellBin, "snell-server", snellVer, opts.SnellSidecar)
	writeKernel(set.ShadowTLSBin, "shadow-tls", stlsVer, opts.ShadowTLSSidecar)
	writeKernel(set.SingBoxBin, "sing-box", sbVer, opts.SingBoxSidecar)

	return set
}

func (m *MockKernelSet) sidecarPath(role string) string {
	switch role {
	case "snell-server":
		return m.SnellBin + ".mock.json"
	case "shadow-tls":
		return m.ShadowTLSBin + ".mock.json"
	case "sing-box":
		return m.SingBoxBin + ".mock.json"
	default:
		return filepath.Join(m.BinDir, role+".mock.json")
	}
}

func (m *MockKernelSet) UpdateSidecar(role string, sc MockKernelSidecar) {
	m.t.Helper()
	if sc.Role == "" {
		sc.Role = role
	}
	if sc.LogDir == "" {
		sc.LogDir = m.LogDir
	}
	if sc.StatsFile == "" {
		sc.StatsFile = m.StatsFile
	}
	b, err := json.MarshalIndent(sc, "", "  ")
	if err != nil {
		m.t.Fatalf("UpdateSidecar marshal: %v", err)
	}
	scPath := m.sidecarPath(role)
	tmp := scPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		m.t.Fatalf("UpdateSidecar write: %v", err)
	}
	if err := os.Rename(tmp, scPath); err != nil {
		m.t.Fatalf("UpdateSidecar rename: %v", err)
	}
}

func (m *MockKernelSet) SetStats(stats []MockUserStat) {
	m.t.Helper()
	b, err := json.Marshal(stats)
	if err != nil {
		m.t.Fatalf("SetStats marshal: %v", err)
	}
	f, err := os.CreateTemp(filepath.Dir(m.StatsFile), "stats-test-*.tmp")
	if err != nil {
		m.t.Fatalf("SetStats create temp: %v", err)
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		m.t.Fatalf("SetStats write: %v", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		m.t.Fatalf("SetStats close: %v", err)
	}
	if err := os.Rename(tmp, m.StatsFile); err != nil {
		_ = os.Remove(tmp)
		m.t.Fatalf("SetStats rename: %v", err)
	}
}

func (m *MockKernelSet) ReadStats() []MockUserStat {
	m.t.Helper()
	raw, err := os.ReadFile(m.StatsFile)
	if err != nil {
		m.t.Fatalf("ReadStats: %v", err)
	}
	var out []MockUserStat
	if err := json.Unmarshal(raw, &out); err != nil {
		m.t.Fatalf("ReadStats decode: %v", err)
	}
	return out
}

func (m *MockKernelSet) Invocations(role string) []MockKernelInvocation {
	m.t.Helper()
	p := filepath.Join(m.LogDir, role+".invocations.jsonl")
	raw, err := os.ReadFile(p)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		m.t.Fatalf("Invocations(%s): %v", role, err)
	}
	var out []MockKernelInvocation
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var inv MockKernelInvocation
		if err := json.Unmarshal([]byte(line), &inv); err == nil {
			out = append(out, inv)
		}
	}
	return out
}

func (m *MockKernelSet) RunningPIDs(role string) []int {
	m.t.Helper()
	entries, err := os.ReadDir(m.LogDir)
	if err != nil {
		return nil
	}
	prefix := role + ".pid."
	var pids []int
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), prefix) {
			continue
		}
		pidStr := strings.TrimPrefix(e.Name(), prefix)
		pid, err := strconv.Atoi(pidStr)
		if err != nil || pid <= 0 {
			continue
		}
		if err := syscall.Kill(pid, 0); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids
}

func (m *MockKernelSet) LiveProcessCount(role string) int {
	return len(m.RunningPIDs(role))
}

const mockKernelSource = `package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

var (
	bakedRole         string
	bakedVersion      string
	bakedCrashOnStart string
	bakedExitCode     string
)

type sidecarCfg struct {
	Role               string ` + "`json:\"role\"`" + `
	Version            string ` + "`json:\"version\"`" + `
	VersionFail        bool   ` + "`json:\"version_fail\"`" + `
	LogDir             string ` + "`json:\"log_dir\"`" + `
	StatsFile          string ` + "`json:\"stats_file\"`" + `
	RejectConfigSubstr string ` + "`json:\"reject_config_substr\"`" + `
	CrashOnStart       bool   ` + "`json:\"crash_on_start\"`" + `
	CrashAfterMS       int    ` + "`json:\"crash_after_ms\"`" + `
	FailPortBind       bool   ` + "`json:\"fail_port_bind\"`" + `
	ExitCode           int    ` + "`json:\"exit_code\"`" + `
}

type invRecord struct {
	Event         string   ` + "`json:\"event\"`" + `
	Role          string   ` + "`json:\"role\"`" + `
	PID           int      ` + "`json:\"pid\"`" + `
	Args          []string ` + "`json:\"args\"`" + `
	Subcommand    string   ` + "`json:\"subcommand,omitempty\"`" + `
	ConfigPath    string   ` + "`json:\"config_path,omitempty\"`" + `
	ConfigContent string   ` + "`json:\"config_content,omitempty\"`" + `
	ExitCode      int      ` + "`json:\"exit_code,omitempty\"`" + `
	TimestampNano int64    ` + "`json:\"timestamp_nano\"`" + `
}

type userStat struct {
	Name  string ` + "`json:\"name\"`" + `
	Value int64  ` + "`json:\"value\"`" + `
}

func loadSidecar() sidecarCfg {
	var cfg sidecarCfg
	exePath, _ := os.Executable()
	candidates := []string{
		os.Args[0] + ".mock.json",
		exePath + ".mock.json",
	}
	for _, p := range candidates {
		if b, err := os.ReadFile(p); err == nil {
			_ = json.Unmarshal(b, &cfg)
			break
		}
	}
	if bakedRole != "" {
		cfg.Role = bakedRole
	}
	if cfg.Role == "" {
		cfg.Role = filepath.Base(os.Args[0])
	}
	if bakedVersion != "" {
		cfg.Version = bakedVersion
	}
	if bakedCrashOnStart == "true" {
		cfg.CrashOnStart = true
	} else if bakedCrashOnStart == "false" {
		cfg.CrashOnStart = false
	}
	if bakedExitCode != "" {
		var code int
		fmt.Sscanf(bakedExitCode, "%d", &code)
		if code != 0 {
			cfg.ExitCode = code
		}
	}
	if cfg.ExitCode == 0 {
		cfg.ExitCode = 1
	}
	return cfg
}

func appendInv(cfg sidecarCfg, rec invRecord) {
	if cfg.LogDir == "" {
		return
	}
	rec.PID = os.Getpid()
	rec.Role = cfg.Role
	rec.TimestampNano = time.Now().UnixNano()
	b, err := json.Marshal(rec)
	if err != nil {
		return
	}
	p := filepath.Join(cfg.LogDir, cfg.Role+".invocations.jsonl")
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.Write(append(b, '\n'))
}

func findArgValue(args []string, flags ...string) string {
	for i := 0; i < len(args); i++ {
		for _, fl := range flags {
			if args[i] == fl && i+1 < len(args) {
				return args[i+1]
			}
			if strings.HasPrefix(args[i], fl+"=") {
				return strings.TrimPrefix(args[i], fl+"=")
			}
		}
	}
	return ""
}

func isVersionCall(args []string) bool {
	for _, a := range args {
		if a == "--version" || a == "-v" || a == "-V" || a == "version" {
			return true
		}
	}
	return false
}

func isCheckCall(args []string) bool {
	for _, a := range args {
		if a == "check" {
			return true
		}
	}
	return false
}

func parseSingBoxBindings(content string) (tcpAddrs []string, udpAddrs []string, statsAddr string) {
	var doc struct {
		Inbounds []struct {
			Type       string ` + "`json:\"type\"`" + `
			Listen     string ` + "`json:\"listen\"`" + `
			ListenPort int    ` + "`json:\"listen_port\"`" + `
			Network    string ` + "`json:\"network\"`" + `
		} ` + "`json:\"inbounds\"`" + `
		Experimental struct {
			V2RayAPI struct {
				Listen string ` + "`json:\"listen\"`" + `
			} ` + "`json:\"v2ray_api\"`" + `
		} ` + "`json:\"experimental\"`" + `
	}
	if err := json.Unmarshal([]byte(content), &doc); err != nil {
		return nil, nil, ""
	}
	for _, inb := range doc.Inbounds {
		if inb.ListenPort <= 0 {
			continue
		}
		host := inb.Listen
		if host == "" {
			host = "127.0.0.1"
		}
		addr := net.JoinHostPort(host, fmt.Sprintf("%d", inb.ListenPort))
		if strings.EqualFold(inb.Network, "udp") {
			udpAddrs = append(udpAddrs, addr)
		} else {
			tcpAddrs = append(tcpAddrs, addr)
		}
	}
	statsAddr = doc.Experimental.V2RayAPI.Listen
	return tcpAddrs, udpAddrs, statsAddr
}

func parseSnellBindings(content string) []string {
	var addrs []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "listen") {
			if idx := strings.IndexByte(line, '='); idx >= 0 {
				val := strings.TrimSpace(line[idx+1:])
				if val != "" {
					addrs = append(addrs, val)
				}
			}
		}
	}
	return addrs
}

func buildStatsDescriptors() (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, error) {
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("v2ray_stats.proto"),
		Package: proto.String("v2ray.core.app.stats.command"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("QueryStatsRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("pattern"),
						Number:   proto.Int32(1),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						JsonName: proto.String("pattern"),
					},
					{
						Name:     proto.String("reset"),
						Number:   proto.Int32(2),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum(),
						JsonName: proto.String("reset"),
					},
				},
			},
			{
				Name: proto.String("Stat"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("name"),
						Number:   proto.Int32(1),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(),
						JsonName: proto.String("name"),
					},
					{
						Name:     proto.String("value"),
						Number:   proto.Int32(2),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum(),
						JsonName: proto.String("value"),
					},
				},
			},
			{
				Name: proto.String("QueryStatsResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{
						Name:     proto.String("stat"),
						Number:   proto.Int32(1),
						Label:    descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(),
						Type:     descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(),
						TypeName: proto.String(".v2ray.core.app.stats.command.Stat"),
						JsonName: proto.String("stat"),
					},
				},
			},
		},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		return nil, nil, nil, err
	}
	return fd.Messages().ByName("QueryStatsRequest"),
		fd.Messages().ByName("QueryStatsResponse"),
		fd.Messages().ByName("Stat"),
		nil
}

type statsServer struct {
	mu        sync.Mutex
	statsFile string
	reqDesc   protoreflect.MessageDescriptor
	respDesc  protoreflect.MessageDescriptor
	statDesc  protoreflect.MessageDescriptor
}

func (s *statsServer) handleQueryStats(ctx context.Context, req *dynamicpb.Message) (*dynamicpb.Message, error) {
	pattern := req.Get(s.reqDesc.Fields().ByName("pattern")).String()
	reset := req.Get(s.reqDesc.Fields().ByName("reset")).Bool()

	s.mu.Lock()
	defer s.mu.Unlock()

	var stats []userStat
	if s.statsFile != "" {
		if raw, err := os.ReadFile(s.statsFile); err == nil {
			_ = json.Unmarshal(raw, &stats)
		}
	}

	resp := dynamicpb.NewMessage(s.respDesc)
	statList := resp.Mutable(s.respDesc.Fields().ByName("stat")).List()
	nameField := s.statDesc.Fields().ByName("name")
	valField := s.statDesc.Fields().ByName("value")

	modified := false
	for i := range stats {
		if pattern == "" || strings.Contains(stats[i].Name, pattern) {
			st := dynamicpb.NewMessage(s.statDesc)
			st.Set(nameField, protoreflect.ValueOfString(stats[i].Name))
			st.Set(valField, protoreflect.ValueOfInt64(stats[i].Value))
			statList.Append(protoreflect.ValueOfMessage(st))
			if reset && stats[i].Value != 0 {
				stats[i].Value = 0
				modified = true
			}
		}
	}
	if reset && modified && s.statsFile != "" {
		if b, err := json.Marshal(stats); err == nil {
			if f, err := os.CreateTemp(filepath.Dir(s.statsFile), "stats-srv-*.tmp"); err == nil {
				tmp := f.Name()
				if _, wErr := f.Write(b); wErr == nil {
					if cErr := f.Close(); cErr == nil {
						if rErr := os.Rename(tmp, s.statsFile); rErr != nil {
							_ = os.Remove(tmp)
						}
					} else {
						_ = os.Remove(tmp)
					}
				} else {
					_ = f.Close()
					_ = os.Remove(tmp)
				}
			}
		}
	}
	return resp, nil
}

func startStatsGRPC(addr, statsFile string) (*grpc.Server, net.Listener, error) {
	reqDesc, respDesc, statDesc, err := buildStatsDescriptors()
	if err != nil {
		return nil, nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, nil, err
	}
	ss := &statsServer{
		statsFile: statsFile,
		reqDesc:   reqDesc,
		respDesc:  respDesc,
		statDesc:  statDesc,
	}
	gs := grpc.NewServer()
	sd := &grpc.ServiceDesc{
		ServiceName: "v2ray.core.app.stats.command.StatsService",
		HandlerType: (*any)(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "QueryStats",
				Handler: func(srv any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
					in := dynamicpb.NewMessage(reqDesc)
					if err := dec(in); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return ss.handleQueryStats(ctx, in)
					}
					info := &grpc.UnaryServerInfo{
						Server:     srv,
						FullMethod: "/v2ray.core.app.stats.command.StatsService/QueryStats",
					}
					return interceptor(ctx, in, info, func(ctx context.Context, req any) (any, error) {
						return ss.handleQueryStats(ctx, req.(*dynamicpb.Message))
					})
				},
			},
		},
	}
	gs.RegisterService(sd, ss)
	go func() { _ = gs.Serve(ln) }()
	return gs, ln, nil
}

func main() {
	cfg := loadSidecar()
	args := os.Args[1:]

	if isVersionCall(args) {
		appendInv(cfg, invRecord{Event: "version", Args: args})
		if cfg.VersionFail {
			fmt.Fprintln(os.Stderr, "mock version failure")
			os.Exit(1)
		}
		fmt.Println(cfg.Version)
		return
	}

	cfgPath := findArgValue(args, "-c", "--config")
	var cfgContent string
	if cfgPath != "" {
		if b, err := os.ReadFile(cfgPath); err == nil {
			cfgContent = string(b)
		}
	}

	if isCheckCall(args) {
		appendInv(cfg, invRecord{
			Event:         "check",
			Args:          args,
			Subcommand:    "check",
			ConfigPath:    cfgPath,
			ConfigContent: cfgContent,
		})
		if cfgPath == "" || cfgContent == "" {
			fmt.Fprintln(os.Stderr, "missing config file for check")
			os.Exit(1)
		}
		if !json.Valid([]byte(cfgContent)) {
			fmt.Fprintln(os.Stderr, "invalid json config")
			os.Exit(1)
		}
		if cfg.RejectConfigSubstr != "" && strings.Contains(cfgContent, cfg.RejectConfigSubstr) {
			fmt.Fprintf(os.Stderr, "rejected config containing %q\n", cfg.RejectConfigSubstr)
			os.Exit(1)
		}
		return
	}

	appendInv(cfg, invRecord{
		Event:         "start",
		Args:          args,
		ConfigPath:    cfgPath,
		ConfigContent: cfgContent,
	})

	if cfg.CrashOnStart {
		appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: cfg.ExitCode})
		fmt.Fprintln(os.Stderr, "mockkernel configured crash_on_start")
		os.Exit(cfg.ExitCode)
	}
	if cfg.FailPortBind {
		appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: 1})
		fmt.Fprintln(os.Stderr, "mockkernel configured fail_port_bind")
		os.Exit(1)
	}

	var tcpListeners []net.Listener
	var udpConns []net.PacketConn
	var grpcSrv *grpc.Server

	closeAll := func() {
		if grpcSrv != nil {
			grpcSrv.Stop()
		}
		for _, l := range tcpListeners {
			_ = l.Close()
		}
		for _, c := range udpConns {
			_ = c.Close()
		}
	}

	var tcpTargets, udpTargets []string
	var statsAddr string

	switch cfg.Role {
	case "shadow-tls":
		if addr := findArgValue(args, "--listen"); addr != "" {
			tcpTargets = append(tcpTargets, addr)
		}
	case "snell-server":
		tcpTargets = append(tcpTargets, parseSnellBindings(cfgContent)...)
	case "sing-box":
		tAddrs, uAddrs, sAddr := parseSingBoxBindings(cfgContent)
		tcpTargets = append(tcpTargets, tAddrs...)
		udpTargets = append(udpTargets, uAddrs...)
		statsAddr = sAddr
	}

	for _, addr := range tcpTargets {
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			closeAll()
			appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: 1})
			fmt.Fprintf(os.Stderr, "failed tcp listen %s: %v\n", addr, err)
			os.Exit(1)
		}
		tcpListeners = append(tcpListeners, ln)
		go func(l net.Listener) {
			for {
				conn, err := l.Accept()
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
						return
					}
					return
				}
				_ = conn.Close()
			}
		}(ln)
	}

	for _, addr := range udpTargets {
		pc, err := net.ListenPacket("udp", addr)
		if err != nil {
			closeAll()
			appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: 1})
			fmt.Fprintf(os.Stderr, "failed udp listen %s: %v\n", addr, err)
			os.Exit(1)
		}
		udpConns = append(udpConns, pc)
	}

	if statsAddr != "" {
		gs, _, err := startStatsGRPC(statsAddr, cfg.StatsFile)
		if err != nil {
			closeAll()
			appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: 1})
			fmt.Fprintf(os.Stderr, "failed stats gRPC %s: %v\n", statsAddr, err)
			os.Exit(1)
		}
		grpcSrv = gs
	}

	var pidFile string
	if cfg.LogDir != "" {
		pidFile = filepath.Join(cfg.LogDir, fmt.Sprintf("%s.pid.%d", cfg.Role, os.Getpid()))
		_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d", os.Getpid())), 0o644)
	}

	if cfg.CrashAfterMS > 0 {
		go func() {
			time.Sleep(time.Duration(cfg.CrashAfterMS) * time.Millisecond)
			if pidFile != "" {
				_ = os.Remove(pidFile)
			}
			closeAll()
			appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: cfg.ExitCode})
			os.Exit(cfg.ExitCode)
		}()
	}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	<-sigCh

	if pidFile != "" {
		_ = os.Remove(pidFile)
	}
	closeAll()
	appendInv(cfg, invRecord{Event: "exit", Args: args, ExitCode: 0})
}
`

// --- 3. /proc/net/dev Fixture Helper ---

// WriteProcNetDevFixture creates a new Linux-formatted /proc/net/dev file in t.TempDir().
func WriteProcNetDevFixture(t *testing.T, iface string, rxBytes, txBytes uint64) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "proc_net_dev")
	UpdateProcNetDevFixture(t, p, iface, rxBytes, txBytes)
	return p
}

// UpdateProcNetDevFixture atomically updates a /proc/net/dev fixture file via temp write + os.Rename.
func UpdateProcNetDevFixture(t *testing.T, path, iface string, rxBytes, txBytes uint64) {
	t.Helper()
	content := fmt.Sprintf(
		"Inter-|   Receive                                                |  Transmit\n"+
			" face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"+
			"    lo: 1024000    1000    0    0    0     0          0         0  1024000    1000    0    0    0     0       0          0\n"+
			"%6s: %d    5000    0    0    0     0          0         0 %d    4000    0    0    0     0       0          0\n",
		iface, rxBytes, txBytes,
	)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o644); err != nil {
		t.Fatalf("UpdateProcNetDevFixture write: %v", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("UpdateProcNetDevFixture rename: %v", err)
	}
}

// --- 4. Mock Webhook Server ---

type CapturedWebhookRequest struct {
	Method     string
	Path       string
	Header     http.Header
	Body       string
	ReceivedAt time.Time
}

type MockWebhookServer struct {
	srv        *httptest.Server
	mu         sync.Mutex
	requests   []CapturedWebhookRequest
	statusCode int
	respBody   string
	delay      time.Duration
}

// StartMockWebhookServer launches an httptest.Server recording all incoming webhook requests.
func StartMockWebhookServer(t *testing.T) *MockWebhookServer {
	t.Helper()
	m := &MockWebhookServer{
		statusCode: http.StatusOK,
		respBody:   `{"code":0,"errcode":0,"errmsg":"ok"}`,
	}
	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()

		m.mu.Lock()
		delay := m.delay
		status := m.statusCode
		respBody := m.respBody
		m.requests = append(m.requests, CapturedWebhookRequest{
			Method:     r.Method,
			Path:       r.URL.RequestURI(),
			Header:     r.Header.Clone(),
			Body:       string(raw),
			ReceivedAt: time.Now(),
		})
		m.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, respBody)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *MockWebhookServer) URL() string { return m.srv.URL }

func (m *MockWebhookServer) SetResponse(status int, body string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCode = status
	m.respBody = body
}

func (m *MockWebhookServer) SetDelay(d time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delay = d
}

func (m *MockWebhookServer) Requests() []CapturedWebhookRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]CapturedWebhookRequest, len(m.requests))
	copy(out, m.requests)
	return out
}

func (m *MockWebhookServer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests = nil
}

func (m *MockWebhookServer) WaitForRequests(n int, timeout time.Duration) ([]CapturedWebhookRequest, bool) {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		reqs := m.Requests()
		if len(reqs) >= n {
			return reqs, true
		}
		time.Sleep(25 * time.Millisecond)
	}
	return m.Requests(), false
}

// --- 5. Mock GitHub Releases Server ---

type MockGitHubAsset struct {
	Name        string
	Archive     bool   // if true, serves a .tar.gz containing BinaryName
	BinaryName  string // name inside tar archive
	Payload     []byte
	ContentType string
}

type MockGitHubRelease struct {
	Owner   string
	Repo    string
	TagName string
	Assets  []MockGitHubAsset
}

type MockGitHubOptions struct {
	Releases           []MockGitHubRelease
	ServeCorruptBytes  bool
	ForceStatusCode    int
	ExtraReleaseHeader map[string]string
}

type MockGitHubServer struct {
	srv     *httptest.Server
	mu      sync.Mutex
	corrupt bool
	status  int
	assets  map[string][]byte
	sha256s map[string]string
	reqs    []string
}

func buildTarGzAsset(t *testing.T, entryName string, content []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	hdr := &tar.Header{
		Name: entryName,
		Mode: 0o755,
		Size: int64(len(content)),
	}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatalf("buildTarGzAsset WriteHeader: %v", err)
	}
	if _, err := tw.Write(content); err != nil {
		t.Fatalf("buildTarGzAsset Write: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("buildTarGzAsset tar Close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("buildTarGzAsset gzip Close: %v", err)
	}
	return buf.Bytes()
}

// StartMockGitHubServer serves GitHub-compatible Releases JSON and binary/.tar.gz asset downloads.
func StartMockGitHubServer(t *testing.T, opts MockGitHubOptions) *MockGitHubServer {
	t.Helper()
	m := &MockGitHubServer{
		corrupt: opts.ServeCorruptBytes,
		status:  opts.ForceStatusCode,
		assets:  make(map[string][]byte),
		sha256s: make(map[string]string),
	}

	for _, rel := range opts.Releases {
		for _, a := range rel.Assets {
			data := a.Payload
			if a.Archive {
				entry := a.BinaryName
				if entry == "" {
					entry = strings.TrimSuffix(a.Name, ".tar.gz")
				}
				data = buildTarGzAsset(t, entry, a.Payload)
			}
			m.assets[a.Name] = data
			sum := sha256.Sum256(data)
			m.sha256s[a.Name] = hex.EncodeToString(sum[:])
		}
	}

	m.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.reqs = append(m.reqs, r.URL.Path)
		corrupt := m.corrupt
		forcedStatus := m.status
		m.mu.Unlock()

		if forcedStatus != 0 {
			http.Error(w, "forced error", forcedStatus)
			return
		}

		if strings.HasPrefix(r.URL.Path, "/download/") {
			name := strings.TrimPrefix(r.URL.Path, "/download/")
			data, ok := m.assets[name]
			if !ok {
				http.NotFound(w, r)
				return
			}
			if corrupt {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte("corrupted-non-archive-bytes"))
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(data)
			return
		}

		// Match /repos/{owner}/{repo}/releases or /repos/{owner}/{repo}/releases/latest
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) >= 4 && parts[0] == "repos" && parts[3] == "releases" {
			owner, repo := parts[1], parts[2]
			matched := make([]map[string]any, 0)
			for _, rel := range opts.Releases {
				if rel.Owner == owner && rel.Repo == repo {
					assetsJSON := make([]map[string]any, 0, len(rel.Assets))
					for _, a := range rel.Assets {
						assetsJSON = append(assetsJSON, map[string]any{
							"name":                 a.Name,
							"browser_download_url": m.srv.URL + "/download/" + a.Name,
							"size":                 len(m.assets[a.Name]),
						})
					}
					matched = append(matched, map[string]any{
						"tag_name": rel.TagName,
						"name":     rel.TagName,
						"assets":   assetsJSON,
					})
				}
			}
			w.Header().Set("Content-Type", "application/json")
			for k, v := range opts.ExtraReleaseHeader {
				w.Header().Set(k, v)
			}
			if len(parts) == 5 && parts[4] == "latest" {
				if len(matched) == 0 {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(matched[0])
				return
			}
			_ = json.NewEncoder(w).Encode(matched)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *MockGitHubServer) URL() string { return m.srv.URL }

func (m *MockGitHubServer) AssetURL(assetName string) string {
	return m.srv.URL + "/download/" + assetName
}

func (m *MockGitHubServer) AssetSHA256(assetName string) string {
	return m.sha256s[assetName]
}

func (m *MockGitHubServer) SetCorruptArchive(corrupt bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.corrupt = corrupt
}

func (m *MockGitHubServer) SetStatusCode(code int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.status = code
}

func (m *MockGitHubServer) PathsRequested() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.reqs))
	copy(out, m.reqs)
	return out
}

// --- Doubles Self-Tests ---

func TestDoubles_MockDNSServer(t *testing.T) {
	srv := StartMockDNSServer(t, MockDNSOptions{
		Records: map[string][]string{
			"netflix.com": {"203.0.113.55"},
			"example.com": {"93.184.216.34"},
		},
		AAAARecords: map[string][]string{
			"netflix.com": {"2001:db8::55"},
		},
		TXTRecords: map[string][]string{
			"txt.example.com": {"v=spf1"},
		},
		CNAMERecords: map[string]string{
			"alias.example.com": "example.com.",
		},
		HTTPSRecords: map[string]bool{
			"netflix.com": true,
		},
		SVCBRecords: map[string]bool{
			"netflix.com": true,
		},
		PerDomainRcode: map[string]int{
			"servfail.test": dns.RcodeServerFailure,
		},
		DefaultRcode: dns.RcodeNameError,
	})

	for _, protoName := range []string{"udp", "tcp"} {
		c := &dns.Client{Net: protoName, Timeout: 2 * time.Second}
		m := new(dns.Msg)
		m.SetQuestion("netflix.com.", dns.TypeA)
		resp, _, err := c.Exchange(m, srv.Addr())
		if err != nil {
			t.Fatalf("%s A query failed: %v", protoName, err)
		}
		if len(resp.Answer) != 1 || resp.Answer[0].(*dns.A).A.String() != "203.0.113.55" {
			t.Fatalf("%s A query unexpected answer: %+v", protoName, resp.Answer)
		}
	}

	c := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	for _, qt := range []uint16{dns.TypeAAAA, dns.TypeHTTPS, dns.TypeSVCB} {
		m := new(dns.Msg)
		m.SetQuestion("netflix.com.", qt)
		resp, _, err := c.Exchange(m, srv.Addr())
		if err != nil || len(resp.Answer) != 1 {
			t.Fatalf("qtype %d expected 1 answer, got err=%v ans=%d", qt, err, len(resp.Answer))
		}
	}

	anyMsg := new(dns.Msg)
	anyMsg.SetQuestion("netflix.com.", dns.TypeANY)
	anyResp, _, err := c.Exchange(anyMsg, srv.Addr())
	if err != nil || len(anyResp.Answer) != 1 || anyResp.Answer[0].(*dns.A).A.String() != "203.0.113.55" {
		t.Fatalf("expected TypeANY answer 203.0.113.55, got err=%v ans=%+v", err, anyResp)
	}

	nxMsg := new(dns.Msg)
	nxMsg.SetQuestion("missing.invalid.", dns.TypeA)
	nxResp, _, err := c.Exchange(nxMsg, srv.Addr())
	if err != nil || nxResp.Rcode != dns.RcodeNameError {
		t.Fatalf("expected NXDOMAIN, got err=%v rcode=%d", err, nxResp.Rcode)
	}

	sfMsg := new(dns.Msg)
	sfMsg.SetQuestion("servfail.test.", dns.TypeA)
	sfResp, _, err := c.Exchange(sfMsg, srv.Addr())
	if err != nil || sfResp.Rcode != dns.RcodeServerFailure {
		t.Fatalf("expected SERVFAIL, got err=%v rcode=%d", err, sfResp.Rcode)
	}

	// Concurrent UDP + TCP queries
	var wg sync.WaitGroup
	errCh := make(chan error, 32)
	for i := 0; i < 8; i++ {
		for _, protoName := range []string{"udp", "tcp"} {
			wg.Add(1)
			go func(netProto string) {
				defer wg.Done()
				cli := &dns.Client{Net: netProto, Timeout: 2 * time.Second}
				q := new(dns.Msg)
				q.SetQuestion("netflix.com.", dns.TypeA)
				r, _, qErr := cli.Exchange(q, srv.Addr())
				if qErr != nil || len(r.Answer) != 1 || r.Answer[0].(*dns.A).A.String() != "203.0.113.55" {
					errCh <- fmt.Errorf("%s concurrent query failed: err=%v ans=%+v", netProto, qErr, r)
				}
			}(protoName)
		}
	}
	wg.Wait()
	close(errCh)
	for qErr := range errCh {
		t.Fatal(qErr)
	}

	if len(srv.Queries()) < 24 {
		t.Fatalf("expected >=24 recorded DNS queries, got %d", len(srv.Queries()))
	}
}

func buildTestStatsDescriptors(t *testing.T) (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, protoreflect.MessageDescriptor) {
	t.Helper()
	fdp := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("v2ray_stats_client.proto"),
		Package: proto.String("v2ray.core.app.stats.command"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("QueryStatsRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("pattern"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), JsonName: proto.String("pattern")},
					{Name: proto.String("reset"), Number: proto.Int32(2), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_BOOL.Enum(), JsonName: proto.String("reset")},
				},
			},
			{
				Name: proto.String("Stat"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("name"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum(), JsonName: proto.String("name")},
					{Name: proto.String("value"), Number: proto.Int32(2), Label: descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum(), JsonName: proto.String("value")},
				},
			},
			{
				Name: proto.String("QueryStatsResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("stat"), Number: proto.Int32(1), Label: descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum(), Type: descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum(), TypeName: proto.String(".v2ray.core.app.stats.command.Stat"), JsonName: proto.String("stat")},
				},
			},
		},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("protodesc.NewFile: %v", err)
	}
	return fd.Messages().ByName("QueryStatsRequest"),
		fd.Messages().ByName("QueryStatsResponse"),
		fd.Messages().ByName("Stat")
}

func TestDoubles_MockKernels_And_GRPCStats(t *testing.T) {
	kernels := BuildMockKernels(t, MockKernelOptions{
		SingBoxSidecar: &MockKernelSidecar{
			Version:            "sing-box version 1.11.4",
			RejectConfigSubstr: "POISON_CONFIG",
		},
	})

	// 1. --version check
	out, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "1.11.4") {
		t.Fatalf("sing-box version failed: err=%v out=%s", err, string(out))
	}

	// 2. sing-box check -c valid & poison
	cfgDir := t.TempDir()
	goodCfgPath := filepath.Join(cfgDir, "good.json")
	statsPort := AllocFreePort(t)
	ssPort := AllocFreePort(t)
	udpPort := AllocFreeUDPPort(t)
	goodCfg := fmt.Sprintf(`{
		"inbounds":[
			{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d},
			{"type":"shadowsocks","listen":"127.0.0.1","listen_port":%d,"network":"udp"}
		],
		"experimental":{"v2ray_api":{"listen":"127.0.0.1:%d"}}
	}`, ssPort, udpPort, statsPort)
	if err := os.WriteFile(goodCfgPath, []byte(goodCfg), 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(kernels.SingBoxBin, "check", "-c", goodCfgPath).CombinedOutput(); err != nil {
		t.Fatalf("sing-box check valid failed: err=%v out=%s", err, string(out))
	}

	badCfgPath := filepath.Join(cfgDir, "bad.json")
	if err := os.WriteFile(badCfgPath, []byte(`{"inbounds":[{"tag":"POISON_CONFIG"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command(kernels.SingBoxBin, "check", "-c", badCfgPath).Run(); err == nil {
		t.Fatal("expected sing-box check to reject POISON_CONFIG")
	}

	// 3. Seed stats and run sing-box daemon
	kernels.SetStats([]MockUserStat{
		{Name: "user>>>alice>>>traffic>>>uplink", Value: 1234},
		{Name: "user>>>alice>>>traffic>>>downlink", Value: 5678},
	})

	cmd := exec.Command(kernels.SingBoxBin, "run", "-c", goodCfgPath)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start mock sing-box: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Signal(syscall.SIGTERM)
			_, _ = cmd.Process.Wait()
		}
	})

	// Wait for stats gRPC port
	statsAddr := fmt.Sprintf("127.0.0.1:%d", statsPort)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		conn, dErr := net.DialTimeout("tcp", statsAddr, 100*time.Millisecond)
		if dErr == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(25 * time.Millisecond)
	}

	if kernels.LiveProcessCount("sing-box") != 1 {
		t.Fatalf("expected 1 running sing-box PID, got %v", kernels.RunningPIDs("sing-box"))
	}

	// 4. Call gRPC QueryStats via dynamicpb (reset=false then reset=true)
	reqDesc, respDesc, statDesc := buildTestStatsDescriptors(t)
	gc, err := grpc.NewClient(statsAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer gc.Close()

	query := func(reset bool) map[string]int64 {
		reqMsg := dynamicpb.NewMessage(reqDesc)
		reqMsg.Set(reqDesc.Fields().ByName("pattern"), protoreflect.ValueOfString("user>>>"))
		reqMsg.Set(reqDesc.Fields().ByName("reset"), protoreflect.ValueOfBool(reset))
		respMsg := dynamicpb.NewMessage(respDesc)
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := gc.Invoke(ctx, "/v2ray.core.app.stats.command.StatsService/QueryStats", reqMsg, respMsg); err != nil {
			t.Fatalf("gRPC QueryStats(reset=%v) failed: %v", reset, err)
		}
		out := make(map[string]int64)
		list := respMsg.Get(respDesc.Fields().ByName("stat")).List()
		for i := 0; i < list.Len(); i++ {
			st := list.Get(i).Message()
			n := st.Get(statDesc.Fields().ByName("name")).String()
			v := st.Get(statDesc.Fields().ByName("value")).Int()
			out[n] = v
		}
		return out
	}

	got1 := query(false)
	if got1["user>>>alice>>>traffic>>>uplink"] != 1234 || got1["user>>>alice>>>traffic>>>downlink"] != 5678 {
		t.Fatalf("unexpected QueryStats(reset=false): %+v", got1)
	}
	got2 := query(true)
	if got2["user>>>alice>>>traffic>>>uplink"] != 1234 {
		t.Fatalf("expected pre-reset value 1234 on reset=true call, got %+v", got2)
	}
	got3 := query(false)
	if got3["user>>>alice>>>traffic>>>uplink"] != 0 || got3["user>>>alice>>>traffic>>>downlink"] != 0 {
		t.Fatalf("expected stats zeroed after reset=true, got %+v", got3)
	}

	// Stop initial sing-box daemon before replacing kernels.SingBoxBin in-place
	_ = gc.Close()
	if cmd.Process != nil {
		_ = cmd.Process.Signal(syscall.SIGTERM)
		_, _ = cmd.Process.Wait()
		cmd.Process = nil
	}

	// 5. os.Rename replacement of kernels.SingBoxBin with BuildMockKernelVariant (CrashOnStart=true then false)
	crashBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 9.9.9-crash", true)
	crashStage := filepath.Join(kernels.BinDir, "sing-box.crash.new")
	if err := os.WriteFile(crashStage, crashBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(crashStage, kernels.SingBoxBin); err != nil {
		t.Fatalf("os.Rename crash variant over SingBoxBin: %v", err)
	}
	if verOut, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput(); err != nil || !strings.Contains(string(verOut), "9.9.9-crash") {
		t.Fatalf("replaced crash variant version failed: err=%v out=%s", err, string(verOut))
	}
	if err := exec.Command(kernels.SingBoxBin, "run", "-c", goodCfgPath).Run(); err == nil {
		t.Fatal("expected os.Rename CrashOnStart variant to exit non-zero")
	}

	// Verify bakedCrashOnStart="false" overrides sidecar CrashOnStart:true after os.Rename
	kernels.UpdateSidecar("sing-box", MockKernelSidecar{
		Version:      "sing-box version 1.11.4",
		CrashOnStart: true,
	})
	healthyBytes := BuildMockKernelVariant(t, "sing-box", "sing-box version 1.12.0-healthy", false)
	healthyStage := filepath.Join(kernels.BinDir, "sing-box.healthy.new")
	if err := os.WriteFile(healthyStage, healthyBytes, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(healthyStage, kernels.SingBoxBin); err != nil {
		t.Fatalf("os.Rename healthy variant over SingBoxBin: %v", err)
	}
	if verOut, err := exec.Command(kernels.SingBoxBin, "version").CombinedOutput(); err != nil || !strings.Contains(string(verOut), "1.12.0-healthy") {
		t.Fatalf("replaced healthy variant version failed: err=%v out=%s", err, string(verOut))
	}
	cmd2 := exec.Command(kernels.SingBoxBin, "run", "-c", goodCfgPath)
	if err := cmd2.Start(); err != nil {
		t.Fatalf("start replaced healthy sing-box: %v", err)
	}
	t.Cleanup(func() {
		if cmd2.Process != nil {
			_ = cmd2.Process.Signal(syscall.SIGTERM)
			_, _ = cmd2.Process.Wait()
		}
	})
	ready := false
	dl2 := time.Now().Add(5 * time.Second)
	for time.Now().Before(dl2) {
		conn, dErr := net.DialTimeout("tcp", statsAddr, 100*time.Millisecond)
		if dErr == nil {
			_ = conn.Close()
			ready = true
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if !ready {
		t.Fatalf("replaced healthy variant did not bind %s (sidecar CrashOnStart override failed?)", statsAddr)
	}
}

func TestDoubles_ProcNetDevFixture(t *testing.T) {
	p := WriteProcNetDevFixture(t, "eth0", 1000, 2000)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 4 || !strings.Contains(lines[3], "eth0: 1000") {
		t.Fatalf("unexpected /proc/net/dev fixture content:\n%s", string(raw))
	}

	UpdateProcNetDevFixture(t, p, "eth0", 5000, 9000)
	raw2, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("read updated fixture: %v", err)
	}
	if !strings.Contains(string(raw2), "eth0: 5000") || !strings.Contains(string(raw2), " 9000 ") {
		t.Fatalf("unexpected updated /proc/net/dev fixture:\n%s", string(raw2))
	}
}

func TestDoubles_MockWebhookServer(t *testing.T) {
	wh := StartMockWebhookServer(t)
	resp, err := http.Post(wh.URL()+"/hook?sign=abc", "application/json", strings.NewReader(`{"msg":"hello"}`))
	if err != nil {
		t.Fatalf("POST webhook: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	wh.SetResponse(http.StatusInternalServerError, `{"error":"boom"}`)
	resp2, err := http.Post(wh.URL()+"/fail", "application/json", strings.NewReader(`{"msg":"retry"}`))
	if err != nil {
		t.Fatalf("POST webhook fail mode: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", resp2.StatusCode)
	}

	reqs, ok := wh.WaitForRequests(2, 2*time.Second)
	if !ok || len(reqs) != 2 {
		t.Fatalf("expected 2 webhook requests, got %d", len(reqs))
	}
	if reqs[0].Path != "/hook?sign=abc" || reqs[0].Body != `{"msg":"hello"}` {
		t.Fatalf("unexpected captured request 0: %+v", reqs[0])
	}
}

func TestDoubles_MockGitHubServer(t *testing.T) {
	payload := []byte("#!/bin/sh\necho mock-binary\n")
	gh := StartMockGitHubServer(t, MockGitHubOptions{
		ExtraReleaseHeader: map[string]string{
			"X-RateLimit-Remaining": "59",
		},
		Releases: []MockGitHubRelease{
			{
				Owner:   "SagerNet",
				Repo:    "sing-box",
				TagName: "v1.11.4",
				Assets: []MockGitHubAsset{
					{
						Name:       "sing-box-1.11.4-linux-amd64.tar.gz",
						Archive:    true,
						BinaryName: "sing-box-1.11.4-linux-amd64/sing-box",
						Payload:    payload,
					},
				},
			},
		},
	})

	resp, err := http.Get(gh.URL() + "/repos/SagerNet/sing-box/releases")
	if err != nil {
		t.Fatalf("GET releases: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-RateLimit-Remaining"); got != "59" {
		t.Fatalf("expected X-RateLimit-Remaining=59, got %q", got)
	}
	var rels []struct {
		TagName string `json:"tag_name"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		} `json:"assets"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rels); err != nil {
		t.Fatalf("decode releases: %v", err)
	}
	if len(rels) != 1 || rels[0].TagName != "v1.11.4" || len(rels[0].Assets) != 1 {
		t.Fatalf("unexpected releases response: %+v", rels)
	}

	dlResp, err := http.Get(rels[0].Assets[0].BrowserDownloadURL)
	if err != nil {
		t.Fatalf("GET asset: %v", err)
	}
	defer dlResp.Body.Close()
	rawArchive, err := io.ReadAll(dlResp.Body)
	if err != nil {
		t.Fatalf("read asset: %v", err)
	}
	sum := sha256.Sum256(rawArchive)
	if hex.EncodeToString(sum[:]) != gh.AssetSHA256("sing-box-1.11.4-linux-amd64.tar.gz") {
		t.Fatal("SHA256 mismatch on downloaded asset")
	}

	gz, err := gzip.NewReader(bytes.NewReader(rawArchive))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "sing-box-1.11.4-linux-amd64/sing-box" {
		t.Fatalf("unexpected tar header: hdr=%+v err=%v", hdr, err)
	}
	gotPayload, err := io.ReadAll(tr)
	if err != nil || !bytes.Equal(gotPayload, payload) {
		t.Fatalf("unexpected extracted payload: %q err=%v", string(gotPayload), err)
	}

	// Empty releases list must encode as JSON [] (not null) and apply ExtraReleaseHeader
	emptyResp, err := http.Get(gh.URL() + "/repos/unknown/repo/releases")
	if err != nil {
		t.Fatalf("GET empty releases: %v", err)
	}
	defer emptyResp.Body.Close()
	if got := emptyResp.Header.Get("X-RateLimit-Remaining"); got != "59" {
		t.Fatalf("expected X-RateLimit-Remaining=59 on empty releases, got %q", got)
	}
	emptyBody, err := io.ReadAll(emptyResp.Body)
	if err != nil {
		t.Fatalf("read empty releases: %v", err)
	}
	if strings.TrimSpace(string(emptyBody)) != "[]" {
		t.Fatalf("expected empty releases JSON [], got %q", string(emptyBody))
	}
}
