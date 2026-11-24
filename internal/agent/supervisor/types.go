package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"snell-panel/internal/protocol"
)

const (
	defaultSnellBin        = "snell-server"
	defaultShadowTLSBin    = "shadow-tls"
	defaultSingBoxBin      = "sing-box"
	defaultStatsPort       = 18080
	defaultLocalDNSPort    = 1053
	defaultSnellInnerStart = 31001
	defaultSSInnerStart    = 31002

	defaultStartupGrace     = 350 * time.Millisecond
	defaultStopTimeout      = 3 * time.Second
	defaultCrashBackoffBase = 500 * time.Millisecond
	defaultCrashBackoffMax  = 30 * time.Second
	defaultStabilityWindow  = 10 * time.Second
	defaultProbeTimeout     = 5 * time.Second
	defaultSnellProbeStep   = 1500 * time.Millisecond
	defaultCheckTimeout     = 10 * time.Second

	maxStderrTailBytes = 16 * 1024
)

var (
	// ErrStopped is returned when an operation is invoked after Stop.
	ErrStopped = errors.New("supervisor: stopped")
	// ErrNoActiveConfig is returned when a kernel lifecycle operation is called before any config has been applied.
	ErrNoActiveConfig = errors.New("supervisor: no active configuration applied")
	// ErrKernelDisabled is returned when starting or restarting a kernel disabled in the active config.
	ErrKernelDisabled = errors.New("supervisor: kernel is disabled in active configuration")
	// ErrInvalidKernel is returned when an unknown kernel identifier is supplied.
	ErrInvalidKernel = errors.New("supervisor: unknown kernel")
	// ErrInvalidServiceAction is returned when an unknown service control action is supplied.
	ErrInvalidServiceAction = errors.New("supervisor: invalid service control action")
	// ErrValidation indicates pre-apply configuration or binary validation failure.
	ErrValidation = errors.New("supervisor: config validation failed")
)

// EventHandler receives asynchronous lifecycle and configuration events from the Supervisor.
type EventHandler func(protocol.AgentEvent)

// ValidatorFunc is an optional custom config validation hook invoked during ApplyConfig.
type ValidatorFunc func(ctx context.Context, kernel, configPath string) error

// Options configures the 3-kernel Supervisor.
type Options struct {
	DataDir                 string
	SnellBin                string
	ShadowTLSBin            string
	SingBoxBin              string
	StatsPort               int
	LocalDNSPort            int
	SSInnerTCPPort          int
	OnEvent                 EventHandler
	DisableBinaryValidation bool
	Validator               ValidatorFunc

	StartupGrace       time.Duration
	StartupVerifyDelay time.Duration
	StopTimeout        time.Duration
	CrashBackoffBase   time.Duration
	CrashBackoffMax    time.Duration
	StabilityWindow    time.Duration
}

type resolvedPorts struct {
	EffectiveDNSPort int
	StatsPort        int
	SnellInnerPort   int
	SSInnerTCPPort   int
}

type adminFingerprint struct {
	Enabled       bool
	SnellConf     string
	ShadowTLSArgs string
	SnellBin      string
	ShadowTLSBin  string
}

type ssFingerprint struct {
	Enabled     bool
	SingBoxJSON string
	SingBoxBin  string
}

type kernelSlot struct {
	kernel          string
	desiredEnabled  bool
	verifyingUpdate bool
	generation      uint64
	backoffAttempt  int
	current         *procInstance
}

type kernelInactiveError struct {
	err    error
	reason string
}

func (e *kernelInactiveError) Error() string {
	return e.err.Error()
}

func (e *kernelInactiveError) Unwrap() error {
	return e.err
}

func (e *kernelInactiveError) KernelInactive() bool {
	return true
}

func (e *kernelInactiveError) InactiveReason() string {
	return e.reason
}

type versionCacheEntry struct {
	path        string
	modTime     time.Time
	size        int64
	version     string
	useTyped    bool
	hasV2RayAPI bool
}

// Supervisor manages physically isolated snell-server + shadow-tls (admin channel)
// and sing-box (user SS2022 + ShadowTLS v3 channel) subprocesses.
type Supervisor struct {
	opts       Options
	configsDir string
	tmpDir     string
	snellConf  string
	singBoxCfg string

	opMu sync.Mutex

	mu                    sync.RWMutex
	hasActiveConfig       bool
	activeConfig          protocol.ServerConfigSync
	activePorts           resolvedPorts
	currentRevision       int64
	activeAdminFP         adminFingerprint
	activeSSFP            ssFingerprint
	activeSingBoxV2RayAPI bool
	slots                 map[string]*kernelSlot

	versionCacheMu sync.Mutex
	versionCache   *versionCacheEntry

	stopped    atomic.Bool
	stopCtx    context.Context
	stopCancel context.CancelFunc
	wg         sync.WaitGroup
	nextProcID atomic.Uint64
}

// New validates Options, ensures <DataDir>/configs and <DataDir>/tmp exist,
// and returns a new Supervisor ready to start and apply configs.
func New(opts Options) (*Supervisor, error) {
	opts.DataDir = strings.TrimSpace(opts.DataDir)
	if opts.DataDir == "" {
		return nil, errors.New("supervisor: DataDir is required")
	}
	if strings.TrimSpace(opts.SnellBin) == "" {
		opts.SnellBin = defaultSnellBin
	} else {
		opts.SnellBin = strings.TrimSpace(opts.SnellBin)
	}
	if strings.TrimSpace(opts.ShadowTLSBin) == "" {
		opts.ShadowTLSBin = defaultShadowTLSBin
	} else {
		opts.ShadowTLSBin = strings.TrimSpace(opts.ShadowTLSBin)
	}
	if strings.TrimSpace(opts.SingBoxBin) == "" {
		opts.SingBoxBin = defaultSingBoxBin
	} else {
		opts.SingBoxBin = strings.TrimSpace(opts.SingBoxBin)
	}

	if opts.StatsPort == 0 {
		opts.StatsPort = defaultStatsPort
	}
	if opts.LocalDNSPort == 0 {
		opts.LocalDNSPort = defaultLocalDNSPort
	}
	if opts.StatsPort < 1 || opts.StatsPort > 65535 {
		return nil, fmt.Errorf("supervisor: invalid StatsPort %d: must be 1..65535", opts.StatsPort)
	}
	if opts.LocalDNSPort < 1 || opts.LocalDNSPort > 65535 {
		return nil, fmt.Errorf("supervisor: invalid LocalDNSPort %d: must be 1..65535", opts.LocalDNSPort)
	}
	if opts.StatsPort == opts.LocalDNSPort {
		return nil, fmt.Errorf("supervisor: StatsPort (%d) must differ from LocalDNSPort (%d)", opts.StatsPort, opts.LocalDNSPort)
	}
	if opts.SSInnerTCPPort < 0 || opts.SSInnerTCPPort > 65535 {
		return nil, fmt.Errorf("supervisor: invalid SSInnerTCPPort %d: must be 0 or 1..65535", opts.SSInnerTCPPort)
	}
	if opts.SSInnerTCPPort > 0 && (opts.SSInnerTCPPort == opts.StatsPort || opts.SSInnerTCPPort == opts.LocalDNSPort) {
		return nil, fmt.Errorf("supervisor: SSInnerTCPPort (%d) collides with reserved ports", opts.SSInnerTCPPort)
	}

	if opts.StartupGrace <= 0 {
		if opts.StartupVerifyDelay > 0 {
			opts.StartupGrace = opts.StartupVerifyDelay
		} else {
			opts.StartupGrace = defaultStartupGrace
		}
	}
	if opts.StartupVerifyDelay <= 0 {
		opts.StartupVerifyDelay = opts.StartupGrace
	}
	if opts.StopTimeout <= 0 {
		opts.StopTimeout = defaultStopTimeout
	}
	if opts.CrashBackoffBase <= 0 {
		opts.CrashBackoffBase = defaultCrashBackoffBase
	}
	if opts.CrashBackoffMax <= 0 {
		opts.CrashBackoffMax = defaultCrashBackoffMax
	}
	if opts.CrashBackoffMax < opts.CrashBackoffBase {
		opts.CrashBackoffMax = opts.CrashBackoffBase
	}
	if opts.StabilityWindow <= 0 {
		opts.StabilityWindow = defaultStabilityWindow
	}

	configsDir := filepath.Join(opts.DataDir, "configs")
	tmpDir := filepath.Join(opts.DataDir, "tmp")
	if err := os.MkdirAll(configsDir, 0o750); err != nil {
		return nil, fmt.Errorf("supervisor: create configs dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return nil, fmt.Errorf("supervisor: create tmp dir: %w", err)
	}

	stopCtx, stopCancel := context.WithCancel(context.Background())

	s := &Supervisor{
		opts:       opts,
		configsDir: configsDir,
		tmpDir:     tmpDir,
		snellConf:  filepath.Join(configsDir, "snell-server.conf"),
		singBoxCfg: filepath.Join(configsDir, "sing-box.json"),
		slots: map[string]*kernelSlot{
			protocol.KernelSnellServer: {kernel: protocol.KernelSnellServer},
			protocol.KernelShadowTLS:   {kernel: protocol.KernelShadowTLS},
			protocol.KernelSingBox:     {kernel: protocol.KernelSingBox},
		},
		stopCtx:    stopCtx,
		stopCancel: stopCancel,
	}
	return s, nil
}
