package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"snell-panel/internal/protocol"
)

const (
	// StatusUpdateSuccess is emitted on AgentEvent.Status when a kernel update succeeds.
	StatusUpdateSuccess = "update_success"
	// StatusUpdateFailed is emitted on AgentEvent.Status when a kernel update fails or rolls back.
	StatusUpdateFailed = "update_failed"

	defaultHealthObserveDuration = 3 * time.Second
	defaultHealthPollInterval    = 250 * time.Millisecond
	defaultPortDialTimeout       = 500 * time.Millisecond
	defaultDownloadTimeout       = 5 * time.Minute
	defaultProbeTimeout          = 5 * time.Second
	defaultRollbackTimeout       = 15 * time.Second
	defaultMaxDownloadBytes      = int64(256 << 20)
	defaultMaxExtractBytes       = int64(512 << 20)
)

// ErrKernelInactive may be returned by KernelController.RestartKernel when the target
// kernel is disabled in the active configuration or no active configuration has been applied yet.
var ErrKernelInactive = errors.New("updater: kernel is inactive")

// KernelController abstracts supervisor lifecycle hooks for a managed kernel binary.
type KernelController interface {
	BinaryPath(kernel string) (string, error)
	RestartKernel(ctx context.Context, kernel string) error
	IsKernelHealthy(kernel string) bool
	ListenAddrs(kernel string) []string
	ProbeVersion(ctx context.Context, kernel string, binPath string) (string, error)
}

// UpdateGuardController is an optional extension of KernelController that suppresses
// spurious crash-event emission and background crash-backoff restarts while Updater
// owns the post-update health verification window.
type UpdateGuardController interface {
	BeginKernelUpdateVerification(kernel string)
	EndKernelUpdateVerification(kernel string)
}

func isInactiveKernelErr(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	if errors.Is(err, ErrKernelInactive) {
		return "stopped", true
	}
	var ik interface {
		KernelInactive() bool
	}
	if errors.As(err, &ik) && ik.KernelInactive() {
		var ir interface {
			InactiveReason() string
		}
		if errors.As(err, &ir) && strings.TrimSpace(ir.InactiveReason()) != "" {
			return ir.InactiveReason(), true
		}
		return "stopped", true
	}
	return "", false
}

// Options configures the kernel Updater.
type Options struct {
	DataDir               string
	Controller            KernelController
	HTTPClient            *http.Client
	HealthObserveDuration time.Duration
	HealthPollInterval    time.Duration
	PortDialTimeout       time.Duration
	DownloadTimeout       time.Duration
	ProbeTimeout          time.Duration
	RollbackTimeout       time.Duration
	MaxDownloadBytes      int64
	MaxExtractBytes       int64
	OnEvent               func(protocol.AgentEvent)

	// AcquireApplyLock optionally serializes the post-download critical section
	// (atomic binary swap, kernel restart, health observation, and rollback)
	// against concurrent config_sync or service_ctl operations without blocking
	// network download, archive extraction, or staged version probing.
	AcquireApplyLock func(ctx context.Context) (unlock func(), err error)
}

// Updater performs serialized online kernel updates with automatic rollback.
type Updater struct {
	opts    Options
	tmpDir  string
	sem     chan struct{}
	eventMu sync.Mutex
}

// New validates Options, ensures <DataDir>/tmp exists, sweeps stale temp dirs, and returns an Updater.
func New(opts Options) (*Updater, error) {
	opts.DataDir = strings.TrimSpace(opts.DataDir)
	if opts.DataDir == "" {
		return nil, errors.New("updater: DataDir is required")
	}
	if opts.Controller == nil {
		return nil, errors.New("updater: Controller is required")
	}

	if opts.HealthObserveDuration <= 0 {
		opts.HealthObserveDuration = defaultHealthObserveDuration
	}
	if opts.HealthPollInterval <= 0 {
		opts.HealthPollInterval = defaultHealthPollInterval
	}
	if opts.PortDialTimeout <= 0 {
		opts.PortDialTimeout = defaultPortDialTimeout
	}
	if opts.DownloadTimeout <= 0 {
		opts.DownloadTimeout = defaultDownloadTimeout
	}
	if opts.ProbeTimeout <= 0 {
		opts.ProbeTimeout = defaultProbeTimeout
	}
	if opts.RollbackTimeout <= 0 {
		opts.RollbackTimeout = defaultRollbackTimeout
	}
	if opts.MaxDownloadBytes <= 0 {
		opts.MaxDownloadBytes = defaultMaxDownloadBytes
	}
	if opts.MaxExtractBytes <= 0 {
		opts.MaxExtractBytes = defaultMaxExtractBytes
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{
			Transport: &http.Transport{
				Proxy: http.ProxyFromEnvironment,
				DialContext: (&net.Dialer{
					Timeout:   15 * time.Second,
					KeepAlive: 30 * time.Second,
				}).DialContext,
				TLSHandshakeTimeout:   15 * time.Second,
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       60 * time.Second,
			},
		}
	}

	tmpDir := filepath.Join(opts.DataDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return nil, fmt.Errorf("updater: create tmp dir %q: %w", tmpDir, err)
	}
	sweepStaleTempDirs(tmpDir)

	return &Updater{
		opts:   opts,
		tmpDir: tmpDir,
		sem:    make(chan struct{}, 1),
	}, nil
}

// ApplyUpdate downloads, verifies, extracts, probes, swaps, restarts, and monitors
// a kernel binary for HealthObserveDuration, rolling back to <binary>.bak on any failure.
func (u *Updater) ApplyUpdate(ctx context.Context, req protocol.ServerKernelUpdate) error {
	if ctx == nil {
		ctx = context.Background()
	}

	if err := ctx.Err(); err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel update cancelled before start", err.Error())
		return err
	}

	select {
	case u.sem <- struct{}{}:
		defer func() { <-u.sem }()
	case <-ctx.Done():
		err := ctx.Err()
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel update cancelled while waiting for lock", err.Error())
		return err
	}

	// Validate request inputs before any network or disk side effects.
	parsedURL, expectedSHA256, hasExpectedSHA256, targetBinary, err := u.validateRequest(req)
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "invalid kernel update request", err.Error())
		return err
	}

	if err := os.MkdirAll(u.tmpDir, 0o750); err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "failed to prepare temp directory", err.Error())
		return fmt.Errorf("updater: ensure tmp dir: %w", err)
	}
	sweepStaleTempDirs(u.tmpDir)

	workDir, err := os.MkdirTemp(u.tmpDir, "update-"+req.Kernel+"-*")
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "failed to create update workspace", err.Error())
		return fmt.Errorf("updater: create work dir: %w", err)
	}
	defer os.RemoveAll(workDir)

	// 1. Download & optional SHA-256 verification.
	u.emitProgress(req.Kernel, req.Version, "downloading", "")
	dlResult, err := u.downloadArtifact(ctx, workDir, req.Kernel, req.Version, parsedURL, expectedSHA256, hasExpectedSHA256)
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel download or verification failed", err.Error())
		return err
	}

	// 2. Detect format & extract candidate binary safely.
	u.emitProgress(req.Kernel, req.Version, "extracting", "")
	extractedPath, err := u.extractBinary(workDir, req.Kernel, dlResult)
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel extraction failed", err.Error())
		return err
	}

	// 3. Stage into target directory (same filesystem) and probe version before touching live binary.
	stagePath, err := stageBinary(extractedPath, targetBinary)
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "failed to stage kernel binary", err.Error())
		return err
	}
	defer func() {
		if stagePath != "" {
			_ = os.Remove(stagePath)
		}
	}()

	u.emitProgress(req.Kernel, req.Version, "probing", "")
	probeCtx, probeCancel := context.WithTimeout(ctx, u.opts.ProbeTimeout)
	probedVersion, err := u.opts.Controller.ProbeVersion(probeCtx, req.Kernel, stagePath)
	probeCancel()
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel version probe failed", err.Error())
		return fmt.Errorf("updater: probe version: %w", err)
	}

	// 4. Serialize post-download critical section (swap -> restart -> health check -> rollback)
	//    against concurrent config_sync / service_ctl while keeping network download/extract/probe non-blocking.
	if u.opts.AcquireApplyLock != nil {
		unlockApply, err := u.opts.AcquireApplyLock(ctx)
		if err != nil {
			u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel update cancelled while waiting to apply", err.Error())
			return err
		}
		if unlockApply != nil {
			defer unlockApply()
		}
	}

	// Backup existing binary (if present) and atomically swap new binary into place.
	u.emitProgress(req.Kernel, req.Version, "swapping", "")
	swapInfo, err := atomicSwap(stagePath, targetBinary)
	if err != nil {
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "failed to swap kernel binary", err.Error())
		return err
	}
	stagePath = "" // ownership transferred to targetBinary

	// 5. Restart kernel and observe health + listen ports; auto-rollback on any post-swap failure.
	var guardEnded bool
	endGuard := func() {}
	if guard, ok := u.opts.Controller.(UpdateGuardController); ok {
		guard.BeginKernelUpdateVerification(req.Kernel)
		endGuard = func() {
			if !guardEnded {
				guardEnded = true
				guard.EndKernelUpdateVerification(req.Kernel)
			}
		}
		defer endGuard()
	}

	u.emitProgress(req.Kernel, req.Version, "restarting", "")
	if err := u.opts.Controller.RestartKernel(ctx, req.Kernel); err != nil {
		if reason, inactive := isInactiveKernelErr(err); inactive {
			endGuard()
			resolvedVersion := strings.TrimSpace(req.Version)
			if resolvedVersion == "" {
				resolvedVersion = strings.TrimSpace(probedVersion)
			}
			msg := "kernel updated while stopped"
			if reason == "unconfigured" {
				msg = "kernel updated while unconfigured"
			}
			detail := fmt.Sprintf("kernel updated while %s (live health check skipped); probed version: %s", reason, strings.TrimSpace(probedVersion))
			u.emitResult(req.Kernel, protocol.EventStatusSuccess, resolvedVersion, msg, detail)
			return nil
		}
		return u.rollbackAndFail(ctx, req, targetBinary, swapInfo, fmt.Errorf("restart kernel failed: %w", err))
	}

	u.emitProgress(req.Kernel, req.Version, "health_checking", "")
	if err := u.observeHealth(ctx, req.Kernel); err != nil {
		return u.rollbackAndFail(ctx, req, targetBinary, swapInfo, fmt.Errorf("post-update health check failed: %w", err))
	}
	endGuard()

	resolvedVersion := strings.TrimSpace(req.Version)
	if resolvedVersion == "" {
		resolvedVersion = strings.TrimSpace(probedVersion)
	}
	detail := fmt.Sprintf("probed version: %s", strings.TrimSpace(probedVersion))
	u.emitResult(req.Kernel, StatusUpdateSuccess, resolvedVersion, "kernel updated successfully", detail)
	return nil
}

func (u *Updater) validateRequest(req protocol.ServerKernelUpdate) (*url.URL, []byte, bool, string, error) {
	if !protocol.IsValidKernel(req.Kernel) {
		return nil, nil, false, "", fmt.Errorf("unsupported kernel %q", req.Kernel)
	}

	rawURL := strings.TrimSpace(req.DownloadURL)
	if rawURL == "" {
		return nil, nil, false, "", errors.New("download_url is required")
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("invalid download_url: %w", err)
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if (scheme != "http" && scheme != "https") || parsedURL.Host == "" {
		return nil, nil, false, "", fmt.Errorf("download_url must be a valid http/https URL: %q", req.DownloadURL)
	}

	expectedSHA256, hasSHA256, err := parseExpectedSHA256(req.SHA256)
	if err != nil {
		return nil, nil, false, "", err
	}

	targetBinary, err := u.opts.Controller.BinaryPath(req.Kernel)
	if err != nil {
		return nil, nil, false, "", fmt.Errorf("resolve binary path for %q: %w", req.Kernel, err)
	}
	targetBinary = strings.TrimSpace(targetBinary)
	if targetBinary == "" {
		return nil, nil, false, "", fmt.Errorf("empty binary path returned for %q", req.Kernel)
	}

	return parsedURL, expectedSHA256, hasSHA256, targetBinary, nil
}

func parseExpectedSHA256(raw string) ([]byte, bool, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, false, nil
	}
	lower := strings.ToLower(trimmed)
	if len(lower) != sha256.Size*2 {
		return nil, false, fmt.Errorf("invalid sha256 length %d: expected %d hex characters", len(lower), sha256.Size*2)
	}
	decoded, err := hex.DecodeString(lower)
	if err != nil || len(decoded) != sha256.Size {
		return nil, false, fmt.Errorf("invalid sha256 hex digest: %w", err)
	}
	return decoded, true, nil
}

func (u *Updater) observeHealth(ctx context.Context, kernel string) error {
	deadline := time.Now().Add(u.opts.HealthObserveDuration)
	becameReady := false

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		healthy := u.opts.Controller.IsKernelHealthy(kernel)
		addrs := u.opts.Controller.ListenAddrs(kernel)
		var portErr error
		if len(addrs) > 0 {
			portErr = checkListenAddrs(ctx, addrs, u.opts.PortDialTimeout)
		}

		ready := healthy && portErr == nil
		if ready {
			becameReady = true
		} else if becameReady {
			if !healthy {
				return errors.New("kernel became unhealthy during observation window")
			}
			return fmt.Errorf("kernel listening port became unreachable during observation window: %w", portErr)
		}

		now := time.Now()
		if !now.Before(deadline) {
			if becameReady {
				return nil
			}
			if !healthy {
				return errors.New("kernel never became healthy within observation window")
			}
			if portErr != nil {
				return fmt.Errorf("kernel listening ports not ready within observation window: %w", portErr)
			}
			return errors.New("kernel did not become ready within observation window")
		}

		wait := u.opts.HealthPollInterval
		if rem := deadline.Sub(now); rem < wait {
			wait = rem
		}
		if wait <= 0 {
			continue
		}

		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func checkListenAddrs(ctx context.Context, addrs []string, dialTimeout time.Duration) error {
	for _, raw := range addrs {
		if err := checkSingleListenAddr(ctx, raw, dialTimeout); err != nil {
			return err
		}
	}
	return nil
}

func checkSingleListenAddr(ctx context.Context, raw string, dialTimeout time.Duration) error {
	addr := strings.TrimSpace(raw)
	if addr == "" {
		return errors.New("empty listen address")
	}

	isUDP := false
	switch {
	case strings.HasPrefix(addr, "tcp://"):
		addr = strings.TrimPrefix(addr, "tcp://")
	case strings.HasPrefix(addr, "udp://"):
		addr = strings.TrimPrefix(addr, "udp://")
		isUDP = true
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen address %q: %w", raw, err)
	}
	if strings.TrimSpace(port) == "" {
		return fmt.Errorf("missing port in listen address %q", raw)
	}

	if isUDP {
		// UDP connect(2) does not verify a remote listener; rely on IsKernelHealthy for UDP-only endpoints.
		return nil
	}

	var targets []string
	switch host {
	case "":
		targets = []string{
			net.JoinHostPort("127.0.0.1", port),
			net.JoinHostPort("::1", port),
		}
	case "0.0.0.0":
		targets = []string{net.JoinHostPort("127.0.0.1", port)}
	case "::":
		targets = []string{
			net.JoinHostPort("::1", port),
			net.JoinHostPort("127.0.0.1", port),
		}
	default:
		targets = []string{net.JoinHostPort(host, port)}
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	var lastErr error
	for _, target := range targets {
		dialCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		conn, err := dialer.DialContext(dialCtx, "tcp", target)
		cancel()
		if err == nil {
			_ = conn.Close()
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("dial %q failed: %w", raw, lastErr)
}

func (u *Updater) rollbackAndFail(ctx context.Context, req protocol.ServerKernelUpdate, targetBinary string, swapInfo swapState, cause error) error {
	u.emitProgress(req.Kernel, req.Version, "rolling_back", cause.Error())

	rbCtx, rbCancel := context.WithTimeout(context.WithoutCancel(ctx), u.opts.RollbackTimeout)
	defer rbCancel()

	var rbErrs []string
	if err := restoreBackup(targetBinary, swapInfo); err != nil {
		rbErrs = append(rbErrs, fmt.Sprintf("restore backup: %v", err))
	} else if swapInfo.hadOriginal {
		if err := u.opts.Controller.RestartKernel(rbCtx, req.Kernel); err != nil {
			rbErrs = append(rbErrs, fmt.Sprintf("restart previous kernel: %v", err))
		}
	}

	if len(rbErrs) > 0 {
		combined := fmt.Errorf("%w; rollback errors: %s", cause, strings.Join(rbErrs, "; "))
		u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel update failed and rollback encountered errors", combined.Error())
		return combined
	}

	detail := fmt.Sprintf("%v (rolled back cleanly)", cause)
	u.emitResult(req.Kernel, StatusUpdateFailed, req.Version, "kernel update failed and rolled back", detail)
	return cause
}

func (u *Updater) emitProgress(kernel, version, stage, detail string) {
	u.emit(protocol.AgentEvent{
		Event:   protocol.EventKernelUpdateProgress,
		Kernel:  kernel,
		Status:  protocol.EventStatusInProgress,
		Version: version,
		Message: stage,
		Detail:  detail,
	})
}

func (u *Updater) emitResult(kernel, status, version, message, detail string) {
	u.emit(protocol.AgentEvent{
		Event:   protocol.EventKernelUpdateResult,
		Kernel:  kernel,
		Status:  status,
		Version: version,
		Message: message,
		Detail:  detail,
	})
}

func (u *Updater) emit(ev protocol.AgentEvent) {
	if u.opts.OnEvent == nil {
		return
	}
	u.eventMu.Lock()
	defer u.eventMu.Unlock()
	u.opts.OnEvent(ev)
}

func sweepStaleTempDirs(tmpDir string) {
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, "update-") && !strings.HasSuffix(name, ".bak") {
			_ = os.RemoveAll(filepath.Join(tmpDir, name))
		}
	}
}
