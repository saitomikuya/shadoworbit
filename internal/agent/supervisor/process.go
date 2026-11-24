package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"snell-panel/internal/protocol"
)

const (
	procStateStarting int32 = iota
	procStateRunning
	procStateFailedStartup
)

type boundedBuffer struct {
	mu  sync.Mutex
	max int
	buf []byte
}

func newBoundedBuffer(maxBytes int) *boundedBuffer {
	return &boundedBuffer{max: maxBytes}
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.max <= 0 {
		return len(p), nil
	}
	if len(p) >= b.max {
		b.buf = append(b.buf[:0], p[len(p)-b.max:]...)
		return len(p), nil
	}
	total := len(b.buf) + len(p)
	if total > b.max {
		drop := total - b.max
		copy(b.buf, b.buf[drop:])
		b.buf = b.buf[:len(b.buf)-drop]
	}
	b.buf = append(b.buf, p...)
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.buf))
}

type procInstance struct {
	id              uint64
	kernel          string
	cmd             *exec.Cmd
	pid             int
	state           atomic.Int32
	intentionalStop atomic.Bool
	exited          atomic.Bool
	doneCh          chan struct{}
	startedAt       time.Time
	stderrTail      *boundedBuffer
	exitErr         error
	exitCode        int
}

type procSpec struct {
	kernel string
	bin    string
	args   []string
}

func atomicWriteFile(targetPath string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(targetPath)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Chmod(perm); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, targetPath); err != nil {
		return err
	}
	cleanup = false
	return nil
}

func (s *Supervisor) resolveBinary(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("empty binary path")
	}
	if strings.Contains(raw, "/") || filepath.IsAbs(raw) {
		return filepath.Abs(raw)
	}
	resolved, err := exec.LookPath(raw)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

func (s *Supervisor) startProcLocked(spec procSpec, expectedGen uint64) (*procInstance, error) {
	if s.stopped.Load() {
		return nil, ErrStopped
	}
	binPath, err := s.resolveBinary(spec.bin)
	if err != nil {
		return nil, fmt.Errorf("resolve %s binary %q: %w", spec.kernel, spec.bin, err)
	}

	stderrTail := newBoundedBuffer(maxStderrTailBytes)
	cmd := exec.Command(binPath, spec.args...)
	cmd.Dir = s.configsDir
	cmd.Stderr = stderrTail

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s (%s): %w", spec.kernel, binPath, err)
	}

	proc := &procInstance{
		id:         s.nextProcID.Add(1),
		kernel:     spec.kernel,
		cmd:        cmd,
		pid:        cmd.Process.Pid,
		doneCh:     make(chan struct{}),
		startedAt:  time.Now(),
		stderrTail: stderrTail,
	}
	proc.state.Store(procStateStarting)

	s.mu.Lock()
	s.slots[spec.kernel].current = proc
	s.mu.Unlock()

	s.wg.Add(1)
	go s.watchProc(proc, expectedGen)

	return proc, nil
}

func (s *Supervisor) waitStartup(ctx context.Context, proc *procInstance) error {
	grace := s.opts.StartupGrace
	timer := time.NewTimer(grace)
	defer timer.Stop()

	select {
	case <-proc.doneCh:
		detail := proc.stderrTail.String()
		if detail != "" {
			return fmt.Errorf("%s exited during startup (code %d): %s", proc.kernel, proc.exitCode, detail)
		}
		return fmt.Errorf("%s exited during startup (code %d): %v", proc.kernel, proc.exitCode, proc.exitErr)
	case <-s.stopCtx.Done():
		return ErrStopped
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		if proc.state.CompareAndSwap(procStateStarting, procStateRunning) {
			return nil
		}
		<-proc.doneCh
		detail := proc.stderrTail.String()
		if detail != "" {
			return fmt.Errorf("%s exited during startup (code %d): %s", proc.kernel, proc.exitCode, detail)
		}
		return fmt.Errorf("%s exited during startup (code %d): %v", proc.kernel, proc.exitCode, proc.exitErr)
	}
}

func (s *Supervisor) stopProc(ctx context.Context, proc *procInstance) {
	if proc == nil {
		return
	}
	proc.intentionalStop.Store(true)

	select {
	case <-proc.doneCh:
		return
	default:
	}

	if proc.cmd.Process != nil {
		_ = proc.cmd.Process.Signal(syscall.SIGTERM)
	}

	timer := time.NewTimer(s.opts.StopTimeout)
	defer timer.Stop()

	select {
	case <-proc.doneCh:
		return
	case <-timer.C:
	case <-ctx.Done():
	}

	if proc.cmd.Process != nil {
		_ = proc.cmd.Process.Kill()
	}
	<-proc.doneCh
}

func (s *Supervisor) stopKernelSlotLocked(ctx context.Context, kernel string, disableSlot bool) {
	s.mu.Lock()
	slot := s.slots[kernel]
	slot.generation++
	if disableSlot {
		slot.desiredEnabled = false
	}
	slot.backoffAttempt = 0
	proc := slot.current
	if proc != nil {
		proc.intentionalStop.Store(true)
	}
	s.mu.Unlock()

	if proc != nil {
		s.stopProc(ctx, proc)
	}

	s.mu.Lock()
	if slot.current == proc {
		slot.current = nil
	}
	s.mu.Unlock()
}

func (s *Supervisor) watchProc(proc *procInstance, expectedGen uint64) {
	defer s.wg.Done()

	err := proc.cmd.Wait()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	proc.exitErr = err
	proc.exitCode = exitCode
	proc.exited.Store(true)
	close(proc.doneCh)

	if proc.intentionalStop.Load() || s.stopped.Load() {
		return
	}

	if proc.state.CompareAndSwap(procStateStarting, procStateFailedStartup) {
		return
	}

	s.handleCrash(proc, expectedGen)
}

func (s *Supervisor) handleCrash(crashedProc *procInstance, expectedGen uint64) {
	s.mu.Lock()
	slot := s.slots[crashedProc.kernel]
	if slot.generation != expectedGen || !slot.desiredEnabled || s.stopped.Load() || slot.verifyingUpdate {
		if slot.current == crashedProc {
			slot.current = nil
		}
		s.mu.Unlock()
		return
	}
	if slot.current == crashedProc {
		slot.current = nil
	}
	if time.Since(crashedProc.startedAt) >= s.opts.StabilityWindow {
		slot.backoffAttempt = 0
	}
	attempt := slot.backoffAttempt
	slot.backoffAttempt++
	rev := s.currentRevision
	s.mu.Unlock()

	msg := fmt.Sprintf("%s exited unexpectedly (exit code %d)", crashedProc.kernel, crashedProc.exitCode)
	s.emitEvent(protocol.AgentEvent{
		Event:          protocol.EventProcessCrashed,
		ConfigRevision: rev,
		Kernel:         crashedProc.kernel,
		Status:         protocol.EventStatusFailed,
		Message:        msg,
		Detail:         crashedProc.stderrTail.String(),
	})

	for {
		delay := s.computeBackoff(attempt)
		timer := time.NewTimer(delay)
		select {
		case <-s.stopCtx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		if s.stopped.Load() {
			return
		}

		s.opMu.Lock()
		if s.stopped.Load() {
			s.opMu.Unlock()
			return
		}

		s.mu.RLock()
		stillDesired := slot.generation == expectedGen && slot.desiredEnabled && slot.current == nil && s.hasActiveConfig
		cfg := s.activeConfig
		ports := s.activePorts
		s.mu.RUnlock()

		if !stillDesired {
			s.opMu.Unlock()
			return
		}

		spec, err := s.buildProcSpec(crashedProc.kernel, cfg, ports)
		if err != nil {
			s.opMu.Unlock()
			return
		}

		newProc, err := s.startProcLocked(spec, expectedGen)
		if err != nil {
			s.mu.Lock()
			attempt = slot.backoffAttempt
			slot.backoffAttempt++
			rev = s.currentRevision
			s.mu.Unlock()
			s.opMu.Unlock()

			s.emitEvent(protocol.AgentEvent{
				Event:          protocol.EventProcessCrashed,
				ConfigRevision: rev,
				Kernel:         crashedProc.kernel,
				Status:         protocol.EventStatusFailed,
				Message:        fmt.Sprintf("%s restart failed", crashedProc.kernel),
				Detail:         err.Error(),
			})
			continue
		}

		err = s.waitStartup(s.stopCtx, newProc)
		if err == nil {
			s.opMu.Unlock()
			return
		}

		s.stopProc(s.stopCtx, newProc)
		s.mu.Lock()
		if slot.current == newProc {
			slot.current = nil
		}
		stillDesiredAfter := slot.generation == expectedGen && slot.desiredEnabled && !s.stopped.Load()
		attempt = slot.backoffAttempt
		slot.backoffAttempt++
		rev = s.currentRevision
		s.mu.Unlock()
		s.opMu.Unlock()

		if !stillDesiredAfter || errors.Is(err, ErrStopped) {
			return
		}

		s.emitEvent(protocol.AgentEvent{
			Event:          protocol.EventProcessCrashed,
			ConfigRevision: rev,
			Kernel:         crashedProc.kernel,
			Status:         protocol.EventStatusFailed,
			Message:        fmt.Sprintf("%s restart exited during startup", crashedProc.kernel),
			Detail:         err.Error(),
		})
	}
}

func (s *Supervisor) computeBackoff(attempt int) time.Duration {
	if attempt <= 0 {
		return s.opts.CrashBackoffBase
	}
	delay := s.opts.CrashBackoffBase
	for i := 0; i < attempt; i++ {
		if delay >= s.opts.CrashBackoffMax/2 {
			return s.opts.CrashBackoffMax
		}
		delay *= 2
	}
	if delay > s.opts.CrashBackoffMax {
		return s.opts.CrashBackoffMax
	}
	return delay
}

func (s *Supervisor) buildProcSpec(kernel string, cfg protocol.ServerConfigSync, ports resolvedPorts) (procSpec, error) {
	switch kernel {
	case protocol.KernelSnellServer:
		return procSpec{
			kernel: protocol.KernelSnellServer,
			bin:    s.opts.SnellBin,
			args:   []string{"-c", s.snellConf},
		}, nil
	case protocol.KernelShadowTLS:
		args, err := shadowTLSArgs(cfg.Snell, ports.SnellInnerPort)
		if err != nil {
			return procSpec{}, err
		}
		return procSpec{
			kernel: protocol.KernelShadowTLS,
			bin:    s.opts.ShadowTLSBin,
			args:   args,
		}, nil
	case protocol.KernelSingBox:
		return procSpec{
			kernel: protocol.KernelSingBox,
			bin:    s.opts.SingBoxBin,
			args:   []string{"run", "-c", s.singBoxCfg},
		}, nil
	default:
		return procSpec{}, fmt.Errorf("%w: %s", ErrInvalidKernel, kernel)
	}
}

// ProbeVersion executes a kernel binary's version flag(s) and extracts a non-empty version string.
func (s *Supervisor) ProbeVersion(ctx context.Context, kernel string, binPath string) (string, error) {
	if !protocol.IsValidKernel(kernel) {
		return "", fmt.Errorf("%w: %s", ErrInvalidKernel, kernel)
	}

	target := strings.TrimSpace(binPath)
	if target == "" {
		resolved, err := s.BinaryPath(kernel)
		if err != nil {
			return "", err
		}
		target = resolved
	}

	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultProbeTimeout)
		defer cancel()
	}

	var attempts [][]string
	switch kernel {
	case protocol.KernelSingBox:
		attempts = [][]string{{"version"}, {"--version"}, {"-v"}}
	case protocol.KernelShadowTLS:
		attempts = [][]string{{"--version"}, {"-V"}, {"-v"}}
	case protocol.KernelSnellServer:
		attempts = [][]string{{"--version"}, {"-v"}}
	}

	var probeWorkDir string
	if kernel == protocol.KernelSnellServer {
		dir, err := os.MkdirTemp("", "snell-probe-*")
		if err == nil {
			probeWorkDir = dir
			defer os.RemoveAll(dir)
		}
	}

	var lastErr error
	var lastOut string
	for _, args := range attempts {
		stepTimeout := defaultProbeTimeout
		if kernel == protocol.KernelSnellServer {
			stepTimeout = defaultSnellProbeStep
		}
		stepCtx, stepCancel := context.WithTimeout(ctx, stepTimeout)
		cmd := exec.CommandContext(stepCtx, target, args...)
		if probeWorkDir != "" {
			cmd.Dir = probeWorkDir
		}
		outBytes, err := cmd.CombinedOutput()
		stepCancel()

		outStr := strings.TrimSpace(string(outBytes))
		if outStr != "" {
			lastOut = outStr
		}
		if err == nil && outStr != "" {
			return extractCleanVersion(outStr), nil
		}
		if err != nil {
			lastErr = err
		} else {
			lastErr = errors.New("empty version output")
		}
	}

	// Real snell-server binaries may print usage instead of supporting --version/-v.
	if kernel == protocol.KernelSnellServer && looksLikeSnellUsage(lastOut) {
		if v := extractCleanVersion(lastOut); v != "" && cleanVersionRegex.MatchString(" "+v+" ") {
			return v, nil
		}
		if m := semverRegex.FindString(lastOut); m != "" {
			return m, nil
		}
		return "unknown", nil
	}

	if lastOut != "" {
		return "", fmt.Errorf("probe %s version (%s): %w: %s", kernel, target, lastErr, firstNonEmptyLine(lastOut))
	}
	return "", fmt.Errorf("probe %s version (%s): %w", kernel, target, lastErr)
}

var cleanVersionRegex = regexp.MustCompile(`(?:^|[\s(])(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)(?:$|[\s),;])`)

// extractCleanVersion strips binary names, timestamps, and log prefixes from kernel version outputs.
func extractCleanVersion(raw string) string {
	line := firstNonEmptyLine(raw)
	if line == "" {
		return ""
	}
	if m := cleanVersionRegex.FindStringSubmatch(line); len(m) >= 2 && m[1] != "" {
		return m[1]
	}
	if m := cleanVersionRegex.FindStringSubmatch(raw); len(m) >= 2 && m[1] != "" {
		return m[1]
	}
	return line
}

func looksLikeSnellUsage(out string) bool {
	lower := strings.ToLower(out)
	return strings.Contains(lower, "usage:") && (strings.Contains(lower, "snell") || strings.Contains(lower, "-c"))
}

func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return strings.TrimSpace(s)
}

func (s *Supervisor) probeSingBoxVersionOutput(ctx context.Context, target string) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultProbeTimeout)
		defer cancel()
	}

	stepCtx, stepCancel := context.WithTimeout(ctx, defaultProbeTimeout)
	outBytes, err := exec.CommandContext(stepCtx, target, "version").CombinedOutput()
	stepCancel()
	outStr := strings.TrimSpace(string(outBytes))
	if err == nil && outStr != "" {
		return outStr, nil
	}

	return s.ProbeVersion(ctx, protocol.KernelSingBox, target)
}

func (s *Supervisor) detectSingBoxCapabilities(ctx context.Context) (useTypedDNS bool, hasV2RayAPI bool) {
	resolved, err := s.resolveBinary(s.opts.SingBoxBin)
	if err != nil {
		return false, true
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return false, true
	}

	s.versionCacheMu.Lock()
	if s.versionCache != nil &&
		s.versionCache.path == resolved &&
		s.versionCache.modTime.Equal(info.ModTime()) &&
		s.versionCache.size == info.Size() {
		useTyped := s.versionCache.useTyped
		hasV2Ray := s.versionCache.hasV2RayAPI
		s.versionCacheMu.Unlock()
		return useTyped, hasV2Ray
	}
	s.versionCacheMu.Unlock()

	fullOut, err := s.probeSingBoxVersionOutput(ctx, resolved)
	useTyped := false
	hasV2Ray := true
	ver := ""
	if err == nil {
		ver = firstNonEmptyLine(fullOut)
		useTyped = parseSingBoxVersionGTE112(ver)
		hasV2Ray = parseSingBoxHasV2RayAPI(fullOut)
	}

	s.versionCacheMu.Lock()
	s.versionCache = &versionCacheEntry{
		path:        resolved,
		modTime:     info.ModTime(),
		size:        info.Size(),
		version:     ver,
		useTyped:    useTyped,
		hasV2RayAPI: hasV2Ray,
	}
	s.versionCacheMu.Unlock()

	return useTyped, hasV2Ray
}

func (s *Supervisor) detectSingBoxTypedDNS(ctx context.Context) bool {
	useTyped, _ := s.detectSingBoxCapabilities(ctx)
	return useTyped
}
