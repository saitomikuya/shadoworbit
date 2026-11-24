package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"snell-panel/internal/protocol"
)

const rollbackTimeout = 15 * time.Second

// Start initializes the supervisor directories and validates it has not been stopped.
func (s *Supervisor) Start(ctx context.Context) error {
	if s.stopped.Load() {
		return ErrStopped
	}
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	if err := os.MkdirAll(s.configsDir, 0o750); err != nil {
		return fmt.Errorf("supervisor: create configs dir: %w", err)
	}
	if err := os.MkdirAll(s.tmpDir, 0o750); err != nil {
		return fmt.Errorf("supervisor: create tmp dir: %w", err)
	}
	return nil
}

// Stop shuts down all supervised kernel processes cleanly and waits for watcher goroutines to exit.
func (s *Supervisor) Stop(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	s.stopped.Store(true)
	s.stopCancel()

	s.opMu.Lock()
	var procs []*procInstance
	s.mu.Lock()
	for _, k := range []string{protocol.KernelShadowTLS, protocol.KernelSnellServer, protocol.KernelSingBox} {
		slot := s.slots[k]
		slot.generation++
		slot.desiredEnabled = false
		slot.backoffAttempt = 0
		if slot.current != nil {
			slot.current.intentionalStop.Store(true)
			procs = append(procs, slot.current)
		}
	}
	s.mu.Unlock()

	for _, p := range procs {
		s.stopProc(ctx, p)
	}

	s.mu.Lock()
	for _, slot := range s.slots {
		slot.current = nil
	}
	s.mu.Unlock()
	s.opMu.Unlock()

	s.wg.Wait()
	return nil
}

// ApplyConfig validates, stages, and applies a configuration snapshot with physical channel isolation and rollback.
func (s *Supervisor) ApplyConfig(ctx context.Context, cfg protocol.ServerConfigSync) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if s.stopped.Load() {
		return ErrStopped
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.stopped.Load() {
		return ErrStopped
	}

	cloned := cloneConfig(cfg)

	s.mu.RLock()
	hasPrev := s.hasActiveConfig
	prevCfg := cloneConfig(s.activeConfig)
	prevPorts := s.activePorts
	prevRev := s.currentRevision
	prevAdminFP := s.activeAdminFP
	prevSSFP := s.activeSSFP
	prevSingBoxV2RayAPI := s.activeSingBoxV2RayAPI
	s.mu.RUnlock()

	ports, err := validateAndResolve(cloned, s.opts, prevPorts, hasPrev)
	if err != nil {
		s.emitEvent(protocol.AgentEvent{
			Event:          protocol.EventConfigError,
			ConfigRevision: cloned.ConfigRevision,
			Kernel:         validationErrKernel(err),
			Status:         protocol.EventStatusFailed,
			Message:        "config validation failed",
			Detail:         err.Error(),
		})
		return err
	}

	var snellBytes []byte
	var nextAdminFP adminFingerprint
	if cloned.Snell.Enabled {
		snellStr := renderSnellConf(cloned, ports.EffectiveDNSPort, ports.SnellInnerPort)
		snellBytes = []byte(snellStr)
		stlsArgs, err := shadowTLSArgs(cloned.Snell, ports.SnellInnerPort)
		if err != nil {
			s.emitEvent(protocol.AgentEvent{
				Event:          protocol.EventConfigError,
				ConfigRevision: cloned.ConfigRevision,
				Kernel:         protocol.KernelShadowTLS,
				Status:         protocol.EventStatusFailed,
				Message:        "shadow-tls config render failed",
				Detail:         err.Error(),
			})
			return err
		}
		nextAdminFP = adminFingerprint{
			Enabled:       true,
			SnellConf:     snellStr,
			ShadowTLSArgs: strings.Join(stlsArgs, "\x00"),
			SnellBin:      s.opts.SnellBin,
			ShadowTLSBin:  s.opts.ShadowTLSBin,
		}
	}

	var singBoxBytes []byte
	var nextSSFP ssFingerprint
	var hasV2RayAPI bool
	if cloned.SS.Enabled {
		var useTypedDNS bool
		useTypedDNS, hasV2RayAPI = s.detectSingBoxCapabilities(ctx)
		singBoxBytes, err = renderSingBoxJSON(cloned.SS, ports.EffectiveDNSPort, ports.StatsPort, ports.SSInnerTCPPort, useTypedDNS, hasV2RayAPI)
		if err != nil {
			s.emitEvent(protocol.AgentEvent{
				Event:          protocol.EventConfigError,
				ConfigRevision: cloned.ConfigRevision,
				Kernel:         protocol.KernelSingBox,
				Status:         protocol.EventStatusFailed,
				Message:        "sing-box config render failed",
				Detail:         err.Error(),
			})
			return err
		}
		nextSSFP = ssFingerprint{
			Enabled:     true,
			SingBoxJSON: string(singBoxBytes),
			SingBoxBin:  s.opts.SingBoxBin,
		}
	}

	s.mu.RLock()
	snellAlive := s.isSlotAliveLocked(protocol.KernelSnellServer)
	stlsAlive := s.isSlotAliveLocked(protocol.KernelShadowTLS)
	sbAlive := s.isSlotAliveLocked(protocol.KernelSingBox)
	snellDesired := s.slots[protocol.KernelSnellServer].desiredEnabled
	stlsDesired := s.slots[protocol.KernelShadowTLS].desiredEnabled
	sbDesired := s.slots[protocol.KernelSingBox].desiredEnabled
	s.mu.RUnlock()

	var adminChanged bool
	if !cloned.Snell.Enabled {
		adminChanged = snellAlive || stlsAlive || snellDesired || stlsDesired
	} else {
		adminChanged = !hasPrev || prevAdminFP != nextAdminFP || !snellAlive || !stlsAlive
	}

	var ssChanged bool
	if !cloned.SS.Enabled {
		ssChanged = sbAlive || sbDesired
	} else {
		ssChanged = !hasPrev || prevSSFP != nextSSFP || !sbAlive
	}

	if err := s.runStagedValidation(ctx, cloned, adminChanged, ssChanged, snellBytes, singBoxBytes); err != nil {
		s.emitEvent(protocol.AgentEvent{
			Event:          protocol.EventConfigError,
			ConfigRevision: cloned.ConfigRevision,
			Kernel:         validationErrKernel(err),
			Status:         protocol.EventStatusFailed,
			Message:        "staged config validation failed",
			Detail:         err.Error(),
		})
		return err
	}

	if !adminChanged && !ssChanged {
		s.mu.Lock()
		s.hasActiveConfig = true
		s.activeConfig = cloned
		s.activePorts = ports
		s.currentRevision = cloned.ConfigRevision
		s.activeAdminFP = nextAdminFP
		s.activeSSFP = nextSSFP
		s.activeSingBoxV2RayAPI = cloned.SS.Enabled && hasV2RayAPI
		s.mu.Unlock()

		s.emitEvent(protocol.AgentEvent{
			Event:          protocol.EventConfigApplied,
			ConfigRevision: cloned.ConfigRevision,
			Status:         protocol.EventStatusSuccess,
			Message:        "configuration applied",
		})
		return nil
	}

	var prevSnellBytes []byte
	var prevSnellExists bool
	if adminChanged {
		if b, readErr := os.ReadFile(s.snellConf); readErr == nil {
			prevSnellBytes = b
			prevSnellExists = true
		}
	}

	var prevSingBoxBytes []byte
	var prevSingBoxExists bool
	if ssChanged {
		if b, readErr := os.ReadFile(s.singBoxCfg); readErr == nil {
			prevSingBoxBytes = b
			prevSingBoxExists = true
		}
	}

	// Stop old processes of changed channels first (port-swap safety).
	if adminChanged {
		s.stopKernelSlotLocked(ctx, protocol.KernelShadowTLS, true)
		s.stopKernelSlotLocked(ctx, protocol.KernelSnellServer, true)
	}
	if ssChanged {
		s.stopKernelSlotLocked(ctx, protocol.KernelSingBox, true)
	}

	rollback := func(failedKernel string, cause error) error {
		rbCtx, rbCancel := context.WithTimeout(s.stopCtx, rollbackTimeout)
		defer rbCancel()

		var rbErrs []string

		if adminChanged {
			s.stopKernelSlotLocked(rbCtx, protocol.KernelShadowTLS, true)
			s.stopKernelSlotLocked(rbCtx, protocol.KernelSnellServer, true)
			if prevSnellExists {
				if err := atomicWriteFile(s.snellConf, prevSnellBytes, 0o600); err != nil {
					rbErrs = append(rbErrs, fmt.Sprintf("restore snell-server.conf: %v", err))
				}
			} else {
				if err := os.Remove(s.snellConf); err != nil && !errors.Is(err, os.ErrNotExist) {
					rbErrs = append(rbErrs, fmt.Sprintf("remove snell-server.conf: %v", err))
				}
			}
			if hasPrev && prevCfg.Snell.Enabled && !s.stopped.Load() {
				if err := s.startAndVerifySlotLocked(rbCtx, protocol.KernelSnellServer, prevCfg, prevPorts); err != nil {
					rbErrs = append(rbErrs, fmt.Sprintf("rollback start %s: %v", protocol.KernelSnellServer, err))
				} else if err := s.startAndVerifySlotLocked(rbCtx, protocol.KernelShadowTLS, prevCfg, prevPorts); err != nil {
					rbErrs = append(rbErrs, fmt.Sprintf("rollback start %s: %v", protocol.KernelShadowTLS, err))
					s.stopKernelSlotLocked(rbCtx, protocol.KernelSnellServer, true)
				}
			}
		}

		if ssChanged {
			s.stopKernelSlotLocked(rbCtx, protocol.KernelSingBox, true)
			if prevSingBoxExists {
				if err := atomicWriteFile(s.singBoxCfg, prevSingBoxBytes, 0o600); err != nil {
					rbErrs = append(rbErrs, fmt.Sprintf("restore sing-box.json: %v", err))
				}
			} else {
				if err := os.Remove(s.singBoxCfg); err != nil && !errors.Is(err, os.ErrNotExist) {
					rbErrs = append(rbErrs, fmt.Sprintf("remove sing-box.json: %v", err))
				}
			}
			if hasPrev && prevCfg.SS.Enabled && !s.stopped.Load() {
				if err := s.startAndVerifySlotLocked(rbCtx, protocol.KernelSingBox, prevCfg, prevPorts); err != nil {
					rbErrs = append(rbErrs, fmt.Sprintf("rollback start %s: %v", protocol.KernelSingBox, err))
				}
			}
		}

		s.mu.Lock()
		s.hasActiveConfig = hasPrev
		if hasPrev {
			s.activeConfig = prevCfg
			s.activePorts = prevPorts
			s.currentRevision = prevRev
			s.activeAdminFP = prevAdminFP
			s.activeSSFP = prevSSFP
			s.activeSingBoxV2RayAPI = prevSingBoxV2RayAPI
		} else {
			s.activeSingBoxV2RayAPI = false
		}
		s.mu.Unlock()

		detail := cause.Error()
		if len(rbErrs) > 0 {
			detail = fmt.Sprintf("%s; rollback errors: %s", detail, strings.Join(rbErrs, "; "))
		}

		s.emitEvent(protocol.AgentEvent{
			Event:          protocol.EventConfigError,
			ConfigRevision: cloned.ConfigRevision,
			Kernel:         failedKernel,
			Status:         protocol.EventStatusFailed,
			Message:        fmt.Sprintf("%s failed startup and rolled back", failedKernel),
			Detail:         detail,
		})
		return cause
	}

	if adminChanged && cloned.Snell.Enabled {
		if err := atomicWriteFile(s.snellConf, snellBytes, 0o600); err != nil {
			return rollback(protocol.KernelSnellServer, fmt.Errorf("write snell-server.conf: %w", err))
		}
	}
	if ssChanged && cloned.SS.Enabled {
		if err := atomicWriteFile(s.singBoxCfg, singBoxBytes, 0o600); err != nil {
			return rollback(protocol.KernelSingBox, fmt.Errorf("write sing-box.json: %w", err))
		}
	}

	if adminChanged && cloned.Snell.Enabled {
		if err := s.startAndVerifySlotLocked(ctx, protocol.KernelSnellServer, cloned, ports); err != nil {
			return rollback(protocol.KernelSnellServer, err)
		}
		if err := s.startAndVerifySlotLocked(ctx, protocol.KernelShadowTLS, cloned, ports); err != nil {
			return rollback(protocol.KernelShadowTLS, err)
		}
	}
	if ssChanged && cloned.SS.Enabled {
		if err := s.startAndVerifySlotLocked(ctx, protocol.KernelSingBox, cloned, ports); err != nil {
			return rollback(protocol.KernelSingBox, err)
		}
	}

	s.mu.Lock()
	s.hasActiveConfig = true
	s.activeConfig = cloned
	s.activePorts = ports
	s.currentRevision = cloned.ConfigRevision
	s.activeAdminFP = nextAdminFP
	s.activeSSFP = nextSSFP
	s.activeSingBoxV2RayAPI = cloned.SS.Enabled && hasV2RayAPI
	s.mu.Unlock()

	s.emitEvent(protocol.AgentEvent{
		Event:          protocol.EventConfigApplied,
		ConfigRevision: cloned.ConfigRevision,
		Status:         protocol.EventStatusSuccess,
		Message:        "configuration applied",
	})
	return nil
}

// ServiceControl executes an isolated restart action (`restart_snell`, `restart_singbox`, `restart_all`).
func (s *Supervisor) ServiceControl(ctx context.Context, action string) error {
	if !protocol.IsValidServiceAction(action) {
		return fmt.Errorf("%w: %s", ErrInvalidServiceAction, action)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.stopped.Load() {
		return ErrStopped
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.stopped.Load() {
		return ErrStopped
	}

	s.mu.RLock()
	hasActive := s.hasActiveConfig
	cfg := cloneConfig(s.activeConfig)
	ports := s.activePorts
	s.mu.RUnlock()

	if !hasActive {
		return ErrNoActiveConfig
	}

	restartAdmin := func() error {
		s.stopKernelSlotLocked(ctx, protocol.KernelShadowTLS, true)
		s.stopKernelSlotLocked(ctx, protocol.KernelSnellServer, true)
		if !cfg.Snell.Enabled {
			return nil
		}
		if err := s.startAndVerifySlotLocked(ctx, protocol.KernelSnellServer, cfg, ports); err != nil {
			return err
		}
		if err := s.startAndVerifySlotLocked(ctx, protocol.KernelShadowTLS, cfg, ports); err != nil {
			s.stopKernelSlotLocked(ctx, protocol.KernelSnellServer, true)
			return err
		}
		return nil
	}

	restartSingBox := func() error {
		if !cfg.SS.Enabled {
			s.stopKernelSlotLocked(ctx, protocol.KernelSingBox, true)
			return nil
		}
		return s.restartSingBoxLocked(ctx, cfg, ports)
	}

	switch action {
	case protocol.ServiceActionRestartSnell:
		return restartAdmin()
	case protocol.ServiceActionRestartSingBox:
		return restartSingBox()
	case protocol.ServiceActionRestartAll:
		if err := restartAdmin(); err != nil {
			return err
		}
		return restartSingBox()
	default:
		return fmt.Errorf("%w: %s", ErrInvalidServiceAction, action)
	}
}

// Health returns a snapshot of kernel process liveness.
func (s *Supervisor) Health() protocol.AgentHealth {
	return protocol.AgentHealth{
		Snell:     s.IsKernelHealthy(protocol.KernelSnellServer),
		ShadowTLS: s.IsKernelHealthy(protocol.KernelShadowTLS),
		SingBox:   s.IsKernelHealthy(protocol.KernelSingBox),
	}
}

// Versions probes all managed kernel binaries best-effort and returns AgentVersions.
func (s *Supervisor) Versions(ctx context.Context) protocol.AgentVersions {
	probe := func(kernel string) string {
		v, err := s.ProbeVersion(ctx, kernel, "")
		if err != nil || strings.TrimSpace(v) == "" {
			return "unknown"
		}
		return v
	}
	return protocol.AgentVersions{
		SingBox:     probe(protocol.KernelSingBox),
		SnellServer: probe(protocol.KernelSnellServer),
		ShadowTLS:   probe(protocol.KernelShadowTLS),
	}
}

// StopKernel cleanly stops a single kernel process without triggering crash recovery.
func (s *Supervisor) StopKernel(ctx context.Context, kernel string) error {
	if !protocol.IsValidKernel(kernel) {
		return fmt.Errorf("%w: %s", ErrInvalidKernel, kernel)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.stopped.Load() {
		return ErrStopped
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.stopped.Load() {
		return ErrStopped
	}

	s.stopKernelSlotLocked(ctx, kernel, true)
	return nil
}

// StartKernel starts an enabled kernel process using the active configuration.
func (s *Supervisor) StartKernel(ctx context.Context, kernel string) error {
	if !protocol.IsValidKernel(kernel) {
		return fmt.Errorf("%w: %s", ErrInvalidKernel, kernel)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.stopped.Load() {
		return ErrStopped
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.stopped.Load() {
		return ErrStopped
	}

	s.mu.RLock()
	hasActive := s.hasActiveConfig
	cfg := cloneConfig(s.activeConfig)
	ports := s.activePorts
	alive := s.isSlotAliveLocked(kernel)
	s.mu.RUnlock()

	if !hasActive {
		return ErrNoActiveConfig
	}
	if !isKernelConfigEnabled(cfg, kernel) {
		return fmt.Errorf("%w: %s", ErrKernelDisabled, kernel)
	}
	if alive {
		s.mu.Lock()
		s.slots[kernel].desiredEnabled = true
		s.mu.Unlock()
		return nil
	}

	return s.startAndVerifySlotLocked(ctx, kernel, cfg, ports)
}

// BeginKernelUpdateVerification marks a kernel slot as undergoing post-update health verification,
// suppressing spurious process_crashed events and background crash-backoff restarts during the window.
func (s *Supervisor) BeginKernelUpdateVerification(kernel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot, ok := s.slots[kernel]; ok {
		slot.verifyingUpdate = true
	}
}

// EndKernelUpdateVerification clears the post-update verification guard for a kernel slot.
func (s *Supervisor) EndKernelUpdateVerification(kernel string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot, ok := s.slots[kernel]; ok {
		slot.verifyingUpdate = false
	}
}

// RestartKernel stops and restarts a single enabled kernel process.
func (s *Supervisor) RestartKernel(ctx context.Context, kernel string) error {
	if !protocol.IsValidKernel(kernel) {
		return fmt.Errorf("%w: %s", ErrInvalidKernel, kernel)
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if s.stopped.Load() {
		return ErrStopped
	}

	s.opMu.Lock()
	defer s.opMu.Unlock()

	if s.stopped.Load() {
		return ErrStopped
	}

	s.mu.RLock()
	hasActive := s.hasActiveConfig
	cfg := cloneConfig(s.activeConfig)
	ports := s.activePorts
	s.mu.RUnlock()

	if !hasActive {
		return &kernelInactiveError{
			err:    ErrNoActiveConfig,
			reason: "unconfigured",
		}
	}
	if !isKernelConfigEnabled(cfg, kernel) {
		s.stopKernelSlotLocked(ctx, kernel, true)
		return &kernelInactiveError{
			err:    fmt.Errorf("%w: %s", ErrKernelDisabled, kernel),
			reason: "disabled",
		}
	}

	if kernel == protocol.KernelSingBox {
		return s.restartSingBoxLocked(ctx, cfg, ports)
	}

	s.stopKernelSlotLocked(ctx, kernel, true)
	return s.startAndVerifySlotLocked(ctx, kernel, cfg, ports)
}

func (s *Supervisor) restartSingBoxLocked(ctx context.Context, cfg protocol.ServerConfigSync, ports resolvedPorts) error {
	s.stopKernelSlotLocked(ctx, protocol.KernelSingBox, true)

	// Always re-probe the current sing-box binary on disk so cross-major updates/rollbacks
	// (<1.12 legacy DNS vs >=1.12 typed DNS) render matching sing-box.json syntax.
	s.versionCacheMu.Lock()
	s.versionCache = nil
	s.versionCacheMu.Unlock()

	useTypedDNS, hasV2RayAPI := s.detectSingBoxCapabilities(ctx)
	singBoxBytes, err := renderSingBoxJSON(cfg.SS, ports.EffectiveDNSPort, ports.StatsPort, ports.SSInnerTCPPort, useTypedDNS, hasV2RayAPI)
	if err != nil {
		return fmt.Errorf("render sing-box.json on restart: %w", err)
	}

	var prevSingBoxBytes []byte
	var prevSingBoxExists bool
	if b, readErr := os.ReadFile(s.singBoxCfg); readErr == nil {
		prevSingBoxBytes = b
		prevSingBoxExists = true
	}

	if err := atomicWriteFile(s.singBoxCfg, singBoxBytes, 0o600); err != nil {
		return fmt.Errorf("write sing-box.json on restart: %w", err)
	}

	if err := s.startAndVerifySlotLocked(ctx, protocol.KernelSingBox, cfg, ports); err != nil {
		if prevSingBoxExists {
			_ = atomicWriteFile(s.singBoxCfg, prevSingBoxBytes, 0o600)
		}
		return err
	}

	s.mu.Lock()
	s.activeSSFP = ssFingerprint{
		Enabled:     true,
		SingBoxJSON: string(singBoxBytes),
		SingBoxBin:  s.opts.SingBoxBin,
	}
	s.activeSingBoxV2RayAPI = hasV2RayAPI
	s.mu.Unlock()
	return nil
}

// BinaryPath returns the resolved filesystem path for a managed kernel binary.
func (s *Supervisor) BinaryPath(kernel string) (string, error) {
	var raw string
	switch kernel {
	case protocol.KernelSnellServer:
		raw = s.opts.SnellBin
	case protocol.KernelShadowTLS:
		raw = s.opts.ShadowTLSBin
	case protocol.KernelSingBox:
		raw = s.opts.SingBoxBin
	default:
		return "", fmt.Errorf("%w: %s", ErrInvalidKernel, kernel)
	}
	resolved, err := s.resolveBinary(raw)
	if err != nil {
		return "", fmt.Errorf("resolve %s binary %q: %w", kernel, raw, err)
	}
	return resolved, nil
}

// ListenAddrs returns TCP-dialable 127.0.0.1:<port> endpoints for an enabled kernel.
func (s *Supervisor) ListenAddrs(kernel string) []string {
	if s.stopped.Load() {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.stopped.Load() || !s.hasActiveConfig {
		return nil
	}

	switch kernel {
	case protocol.KernelSnellServer:
		if !s.activeConfig.Snell.Enabled {
			return nil
		}
		return []string{fmt.Sprintf("127.0.0.1:%d", s.activePorts.SnellInnerPort)}
	case protocol.KernelShadowTLS:
		if !s.activeConfig.Snell.Enabled {
			return nil
		}
		return []string{fmt.Sprintf("127.0.0.1:%d", s.activeConfig.Snell.PublicPort)}
	case protocol.KernelSingBox:
		if !s.activeConfig.SS.Enabled {
			return nil
		}
		addrs := []string{fmt.Sprintf("127.0.0.1:%d", s.activeConfig.SS.TCPPort)}
		if s.activeSingBoxV2RayAPI {
			addrs = append(addrs, fmt.Sprintf("127.0.0.1:%d", s.activePorts.StatsPort))
		}
		return addrs
	default:
		return nil
	}
}

// SingBoxV2RayAPIEnabled reports whether the active sing-box instance was rendered with experimental.v2ray_api enabled.
func (s *Supervisor) SingBoxV2RayAPIEnabled() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasActiveConfig && s.activeConfig.SS.Enabled && s.activeSingBoxV2RayAPI
}

// IsKernelHealthy reports whether the given kernel process is currently alive and verified running.
func (s *Supervisor) IsKernelHealthy(kernel string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slot, ok := s.slots[kernel]
	if !ok || slot.current == nil {
		return false
	}
	return !slot.current.exited.Load() && slot.current.state.Load() == procStateRunning
}

// KernelPID returns the live OS PID for the given kernel process, or 0 if not running.
func (s *Supervisor) KernelPID(kernel string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	slot, ok := s.slots[kernel]
	if !ok || slot.current == nil || slot.current.exited.Load() {
		return 0
	}
	return slot.current.pid
}

func (s *Supervisor) isSlotAliveLocked(kernel string) bool {
	slot, ok := s.slots[kernel]
	if !ok || slot.current == nil {
		return false
	}
	return !slot.current.exited.Load()
}

func (s *Supervisor) startAndVerifySlotLocked(ctx context.Context, kernel string, cfg protocol.ServerConfigSync, ports resolvedPorts) error {
	spec, err := s.buildProcSpec(kernel, cfg, ports)
	if err != nil {
		return err
	}

	s.mu.Lock()
	slot := s.slots[kernel]
	slot.generation++
	slot.desiredEnabled = true
	slot.backoffAttempt = 0
	gen := slot.generation
	s.mu.Unlock()

	proc, err := s.startProcLocked(spec, gen)
	if err != nil {
		s.mu.Lock()
		slot.desiredEnabled = false
		s.mu.Unlock()
		return err
	}

	if err := s.waitStartup(ctx, proc); err != nil {
		s.stopKernelSlotLocked(ctx, kernel, true)
		return err
	}
	return nil
}

func (s *Supervisor) emitEvent(ev protocol.AgentEvent) {
	if s.opts.OnEvent != nil {
		s.opts.OnEvent(ev)
	}
}

func isKernelConfigEnabled(cfg protocol.ServerConfigSync, kernel string) bool {
	switch kernel {
	case protocol.KernelSnellServer, protocol.KernelShadowTLS:
		return cfg.Snell.Enabled
	case protocol.KernelSingBox:
		return cfg.SS.Enabled
	default:
		return false
	}
}

func cloneConfig(cfg protocol.ServerConfigSync) protocol.ServerConfigSync {
	out := cfg
	if cfg.SS.Users != nil {
		out.SS.Users = make([]protocol.SSUserEntry, len(cfg.SS.Users))
		copy(out.SS.Users, cfg.SS.Users)
	}
	if cfg.DNS.Rules != nil {
		out.DNS.Rules = make([]string, len(cfg.DNS.Rules))
		copy(out.DNS.Rules, cfg.DNS.Rules)
	}
	return out
}

// Keep unused error reference check clear if external callers use errors.Is.
var _ = errors.Is
