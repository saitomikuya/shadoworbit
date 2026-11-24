package supervisor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"snell-panel/internal/protocol"
)

func TestPreApplyValidationFailureAndRollback(t *testing.T) {
	env := newHelperEnv(t)
	env.setBehavior(protocol.KernelSingBox, helperBehavior{
		VersionOut:        "sing-box version 1.11.4",
		CheckRejectSubstr: "REJECT_THIS_SNI",
	})
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, nil)
	ctx := context.Background()

	cfg1 := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg1); err != nil {
		t.Fatalf("ApplyConfig v1 failed: %v", err)
	}

	snellPID1 := kernelPID(t, sup, protocol.KernelSnellServer)
	stlsPID1 := kernelPID(t, sup, protocol.KernelShadowTLS)
	sbPID1 := kernelPID(t, sup, protocol.KernelSingBox)
	origSBBytes, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}

	// 1. Structural error -> zero side effects.
	badStruct := cfg1
	badStruct.ConfigRevision = 2
	badStruct.SS.UDPPort = cfg1.DNS.LocalPort
	if err := sup.ApplyConfig(ctx, badStruct); err == nil {
		t.Fatal("expected structural validation failure")
	}

	// 2. sing-box check -c failure -> zero side effects, active config and PIDs preserved.
	badCheck := cfg1
	badCheck.ConfigRevision = 3
	badCheck.SS.STLSSNI = "REJECT_THIS_SNI.example.com"
	if err := sup.ApplyConfig(ctx, badCheck); err == nil {
		t.Fatal("expected sing-box check -c failure")
	}

	if kernelPID(t, sup, protocol.KernelSnellServer) != snellPID1 ||
		kernelPID(t, sup, protocol.KernelShadowTLS) != stlsPID1 ||
		kernelPID(t, sup, protocol.KernelSingBox) != sbPID1 {
		t.Fatal("pre-apply validation failure must not touch running processes")
	}
	afterSBBytes, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(afterSBBytes) != string(origSBBytes) {
		t.Fatal("pre-apply validation failure mutated sing-box.json")
	}

	// 3. Custom Validator hook failure.
	supCustom := newTestSupervisor(t, newHelperEnv(t), rec, func(o *Options) {
		o.Validator = func(ctx context.Context, kernel, configPath string) error {
			if kernel == protocol.KernelSnellServer {
				return errors.New("custom snell reject")
			}
			return nil
		}
	})
	if err := supCustom.ApplyConfig(ctx, cfg1); err == nil {
		t.Fatal("expected custom Validator failure")
	}

	if rec.countEvent(protocol.EventConfigError) < 3 {
		t.Fatalf("expected config_error events emitted, got: %+v", rec.snapshot())
	}
}

func TestStartupFailureRollback(t *testing.T) {
	t.Run("sing-box startup crash rolls back SS only without touching Snell", func(t *testing.T) {
		env := newHelperEnv(t)
		env.setBehavior(protocol.KernelSingBox, helperBehavior{
			VersionOut:          "sing-box version 1.11.4",
			CrashOnConfigSubstr: "CRASH_ME_SNI",
			CrashStderr:         "fatal bind failure in sing-box v2",
		})
		rec := &eventRecorder{}
		sup := newTestSupervisor(t, env, rec, func(o *Options) {
			o.StartupGrace = 1500 * time.Millisecond
		})
		ctx := context.Background()

		cfg1 := testSyncConfig(t)
		if err := sup.ApplyConfig(ctx, cfg1); err != nil {
			t.Fatalf("ApplyConfig v1 failed: %v", err)
		}
		waitUntil(t, 10*time.Second, "initial start invocation events for v1", func() bool {
			return len(env.startEvents(protocol.KernelSnellServer)) == 1 &&
				len(env.startEvents(protocol.KernelShadowTLS)) == 1 &&
				len(env.startEvents(protocol.KernelSingBox)) == 1
		})

		snellPID1 := kernelPID(t, sup, protocol.KernelSnellServer)
		stlsPID1 := kernelPID(t, sup, protocol.KernelShadowTLS)
		origSBBytes, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "sing-box.json"))
		if err != nil {
			t.Fatal(err)
		}

		cfg2 := cfg1
		cfg2.ConfigRevision = 2
		cfg2.SS.STLSSNI = "CRASH_ME_SNI.example.com"
		err = sup.ApplyConfig(ctx, cfg2)
		if err == nil {
			t.Fatal("expected ApplyConfig v2 to fail startup")
		}

		// Snell + ShadowTLS MUST remain untouched (identical PIDs and 1 start count).
		if kernelPID(t, sup, protocol.KernelSnellServer) != snellPID1 || kernelPID(t, sup, protocol.KernelShadowTLS) != stlsPID1 {
			t.Fatal("sing-box startup rollback must NEVER touch snell-server or shadow-tls")
		}
		if len(env.startEvents(protocol.KernelSnellServer)) != 1 || len(env.startEvents(protocol.KernelShadowTLS)) != 1 {
			t.Fatal("unexpected restart of admin channel during SS rollback")
		}

		// sing-box rolled back to v1 config and restarted cleanly.
		restoredBytes, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "sing-box.json"))
		if err != nil {
			t.Fatal(err)
		}
		if string(restoredBytes) != string(origSBBytes) {
			t.Fatal("sing-box.json was not restored on startup rollback")
		}
		h := sup.Health()
		if !h.Snell || !h.ShadowTLS || !h.SingBox {
			t.Fatalf("expected all 3 healthy after rollback, got: %+v", h)
		}
		if rec.countEvent(protocol.EventProcessCrashed) != 0 {
			t.Fatalf("startup rollback must not emit spurious process_crashed: %+v", rec.snapshot())
		}
		events := rec.snapshot()
		lastEv := events[len(events)-1]
		if lastEv.Event != protocol.EventConfigError || lastEv.Kernel != protocol.KernelSingBox || lastEv.ConfigRevision != 2 {
			t.Fatalf("unexpected rollback event: %+v", lastEv)
		}
	})

	t.Run("shadow-tls startup crash rolls back admin channel without touching sing-box", func(t *testing.T) {
		env := newHelperEnv(t)
		rec := &eventRecorder{}
		sup := newTestSupervisor(t, env, rec, func(o *Options) {
			o.StartupGrace = 1500 * time.Millisecond
		})
		ctx := context.Background()

		cfg1 := testSyncConfig(t)
		if err := sup.ApplyConfig(ctx, cfg1); err != nil {
			t.Fatalf("ApplyConfig v1 failed: %v", err)
		}
		sbPID1 := kernelPID(t, sup, protocol.KernelSingBox)
		origSnellConf, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "snell-server.conf"))
		if err != nil {
			t.Fatal(err)
		}

		// Break shadow-tls on next start via CrashOnStart, then clear after ApplyConfig fails?
		// Better: use Snell.STLSPassword via a custom Check? Shadow-tls receives args, so use CrashOnStart and verify rollback?
		// Wait: if CrashOnStart is true for shadow-tls during rollback, rollback itself can't restart shadow-tls unless we clear CrashOnStart, OR we inspect args/behavior.
		// To make shadow-tls fail ONLY v2 and succeed rollback v1, flip behavior right when snell-server starts or use Snell.Enabled=false->true!
		// Even better: test Snell.Enabled=false -> Snell.Enabled=true with CrashOnStart=true, so rollback keeps Snell stopped and sing-box untouched!
		cfgDisabled := cfg1
		cfgDisabled.ConfigRevision = 2
		cfgDisabled.Snell.Enabled = false
		if err := sup.ApplyConfig(ctx, cfgDisabled); err != nil {
			t.Fatalf("disable snell failed: %v", err)
		}
		_ = origSnellConf

		env.setBehavior(protocol.KernelShadowTLS, helperBehavior{
			VersionOut:   "shadow-tls 0.2.25",
			CrashOnStart: true,
			CrashStderr:  "shadow-tls v2 fail",
		})
		cfgEnableFail := cfg1
		cfgEnableFail.ConfigRevision = 3
		if err := sup.ApplyConfig(ctx, cfgEnableFail); err == nil {
			t.Fatal("expected shadow-tls startup crash")
		}

		if kernelPID(t, sup, protocol.KernelSingBox) != sbPID1 {
			t.Fatal("shadow-tls rollback touched sing-box")
		}
		h := sup.Health()
		if h.Snell || h.ShadowTLS || !h.SingBox {
			t.Fatalf("expected Snell+ShadowTLS stopped and SingBox running after rollback, got: %+v", h)
		}
	})
}

func TestCrashDetectionStderrCaptureAndBackoff(t *testing.T) {
	env := newHelperEnv(t)
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, func(o *Options) {
		o.CrashBackoffBase = 60 * time.Millisecond
		o.CrashBackoffMax = 240 * time.Millisecond
	})
	ctx := context.Background()

	cfg := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	origPID := kernelPID(t, sup, protocol.KernelSingBox)
	if origPID == 0 {
		t.Fatal("expected non-zero sing-box PID")
	}

	// Write something to sing-box stderr? Note: SIGKILL produces exit code -1/non-zero;
	// verify process_crashed is emitted and auto-restart succeeds with new PID.
	if err := syscall.Kill(origPID, syscall.SIGKILL); err != nil {
		t.Fatalf("kill sing-box failed: %v", err)
	}

	waitUntil(t, 5*time.Second, "sing-box crash event and auto-restart", func() bool {
		newPID := kernelPID(t, sup, protocol.KernelSingBox)
		return rec.countEvent(protocol.EventProcessCrashed) >= 1 && newPID != 0 && newPID != origPID && sup.IsKernelHealthy(protocol.KernelSingBox)
	})

	var crashEv *protocol.AgentEvent
	for _, ev := range rec.snapshot() {
		if ev.Event == protocol.EventProcessCrashed {
			evCopy := ev
			crashEv = &evCopy
			break
		}
	}
	if crashEv == nil || crashEv.Kernel != protocol.KernelSingBox || crashEv.ConfigRevision != cfg.ConfigRevision {
		t.Fatalf("unexpected process_crashed event: %+v", crashEv)
	}

	// Now make sing-box crash on every start with custom stderr, kill it, verify backoff + stderr capture,
	// then abort pending backoff cleanly via ApplyConfig disabling SS.
	env.setBehavior(protocol.KernelSingBox, helperBehavior{
		VersionOut:   "sing-box version 1.11.4",
		CrashOnStart: true,
		CrashStderr:  "boom stderr diagnostic line",
		ExitCode:     42,
	})
	curPID := kernelPID(t, sup, protocol.KernelSingBox)
	_ = syscall.Kill(curPID, syscall.SIGKILL)

	waitUntil(t, 5*time.Second, "crash restart failure with stderr detail", func() bool {
		for _, ev := range rec.snapshot() {
			if ev.Event == protocol.EventProcessCrashed && strings.Contains(ev.Detail, "boom stderr diagnostic line") {
				return true
			}
		}
		return false
	})

	// Disable SS while crash-backoff loop is running -> must abort cleanly.
	cfgOff := cfg
	cfgOff.ConfigRevision = 2
	cfgOff.SS.Enabled = false
	if err := sup.ApplyConfig(ctx, cfgOff); err != nil {
		t.Fatalf("disable SS during backoff failed: %v", err)
	}
	if sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected sing-box unhealthy after disabling SS")
	}
}

func TestServiceControlHealthVersionsAndUpdaterHooks(t *testing.T) {
	env := newHelperEnv(t)
	for _, k := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		env.setBehavior(k, helperBehavior{VersionOut: k + " 9.9.9", BindPorts: true})
	}
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, nil)
	ctx := context.Background()

	// Before any config: StartKernel/RestartKernel/ServiceControl must fail cleanly.
	if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartAll); !errors.Is(err, ErrNoActiveConfig) {
		t.Fatalf("expected ErrNoActiveConfig, got: %v", err)
	}
	if err := sup.StartKernel(ctx, protocol.KernelSingBox); !errors.Is(err, ErrNoActiveConfig) {
		t.Fatalf("expected ErrNoActiveConfig, got: %v", err)
	}
	if err := sup.ServiceControl(ctx, "bad_action"); !errors.Is(err, ErrInvalidServiceAction) {
		t.Fatalf("expected ErrInvalidServiceAction, got: %v", err)
	}

	cfg := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg); err != nil {
		t.Fatalf("ApplyConfig failed: %v", err)
	}

	// ListenAddrs TCP dial check.
	for _, k := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		addrs := sup.ListenAddrs(k)
		if len(addrs) == 0 {
			t.Fatalf("expected non-empty ListenAddrs for %s", k)
		}
		for _, addr := range addrs {
			waitUntil(t, 2*time.Second, fmt.Sprintf("dial ListenAddr %s (%s)", addr, k), func() bool {
				conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
				if err != nil {
					return false
				}
				_ = conn.Close()
				return true
			})
		}
	}

	// BinaryPath & Versions & ProbeVersion.
	for _, k := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		p, err := sup.BinaryPath(k)
		if err != nil || p != env.bins[k] {
			t.Fatalf("BinaryPath(%s) = (%q, %v), want %q", k, p, err, env.bins[k])
		}
	}
	vers := sup.Versions(ctx)
	if vers.SnellServer != "9.9.9" || vers.ShadowTLS != "9.9.9" || vers.SingBox != "9.9.9" {
		t.Fatalf("unexpected Versions: %+v", vers)
	}
	if got := extractCleanVersion("2026-11-24 12:00:00 [server_main] <NOTIFY> v5.0.0\nUsage: snell"); got != "v5.0.0" {
		t.Fatalf("extractCleanVersion snell failed: got %q", got)
	}
	if got := extractCleanVersion("sing-box version 1.14.4\nTags: with_v2ray_api"); got != "1.14.4" {
		t.Fatalf("extractCleanVersion sing-box failed: got %q", got)
	}
	if got := extractCleanVersion("shadow-tls 0.2.25"); got != "0.2.25" {
		t.Fatalf("extractCleanVersion shadow-tls failed: got %q", got)
	}

	// snell-server real usage fallback vs VersionFail.
	env.setBehavior(protocol.KernelSnellServer, helperBehavior{SnellUsageOnVersion: true})
	if v, err := sup.ProbeVersion(ctx, protocol.KernelSnellServer, ""); err != nil || v != "unknown" {
		t.Fatalf("expected usage fallback (unknown, nil), got (%q, %v)", v, err)
	}
	env.setBehavior(protocol.KernelSnellServer, helperBehavior{SnellUsageOnFirstFlagOnly: true})
	if v, err := sup.ProbeVersion(ctx, protocol.KernelSnellServer, ""); err != nil || v != "v5.0.1" {
		t.Fatalf("expected retained usage output from first flag (v5.0.1, nil), got (%q, %v)", v, err)
	}
	env.setBehavior(protocol.KernelSnellServer, helperBehavior{VersionFail: true})
	if _, err := sup.ProbeVersion(ctx, protocol.KernelSnellServer, ""); err == nil {
		t.Fatal("expected ProbeVersion error on VersionFail")
	}
	if versFail := sup.Versions(ctx); versFail.SnellServer != "unknown" {
		t.Fatalf("expected Versions fallback 'unknown', got %q", versFail.SnellServer)
	}
	env.setBehavior(protocol.KernelSnellServer, helperBehavior{VersionOut: "snell-server 9.9.9", BindPorts: true})

	// ServiceControl: restart_snell touches ONLY snell + shadow-tls.
	snell1 := kernelPID(t, sup, protocol.KernelSnellServer)
	stls1 := kernelPID(t, sup, protocol.KernelShadowTLS)
	sb1 := kernelPID(t, sup, protocol.KernelSingBox)

	if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartSnell); err != nil {
		t.Fatalf("restart_snell failed: %v", err)
	}
	if kernelPID(t, sup, protocol.KernelSnellServer) == snell1 || kernelPID(t, sup, protocol.KernelShadowTLS) == stls1 {
		t.Fatal("restart_snell did not restart snell+shadow-tls")
	}
	if kernelPID(t, sup, protocol.KernelSingBox) != sb1 {
		t.Fatal("restart_snell touched sing-box")
	}

	// ServiceControl: restart_singbox touches ONLY sing-box.
	snell2 := kernelPID(t, sup, protocol.KernelSnellServer)
	stls2 := kernelPID(t, sup, protocol.KernelShadowTLS)
	if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartSingBox); err != nil {
		t.Fatalf("restart_singbox failed: %v", err)
	}
	if kernelPID(t, sup, protocol.KernelSnellServer) != snell2 || kernelPID(t, sup, protocol.KernelShadowTLS) != stls2 {
		t.Fatal("restart_singbox touched snell or shadow-tls")
	}
	if kernelPID(t, sup, protocol.KernelSingBox) == sb1 {
		t.Fatal("restart_singbox did not restart sing-box")
	}

	// StopKernel / StartKernel / RestartKernel.
	if err := sup.StopKernel(ctx, protocol.KernelSingBox); err != nil {
		t.Fatalf("StopKernel failed: %v", err)
	}
	if sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected sing-box unhealthy after StopKernel")
	}
	if err := sup.StartKernel(ctx, protocol.KernelSingBox); err != nil {
		t.Fatalf("StartKernel failed: %v", err)
	}
	if !sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected sing-box healthy after StartKernel")
	}
	sbBeforeRestart := kernelPID(t, sup, protocol.KernelSingBox)
	if err := sup.RestartKernel(ctx, protocol.KernelSingBox); err != nil {
		t.Fatalf("RestartKernel failed: %v", err)
	}
	if kernelPID(t, sup, protocol.KernelSingBox) == sbBeforeRestart {
		t.Fatal("RestartKernel did not spawn new process")
	}

	// SIGKILL fallback when child ignores SIGTERM.
	env.setBehavior(protocol.KernelSingBox, helperBehavior{VersionOut: "sing-box 9.9.9", IgnoreSIGTERM: true})
	if err := sup.RestartKernel(ctx, protocol.KernelSingBox); err != nil {
		t.Fatalf("RestartKernel with SIGTERM-ignoring process failed: %v", err)
	}
	if err := sup.StopKernel(ctx, protocol.KernelSingBox); err != nil {
		t.Fatalf("StopKernel SIGKILL fallback failed: %v", err)
	}
	if err := sup.StartKernel(ctx, protocol.KernelSingBox); err != nil {
		t.Fatalf("StartKernel after SIGKILL fallback failed: %v", err)
	}

	// Disable SS -> restart_all respects disabled channel, ListenAddrs returns nil, StartKernel returns ErrKernelDisabled.
	cfgOff := cfg
	cfgOff.ConfigRevision = 2
	cfgOff.SS.Enabled = false
	if err := sup.ApplyConfig(ctx, cfgOff); err != nil {
		t.Fatalf("disable SS failed: %v", err)
	}
	if addrs := sup.ListenAddrs(protocol.KernelSingBox); addrs != nil {
		t.Fatalf("expected nil ListenAddrs when disabled, got: %v", addrs)
	}
	if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartAll); err != nil {
		t.Fatalf("restart_all with SS disabled failed: %v", err)
	}
	if sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("restart_all must not start disabled sing-box")
	}
	if err := sup.StartKernel(ctx, protocol.KernelSingBox); !errors.Is(err, ErrKernelDisabled) {
		t.Fatalf("expected ErrKernelDisabled, got: %v", err)
	}
	if err := sup.StopKernel(ctx, "unknown"); !errors.Is(err, ErrInvalidKernel) {
		t.Fatalf("expected ErrInvalidKernel on StopKernel, got: %v", err)
	}
	if _, err := sup.BinaryPath("unknown"); !errors.Is(err, ErrInvalidKernel) {
		t.Fatalf("expected ErrInvalidKernel on BinaryPath, got: %v", err)
	}
	if addrs := sup.ListenAddrs("unknown"); addrs != nil {
		t.Fatalf("expected nil ListenAddrs for unknown kernel, got: %v", addrs)
	}

	if rec.countEvent(protocol.EventProcessCrashed) != 0 {
		t.Fatalf("expected zero process_crashed events across clean lifecycle ops, got: %+v", rec.snapshot())
	}

	// Post-Stop calls return ErrStopped cleanly, Stop is idempotent, and ListenAddrs returns nil.
	if err := sup.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	for _, k := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		if addrs := sup.ListenAddrs(k); addrs != nil {
			t.Fatalf("expected nil ListenAddrs for %s after Stop, got: %v", k, addrs)
		}
	}
	if err := sup.Stop(ctx); err != nil {
		t.Fatalf("idempotent Stop failed: %v", err)
	}
	if err := sup.ApplyConfig(ctx, cfg); !errors.Is(err, ErrStopped) {
		t.Fatalf("expected ErrStopped after Stop, got: %v", err)
	}
	if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartAll); !errors.Is(err, ErrStopped) {
		t.Fatalf("expected ErrStopped on ServiceControl after Stop, got: %v", err)
	}
}

func TestSingBoxVersionAwareRendering(t *testing.T) {
	env := newHelperEnv(t)
	sup := newTestSupervisor(t, env, nil, nil)
	ctx := context.Background()

	cfg := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg); err != nil {
		t.Fatalf("ApplyConfig 1.11 failed: %v", err)
	}
	sbJSON1, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sbJSON1), `"address": "udp://127.0.0.1:`) {
		t.Fatalf("expected legacy DNS address for 1.11.4:\n%s", sbJSON1)
	}

	// Simulate binary upgrade to 1.12.5 with modified mtime/size so cache invalidates.
	env.setBehavior(protocol.KernelSingBox, helperBehavior{VersionOut: "sing-box version 1.12.5"})
	binPath := env.bins[protocol.KernelSingBox]
	origScript, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binPath, append(origScript, []byte("\n# upgraded\n")...), 0o755); err != nil {
		t.Fatal(err)
	}

	cfg2 := cfg
	cfg2.ConfigRevision = 2
	if err := sup.ApplyConfig(ctx, cfg2); err != nil {
		t.Fatalf("ApplyConfig 1.12 failed: %v", err)
	}
	sbJSON2, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "sing-box.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sbJSON2), `"type": "udp"`) || !strings.Contains(string(sbJSON2), `"default_domain_resolver": "local-dns"`) {
		t.Fatalf("expected typed DNS for 1.12.5:\n%s", sbJSON2)
	}
}

func TestConcurrencyAndRaceSafety(t *testing.T) {
	env := newHelperEnv(t)
	sup := newTestSupervisor(t, env, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	base := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, base); err != nil {
		t.Fatalf("initial ApplyConfig failed: %v", err)
	}

	var wg sync.WaitGroup

	// Concurrent ApplyConfig writers.
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				cfg := base
				cfg.ConfigRevision = int64(id*10 + j + 2)
				cfg.SS.Users = []protocol.SSUserEntry{
					{
						UserID:       int64(j + 1),
						Username:     fmt.Sprintf("u_%d_%d", id, j),
						UPSK:         b64Key(32, byte(id+j+5)),
						STLSPassword: fmt.Sprintf("pwd-%d-%d", id, j),
					},
				}
				_ = sup.ApplyConfig(ctx, cfg)
			}
		}(i)
	}

	// Concurrent ServiceControl / RestartKernel callers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for j := 0; j < 4; j++ {
			_ = sup.ServiceControl(ctx, protocol.ServiceActionRestartSingBox)
			_ = sup.RestartKernel(ctx, protocol.KernelSnellServer)
		}
	}()

	// Concurrent readers (Health, IsKernelHealthy, ListenAddrs, Versions).
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				_ = sup.Health()
				_ = sup.IsKernelHealthy(protocol.KernelSnellServer)
				_ = sup.IsKernelHealthy(protocol.KernelShadowTLS)
				_ = sup.IsKernelHealthy(protocol.KernelSingBox)
				_ = sup.ListenAddrs(protocol.KernelSingBox)
				if j%5 == 0 {
					_ = sup.Versions(ctx)
				}
				time.Sleep(5 * time.Millisecond)
			}
		}()
	}

	// Stop mid-flight after a short delay to test clean teardown under contention.
	time.Sleep(250 * time.Millisecond)
	if err := sup.Stop(context.Background()); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	wg.Wait()
}

func TestPickFreeTCPPortSkipsBusyHostPort(t *testing.T) {
	// 1. Direct unit check on pickFreeTCPPort with a live loopback listener.
	busyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ephemeral failed: %v", err)
	}
	defer busyLn.Close()
	busyPort := busyLn.Addr().(*net.TCPAddr).Port

	got, err := pickFreeTCPPort(busyPort, map[int]string{})
	if err != nil {
		t.Fatalf("pickFreeTCPPort failed: %v", err)
	}
	if got == busyPort {
		t.Fatalf("pickFreeTCPPort returned busy host port %d", busyPort)
	}

	// 2. End-to-end ApplyConfig check when default port 31002 is occupied on 127.0.0.1.
	defaultAddr := fmt.Sprintf("127.0.0.1:%d", defaultSSInnerStart)
	var ln31002 net.Listener
	var lerr error
	for attempt := 0; attempt < 10; attempt++ {
		ln31002, lerr = net.Listen("tcp", defaultAddr)
		if lerr == nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if lerr != nil {
		t.Fatalf("listen %s failed: %v", defaultAddr, lerr)
	}
	defer ln31002.Close()

	env := newHelperEnv(t)
	for _, k := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		env.setBehavior(k, helperBehavior{VersionOut: k + " 1.0.0", BindPorts: true})
	}
	sup := newTestSupervisor(t, env, nil, func(o *Options) {
		o.SSInnerTCPPort = 0
	})
	ctx := context.Background()

	cfg1 := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg1); err != nil {
		t.Fatalf("ApplyConfig with busy default port failed: %v", err)
	}
	if !sup.Health().SingBox {
		t.Fatalf("expected sing-box healthy, got: %+v", sup.Health())
	}

	sup.mu.RLock()
	allocatedPort := sup.activePorts.SSInnerTCPPort
	sup.mu.RUnlock()
	if allocatedPort <= defaultSSInnerStart {
		t.Fatalf("expected SSInnerTCPPort > %d when %d is busy, got %d", defaultSSInnerStart, defaultSSInnerStart, allocatedPort)
	}

	// 3. Subsequent SS reload retains already-bound prevPorts.SSInnerTCPPort without self-collision.
	cfg2 := cfg1
	cfg2.ConfigRevision = 2
	cfg2.SS.Users = append(cfg2.SS.Users, protocol.SSUserEntry{
		UserID:       2,
		Username:     "user2",
		UPSK:         b64Key(32, 20),
		STLSPassword: "user2-stls",
	})
	if err := sup.ApplyConfig(ctx, cfg2); err != nil {
		t.Fatalf("ApplyConfig v2 reload failed: %v", err)
	}
	sup.mu.RLock()
	reusedPort := sup.activePorts.SSInnerTCPPort
	sup.mu.RUnlock()
	if reusedPort != allocatedPort {
		t.Fatalf("expected prevPorts reuse %d on SS reload, got %d", allocatedPort, reusedPort)
	}
}

func TestCustomValidatorRunsWhenDisableBinaryValidationTrue(t *testing.T) {
	env := newHelperEnv(t)
	// Configure sing-box check to reject everything so we prove binary check is NOT executed
	// when DisableBinaryValidation=true + custom Validator returns nil.
	env.setBehavior(protocol.KernelSingBox, helperBehavior{
		VersionOut:        "sing-box version 1.11.4",
		CheckRejectSubstr: "stls-in",
	})

	var validatedKernels []string
	var rejectSnell bool
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, func(o *Options) {
		o.DisableBinaryValidation = true
		o.Validator = func(ctx context.Context, kernel, configPath string) error {
			validatedKernels = append(validatedKernels, kernel)
			if _, err := os.Stat(configPath); err != nil {
				return fmt.Errorf("staged config missing: %w", err)
			}
			if rejectSnell && kernel == protocol.KernelSnellServer {
				return errors.New("custom reject with DisableBinaryValidation=true")
			}
			return nil
		}
	})
	ctx := context.Background()

	cfg := testSyncConfig(t)
	rejectSnell = true
	err := sup.ApplyConfig(ctx, cfg)
	if err == nil || !errors.Is(err, ErrValidation) {
		t.Fatalf("expected ErrValidation from custom Validator when DisableBinaryValidation=true, got: %v", err)
	}
	if len(validatedKernels) == 0 {
		t.Fatal("expected custom Validator to be called when DisableBinaryValidation=true")
	}

	validatedKernels = nil
	rejectSnell = false
	if err := sup.ApplyConfig(ctx, cfg); err != nil {
		t.Fatalf("expected ApplyConfig to succeed with custom Validator and DisableBinaryValidation=true, got: %v", err)
	}
	if len(validatedKernels) != 2 {
		t.Fatalf("expected custom Validator called for both channels, got: %v", validatedKernels)
	}
}

func TestRollbackAndRestartAdminConsistency(t *testing.T) {
	t.Run("rollback error captured in EventConfigError Detail", func(t *testing.T) {
		env := newHelperEnv(t)
		rec := &eventRecorder{}
		sup := newTestSupervisor(t, env, rec, func(o *Options) {
			o.StartupGrace = 1200 * time.Millisecond
		})
		ctx := context.Background()

		cfg1 := testSyncConfig(t)
		if err := sup.ApplyConfig(ctx, cfg1); err != nil {
			t.Fatalf("ApplyConfig v1 failed: %v", err)
		}

		// Force sing-box to crash both on v2 AND on rollback v1.
		env.setBehavior(protocol.KernelSingBox, helperBehavior{
			VersionOut:   "sing-box version 1.11.4",
			CrashOnStart: true,
			CrashStderr:  "persistent sing-box failure",
		})
		cfg2 := cfg1
		cfg2.ConfigRevision = 2
		cfg2.SS.STLSSNI = "updated.example.com"
		if err := sup.ApplyConfig(ctx, cfg2); err == nil {
			t.Fatal("expected ApplyConfig v2 to fail")
		}

		events := rec.snapshot()
		lastEv := events[len(events)-1]
		if lastEv.Event != protocol.EventConfigError {
			t.Fatalf("expected EventConfigError, got: %+v", lastEv)
		}
		if !strings.Contains(lastEv.Detail, "rollback errors:") || !strings.Contains(lastEv.Detail, "rollback start sing-box") {
			t.Fatalf("expected rollback failure details in EventConfigError.Detail, got: %q", lastEv.Detail)
		}
	})

	t.Run("shadow-tls start failure stops snell-server in ServiceControl and admin rollback", func(t *testing.T) {
		env := newHelperEnv(t)
		rec := &eventRecorder{}
		sup := newTestSupervisor(t, env, rec, func(o *Options) {
			o.StartupGrace = 1200 * time.Millisecond
		})
		ctx := context.Background()

		cfg1 := testSyncConfig(t)
		if err := sup.ApplyConfig(ctx, cfg1); err != nil {
			t.Fatalf("ApplyConfig v1 failed: %v", err)
		}

		env.setBehavior(protocol.KernelShadowTLS, helperBehavior{
			VersionOut:   "shadow-tls 0.2.25",
			CrashOnStart: true,
			CrashStderr:  "shadow-tls start failure",
		})

		if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartSnell); err == nil {
			t.Fatal("expected restart_snell error when shadow-tls crashes on start")
		}
		h := sup.Health()
		if h.Snell || h.ShadowTLS || !h.SingBox {
			t.Fatalf("expected snell-server stopped when shadow-tls failed in restart_snell (and sing-box untouched), got: %+v", h)
		}

		if err := sup.ServiceControl(ctx, protocol.ServiceActionRestartAll); err == nil {
			t.Fatal("expected restart_all error when shadow-tls crashes on start")
		}
		h = sup.Health()
		if h.Snell || h.ShadowTLS {
			t.Fatalf("expected snell-server and shadow-tls stopped after restart_all failure, got: %+v", h)
		}

		// Also verify admin rollback stops snell-server if shadow-tls fails during rollback.
		env.setBehavior(protocol.KernelShadowTLS, helperBehavior{VersionOut: "shadow-tls 0.2.25"})
		if err := sup.ApplyConfig(ctx, cfg1); err != nil {
			t.Fatalf("re-apply cfg1 failed: %v", err)
		}
		env.setBehavior(protocol.KernelShadowTLS, helperBehavior{
			VersionOut:   "shadow-tls 0.2.25",
			CrashOnStart: true,
			CrashStderr:  "shadow-tls fail forward and rollback",
		})
		cfg2 := cfg1
		cfg2.ConfigRevision = 2
		cfg2.Snell.PSK = "snell-psk-2"
		if err := sup.ApplyConfig(ctx, cfg2); err == nil {
			t.Fatal("expected ApplyConfig v2 to fail when shadow-tls crashes")
		}
		h = sup.Health()
		if h.Snell || h.ShadowTLS {
			t.Fatalf("expected snell-server stopped when shadow-tls failed during admin rollback, got: %+v", h)
		}
		events := rec.snapshot()
		lastEv := events[len(events)-1]
		if !strings.Contains(lastEv.Detail, "rollback start shadow-tls") {
			t.Fatalf("expected rollback start shadow-tls error in EventConfigError.Detail, got: %q", lastEv.Detail)
		}
	})
}

func TestPickFreeTCPPort_WraparoundAndExhaustion(t *testing.T) {
	// 1. Wraparound: start near 65535 with 65530..65535 marked busy -> wraps to 1024..
	used := make(map[int]string)
	for p := 65530; p <= 65535; p++ {
		used[p] = "busy"
	}
	got, err := pickFreeTCPPort(65530, used)
	if err != nil {
		t.Fatalf("pickFreeTCPPort wraparound failed: %v", err)
	}
	if got < 1024 || got >= 65530 {
		t.Fatalf("expected wrapped port in [1024, 65530), got %d", got)
	}

	// 2. Exhaustion: all ports [1024..65535] marked busy -> returns error.
	allBusy := make(map[int]string, 65535-1024+1)
	for p := 1024; p <= 65535; p++ {
		allBusy[p] = "busy"
	}
	if p, err := pickFreeTCPPort(31001, allBusy); err == nil {
		t.Fatalf("expected error when all ports busy, got port %d", p)
	}
}

func TestSupervisor_CrashBackoffGenerationRace(t *testing.T) {
	env := newHelperEnv(t)
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, func(o *Options) {
		o.StartupGrace = 120 * time.Millisecond
		o.CrashBackoffBase = 350 * time.Millisecond
		o.CrashBackoffMax = 350 * time.Millisecond
	})
	ctx := context.Background()

	cfg1 := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg1); err != nil {
		t.Fatalf("ApplyConfig rev 1 failed: %v", err)
	}

	// Cause rev 1's sing-box to crash on restart and kill current process so it enters 350ms backoff.
	env.setBehavior(protocol.KernelSingBox, helperBehavior{
		VersionOut:   "sing-box version 1.11.4",
		CrashOnStart: true,
		CrashStderr:  "rev1 crash in backoff",
	})
	pid1 := kernelPID(t, sup, protocol.KernelSingBox)
	if err := syscall.Kill(pid1, syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 3*time.Second, "process_crashed event for rev 1", func() bool {
		return rec.countEvent(protocol.EventProcessCrashed) >= 1
	})

	// Immediately switch behavior back to healthy and apply rev 2 while rev 1 backoff timer is sleeping.
	env.setBehavior(protocol.KernelSingBox, helperBehavior{VersionOut: "sing-box version 1.11.4"})
	cfg2 := cfg1
	cfg2.ConfigRevision = 2
	cfg2.SS.STLSSNI = "rev2.example.com"
	if err := sup.ApplyConfig(ctx, cfg2); err != nil {
		t.Fatalf("ApplyConfig rev 2 failed: %v", err)
	}
	pid2 := kernelPID(t, sup, protocol.KernelSingBox)
	if pid2 == 0 || pid2 == pid1 {
		t.Fatalf("expected new rev 2 sing-box PID, got %d", pid2)
	}

	// Wait past rev 1's 350ms backoff window and confirm old backoff timer did NOT restart or disturb rev 2!
	time.Sleep(550 * time.Millisecond)
	if got := kernelPID(t, sup, protocol.KernelSingBox); got != pid2 {
		t.Fatalf("stale backoff timer replaced rev 2 sing-box PID: want %d, got %d", pid2, got)
	}
	if !sup.IsKernelHealthy(protocol.KernelSingBox) {
		t.Fatal("expected sing-box healthy after rev 2")
	}
}
