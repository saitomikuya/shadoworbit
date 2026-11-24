package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"snell-panel/internal/protocol"
)

func kernelPID(t *testing.T, sup *Supervisor, kernel string) int {
	t.Helper()
	sup.mu.RLock()
	defer sup.mu.RUnlock()
	slot := sup.slots[kernel]
	if slot == nil || slot.current == nil {
		return 0
	}
	return slot.current.pid
}

func TestZeroInterruptionSnellIsolation(t *testing.T) {
	env := newHelperEnv(t)
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, nil)
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

	h := sup.Health()
	if !h.Snell || !h.ShadowTLS || !h.SingBox {
		t.Fatalf("expected all 3 kernels healthy, got: %+v", h)
	}

	snellPID1 := kernelPID(t, sup, protocol.KernelSnellServer)
	stlsPID1 := kernelPID(t, sup, protocol.KernelShadowTLS)
	sbPID1 := kernelPID(t, sup, protocol.KernelSingBox)
	if snellPID1 == 0 || stlsPID1 == 0 || sbPID1 == 0 {
		t.Fatalf("expected non-zero PIDs: snell=%d stls=%d sb=%d", snellPID1, stlsPID1, sbPID1)
	}

	// Rev 2: modify SS users and cipher -> ONLY sing-box should restart; snell-server and shadow-tls PIDs MUST remain identical.
	cfg2 := cfg1
	cfg2.ConfigRevision = 2
	cfg2.SS.Cipher = protocol.CipherAES128GCM
	cfg2.SS.IPSK = b64Key(16, 40)
	cfg2.SS.Users = []protocol.SSUserEntry{
		{UserID: 1, Username: "user1", UPSK: b64Key(16, 41), STLSPassword: "user1-stls"},
		{UserID: 2, Username: "user2", UPSK: b64Key(16, 42), STLSPassword: "user2-stls"},
	}
	if err := sup.ApplyConfig(ctx, cfg2); err != nil {
		t.Fatalf("ApplyConfig v2 failed: %v", err)
	}
	waitUntil(t, 10*time.Second, "sing-box restart invocation event for v2", func() bool {
		return len(env.startEvents(protocol.KernelSingBox)) == 2
	})

	if got := kernelPID(t, sup, protocol.KernelSnellServer); got != snellPID1 {
		t.Fatalf("snell-server PID changed on SS-only reload: got %d, want %d", got, snellPID1)
	}
	if got := kernelPID(t, sup, protocol.KernelShadowTLS); got != stlsPID1 {
		t.Fatalf("shadow-tls PID changed on SS-only reload: got %d, want %d", got, stlsPID1)
	}
	sbPID2 := kernelPID(t, sup, protocol.KernelSingBox)
	if sbPID2 == 0 || sbPID2 == sbPID1 {
		t.Fatalf("expected sing-box PID to change on SS reload: old=%d new=%d", sbPID1, sbPID2)
	}
	if n := len(env.startEvents(protocol.KernelSnellServer)); n != 1 {
		t.Fatalf("expected snell-server start count 1, got %d", n)
	}
	if n := len(env.startEvents(protocol.KernelShadowTLS)); n != 1 {
		t.Fatalf("expected shadow-tls start count 1, got %d", n)
	}
	if n := len(env.startEvents(protocol.KernelSingBox)); n != 2 {
		t.Fatalf("expected sing-box start count 2, got %d", n)
	}

	// Rev 3: modify DNS.Rules / UnlockServer / UpstreamDNS (same LocalPort & UnlockEnabled) -> 0 restarts.
	cfg3 := cfg2
	cfg3.ConfigRevision = 3
	cfg3.DNS.Rules = []string{"openai.com", "*.netflix.com"}
	cfg3.DNS.UnlockServer = "9.9.9.9:3535"
	cfg3.DNS.UpstreamDNS = "8.8.8.8:53"
	if err := sup.ApplyConfig(ctx, cfg3); err != nil {
		t.Fatalf("ApplyConfig v3 failed: %v", err)
	}

	if kernelPID(t, sup, protocol.KernelSnellServer) != snellPID1 ||
		kernelPID(t, sup, protocol.KernelShadowTLS) != stlsPID1 ||
		kernelPID(t, sup, protocol.KernelSingBox) != sbPID2 {
		t.Fatal("expected zero kernel restarts on DNS rule-only update")
	}

	// Rev 4: modify DNS.LocalPort to 53 -> both channels reload with new DNS port.
	cfg4 := cfg3
	cfg4.ConfigRevision = 4
	cfg4.DNS.LocalPort = 53
	if err := sup.ApplyConfig(ctx, cfg4); err != nil {
		t.Fatalf("ApplyConfig v4 failed: %v", err)
	}
	if kernelPID(t, sup, protocol.KernelSnellServer) == snellPID1 ||
		kernelPID(t, sup, protocol.KernelShadowTLS) == stlsPID1 ||
		kernelPID(t, sup, protocol.KernelSingBox) == sbPID2 {
		t.Fatal("expected all kernels to reload when DNS.LocalPort changes")
	}

	if rec.countEvent(protocol.EventProcessCrashed) != 0 {
		t.Fatalf("expected zero process_crashed events, got: %+v", rec.snapshot())
	}
}

func TestIndependentEnableDisable_StopSSOnlyVsStopAll(t *testing.T) {
	env := newHelperEnv(t)
	rec := &eventRecorder{}
	sup := newTestSupervisor(t, env, rec, nil)
	ctx := context.Background()

	cfg1 := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg1); err != nil {
		t.Fatalf("ApplyConfig v1 failed: %v", err)
	}
	snellPID := kernelPID(t, sup, protocol.KernelSnellServer)
	stlsPID := kernelPID(t, sup, protocol.KernelShadowTLS)

	// stop_ss_only: SS.Enabled = false, Snell.Enabled = true
	cfg2 := cfg1
	cfg2.ConfigRevision = 2
	cfg2.SS.Enabled = false
	if err := sup.ApplyConfig(ctx, cfg2); err != nil {
		t.Fatalf("ApplyConfig stop_ss_only failed: %v", err)
	}

	h := sup.Health()
	if !h.Snell || !h.ShadowTLS || h.SingBox {
		t.Fatalf("expected Snell+ShadowTLS healthy and SingBox stopped, got: %+v", h)
	}
	if kernelPID(t, sup, protocol.KernelSnellServer) != snellPID || kernelPID(t, sup, protocol.KernelShadowTLS) != stlsPID {
		t.Fatal("stop_ss_only must NEVER restart or interrupt snell-server or shadow-tls")
	}

	// Re-enable SS: sing-box starts, snell-server + shadow-tls remain untouched.
	cfg3 := cfg1
	cfg3.ConfigRevision = 3
	if err := sup.ApplyConfig(ctx, cfg3); err != nil {
		t.Fatalf("ApplyConfig re-enable SS failed: %v", err)
	}
	h = sup.Health()
	if !h.Snell || !h.ShadowTLS || !h.SingBox {
		t.Fatalf("expected all 3 healthy after re-enable, got: %+v", h)
	}
	if kernelPID(t, sup, protocol.KernelSnellServer) != snellPID || kernelPID(t, sup, protocol.KernelShadowTLS) != stlsPID {
		t.Fatal("re-enabling SS must NEVER restart snell-server or shadow-tls")
	}

	// stop_all: both disabled
	cfg4 := cfg3
	cfg4.ConfigRevision = 4
	cfg4.Snell.Enabled = false
	cfg4.SS.Enabled = false
	if err := sup.ApplyConfig(ctx, cfg4); err != nil {
		t.Fatalf("ApplyConfig stop_all failed: %v", err)
	}
	h = sup.Health()
	if h.Snell || h.ShadowTLS || h.SingBox {
		t.Fatalf("expected all 3 stopped on stop_all, got: %+v", h)
	}

	// Snell disabled, SS enabled
	cfg5 := cfg1
	cfg5.ConfigRevision = 5
	cfg5.Snell.Enabled = false
	cfg5.SS.Enabled = true
	if err := sup.ApplyConfig(ctx, cfg5); err != nil {
		t.Fatalf("ApplyConfig snell=false ss=true failed: %v", err)
	}
	h = sup.Health()
	if h.Snell || h.ShadowTLS || !h.SingBox {
		t.Fatalf("expected only SingBox running, got: %+v", h)
	}

	if rec.countEvent(protocol.EventProcessCrashed) != 0 {
		t.Fatalf("expected 0 process_crashed events, got: %+v", rec.snapshot())
	}
}

func TestBothChannelsSwapPortsSafely(t *testing.T) {
	env := newHelperEnv(t)
	for _, k := range []string{protocol.KernelSnellServer, protocol.KernelShadowTLS, protocol.KernelSingBox} {
		env.setBehavior(k, helperBehavior{VersionOut: k + " 1.0.0", BindPorts: true})
	}
	sup := newTestSupervisor(t, env, nil, nil)
	ctx := context.Background()

	cfg1 := testSyncConfig(t)
	if err := sup.ApplyConfig(ctx, cfg1); err != nil {
		t.Fatalf("ApplyConfig v1 failed: %v", err)
	}

	// Swap Snell.PublicPort and SS.TCPPort in a single ApplyConfig.
	cfg2 := cfg1
	cfg2.ConfigRevision = 2
	cfg2.Snell.PublicPort, cfg2.SS.TCPPort = cfg1.SS.TCPPort, cfg1.Snell.PublicPort
	cfg2.SS.UDPPort = cfg2.SS.TCPPort

	if err := sup.ApplyConfig(ctx, cfg2); err != nil {
		t.Fatalf("port swap ApplyConfig failed: %v", err)
	}

	h := sup.Health()
	if !h.Snell || !h.ShadowTLS || !h.SingBox {
		t.Fatalf("expected all 3 healthy after port swap, got: %+v", h)
	}

	snellConfBytes, err := os.ReadFile(filepath.Join(env.dataDir, "configs", "snell-server.conf"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snellConfBytes), "listen = 127.0.0.1:") {
		t.Fatalf("unexpected snell-server.conf: %s", snellConfBytes)
	}
}
