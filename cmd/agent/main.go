package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"snell-panel/internal/agent/collector"
	"snell-panel/internal/agent/dnsproxy"
	"snell-panel/internal/agent/supervisor"
	"snell-panel/internal/agent/updater"
	"snell-panel/internal/agent/wsclient"
	"snell-panel/internal/protocol"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Config holds Node Agent runtime configuration.
type Config struct {
	PanelURL         string
	NodeToken        string
	DataDir          string
	Iface            string
	SnellBin         string
	ShadowTLSBin     string
	SingBoxBin       string
	LocalDNSPort     int
	StatsPort        int
	TLSSkipVerify    bool
	ShowVersion      bool
	ProcNetDevPath   string
	ProcNetRoutePath string
}

type runtimeOptions struct {
	DisableBinaryValidation bool
	PublicIPEndpointsV4     []string
	PublicIPEndpointsV6     []string
	MetricsInterval         time.Duration
	BackoffBase             time.Duration
	BackoffMax              time.Duration
	PingInterval            time.Duration
	StartupGrace            time.Duration
}

// ParseConfig parses flags and environment variables for the Node Agent.
func ParseConfig(args []string, getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	envOrDefault := func(key, def string) string {
		if v := strings.TrimSpace(getenv(key)); v != "" {
			return v
		}
		return def
	}

	localDNSPort := 1053
	if v := strings.TrimSpace(getenv("LOCAL_DNS_PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid LOCAL_DNS_PORT %q: %w", v, err)
		}
		localDNSPort = p
	}

	statsPort := 10085
	if v := strings.TrimSpace(getenv("STATS_PORT")); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid STATS_PORT %q: %w", v, err)
		}
		statsPort = p
	}

	tlsSkipVerify := false
	if v := strings.TrimSpace(getenv("TLS_SKIP_VERIFY")); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return Config{}, fmt.Errorf("invalid TLS_SKIP_VERIFY %q: %w", v, err)
		}
		tlsSkipVerify = b
	}

	cfg := Config{
		PanelURL:         strings.TrimSpace(getenv("PANEL_URL")),
		NodeToken:        strings.TrimSpace(getenv("NODE_TOKEN")),
		DataDir:          envOrDefault("DATA_DIR", "/var/lib/snell-panel-agent"),
		Iface:            strings.TrimSpace(getenv("IFACE")),
		SnellBin:         envOrDefault("SNELL_BIN", "snell-server"),
		ShadowTLSBin:     envOrDefault("SHADOW_TLS_BIN", "shadow-tls"),
		SingBoxBin:       envOrDefault("SING_BOX_BIN", "sing-box"),
		LocalDNSPort:     localDNSPort,
		StatsPort:        statsPort,
		TLSSkipVerify:    tlsSkipVerify,
		ProcNetDevPath:   strings.TrimSpace(getenv("PROC_NET_DEV_PATH")),
		ProcNetRoutePath: strings.TrimSpace(getenv("PROC_NET_ROUTE_PATH")),
	}

	fs := flag.NewFlagSet("agent", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&cfg.PanelURL, "panel-url", cfg.PanelURL, "panel WebSocket/HTTP URL")
	fs.StringVar(&cfg.NodeToken, "token", cfg.NodeToken, "node authentication token")
	fs.StringVar(&cfg.DataDir, "data-dir", cfg.DataDir, "agent persistent state directory")
	fs.StringVar(&cfg.Iface, "iface", cfg.Iface, "primary network interface override")
	fs.StringVar(&cfg.SnellBin, "snell-bin", cfg.SnellBin, "snell-server binary path")
	fs.StringVar(&cfg.ShadowTLSBin, "shadow-tls-bin", cfg.ShadowTLSBin, "shadow-tls binary path")
	fs.StringVar(&cfg.SingBoxBin, "sing-box-bin", cfg.SingBoxBin, "sing-box binary path")
	fs.IntVar(&cfg.LocalDNSPort, "local-dns-port", cfg.LocalDNSPort, "loopback DNS dispatcher port")
	fs.IntVar(&cfg.StatsPort, "stats-port", cfg.StatsPort, "sing-box V2Ray Stats gRPC port")
	fs.BoolVar(&cfg.TLSSkipVerify, "tls-skip-verify", cfg.TLSSkipVerify, "skip TLS certificate verification")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print version information and exit")

	if err := fs.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse flags: %w", err)
	}
	if cfg.ShowVersion {
		return cfg, nil
	}

	normalizedURL, err := validatePanelURL(cfg.PanelURL)
	if err != nil {
		return Config{}, err
	}
	cfg.PanelURL = normalizedURL

	if strings.TrimSpace(cfg.NodeToken) == "" {
		return Config{}, errors.New("NODE_TOKEN cannot be empty")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return Config{}, errors.New("DATA_DIR cannot be empty")
	}
	if err := validateConfigPorts(cfg.LocalDNSPort, cfg.StatsPort); err != nil {
		return Config{}, err
	}

	return cfg, nil
}

func validateConfigPorts(localDNSPort, statsPort int) error {
	if localDNSPort < 1 || localDNSPort > 65535 {
		return fmt.Errorf("invalid local-dns-port %d: must be 1..65535", localDNSPort)
	}
	if statsPort < 1 || statsPort > 65535 {
		return fmt.Errorf("invalid stats-port %d: must be 1..65535", statsPort)
	}
	if localDNSPort == statsPort {
		return fmt.Errorf("local-dns-port (%d) cannot equal stats-port (%d)", localDNSPort, statsPort)
	}
	return nil
}

func validatePanelURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("PANEL_URL cannot be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid PANEL_URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		u.Scheme = strings.ToLower(u.Scheme)
	default:
		return "", fmt.Errorf("unsupported PANEL_URL scheme %q: must be ws, wss, http, or https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("PANEL_URL must include hostname")
	}
	if !strings.HasPrefix(u.Host, "[") && strings.Count(u.Host, ":") > 1 {
		return "", errors.New("IPv6 PANEL_URL host must be enclosed in brackets")
	}
	if strings.HasPrefix(u.Host, "[") {
		if !strings.Contains(u.Host, "]") || net.ParseIP(host) == nil {
			return "", errors.New("PANEL_URL has invalid bracketed IPv6 host")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("PANEL_URL has empty port")
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("invalid PANEL_URL port %q: must be 1..65535", p)
		}
	}
	return u.String(), nil
}

func redactPanelURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "<invalid-url>"
	}
	return u.Redacted()
}

// RedactToken masks a sensitive token while preserving safe diagnostic prefix/suffix characters.
func RedactToken(tok string) string {
	if tok == "" {
		return ""
	}
	const ndLivePrefix = "nd_live_"
	if strings.HasPrefix(tok, ndLivePrefix) {
		if len(tok) <= 16 {
			return "nd_live_***"
		}
		return ndLivePrefix + "***" + tok[len(tok)-4:]
	}
	if len(tok) <= 12 {
		return "***"
	}
	if len(tok) <= 16 {
		return tok[:2] + "***" + tok[len(tok)-2:]
	}
	return tok[:4] + "***" + tok[len(tok)-4:]
}

func supervisorEventHandler(emitEvent func(protocol.AgentEvent)) func(protocol.AgentEvent) {
	return func(ev protocol.AgentEvent) {
		// configCoordinator.Apply emits EventConfigApplied strictly after collector updates,
		// last_config.json persistence, and currentRevision commit complete.
		if ev.Event == protocol.EventConfigApplied {
			return
		}
		if emitEvent != nil {
			emitEvent(ev)
		}
	}
}

func run(ctx context.Context, cfg Config, stdout io.Writer) error {
	return runWithReady(ctx, cfg, stdout, nil)
}

func runWithReady(ctx context.Context, cfg Config, stdout io.Writer, ready chan<- struct{}) error {
	return runWithOptions(ctx, cfg, stdout, ready, runtimeOptions{})
}

func runWithOptions(
	ctx context.Context,
	cfg Config,
	stdout io.Writer,
	ready chan<- struct{},
	opts runtimeOptions,
) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if cfg.ShowVersion {
		_, err := fmt.Fprintf(stdout, "snell-agent version=%s commit=%s date=%s\n", version, commit, date)
		return err
	}

	normalizedURL, err := validatePanelURL(cfg.PanelURL)
	if err != nil {
		return err
	}
	cfg.PanelURL = normalizedURL
	if strings.TrimSpace(cfg.NodeToken) == "" {
		return errors.New("NODE_TOKEN cannot be empty")
	}
	if strings.TrimSpace(cfg.DataDir) == "" {
		return errors.New("DATA_DIR cannot be empty")
	}
	if err := validateConfigPorts(cfg.LocalDNSPort, cfg.StatsPort); err != nil {
		return err
	}

	tmpDir := filepath.Join(cfg.DataDir, "tmp")
	if err := os.MkdirAll(cfg.DataDir, 0o750); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}
	if err := os.MkdirAll(tmpDir, 0o750); err != nil {
		return fmt.Errorf("create tmp dir: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("node agent initialized",
		"panel_url", redactPanelURL(cfg.PanelURL),
		"node_token", RedactToken(cfg.NodeToken),
		"data_dir", cfg.DataDir,
		"iface", cfg.Iface,
		"local_dns_port", cfg.LocalDNSPort,
		"stats_port", cfg.StatsPort,
	)

	procNetDevPath := strings.TrimSpace(cfg.ProcNetDevPath)
	if procNetDevPath == "" {
		procNetDevPath = strings.TrimSpace(os.Getenv("PROC_NET_DEV_PATH"))
	}
	procNetRoutePath := strings.TrimSpace(cfg.ProcNetRoutePath)
	if procNetRoutePath == "" {
		procNetRoutePath = strings.TrimSpace(os.Getenv("PROC_NET_ROUTE_PATH"))
	}

	cachedCfg, hasCached := loadLastConfig(filepath.Join(cfg.DataDir, lastConfigFilename), logger)

	initialDNS := dnsproxy.Config{
		ListenHost:  dnsproxy.DefaultListenHost,
		ListenPort:  cfg.LocalDNSPort,
		UpstreamDNS: dnsproxy.DefaultUpstreamDNS,
	}
	dnsSrv, err := dnsproxy.New(initialDNS)
	if err != nil {
		return fmt.Errorf("init dnsproxy: %w", err)
	}
	if err := dnsSrv.Start(ctx); err != nil {
		return fmt.Errorf("start dnsproxy: %w", err)
	}
	dnsStopped := false
	defer func() {
		if !dnsStopped {
			sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
			_ = dnsSrv.Stop(sctx)
			scancel()
		}
	}()

	var clientPtr atomic.Pointer[wsclient.Client]
	emitEvent := func(ev protocol.AgentEvent) {
		if cl := clientPtr.Load(); cl != nil {
			cl.SendEvent(ev)
		}
	}

	sup, err := supervisor.New(supervisor.Options{
		DataDir:                 cfg.DataDir,
		SnellBin:                cfg.SnellBin,
		ShadowTLSBin:            cfg.ShadowTLSBin,
		SingBoxBin:              cfg.SingBoxBin,
		StatsPort:               cfg.StatsPort,
		LocalDNSPort:            cfg.LocalDNSPort,
		OnEvent:                 supervisorEventHandler(emitEvent),
		DisableBinaryValidation: opts.DisableBinaryValidation,
		StartupGrace:            opts.StartupGrace,
	})
	if err != nil {
		return fmt.Errorf("init supervisor: %w", err)
	}
	if err := sup.Start(ctx); err != nil {
		return fmt.Errorf("start supervisor: %w", err)
	}
	supStopped := false
	defer func() {
		if !supStopped {
			sctx, scancel := context.WithTimeout(context.Background(), 10*time.Second)
			_ = sup.Stop(sctx)
			scancel()
		}
	}()

	col, err := collector.New(collector.Options{
		DataDir:             cfg.DataDir,
		Interface:           cfg.Iface,
		StatsAddr:           fmt.Sprintf("127.0.0.1:%d", cfg.StatsPort),
		ProcNetDevPath:      procNetDevPath,
		ProcNetRoutePath:    procNetRoutePath,
		SnellPIDFunc:        func() int { return sup.KernelPID(protocol.KernelSnellServer) },
		PublicIPEndpointsV4: opts.PublicIPEndpointsV4,
		PublicIPEndpointsV6: opts.PublicIPEndpointsV6,
		Logger:              logger,
	})
	if err != nil {
		return fmt.Errorf("init collector: %w", err)
	}
	col.SetStatsEnabled(false)
	colStopped := false
	defer func() {
		if !colStopped {
			col.Stop()
		}
	}()

	coord := newConfigCoordinator(
		dnsSrv,
		sup,
		col,
		emitEvent,
		logger,
		initialDNS,
		cfg.LocalDNSPort,
		cfg.StatsPort,
		cfg.DataDir,
	)

	// *supervisor.Supervisor directly satisfies updater.KernelController.
	var _ updater.KernelController = sup
	upd, err := updater.New(updater.Options{
		DataDir:          cfg.DataDir,
		Controller:       sup,
		OnEvent:          emitEvent,
		AcquireApplyLock: coord.AcquireOpLock,
	})
	if err != nil {
		return fmt.Errorf("init updater: %w", err)
	}

	wsClient, err := wsclient.New(wsclient.Options{
		PanelURL:        cfg.PanelURL,
		NodeToken:       cfg.NodeToken,
		TLSSkipVerify:   cfg.TLSSkipVerify,
		MetricsInterval: opts.MetricsInterval,
		BackoffBase:     opts.BackoffBase,
		BackoffMax:      opts.BackoffMax,
		PingInterval:    opts.PingInterval,
		Logger:          logger,
		BuildHello: func(hctx context.Context) protocol.AgentHello {
			osName, arch, cpuCores, totalRAM := col.HostInfo()
			var ipv4, ipv6 string
			var versions protocol.AgentVersions

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				ipv4, ipv6 = col.DetectPublicIPs(hctx)
			}()
			go func() {
				defer wg.Done()
				versions = sup.Versions(hctx)
			}()
			wg.Wait()

			return protocol.AgentHello{
				OS:             osName,
				Arch:           arch,
				CPUCores:       cpuCores,
				TotalRAMBytes:  totalRAM,
				PublicIPv4:     ipv4,
				PublicIPv6:     ipv6,
				Versions:       versions,
				ConfigRevision: coord.CurrentRevision(),
			}
		},
		StageMetrics: func(mctx context.Context) (protocol.AgentMetrics, func() error, error) {
			return col.StageMetrics(mctx, sup.Health())
		},
		OnConfigSync: func(cctx context.Context, syncCfg protocol.ServerConfigSync) {
			if err := coord.Apply(cctx, syncCfg, true); err != nil {
				logger.Warn("config_sync apply failed", "revision", syncCfg.ConfigRevision, "error", err)
			}
		},
		OnServiceCtl: func(sctx context.Context, cmd protocol.ServerServiceCtl) {
			unlock, err := coord.AcquireOpLock(sctx)
			if err != nil {
				logger.Warn("service_ctl cancelled while waiting for lock", "action", cmd.Action, "error", err)
				return
			}
			defer unlock()
			if err := sup.ServiceControl(sctx, cmd.Action); err != nil {
				logger.Warn("service_ctl failed", "action", cmd.Action, "error", err)
			}
		},
		OnKernelUpdate: func(uctx context.Context, req protocol.ServerKernelUpdate) {
			if err := upd.ApplyUpdate(uctx, req); err != nil {
				logger.Warn("kernel_update failed", "kernel", req.Kernel, "version", req.Version, "error", err)
			}
		},
	})
	if err != nil {
		return fmt.Errorf("init wsclient: %w", err)
	}
	clientPtr.Store(wsClient)

	// Offline autonomy: apply cached last_config.json immediately before/independently of WS.
	if hasCached {
		if err := coord.Apply(ctx, cachedCfg, false); err != nil {
			logger.Warn("failed to apply cached last_config.json",
				"revision", cachedCfg.ConfigRevision,
				"error", err,
			)
		} else {
			logger.Info("applied cached last_config.json for offline autonomy",
				"revision", cachedCfg.ConfigRevision,
			)
		}
	}

	col.Start(ctx)

	wsDone := make(chan error, 1)
	go func() {
		wsDone <- wsClient.Run(ctx)
	}()

	if ready != nil {
		close(ready)
	}

	<-ctx.Done()
	logger.Info("node agent shutting down")

	// Clean reverse-order shutdown for tini: wsclient -> collector -> supervisor -> dnsproxy.
	wsTimer := time.NewTimer(10 * time.Second)
	select {
	case wsErr := <-wsDone:
		wsTimer.Stop()
		if wsErr != nil {
			logger.Warn("wsclient exited with error", "error", wsErr)
		}
	case <-wsTimer.C:
		logger.Warn("timed out waiting for wsclient shutdown")
	}

	col.Stop()
	colStopped = true

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	if err := sup.Stop(shutdownCtx); err != nil {
		logger.Warn("supervisor shutdown error", "error", err)
	}
	supStopped = true

	if err := dnsSrv.Stop(shutdownCtx); err != nil {
		logger.Warn("dnsproxy shutdown error", "error", err)
	}
	dnsStopped = true

	return nil
}

func main() {
	cfg, err := ParseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "agent config error: %v\n", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "agent error: %v\n", err)
		os.Exit(1)
	}
}
