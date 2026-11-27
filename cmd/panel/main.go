package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"snell-panel/internal/panel/api"
	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/sub"
	"snell-panel/internal/panel/webhook"
	"snell-panel/web"
)

var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Config holds Panel Server runtime configuration.
type Config struct {
	ListenAddr             string
	DBPath                 string
	AdminInitialPass       string
	JWTSecret              string
	GitHubAPIURL           string
	WebhookBlockPrivateIPs bool
	ShowVersion            bool
}

// ParseConfig parses flags and environment variables for the Panel Server.
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

	defaultListen := strings.TrimSpace(getenv("LISTEN_ADDR"))
	if defaultListen == "" {
		if port := strings.TrimSpace(getenv("PORT")); port != "" {
			if strings.Contains(port, ":") {
				defaultListen = port
			} else {
				defaultListen = ":" + port
			}
		} else {
			defaultListen = ":8080"
		}
	}

	blockPrivateIPs := false
	if rawBlock := strings.TrimSpace(getenv("WEBHOOK_BLOCK_PRIVATE_IPS")); rawBlock != "" {
		parsed, err := strconv.ParseBool(rawBlock)
		if err != nil {
			return Config{}, fmt.Errorf("parse WEBHOOK_BLOCK_PRIVATE_IPS: %w", err)
		}
		blockPrivateIPs = parsed
	}

	cfg := Config{
		ListenAddr:             defaultListen,
		DBPath:                 envOrDefault("DB_PATH", "./data/panel.db"),
		AdminInitialPass:       getenv("ADMIN_INITIAL_PASS"),
		JWTSecret:              getenv("JWT_SECRET"),
		GitHubAPIURL:           strings.TrimSpace(getenv("GITHUB_API_URL")),
		WebhookBlockPrivateIPs: blockPrivateIPs,
	}

	fsFlag := flag.NewFlagSet("panel", flag.ContinueOnError)
	fsFlag.SetOutput(io.Discard)
	fsFlag.StringVar(&cfg.ListenAddr, "listen", cfg.ListenAddr, "HTTP listen address")
	fsFlag.StringVar(&cfg.DBPath, "db", cfg.DBPath, "SQLite database path")
	fsFlag.StringVar(&cfg.AdminInitialPass, "admin-pass", cfg.AdminInitialPass, "initial admin password")
	fsFlag.StringVar(&cfg.JWTSecret, "jwt-secret", cfg.JWTSecret, "optional JWT signing secret")
	fsFlag.StringVar(&cfg.GitHubAPIURL, "github-api-url", cfg.GitHubAPIURL, "optional GitHub API base URL override")
	fsFlag.BoolVar(&cfg.WebhookBlockPrivateIPs, "webhook-block-private-ips", cfg.WebhookBlockPrivateIPs, "block webhook requests to private or loopback IPs")
	fsFlag.BoolVar(&cfg.ShowVersion, "version", false, "print version information and exit")

	if err := fsFlag.Parse(args); err != nil {
		return Config{}, fmt.Errorf("parse flags: %w", err)
	}
	if cfg.ShowVersion {
		return cfg, nil
	}
	if strings.TrimSpace(cfg.ListenAddr) == "" {
		return Config{}, errors.New("listen address cannot be empty")
	}
	if strings.TrimSpace(cfg.DBPath) == "" {
		return Config{}, errors.New("database path cannot be empty")
	}
	return cfg, nil
}

// Run starts the Panel Server with optional embedded static assets and blocks until ctx is canceled or serving fails.
func Run(ctx context.Context, cfg Config, staticFS fs.FS, stdout io.Writer) error {
	return runWithReadyAndFS(ctx, cfg, staticFS, stdout, nil)
}

func run(ctx context.Context, cfg Config, stdout io.Writer) error {
	return Run(ctx, cfg, nil, stdout)
}

func runWithReady(ctx context.Context, cfg Config, stdout io.Writer, readyAddr chan<- string) error {
	return runWithReadyAndFS(ctx, cfg, nil, stdout, readyAddr)
}

func runWithReadyAndFS(ctx context.Context, cfg Config, staticFS fs.FS, stdout io.Writer, readyAddr chan<- string) error {
	if stdout == nil {
		stdout = io.Discard
	}
	if cfg.ShowVersion {
		_, err := fmt.Fprintf(stdout, "snell-panel version=%s commit=%s date=%s\n", version, commit, date)
		return err
	}

	logger := slog.New(slog.NewJSONHandler(stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	st, err := store.Open(ctx, cfg.DBPath)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()

	if err := st.SeedDefaults(ctx, store.SeedConfig{
		AdminInitialPass: cfg.AdminInitialPass,
		JWTSecret:        cfg.JWTSecret,
	}); err != nil {
		return fmt.Errorf("seed defaults: %w", err)
	}

	authSvc, err := auth.NewService(ctx, st, auth.Config{})
	if err != nil {
		return fmt.Errorf("init auth service: %w", err)
	}

	wh := webhook.NewEngine(
		st,
		nil,
		webhook.WithLogger(logger),
		webhook.WithBlockPrivateIPs(cfg.WebhookBlockPrivateIPs),
	)
	defer wh.Close()

	subRenderer := sub.NewRenderer(st)

	h := hub.NewHub(st, wh, hub.WithLogger(logger))
	defer h.Close()

	schedOpts := []scheduler.Option{
		scheduler.WithLogger(logger),
	}
	if strings.TrimSpace(cfg.GitHubAPIURL) != "" {
		schedOpts = append(schedOpts, scheduler.WithGitHubAPIBaseURL(strings.TrimSpace(cfg.GitHubAPIURL)))
	}
	sched := scheduler.NewScheduler(st, h, wh, schedOpts...)
	sched.WireHub()
	sched.Start(ctx)
	defer sched.Stop()

	handler := api.NewServer(api.Dependencies{
		Store:     st,
		Auth:      authSvc,
		Hub:       h,
		Sub:       subRenderer,
		Scheduler: sched,
		Webhook:   wh,
		StaticFS:  staticFS,
		Logger:    logger,
	})

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.ListenAddr, err)
	}

	var (
		newConnsMu   sync.Mutex
		newConns     = make(map[net.Conn]struct{})
		shutdownDone bool
		newConnTimer *time.Timer
	)

	srvBaseCtx, srvBaseCancel := context.WithCancel(context.Background())
	defer srvBaseCancel()

	srv := &http.Server{
		Addr:              ln.Addr().String(),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return srvBaseCtx },
		ConnState: func(c net.Conn, state http.ConnState) {
			newConnsMu.Lock()
			if state == http.StateNew {
				newConns[c] = struct{}{}
			} else {
				delete(newConns, c)
			}
			newConnsMu.Unlock()
		},
	}
	srv.RegisterOnShutdown(func() {
		newConnsMu.Lock()
		if shutdownDone {
			newConnsMu.Unlock()
			return
		}
		newConnTimer = time.AfterFunc(200*time.Millisecond, func() {
			newConnsMu.Lock()
			if shutdownDone || len(newConns) == 0 {
				newConnsMu.Unlock()
				return
			}
			conns := make([]net.Conn, 0, len(newConns))
			for c := range newConns {
				conns = append(conns, c)
			}
			newConnsMu.Unlock()
			for _, c := range conns {
				_ = c.Close()
			}
		})
		newConnsMu.Unlock()
	})

	errCh := make(chan error, 1)
	go func() {
		if serveErr := srv.Serve(ln); serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr
			return
		}
		errCh <- nil
	}()

	logger.Info("panel server started", "addr", ln.Addr().String(), "db_path", cfg.DBPath)
	if readyAddr != nil {
		readyAddr <- ln.Addr().String()
	}

	select {
	case serveErr := <-errCh:
		sched.Stop()
		_ = h.Close()
		wh.Close()
		_ = st.Close()
		return serveErr
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2500*time.Millisecond)
		defer cancel()

		var bgShutdownWg sync.WaitGroup
		bgShutdownWg.Add(1)
		go func() {
			defer bgShutdownWg.Done()
			sched.Stop()
			_ = h.Close()
		}()

		err := srv.Shutdown(shutdownCtx)
		newConnsMu.Lock()
		shutdownDone = true
		if newConnTimer != nil {
			newConnTimer.Stop()
		}
		newConnsMu.Unlock()
		if err != nil {
			logger.Warn("http server graceful shutdown timed out; forcing close", "err", err)
			_ = srv.Close()
			srvBaseCancel()
		}
		serveErr := <-errCh
		bgShutdownWg.Wait()
		wh.Close()
		_ = st.Close()
		logger.Info("panel server stopped")
		return serveErr
	}
}

func main() {
	cfg, err := ParseConfig(os.Args[1:], os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "panel config error: %v\n", err)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := Run(ctx, cfg, web.DistFS, os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "panel error: %v\n", err)
		os.Exit(1)
	}
}
