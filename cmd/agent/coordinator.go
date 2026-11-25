package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"snell-panel/internal/agent/dnsproxy"
	"snell-panel/internal/protocol"
)

const lastConfigFilename = "last_config.json"

type ctxMutex struct {
	ch chan struct{}
}

func newCtxMutex() *ctxMutex {
	return &ctxMutex{ch: make(chan struct{}, 1)}
}

func (m *ctxMutex) Lock(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case m.ch <- struct{}{}:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (m *ctxMutex) Unlock() {
	select {
	case <-m.ch:
	default:
		panic("ctxMutex: unlock of unlocked mutex")
	}
}

func (m *ctxMutex) Acquire(ctx context.Context) (func(), error) {
	if err := m.Lock(ctx); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() {
		once.Do(m.Unlock)
	}, nil
}

type dnsManager interface {
	ApplyProtocolConfig(cfg protocol.DNSConfig) error
	UpdateConfig(cfg dnsproxy.Config) error
	Port() int
}

type supervisorManager interface {
	ApplyConfig(ctx context.Context, cfg protocol.ServerConfigSync) error
}

type collectorManager interface {
	SetActiveUsers(users []protocol.SSUserEntry)
	SetStatsEnabled(enabled bool)
}

type configCoordinator struct {
	opLock            *ctxMutex
	mu                sync.Mutex
	dns               dnsManager
	sup               supervisorManager
	col               collectorManager
	emitEvent         func(protocol.AgentEvent)
	saveLastConfig    func(path string, cfg protocol.ServerConfigSync) error
	logger            *slog.Logger
	initialDNS        dnsproxy.Config
	configuredDNSPort int
	statsPort         int
	lastConfigPath    string

	hasPrev          bool
	prevEffectiveDNS protocol.DNSConfig
	currentRevision  atomic.Int64
}

func newConfigCoordinator(
	dns dnsManager,
	sup supervisorManager,
	col collectorManager,
	emitEvent func(protocol.AgentEvent),
	logger *slog.Logger,
	initialDNS dnsproxy.Config,
	configuredDNSPort int,
	statsPort int,
	dataDir string,
) *configCoordinator {
	clonedInitialDNS := cloneDNSProxyConfig(initialDNS)
	if clonedInitialDNS.ListenPort == 0 && dns != nil {
		if bound := dns.Port(); bound > 0 {
			clonedInitialDNS.ListenPort = bound
		}
	}
	return &configCoordinator{
		opLock:            newCtxMutex(),
		dns:               dns,
		sup:               sup,
		col:               col,
		emitEvent:         emitEvent,
		saveLastConfig:    saveLastConfigAtomic,
		logger:            logger,
		initialDNS:        clonedInitialDNS,
		configuredDNSPort: configuredDNSPort,
		statsPort:         statsPort,
		lastConfigPath:    filepath.Join(dataDir, lastConfigFilename),
	}
}

func (c *configCoordinator) CurrentRevision() int64 {
	return c.currentRevision.Load()
}

func (c *configCoordinator) AcquireOpLock(ctx context.Context) (func(), error) {
	return c.opLock.Acquire(ctx)
}

func (c *configCoordinator) emit(ev protocol.AgentEvent) {
	if c.emitEvent != nil {
		c.emitEvent(ev)
	}
}

func (c *configCoordinator) Apply(ctx context.Context, nextCfg protocol.ServerConfigSync, persist bool) error {
	if err := c.opLock.Lock(ctx); err != nil {
		return err
	}
	defer c.opLock.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	curRev := c.currentRevision.Load()
	if curRev > 0 {
		if nextCfg.ConfigRevision < curRev {
			c.logger.Info("ignoring stale server.config_sync",
				"incoming_revision", nextCfg.ConfigRevision,
				"current_revision", curRev,
			)
			return nil
		}
		if nextCfg.ConfigRevision == curRev {
			c.logger.Info("configuration already applied, skipping redundant restart",
				"config_revision", nextCfg.ConfigRevision,
			)
			c.emit(protocol.AgentEvent{
				Event:          protocol.EventConfigApplied,
				ConfigRevision: nextCfg.ConfigRevision,
				Status:         protocol.EventStatusSuccess,
				Message:        "configuration already applied",
			})
			return nil
		}
	}
	if nextCfg.ConfigRevision <= 0 {
		err := fmt.Errorf("invalid config_revision %d: must be > 0", nextCfg.ConfigRevision)
		c.emit(protocol.AgentEvent{
			Event:          protocol.EventConfigError,
			ConfigRevision: nextCfg.ConfigRevision,
			Status:         protocol.EventStatusFailed,
			Message:        "invalid config_revision",
			Detail:         err.Error(),
		})
		return err
	}

	effectiveDNS := cloneProtocolDNS(nextCfg.DNS)
	if effectiveDNS.LocalPort == 0 && c.configuredDNSPort > 0 {
		effectiveDNS.LocalPort = c.configuredDNSPort
	}

	checkPort := effectiveDNS.LocalPort
	if checkPort == 0 {
		checkPort = c.dns.Port()
	}
	if checkPort == c.statsPort {
		err := fmt.Errorf("dns.local_port (%d) cannot equal stats_port (%d)", checkPort, c.statsPort)
		c.emit(protocol.AgentEvent{
			Event:          protocol.EventConfigError,
			ConfigRevision: nextCfg.ConfigRevision,
			Status:         protocol.EventStatusFailed,
			Message:        "dnsproxy port collides with stats_port",
			Detail:         err.Error(),
		})
		return err
	}

	prevDNSPort := c.dns.Port()
	if err := c.dns.ApplyProtocolConfig(effectiveDNS); err != nil {
		c.emit(protocol.AgentEvent{
			Event:          protocol.EventConfigError,
			ConfigRevision: nextCfg.ConfigRevision,
			Status:         protocol.EventStatusFailed,
			Message:        "dnsproxy config apply failed",
			Detail:         err.Error(),
		})
		return err
	}

	boundPort := c.dns.Port()
	if boundPort <= 0 {
		boundPort = effectiveDNS.LocalPort
	}
	if prevDNSPort > 0 && boundPort != prevDNSPort {
		c.logger.Info("reconciled local_dns_port",
			"previous_port", prevDNSPort,
			"effective_port", boundPort,
			"config_revision", nextCfg.ConfigRevision,
		)
	}

	supCfg := cloneServerConfigSync(nextCfg)
	supCfg.DNS.LocalPort = boundPort

	if err := c.sup.ApplyConfig(ctx, supCfg); err != nil {
		// supervisor.ApplyConfig already rolled back kernels and emitted config_error.
		if c.hasPrev {
			if rbErr := c.dns.ApplyProtocolConfig(c.prevEffectiveDNS); rbErr != nil {
				c.logger.Error("failed to rollback dnsproxy to previous config", "error", rbErr)
			}
		} else {
			if rbErr := c.dns.UpdateConfig(c.initialDNS); rbErr != nil {
				c.logger.Error("failed to rollback dnsproxy to initial config", "error", rbErr)
			}
		}
		return err
	}

	c.col.SetActiveUsers(nextCfg.SS.Users)
	statsEnabled := nextCfg.SS.Enabled
	if capProvider, ok := c.sup.(interface{ SingBoxV2RayAPIEnabled() bool }); ok {
		statsEnabled = statsEnabled && capProvider.SingBoxV2RayAPIEnabled()
	}
	c.col.SetStatsEnabled(statsEnabled)

	effectiveDNS.LocalPort = boundPort
	c.prevEffectiveDNS = effectiveDNS
	c.hasPrev = true

	if persist {
		persistFn := c.saveLastConfig
		if persistFn == nil {
			persistFn = saveLastConfigAtomic
		}
		if err := persistFn(c.lastConfigPath, nextCfg); err != nil {
			c.logger.Error("failed to persist last_config.json", "path", c.lastConfigPath, "error", err)
			c.emit(protocol.AgentEvent{
				Event:          protocol.EventConfigError,
				ConfigRevision: nextCfg.ConfigRevision,
				Status:         protocol.EventStatusFailed,
				Message:        "failed to persist last_config.json",
				Detail:         err.Error(),
			})
			return fmt.Errorf("persist last_config.json: %w", err)
		}
	}

	c.currentRevision.Store(nextCfg.ConfigRevision)
	c.emit(protocol.AgentEvent{
		Event:          protocol.EventConfigApplied,
		ConfigRevision: nextCfg.ConfigRevision,
		Status:         protocol.EventStatusSuccess,
		Message:        "configuration applied",
	})
	return nil
}

func loadLastConfig(path string, logger *slog.Logger) (protocol.ServerConfigSync, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Warn("failed to read last_config.json, starting fresh", "path", path, "error", err)
		}
		return protocol.ServerConfigSync{}, false
	}

	quarantine := func(reason string, parseErr error) {
		corruptPath := fmt.Sprintf("%s.corrupt.%d", path, time.Now().UnixNano())
		if renErr := os.Rename(path, corruptPath); renErr != nil {
			logger.Warn("corrupt last_config.json could not be quarantined",
				"path", path,
				"reason", reason,
				"parse_error", parseErr,
				"rename_error", renErr,
			)
			return
		}
		logger.Warn("quarantined corrupt last_config.json",
			"corrupt_path", corruptPath,
			"reason", reason,
			"error", parseErr,
		)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		quarantine("empty file", errors.New("empty config file"))
		return protocol.ServerConfigSync{}, false
	}
	if bytes.Equal(trimmed, []byte("null")) {
		quarantine("null JSON", errors.New("last_config.json contains JSON null"))
		return protocol.ServerConfigSync{}, false
	}

	var cfg protocol.ServerConfigSync
	if err := json.Unmarshal(trimmed, &cfg); err != nil {
		quarantine("invalid JSON", err)
		return protocol.ServerConfigSync{}, false
	}
	if cfg.ConfigRevision <= 0 {
		quarantine("invalid config_revision", fmt.Errorf("config_revision %d must be > 0", cfg.ConfigRevision))
		return protocol.ServerConfigSync{}, false
	}
	return cfg, true
}

func saveLastConfigAtomic(path string, cfg protocol.ServerConfigSync) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(dir, lastConfigFilename+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil {
		cleanup()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if dirFD, err := os.Open(dir); err == nil {
		_ = dirFD.Sync()
		_ = dirFD.Close()
	}
	return nil
}

func cloneDNSProxyConfig(cfg dnsproxy.Config) dnsproxy.Config {
	out := cfg
	out.Rules = slices.Clone(cfg.Rules)
	return out
}

func cloneProtocolDNS(cfg protocol.DNSConfig) protocol.DNSConfig {
	out := cfg
	out.Rules = slices.Clone(cfg.Rules)
	return out
}

func cloneServerConfigSync(cfg protocol.ServerConfigSync) protocol.ServerConfigSync {
	out := cfg
	out.SS.Users = slices.Clone(cfg.SS.Users)
	out.DNS.Rules = slices.Clone(cfg.DNS.Rules)
	return out
}
