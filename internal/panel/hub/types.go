package hub

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

const (
	defaultPingInterval      = 25 * time.Second
	defaultPingTimeout       = 10 * time.Second
	defaultWriteTimeout      = 10 * time.Second
	defaultReadLimit         = int64(1 << 20) // 1 MiB
	defaultPublicDebounce    = 200 * time.Millisecond
	defaultOfflineAlertDelay = 10 * time.Minute

	agentSendQueueCap  = 64
	publicSendQueueCap = 4
)

// Sentinel errors returned by Hub operations.
var (
	ErrNodeOffline    = errors.New("hub: node is offline")
	ErrInvalidCommand = errors.New("hub: invalid command")
	ErrHubClosed      = errors.New("hub: hub is closed")
)

// AlertNotifier dispatches alert events (implemented directly by *webhook.Engine).
type AlertNotifier interface {
	Notify(ctx context.Context, evt webhook.AlertEvent)
}

// TrafficUpdatedFunc is invoked after agent.metrics traffic deltas are persisted.
type TrafficUpdatedFunc func(ctx context.Context, node *store.Node, updatedUserIDs []int64)

// NodeStateChangedFunc is invoked when a node's connection state or public IP/health state changes.
type NodeStateChangedFunc func(ctx context.Context, nodeID int64)

// NodeTelemetry holds the latest in-memory runtime telemetry for a node.
type NodeTelemetry struct {
	NodeID                 int64
	Online                 bool
	OS                     string
	Arch                   string
	CPUCores               int
	TotalRAMBytes          uint64
	PublicIPv4             string
	PublicIPv6             string
	Versions               protocol.AgentVersions
	ReportedConfigRevision int64
	CPUPercent             float64
	MemUsedBytes           uint64
	MemTotalBytes          uint64
	DiskUsedPercent        float64
	UptimeSeconds          uint64
	RxBPS                  uint64
	TxBPS                  uint64
	Health                 protocol.AgentHealth
	LastSeenAt             time.Time
	LastEvent              *protocol.AgentEvent
}

// KernelUpdateStatus tracks the most recent kernel update progress or result event for a node.
type KernelUpdateStatus struct {
	NodeID    int64
	Kernel    string
	Version   string
	Status    string
	Message   string
	Detail    string
	UpdatedAt time.Time
}

// Option configures Hub behavior.
type Option func(*Hub)

// WithLogger overrides the structured logger used by Hub.
func WithLogger(logger *slog.Logger) Option {
	return func(h *Hub) {
		if logger != nil {
			h.logger = logger
		}
	}
}

// WithNow overrides the clock function used by Hub (defaults to time.Now).
func WithNow(now func() time.Time) Option {
	return func(h *Hub) {
		if now != nil {
			h.now = now
		}
	}
}

// WithPingInterval sets the WebSocket keepalive ping interval for agent sessions.
func WithPingInterval(d time.Duration) Option {
	return func(h *Hub) {
		if d > 0 {
			h.pingInterval = d
		}
	}
}

// WithPingTimeout sets the WebSocket keepalive ping timeout for agent sessions.
func WithPingTimeout(d time.Duration) Option {
	return func(h *Hub) {
		if d > 0 {
			h.pingTimeout = d
		}
	}
}

// WithWriteTimeout sets the per-frame WebSocket write timeout.
func WithWriteTimeout(d time.Duration) Option {
	return func(h *Hub) {
		if d > 0 {
			h.writeTimeout = d
		}
	}
}

// WithReadLimit sets the maximum inbound WebSocket frame size in bytes.
func WithReadLimit(limit int64) Option {
	return func(h *Hub) {
		if limit > 0 {
			h.readLimit = limit
		}
	}
}

// WithPublicDebounce sets the debounce interval for coalescing public WS broadcasts.
func WithPublicDebounce(d time.Duration) Option {
	return func(h *Hub) {
		if d >= 0 {
			h.publicDebounce = d
		}
	}
}

// WithOfflineAlertDelay sets how long a node must remain offline before firing node_offline alerts.
func WithOfflineAlertDelay(d time.Duration) Option {
	return func(h *Hub) {
		if d >= 0 {
			h.offlineAlertDelay = d
		}
	}
}

// WithOnTrafficUpdated registers the callback invoked after traffic deltas are applied.
func WithOnTrafficUpdated(fn TrafficUpdatedFunc) Option {
	return func(h *Hub) {
		h.onTrafficUpdated = fn
	}
}
