package hub

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

const defaultOfflineTimeoutSeconds = 60

// Hub manages agent WebSocket sessions, config compilation/dispatch,
// telemetry caching, heartbeat sweeps, and redacted public WS broadcasting.
type Hub struct {
	store    *store.Store
	notifier AlertNotifier

	logger         *slog.Logger
	now            func() time.Time
	pingInterval   time.Duration
	pingTimeout    time.Duration
	writeTimeout   time.Duration
	readLimit      int64
	publicDebounce time.Duration

	callbackMu       sync.RWMutex
	onTrafficUpdated TrafficUpdatedFunc

	baseCtx    context.Context
	cancelBase context.CancelFunc
	wg         sync.WaitGroup

	nextSessionID atomic.Uint64
	nextReqSeq    atomic.Uint64

	mu             sync.RWMutex
	closed         bool
	sessions       map[int64]*agentSession
	telemetry      map[int64]NodeTelemetry
	kernelUpdates  map[int64]KernelUpdateStatus
	offlinePending map[int64]time.Time
	offlineAlerted map[int64]bool

	statusLocksMu sync.Mutex
	statusLocks   map[int64]*sync.Mutex

	publicMu      sync.Mutex
	publicClients map[uint64]*publicClient
	publicDirtyCh chan struct{}
}

// NewHub constructs a Hub and starts its debounced public WS broadcaster.
func NewHub(st *store.Store, notifier AlertNotifier, opts ...Option) *Hub {
	baseCtx, cancelBase := context.WithCancel(context.Background())
	h := &Hub{
		store:          st,
		notifier:       notifier,
		logger:         slog.Default(),
		now:            time.Now,
		pingInterval:   defaultPingInterval,
		pingTimeout:    defaultPingTimeout,
		writeTimeout:   defaultWriteTimeout,
		readLimit:      defaultReadLimit,
		publicDebounce: defaultPublicDebounce,
		baseCtx:        baseCtx,
		cancelBase:     cancelBase,
		sessions:       make(map[int64]*agentSession),
		telemetry:      make(map[int64]NodeTelemetry),
		kernelUpdates:  make(map[int64]KernelUpdateStatus),
		offlinePending: make(map[int64]time.Time),
		offlineAlerted: make(map[int64]bool),
		statusLocks:    make(map[int64]*sync.Mutex),
		publicClients:  make(map[uint64]*publicClient),
		publicDirtyCh:  make(chan struct{}, 1),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}

	h.wg.Add(1)
	go h.publicBroadcasterLoop()

	return h
}

// SetOnTrafficUpdated registers or replaces the traffic-update callback for post-construction wiring.
func (h *Hub) SetOnTrafficUpdated(fn TrafficUpdatedFunc) {
	h.callbackMu.Lock()
	h.onTrafficUpdated = fn
	h.callbackMu.Unlock()
}

func (h *Hub) getOnTrafficUpdated() TrafficUpdatedFunc {
	h.callbackMu.RLock()
	fn := h.onTrafficUpdated
	h.callbackMu.RUnlock()
	return fn
}

// Close cancels the hub context, closes all active agent and public WS connections,
// and waits for all background goroutines to drain cleanly.
func (h *Hub) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		h.wg.Wait()
		return nil
	}
	h.closed = true
	agentSessions := make([]*agentSession, 0, len(h.sessions))
	for _, s := range h.sessions {
		agentSessions = append(agentSessions, s)
	}
	clear(h.sessions)
	h.mu.Unlock()

	h.publicMu.Lock()
	pubClients := make([]*publicClient, 0, len(h.publicClients))
	for _, c := range h.publicClients {
		pubClients = append(pubClients, c)
	}
	clear(h.publicClients)
	h.publicMu.Unlock()

	h.cancelBase()

	for _, s := range agentSessions {
		s.cancel()
		_ = s.conn.CloseNow()
	}
	for _, c := range pubClients {
		c.cancel()
		_ = c.conn.CloseNow()
	}

	h.wg.Wait()
	return nil
}

// EvictNode closes any active agent WS session for nodeID, purges cached
// in-memory state (session, telemetry, kernel updates, offline tracking),
// and triggers a public status broadcast.
func (h *Hub) EvictNode(nodeID int64) {
	if h == nil || nodeID <= 0 {
		return
	}

	h.mu.Lock()
	sess := h.sessions[nodeID]
	if sess != nil {
		sess.superseded.Store(true)
		delete(h.sessions, nodeID)
	}
	delete(h.telemetry, nodeID)
	delete(h.kernelUpdates, nodeID)
	delete(h.offlinePending, nodeID)
	delete(h.offlineAlerted, nodeID)
	closed := h.closed
	h.mu.Unlock()

	if sess != nil {
		sess.cancel()
		_ = sess.conn.CloseNow()
	}
	if !closed {
		h.triggerPublicBroadcast()
	}
}

func (h *Hub) isClosed() bool {
	h.mu.RLock()
	closed := h.closed
	h.mu.RUnlock()
	return closed
}

// GetTelemetry returns a copy of the cached telemetry for nodeID.
func (h *Hub) GetTelemetry(nodeID int64) (NodeTelemetry, bool) {
	h.mu.RLock()
	tel, ok := h.telemetry[nodeID]
	h.mu.RUnlock()
	if !ok {
		return NodeTelemetry{}, false
	}
	if tel.LastEvent != nil {
		evCopy := *tel.LastEvent
		tel.LastEvent = &evCopy
	}
	return tel, true
}

// GetKernelUpdateStatus returns the latest cached kernel update status for nodeID.
func (h *Hub) GetKernelUpdateStatus(nodeID int64) (KernelUpdateStatus, bool) {
	h.mu.RLock()
	st, ok := h.kernelUpdates[nodeID]
	h.mu.RUnlock()
	return st, ok
}

// IsOnline reports whether nodeID currently has an active agent WS session.
func (h *Hub) IsOnline(nodeID int64) bool {
	h.mu.RLock()
	_, ok := h.sessions[nodeID]
	h.mu.RUnlock()
	return ok
}

// OnlineNodeIDs returns a sorted slice of node IDs with active agent WS sessions.
func (h *Hub) OnlineNodeIDs() []int64 {
	h.mu.RLock()
	ids := make([]int64, 0, len(h.sessions))
	for id := range h.sessions {
		ids = append(ids, id)
	}
	h.mu.RUnlock()
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}

func (h *Hub) getSession(nodeID int64) *agentSession {
	h.mu.RLock()
	sess := h.sessions[nodeID]
	h.mu.RUnlock()
	return sess
}

// nodeStatusLock returns the per-node mutex used to serialize DB connection-status
// transitions. Lock ordering invariant: ALWAYS acquire nodeStatusMu OUTSIDE h.mu
// (never acquire nodeStatusMu while holding h.mu).
func (h *Hub) nodeStatusLock(nodeID int64) *sync.Mutex {
	h.statusLocksMu.Lock()
	mu, ok := h.statusLocks[nodeID]
	if !ok {
		mu = &sync.Mutex{}
		h.statusLocks[nodeID] = mu
	}
	h.statusLocksMu.Unlock()
	return mu
}

func (h *Hub) nextReqID() string {
	return fmt.Sprintf("srv-%d-%d", h.now().UTC().UnixMilli(), h.nextReqSeq.Add(1))
}

func (h *Hub) notify(ctx context.Context, evt webhook.AlertEvent) {
	if h.notifier == nil {
		return
	}
	notifyCtx := h.baseCtx
	if ctx != nil && ctx.Err() == nil {
		notifyCtx = context.WithoutCancel(ctx)
	}
	h.notifier.Notify(notifyCtx, evt)
}

// CheckHeartbeats evicts stale live sessions whose LastSeenAt exceeded offlineTimeout,
// marks stale nodes offline in the store (preserving traffic_paused), and fires
// webhook.EventNodeOffline once per offline transition without re-alerting after restarts.
func (h *Hub) CheckHeartbeats(ctx context.Context, offlineTimeout time.Duration) error {
	if h.store == nil {
		return errors.New("hub: nil store")
	}
	if ctx == nil {
		ctx = h.baseCtx
	}
	if offlineTimeout <= 0 {
		val, err := h.store.GetSettingOrDefault(ctx, "offline_timeout_seconds", strconv.Itoa(defaultOfflineTimeoutSeconds))
		if err != nil {
			return err
		}
		secs, convErr := strconv.Atoi(strings.TrimSpace(val))
		if convErr != nil || secs <= 0 {
			secs = defaultOfflineTimeoutSeconds
		}
		offlineTimeout = time.Duration(secs) * time.Second
	}

	nodes, err := h.store.ListNodes(ctx)
	if err != nil {
		return err
	}

	now := h.now().UTC()
	var anyStatusChanged bool

	for _, n := range nodes {
		if !n.Enabled || n.LastSeenAt == nil {
			continue
		}

		nodeStatusMu := h.nodeStatusLock(n.ID)
		nodeStatusMu.Lock()

		h.mu.Lock()
		if h.closed {
			h.mu.Unlock()
			nodeStatusMu.Unlock()
			return nil
		}
		sess := h.sessions[n.ID]
		tel, hasTel := h.telemetry[n.ID]
		lastSeen := n.LastSeenAt.UTC()
		if hasTel && tel.LastSeenAt.After(lastSeen) {
			lastSeen = tel.LastSeenAt.UTC()
		}

		if now.Sub(lastSeen) < offlineTimeout {
			h.mu.Unlock()
			nodeStatusMu.Unlock()
			continue
		}

		// Evict stale half-open live session if present.
		var evicted *agentSession
		if sess != nil {
			evicted = sess
			evicted.superseded.Store(true)
			delete(h.sessions, n.ID)
		}

		if hasTel {
			tel.Online = false
			h.telemetry[n.ID] = tel
		}

		_, isPending := h.offlinePending[n.ID]
		wasOfflineAlerted := h.offlineAlerted[n.ID]
		shouldAlert := (n.Status == protocol.NodeStatusOnline || isPending || evicted != nil) && !wasOfflineAlerted
		needsDBOffline := shouldAlert || n.Status == protocol.NodeStatusOnline || evicted != nil
		if shouldAlert {
			h.offlineAlerted[n.ID] = true
		}
		delete(h.offlinePending, n.ID)
		h.mu.Unlock()

		if evicted != nil {
			evicted.cancel()
			_ = evicted.conn.CloseNow()
		}

		if needsDBOffline || shouldAlert {
			h.mu.Lock()
			if h.closed || h.sessions[n.ID] != nil {
				if shouldAlert && !wasOfflineAlerted {
					delete(h.offlineAlerted, n.ID)
				}
				h.mu.Unlock()
				nodeStatusMu.Unlock()
				continue
			}
			h.mu.Unlock()
		}

		if needsDBOffline {
			if err := h.store.SetNodeConnectionStatus(ctx, n.ID, false, time.Time{}); err != nil {
				if !errors.Is(err, store.ErrNotFound) {
					h.logger.Warn("hub: failed to set stale node offline", "node_id", n.ID, "err", err)
				}
			} else {
				anyStatusChanged = true
			}
		}
		nodeStatusMu.Unlock()

		if shouldAlert {
			h.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventNodeOffline,
				Severity:   webhook.SeverityCritical,
				TargetType: webhook.TargetTypeNode,
				TargetID:   n.ID,
				TargetName: n.Name,
				Title:      "Node Offline",
				Message:    fmt.Sprintf("Node %s heartbeat timed out (last seen %s)", n.Name, lastSeen.Format(time.RFC3339)),
				Resolved:   false,
				Timestamp:  now,
			})
		}
	}

	if anyStatusChanged {
		h.triggerPublicBroadcast()
	}

	return nil
}
