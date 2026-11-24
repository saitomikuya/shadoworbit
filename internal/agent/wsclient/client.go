package wsclient

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/protocol"
)

const (
	AgentWSPath = "/api/v1/agent/ws"

	defaultReadLimit            = int64(1 << 20) // 1 MiB, matching Panel Hub
	defaultDialTimeout          = 15 * time.Second
	defaultWriteTimeout         = 10 * time.Second
	defaultHelloTimeout         = 5 * time.Second
	defaultPingInterval         = 25 * time.Second
	defaultPingTimeout          = 10 * time.Second
	defaultMetricsInterval      = 5 * time.Second
	maxAllowedMetricsInterval   = 10 * time.Second
	defaultBackoffBase          = 1 * time.Second
	defaultBackoffMax           = 30 * time.Second
	maxAllowedBackoff           = 30 * time.Second
	defaultHealthyResetDuration = 5 * time.Second
	defaultEventQueueSize       = 128
	defaultCommandQueueSize     = 64
	defaultUpdateQueueSize      = 4
)

// Options configures the persistent outbound WebSocket client.
type Options struct {
	PanelURL      string
	NodeToken     string
	TLSSkipVerify bool
	HTTPClient    *http.Client

	ReadLimit            int64
	DialTimeout          time.Duration
	WriteTimeout         time.Duration
	HelloTimeout         time.Duration
	PingInterval         time.Duration // < 0 disables client-initiated Ping keepalive; 0 uses default (25s)
	PingTimeout          time.Duration
	MetricsInterval      time.Duration // 0 uses default (5s); must be <= 10s
	BackoffBase          time.Duration // 0 uses default (1s)
	BackoffMax           time.Duration // 0 uses default (30s); capped <= 30s
	HealthyResetDuration time.Duration

	EventQueueSize   int
	CommandQueueSize int
	UpdateQueueSize  int

	Logger *slog.Logger

	BuildHello     func(ctx context.Context) protocol.AgentHello
	StageMetrics   func(ctx context.Context) (protocol.AgentMetrics, func() error, error)
	OnConfigSync   func(ctx context.Context, cfg protocol.ServerConfigSync)
	OnServiceCtl   func(ctx context.Context, cmd protocol.ServerServiceCtl)
	OnKernelUpdate func(ctx context.Context, cmd protocol.ServerKernelUpdate)
}

type inboundCmd struct {
	kind       string
	configSync *protocol.ServerConfigSync
	serviceCtl *protocol.ServerServiceCtl
}

// Client manages a persistent outbound WebSocket session to the Panel Hub.
type Client struct {
	opts       Options
	wsURL      string
	httpClient *http.Client
	logger     *slog.Logger

	reqSeq    atomic.Uint64
	connected atomic.Bool

	eventMu     sync.Mutex
	events      []protocol.AgentEvent
	eventCap    int
	eventClosed bool
	eventNotify chan struct{}
}

// NormalizeWSURL validates raw PanelURL, converts http/https -> ws/wss,
// and appends /api/v1/agent/ws if path is empty or "/" without duplicating
// an existing /api/v1/agent/ws suffix.
func NormalizeWSURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("wsclient: panel URL cannot be empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("wsclient: invalid panel URL: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		u.Scheme = "ws"
	case "https":
		u.Scheme = "wss"
	case "ws", "wss":
		u.Scheme = strings.ToLower(u.Scheme)
	default:
		return "", fmt.Errorf("wsclient: unsupported URL scheme %q: must be ws, wss, http, or https", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return "", errors.New("wsclient: panel URL must include hostname")
	}
	if !strings.HasPrefix(u.Host, "[") && strings.Count(u.Host, ":") > 1 {
		return "", errors.New("wsclient: IPv6 panel URL host must be enclosed in brackets")
	}
	if strings.HasPrefix(u.Host, "[") {
		if !strings.Contains(u.Host, "]") || net.ParseIP(host) == nil {
			return "", errors.New("wsclient: invalid bracketed IPv6 host in panel URL")
		}
	}
	if strings.HasSuffix(u.Host, ":") {
		return "", errors.New("wsclient: panel URL has empty port")
	}
	if p := u.Port(); p != "" {
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 {
			return "", fmt.Errorf("wsclient: invalid panel URL port %q: must be 1..65535", p)
		}
	}

	cleanPath := strings.TrimRight(u.Path, "/")
	switch {
	case cleanPath == "":
		u.Path = AgentWSPath
	case strings.HasSuffix(cleanPath, AgentWSPath):
		u.Path = cleanPath
	default:
		u.Path = cleanPath + AgentWSPath
	}
	u.RawPath = ""

	return u.String(), nil
}

// New validates opts and constructs a Client.
func New(opts Options) (*Client, error) {
	wsURL, err := NormalizeWSURL(opts.PanelURL)
	if err != nil {
		return nil, err
	}
	opts.NodeToken = strings.TrimSpace(opts.NodeToken)
	if opts.NodeToken == "" {
		return nil, errors.New("wsclient: node token cannot be empty")
	}
	if opts.MetricsInterval > maxAllowedMetricsInterval {
		return nil, fmt.Errorf("wsclient: metrics interval (%s) must be <= %s", opts.MetricsInterval, maxAllowedMetricsInterval)
	}

	if opts.ReadLimit <= 0 {
		opts.ReadLimit = defaultReadLimit
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = defaultWriteTimeout
	}
	if opts.HelloTimeout <= 0 {
		opts.HelloTimeout = defaultHelloTimeout
	}
	if opts.PingInterval == 0 {
		opts.PingInterval = defaultPingInterval
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = defaultPingTimeout
	}
	if opts.MetricsInterval <= 0 {
		opts.MetricsInterval = defaultMetricsInterval
	}
	if opts.BackoffBase <= 0 {
		opts.BackoffBase = defaultBackoffBase
	}
	if opts.BackoffMax <= 0 || opts.BackoffMax > maxAllowedBackoff {
		opts.BackoffMax = maxAllowedBackoff
	}
	if opts.BackoffBase > opts.BackoffMax {
		opts.BackoffBase = opts.BackoffMax
	}
	if opts.HealthyResetDuration <= 0 {
		if opts.BackoffBase < 500*time.Millisecond {
			opts.HealthyResetDuration = opts.BackoffBase * 2
			if opts.HealthyResetDuration < 20*time.Millisecond {
				opts.HealthyResetDuration = 20 * time.Millisecond
			}
		} else {
			opts.HealthyResetDuration = defaultHealthyResetDuration
		}
	}
	if opts.EventQueueSize <= 0 {
		opts.EventQueueSize = defaultEventQueueSize
	}
	if opts.CommandQueueSize <= 0 {
		opts.CommandQueueSize = defaultCommandQueueSize
	}
	if opts.UpdateQueueSize <= 0 {
		opts.UpdateQueueSize = defaultUpdateQueueSize
	}

	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	httpClient := opts.HTTPClient
	if httpClient == nil {
		if opts.TLSSkipVerify {
			var tr *http.Transport
			if base, ok := http.DefaultTransport.(*http.Transport); ok && base != nil {
				tr = base.Clone()
			} else {
				tr = &http.Transport{}
			}
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{}
			} else {
				tr.TLSClientConfig = tr.TLSClientConfig.Clone()
			}
			tr.TLSClientConfig.InsecureSkipVerify = true
			httpClient = &http.Client{
				Timeout:   0,
				Transport: tr,
			}
		} else {
			httpClient = &http.Client{Timeout: 0}
		}
	}

	return &Client{
		opts:        opts,
		wsURL:       wsURL,
		httpClient:  httpClient,
		logger:      logger,
		eventCap:    opts.EventQueueSize,
		eventNotify: make(chan struct{}, 1),
	}, nil
}

// EndpointURL returns the normalized WebSocket endpoint URL.
func (c *Client) EndpointURL() string {
	return c.wsURL
}

// Connected reports whether an authenticated session has completed hello and is active.
func (c *Client) Connected() bool {
	return c.connected.Load()
}

// SendEvent enqueues an agent.event without blocking, dropping the oldest queued
// event if the bounded queue is full. It is safe when disconnected or shutting down.
func (c *Client) SendEvent(ev protocol.AgentEvent) {
	c.eventMu.Lock()
	if c.eventClosed {
		c.eventMu.Unlock()
		return
	}
	if len(c.events) >= c.eventCap {
		dropped := c.events[0]
		copy(c.events, c.events[1:])
		c.events[len(c.events)-1] = ev
		c.eventMu.Unlock()
		c.logger.Warn("agent event queue full, dropped oldest event",
			"dropped_event", dropped.Event,
			"dropped_status", dropped.Status,
			"queue_cap", c.eventCap,
		)
	} else {
		c.events = append(c.events, ev)
		c.eventMu.Unlock()
	}

	select {
	case c.eventNotify <- struct{}{}:
	default:
	}
}

func (c *Client) popEvent() (protocol.AgentEvent, bool) {
	c.eventMu.Lock()
	defer c.eventMu.Unlock()
	if len(c.events) == 0 {
		return protocol.AgentEvent{}, false
	}
	ev := c.events[0]
	copy(c.events, c.events[1:])
	c.events[len(c.events)-1] = protocol.AgentEvent{}
	c.events = c.events[:len(c.events)-1]
	return ev, true
}

func (c *Client) prependEvent(ev protocol.AgentEvent) {
	c.eventMu.Lock()
	if c.eventClosed {
		c.eventMu.Unlock()
		return
	}
	if len(c.events) >= c.eventCap {
		// ev was popped from head before newer events arrived; since c.events is already at capacity
		// with newer events, drop ev (the oldest overall) and keep c.events intact.
		queueCap := c.eventCap
		c.eventMu.Unlock()
		c.logger.Warn("wsclient event queue full during re-queue, dropping oldest event",
			"dropped_event", ev.Event,
			"dropped_status", ev.Status,
			"queue_cap", queueCap,
		)
		select {
		case c.eventNotify <- struct{}{}:
		default:
		}
		return
	}
	c.events = append(c.events, protocol.AgentEvent{})
	copy(c.events[1:], c.events[:len(c.events)-1])
	c.events[0] = ev
	c.eventMu.Unlock()
	select {
	case c.eventNotify <- struct{}{}:
	default:
	}
}

func (c *Client) nextReqID() string {
	n := c.reqSeq.Add(1)
	return fmt.Sprintf("agt-%d-%d", time.Now().UnixMilli(), n)
}

// Run maintains the persistent WebSocket connection until ctx is cancelled.
// It cleanly closes any active WebSocket with StatusNormalClosure on shutdown.
func (c *Client) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	cmdCh := make(chan inboundCmd, c.opts.CommandQueueSize)
	updateCh := make(chan protocol.ServerKernelUpdate, c.opts.UpdateQueueSize)

	var workersWG sync.WaitGroup
	workersWG.Add(2)
	go func() {
		defer workersWG.Done()
		c.runCommandWorker(ctx, cmdCh)
	}()
	go func() {
		defer workersWG.Done()
		c.runUpdateWorker(ctx, updateCh)
	}()

	defer func() {
		c.eventMu.Lock()
		c.eventClosed = true
		c.eventMu.Unlock()
		workersWG.Wait()
	}()

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	attempt := 0

	for {
		if ctx.Err() != nil {
			return nil
		}

		dialCtx, dialCancel := context.WithTimeout(ctx, c.opts.DialTimeout)
		headers := http.Header{
			"Authorization": []string{"Bearer " + c.opts.NodeToken},
		}
		conn, resp, err := websocket.Dial(dialCtx, c.wsURL, &websocket.DialOptions{
			HTTPClient: c.httpClient,
			HTTPHeader: headers,
		})
		dialCancel()
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}

		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			status := 0
			if resp != nil {
				status = resp.StatusCode
			}
			delay := computeBackoff(attempt, c.opts.BackoffBase, c.opts.BackoffMax, rng)
			attempt++
			c.logger.Warn("panel websocket dial failed, retrying",
				"status", status,
				"backoff", delay.String(),
				"error", err,
			)
			if !sleepWithContext(ctx, delay) {
				return nil
			}
			continue
		}

		conn.SetReadLimit(c.opts.ReadLimit)
		healthy := c.runSession(ctx, conn, cmdCh, updateCh)
		if ctx.Err() != nil {
			return nil
		}

		if healthy {
			attempt = 0
		}
		delay := computeBackoff(attempt, c.opts.BackoffBase, c.opts.BackoffMax, rng)
		attempt++
		c.logger.Warn("panel websocket disconnected, reconnecting",
			"healthy_session", healthy,
			"backoff", delay.String(),
		)
		if !sleepWithContext(ctx, delay) {
			return nil
		}
	}
}

func (c *Client) runSession(
	agentCtx context.Context,
	conn *websocket.Conn,
	cmdCh chan<- inboundCmd,
	updateCh chan<- protocol.ServerKernelUpdate,
) bool {
	sessCtx, sessCancel := context.WithCancel(context.Background())
	defer sessCancel()

	readCtx, readCancel := context.WithCancel(context.Background())
	defer readCancel()

	var writeMu sync.Mutex
	writeText := func(ctx context.Context, payload []byte) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		wctx, cancel := context.WithTimeout(ctx, c.opts.WriteTimeout)
		defer cancel()
		return conn.Write(wctx, websocket.MessageText, payload)
	}

	var receivedFrame atomic.Bool
	sessionStart := time.Now()

	// Start read loop immediately so control frames (Ping/Pong/Close) never stall
	// even while BuildHello probes external IP endpoints.
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			msgType, data, err := conn.Read(readCtx)
			if err != nil {
				if agentCtx.Err() == nil && sessCtx.Err() == nil {
					c.logger.Debug("websocket read loop ended", "error", err)
				}
				sessCancel()
				return
			}
			if msgType != websocket.MessageText && msgType != websocket.MessageBinary {
				continue
			}
			env, err := protocol.ParseEnvelope(data)
			if err != nil {
				c.logger.Warn("failed to parse server envelope", "error", err)
				continue
			}
			receivedFrame.Store(true)
			c.dispatchInbound(env, cmdCh, updateCh)
		}
	}()

	// Perform agent.hello handshake with bounded sub-context.
	hello := protocol.AgentHello{}
	if c.opts.BuildHello != nil {
		hctx, hcancel := context.WithTimeout(agentCtx, c.opts.HelloTimeout)
		hello = c.opts.BuildHello(hctx)
		hcancel()
	}
	if agentCtx.Err() != nil {
		_ = conn.Close(websocket.StatusNormalClosure, "agent shutting down")
		readCancel()
		<-readDone
		return false
	}

	helloBytes, err := protocol.MarshalEnvelope(protocol.MsgTypeAgentHello, c.nextReqID(), hello)
	if err != nil {
		c.logger.Error("failed to marshal agent.hello", "error", err)
		_ = conn.CloseNow()
		readCancel()
		<-readDone
		return false
	}
	if err := writeText(sessCtx, helloBytes); err != nil {
		c.logger.Warn("failed to write agent.hello", "error", err)
		_ = conn.CloseNow()
		readCancel()
		<-readDone
		return false
	}

	c.connected.Store(true)
	defer c.connected.Store(false)

	var wg sync.WaitGroup

	// Metrics & WAL flush loop: immediate flush right after agent.hello, then periodic.
	if c.opts.StageMetrics != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runMetricsLoop(sessCtx, writeText, sessCancel)
		}()
	}

	// Non-blocking outbound agent.event drain loop.
	wg.Add(1)
	go func() {
		defer wg.Done()
		c.runEventLoop(sessCtx, writeText, sessCancel)
	}()

	// Periodic WS Ping keepalive.
	if c.opts.PingInterval > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.runPingLoop(sessCtx, conn, sessCancel)
		}()
	}

	select {
	case <-agentCtx.Done():
		// Send NormalClosure BEFORE cancelling readCtx/sessCtx so coder/websocket
		// emits status 1000 cleanly instead of an abrupt context cancellation close.
		_ = conn.Close(websocket.StatusNormalClosure, "agent shutting down")
		sessCancel()
		readCancel()
	case <-sessCtx.Done():
		_ = conn.CloseNow()
		readCancel()
	}

	<-readDone
	wg.Wait()

	return receivedFrame.Load() || time.Since(sessionStart) >= c.opts.HealthyResetDuration
}

func (c *Client) dispatchInbound(
	env protocol.Envelope,
	cmdCh chan<- inboundCmd,
	updateCh chan<- protocol.ServerKernelUpdate,
) {
	switch env.Type {
	case protocol.MsgTypeServerConfigSync:
		var cfg protocol.ServerConfigSync
		if err := env.DecodePayload(&cfg); err != nil {
			c.logger.Warn("invalid server.config_sync payload", "req_id", env.ReqID, "error", err)
			return
		}
		select {
		case cmdCh <- inboundCmd{kind: env.Type, configSync: &cfg}:
		default:
			c.logger.Warn("command queue full, dropping server.config_sync", "revision", cfg.ConfigRevision)
		}

	case protocol.MsgTypeServerServiceCtl:
		var ctl protocol.ServerServiceCtl
		if err := env.DecodePayload(&ctl); err != nil {
			c.logger.Warn("invalid server.service_ctl payload", "req_id", env.ReqID, "error", err)
			return
		}
		select {
		case cmdCh <- inboundCmd{kind: env.Type, serviceCtl: &ctl}:
		default:
			c.logger.Warn("command queue full, dropping server.service_ctl", "action", ctl.Action)
		}

	case protocol.MsgTypeServerKernelUpdate:
		var req protocol.ServerKernelUpdate
		if err := env.DecodePayload(&req); err != nil {
			c.logger.Warn("invalid server.kernel_update payload", "req_id", env.ReqID, "error", err)
			return
		}
		select {
		case updateCh <- req:
		default:
			c.logger.Warn("kernel update queue full, rejecting request",
				"kernel", req.Kernel,
				"version", req.Version,
			)
			c.SendEvent(protocol.AgentEvent{
				Event:   protocol.EventKernelUpdateResult,
				Kernel:  req.Kernel,
				Status:  "update_failed",
				Version: req.Version,
				Message: "kernel update queue full",
				Detail:  "kernel update queue overflow",
			})
		}

	default:
		c.logger.Debug("ignoring unrecognized server message type", "type", env.Type, "req_id", env.ReqID)
	}
}

func (c *Client) runCommandWorker(ctx context.Context, cmdCh <-chan inboundCmd) {
	for {
		select {
		case <-ctx.Done():
			return
		case cmd := <-cmdCh:
			if ctx.Err() != nil {
				return
			}
			switch cmd.kind {
			case protocol.MsgTypeServerConfigSync:
				if cmd.configSync != nil && c.opts.OnConfigSync != nil {
					c.opts.OnConfigSync(ctx, *cmd.configSync)
				}
			case protocol.MsgTypeServerServiceCtl:
				if cmd.serviceCtl != nil && c.opts.OnServiceCtl != nil {
					c.opts.OnServiceCtl(ctx, *cmd.serviceCtl)
				}
			}
		}
	}
}

func (c *Client) runUpdateWorker(ctx context.Context, updateCh <-chan protocol.ServerKernelUpdate) {
	for {
		select {
		case <-ctx.Done():
			return
		case req := <-updateCh:
			if ctx.Err() != nil {
				return
			}
			if c.opts.OnKernelUpdate != nil {
				c.opts.OnKernelUpdate(ctx, req)
			}
		}
	}
}

func (c *Client) runMetricsLoop(
	sessCtx context.Context,
	writeText func(context.Context, []byte) error,
	sessCancel context.CancelFunc,
) {
	flush := func() bool {
		batch, ack, err := c.opts.StageMetrics(sessCtx)
		if err != nil {
			if sessCtx.Err() == nil {
				c.logger.Warn("failed to stage agent metrics", "error", err)
			}
			return true
		}
		frame, err := protocol.MarshalEnvelope(protocol.MsgTypeAgentMetrics, c.nextReqID(), batch)
		if err != nil {
			c.logger.Warn("failed to marshal agent.metrics", "error", err)
			return true
		}
		if err := writeText(sessCtx, frame); err != nil {
			if sessCtx.Err() == nil {
				c.logger.Warn("failed to write agent.metrics, retaining WAL", "error", err)
			}
			sessCancel()
			return false
		}
		if ack != nil {
			if err := ack(); err != nil {
				c.logger.Warn("failed to ack flushed traffic WAL", "error", err)
			}
		}
		return true
	}

	// Immediate flush after agent.hello succeeds to drain any offline WAL promptly.
	if !flush() {
		return
	}

	ticker := time.NewTicker(c.opts.MetricsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sessCtx.Done():
			return
		case <-ticker.C:
			if !flush() {
				return
			}
		}
	}
}

func (c *Client) runEventLoop(
	sessCtx context.Context,
	writeText func(context.Context, []byte) error,
	sessCancel context.CancelFunc,
) {
	drain := func() bool {
		for {
			if sessCtx.Err() != nil {
				return false
			}
			ev, ok := c.popEvent()
			if !ok {
				return true
			}
			frame, err := protocol.MarshalEnvelope(protocol.MsgTypeAgentEvent, c.nextReqID(), ev)
			if err != nil {
				c.logger.Warn("failed to marshal agent.event", "event", ev.Event, "error", err)
				continue
			}
			if err := writeText(sessCtx, frame); err != nil {
				c.prependEvent(ev)
				if sessCtx.Err() == nil {
					c.logger.Warn("failed to write agent.event, re-queued for reconnect", "event", ev.Event, "error", err)
				}
				sessCancel()
				return false
			}
		}
	}

	if !drain() {
		return
	}

	for {
		select {
		case <-sessCtx.Done():
			return
		case <-c.eventNotify:
			if !drain() {
				return
			}
		}
	}
}

func (c *Client) runPingLoop(
	sessCtx context.Context,
	conn *websocket.Conn,
	sessCancel context.CancelFunc,
) {
	ticker := time.NewTicker(c.opts.PingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-sessCtx.Done():
			return
		case <-ticker.C:
			pctx, pcancel := context.WithTimeout(sessCtx, c.opts.PingTimeout)
			err := conn.Ping(pctx)
			pcancel()
			if err != nil {
				if sessCtx.Err() == nil {
					c.logger.Warn("websocket ping keepalive failed", "error", err)
				}
				sessCancel()
				return
			}
		}
	}
}

func computeBackoff(attempt int, base, maxDelay time.Duration, rng *rand.Rand) time.Duration {
	if base <= 0 {
		base = defaultBackoffBase
	}
	if maxDelay <= 0 || maxDelay > maxAllowedBackoff {
		maxDelay = maxAllowedBackoff
	}
	if base > maxDelay {
		base = maxDelay
	}
	exp := base
	for i := 0; i < attempt; i++ {
		if exp >= maxDelay || exp > maxDelay/2 {
			exp = maxDelay
			break
		}
		exp *= 2
	}
	if exp > maxDelay {
		exp = maxDelay
	}
	half := exp / 2
	if half <= 0 || rng == nil {
		return exp
	}
	delay := half + time.Duration(rng.Int63n(int64(exp-half)+1))
	if delay > maxDelay {
		delay = maxDelay
	}
	if delay > maxAllowedBackoff {
		delay = maxAllowedBackoff
	}
	return delay
}

func sleepWithContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
