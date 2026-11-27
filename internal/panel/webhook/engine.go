package webhook

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

const (
	DefaultCooldownMinutes = 5
	DefaultDeliveryTimeout = 10 * time.Second
	DefaultMaxConcurrency  = 16
	MaxResponseBodyBytes   = 64 * 1024 // 64 KiB
	SettingCooldownMinutes = "alert_cooldown_minutes"
)

type webhookStore interface {
	ListWebhookChannels(ctx context.Context) ([]store.WebhookChannel, error)
	GetSettingOrDefault(ctx context.Context, key, defaultVal string) (string, error)
}

var resolvedParentEvents = map[string][]string{
	EventNodeOnline:       {EventNodeOffline},
	EventTrafficRecovered: {EventTrafficPaused, EventTrafficWarning},
}

type cooldownKey struct {
	ChannelID  int64
	EventType  string
	TargetType string
	TargetID   int64
}

// Option configures Engine behavior.
type Option func(*Engine)

// WithNow overrides the clock source used by Engine.
func WithNow(fn func() time.Time) Option {
	return func(e *Engine) {
		if fn != nil {
			e.now = fn
		}
	}
}

// WithLogger overrides the structured logger used for async delivery diagnostics.
func WithLogger(logger *slog.Logger) Option {
	return func(e *Engine) {
		if logger != nil {
			e.logger = logger
		}
	}
}

// WithDeliveryTimeout sets the per-delivery HTTP timeout.
func WithDeliveryTimeout(d time.Duration) Option {
	return func(e *Engine) {
		if d > 0 {
			e.deliveryTimeout = d
		}
	}
}

// WithMaxConcurrency sets the maximum concurrent Notify dispatch goroutines.
func WithMaxConcurrency(n int) Option {
	return func(e *Engine) {
		if n > 0 {
			e.maxConcurrency = n
		}
	}
}

// WithBlockPrivateIPs configures the default HTTP client to block loopback, private,
// link-local, multicast, unspecified, and CGNAT IP addresses before TCP connect.
func WithBlockPrivateIPs(block bool) Option {
	return func(e *Engine) {
		e.blockPrivateIPs = block
	}
}

// Engine dispatches alert notifications across configured webhook channels with
// per-channel/event/target cooldown suppression and resolved-closure handling.
type Engine struct {
	store           webhookStore
	httpClient      *http.Client
	now             func() time.Time
	logger          *slog.Logger
	deliveryTimeout time.Duration
	maxConcurrency  int
	blockPrivateIPs bool

	sem chan struct{}

	baseCtx    context.Context
	cancelBase context.CancelFunc

	mu     sync.Mutex
	closed bool
	wg     sync.WaitGroup

	cooldownMu sync.Mutex
	cooldown   map[cooldownKey]time.Time
}

// NewEngine creates a webhook alert Engine backed by st and optional httpClient.
func NewEngine(st *store.Store, httpClient *http.Client, opts ...Option) *Engine {
	baseCtx, cancelBase := context.WithCancel(context.Background())
	e := &Engine{
		now:             time.Now,
		logger:          slog.Default(),
		deliveryTimeout: DefaultDeliveryTimeout,
		maxConcurrency:  DefaultMaxConcurrency,
		baseCtx:         baseCtx,
		cancelBase:      cancelBase,
		cooldown:        make(map[cooldownKey]time.Time),
	}
	if st != nil {
		e.store = st
	}
	for _, opt := range opts {
		if opt != nil {
			opt(e)
		}
	}
	e.sem = make(chan struct{}, e.maxConcurrency)

	if httpClient != nil {
		e.httpClient = httpClient
	} else {
		client := &http.Client{Timeout: e.deliveryTimeout}
		if e.blockPrivateIPs {
			dialer := &net.Dialer{
				Timeout:   5 * time.Second,
				KeepAlive: 30 * time.Second,
				Control:   rejectPrivateIPControl,
			}
			client.Transport = &http.Transport{
				Proxy:                 http.ProxyFromEnvironment,
				DialContext:           dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          32,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
			}
		}
		e.httpClient = client
	}
	return e
}

// Notify asynchronously evaluates subscribed channels, applies cooldown rules,
// and dispatches alerts without blocking the caller.
func (e *Engine) Notify(ctx context.Context, evt AlertEvent) {
	if e == nil {
		return
	}
	if ctx != nil && ctx.Err() != nil {
		return
	}

	normalized := normalizeEvent(evt, e.now)

	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return
	}
	e.wg.Add(1)
	e.mu.Unlock()

	go func() {
		defer e.wg.Done()
		select {
		case e.sem <- struct{}{}:
			defer func() { <-e.sem }()
		case <-e.baseCtx.Done():
			return
		}

		base := context.Background()
		if ctx != nil {
			base = context.WithoutCancel(ctx)
		}
		runCtx, cancel := context.WithCancel(base)
		stop := context.AfterFunc(e.baseCtx, cancel)
		defer func() {
			stop()
			cancel()
		}()

		e.dispatch(runCtx, normalized)
	}()
}

// Wait blocks until all in-flight Notify dispatches complete without closing the Engine.
func (e *Engine) Wait() {
	if e == nil {
		return
	}
	e.wg.Wait()
}

// Close cancels pending async dispatches and waits for all Notify goroutines to exit.
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.mu.Lock()
	if !e.closed {
		e.closed = true
		e.cancelBase()
	}
	e.mu.Unlock()
	e.wg.Wait()
}

// SendTest synchronously delivers a synthetic test notification to ch, bypassing
// channel enabled state, event subscription filters, and cooldown suppression.
func (e *Engine) SendTest(ctx context.Context, ch store.WebhookChannel) error {
	if e == nil {
		return fmt.Errorf("webhook: nil engine")
	}
	if !protocol.IsValidWebhookProvider(ch.Provider) {
		return fmt.Errorf("%w: %q", ErrUnsupportedProvider, ch.Provider)
	}
	if err := ValidateWebhookURL(ch.URL); err != nil {
		return err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, e.deliveryTimeout)
		defer cancel()
	}

	evt := normalizeEvent(AlertEvent{
		Type:       EventTest,
		Severity:   SeverityInfo,
		TargetType: TargetTypeSystem,
		TargetID:   ch.ID,
		TargetName: ch.Name,
		Title:      "ShadowOrbit 告警通道测试",
		Message:    fmt.Sprintf("告警通道「%s」（%s）连通性测试成功。", ch.Name, formatProviderLabel(ch.Provider)),
		Detail:     "收到此消息表示 Webhook 推送地址与签名配置正常。",
		Timestamp:  e.now().UTC(),
	}, e.now)

	return e.deliverOne(ctx, ch, evt)
}

func (e *Engine) dispatch(ctx context.Context, evt AlertEvent) {
	if e.store == nil {
		return
	}
	storeCtx, storeCancel := context.WithTimeout(ctx, e.deliveryTimeout)
	channels, err := e.store.ListWebhookChannels(storeCtx)
	if err != nil {
		storeCancel()
		e.logger.Warn("webhook list channels failed", "event", evt.Type, "error", err)
		return
	}

	cooldown := e.loadCooldownDuration(storeCtx)
	storeCancel()
	now := e.now().UTC()

	for _, ch := range channels {
		if ctx.Err() != nil {
			return
		}
		if !ch.Enabled || !matchesSubscription(ch.SubscribedEvents, evt) {
			continue
		}
		if !e.shouldSendAndRecord(ch.ID, evt, cooldown, now) {
			continue
		}
		chCtx, cancel := context.WithTimeout(ctx, e.deliveryTimeout)
		err := e.deliverOne(chCtx, ch, evt)
		cancel()
		if err != nil {
			e.logger.Warn("webhook delivery failed",
				"channel_id", ch.ID,
				"channel_name", ch.Name,
				"provider", ch.Provider,
				"event", evt.Type,
				"target_type", evt.TargetType,
				"target_id", evt.TargetID,
				"error", err,
			)
		}
	}
}

func (e *Engine) loadCooldownDuration(ctx context.Context) time.Duration {
	def := time.Duration(DefaultCooldownMinutes) * time.Minute
	if e.store == nil {
		return def
	}
	val, err := e.store.GetSettingOrDefault(ctx, SettingCooldownMinutes, strconv.Itoa(DefaultCooldownMinutes))
	if err != nil {
		e.logger.Warn("webhook read cooldown setting failed, using default", "error", err)
		return def
	}
	mins, err := strconv.Atoi(strings.TrimSpace(val))
	if err != nil || mins < 0 {
		e.logger.Warn("webhook invalid cooldown setting, using default", "value", val)
		return def
	}
	if mins == 0 {
		return 0
	}
	return time.Duration(mins) * time.Minute
}

func (e *Engine) shouldSendAndRecord(chID int64, evt AlertEvent, cooldown time.Duration, now time.Time) bool {
	key := cooldownKey{
		ChannelID:  chID,
		EventType:  evt.Type,
		TargetType: evt.TargetType,
		TargetID:   evt.TargetID,
	}

	e.cooldownMu.Lock()
	defer e.cooldownMu.Unlock()

	if len(e.cooldown) > 1024 && cooldown > 0 {
		for k, ts := range e.cooldown {
			if now.Sub(ts) >= cooldown {
				delete(e.cooldown, k)
			}
		}
	}

	if evt.Resolved {
		delete(e.cooldown, key)
		if parents, ok := resolvedParentEvents[evt.Type]; ok {
			for _, p := range parents {
				delete(e.cooldown, cooldownKey{
					ChannelID:  chID,
					EventType:  p,
					TargetType: evt.TargetType,
					TargetID:   evt.TargetID,
				})
			}
		}
		return true
	}

	if cooldown <= 0 {
		return true
	}
	if last, ok := e.cooldown[key]; ok && now.Sub(last) < cooldown {
		return false
	}
	e.cooldown[key] = now
	return true
}

func matchesSubscription(subscribed []string, evt AlertEvent) bool {
	for _, raw := range subscribed {
		s := strings.ToLower(strings.TrimSpace(raw))
		if s == "" {
			continue
		}
		if s == "*" || s == "all" || s == evt.Type {
			return true
		}
		if parents, ok := resolvedParentEvents[evt.Type]; ok && slices.Contains(parents, s) {
			return true
		}
	}
	return false
}

// ValidateWebhookURL checks that rawURL is a valid single-line http/https URL with non-empty host and valid port.
func ValidateWebhookURL(rawURL string) error {
	if rawURL == "" || strings.ContainsAny(rawURL, "\r\n\t\x00") {
		return fmt.Errorf("%w: empty or control characters in url", ErrInvalidURL)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidURL, err)
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return fmt.Errorf("%w: unsupported scheme %q", ErrInvalidURL, u.Scheme)
	}
	if u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%w: missing host", ErrInvalidURL)
	}
	if portStr := u.Port(); portStr != "" {
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			return fmt.Errorf("%w: invalid port %q", ErrInvalidURL, portStr)
		}
	}
	return nil
}

var cgnatPrefix = netip.MustParsePrefix("100.64.0.0/10")

func rejectPrivateIPControl(_, address string, _ syscall.RawConn) error {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		return fmt.Errorf("%w: parse remote addr %q: %v", ErrPrivateIPBlocked, address, err)
	}
	addr := addrPort.Addr().Unmap()
	if addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsMulticast() ||
		addr.IsUnspecified() ||
		cgnatPrefix.Contains(addr) {
		return fmt.Errorf("%w: %s", ErrPrivateIPBlocked, addr.String())
	}
	return nil
}
