package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"reflect"
	"sync"
	"time"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
)

type userLifecycleState struct {
	expired   bool
	exhausted bool
}

// Scheduler coordinates periodic heartbeat sweeps, traffic threshold enforcement,
// monthly billing resets, user expiry/quota hot-syncs, and kernel version synchronization.
type Scheduler struct {
	store    *store.Store
	hub      *hub.Hub
	notifier AlertNotifier

	logger                  *slog.Logger
	now                     func() time.Time
	sweepInterval           time.Duration
	trafficLogPruneInterval time.Duration
	kernelSyncInterval      time.Duration
	githubAPIBaseURL        string
	httpClient              *http.Client
	dnsProviderFactory      DNSProviderFactory

	lifecycleMu sync.Mutex
	started     bool
	stopped     bool
	ctx         context.Context
	cancel      context.CancelFunc
	wg          sync.WaitGroup

	nodeLocksMu sync.Mutex
	nodeLocks   map[int64]*sync.Mutex

	userLocksMu sync.Mutex
	userLocks   map[int64]*sync.Mutex

	groupLocksMu sync.Mutex
	groupLocks   map[int64]*sync.Mutex

	kernelsMu sync.Mutex

	mu         sync.Mutex
	nodeWarned map[int64]bool
	userStates map[int64]userLifecycleState
}

// NewScheduler constructs a Scheduler with the given dependencies and options.
func NewScheduler(st *store.Store, h *hub.Hub, notifier AlertNotifier, opts ...Option) *Scheduler {
	s := &Scheduler{
		store:              st,
		hub:                h,
		notifier:           sanitizeNotifier(notifier),
		logger:                  slog.Default(),
		now:                     time.Now,
		sweepInterval:           defaultSweepInterval,
		trafficLogPruneInterval: defaultTrafficLogPruneInterval,
		kernelSyncInterval:      0,
		githubAPIBaseURL:   defaultGitHubAPIBaseURL,
		httpClient:         &http.Client{Timeout: defaultHTTPTimeout},
		nodeLocks:          make(map[int64]*sync.Mutex),
		userLocks:          make(map[int64]*sync.Mutex),
		groupLocks:         make(map[int64]*sync.Mutex),
		nodeWarned:         make(map[int64]bool),
		userStates:         make(map[int64]userLifecycleState),
	}

	for _, opt := range opts {
		if opt != nil {
			opt(s)
		}
	}

	return s
}

func sanitizeNotifier(n AlertNotifier) AlertNotifier {
	if n == nil {
		return nil
	}
	v := reflect.ValueOf(n)
	switch v.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		if v.IsNil() {
			return nil
		}
	}
	return n
}

// WireHub registers the OnTrafficUpdated callback on the Hub if h != nil.
// The callback detaches from the agent session context with a bounded timeout so an
// immediate agent disconnect does not abort threshold persistence, sync, or alerts.
func (s *Scheduler) WireHub() {
	if s.hub == nil {
		return
	}
	s.hub.SetOnTrafficUpdated(func(cbCtx context.Context, node *store.Node, updatedUserIDs []int64) {
		s.lifecycleMu.Lock()
		stopped := s.stopped
		schedCtx := s.ctx
		s.lifecycleMu.Unlock()

		if stopped || (schedCtx != nil && schedCtx.Err() != nil) {
			return
		}

		base := context.Background()
		if cbCtx != nil {
			base = context.WithoutCancel(cbCtx)
		}
		detachedCtx, cancel := context.WithTimeout(base, trafficCallbackTimeout)
		if schedCtx != nil {
			stopAfter := context.AfterFunc(schedCtx, cancel)
			defer stopAfter()
		}
		defer cancel()

		if node != nil && node.ID > 0 {
			if err := s.EvaluateNodeThreshold(detachedCtx, node.ID); err != nil {
				s.logger.Warn("scheduler: evaluate node threshold failed", "node_id", node.ID, "err", err)
			}
			if err := s.EvaluateLBGroupForNode(detachedCtx, node.ID); err != nil {
				s.logger.Warn("scheduler: evaluate lb group on traffic update failed", "node_id", node.ID, "err", err)
			}
		}
		if len(updatedUserIDs) > 0 {
			if err := s.EvaluateUsers(detachedCtx, updatedUserIDs); err != nil {
				s.logger.Warn("scheduler: evaluate users failed", "err", err)
			}
		}
	})

	s.hub.SetOnNodeStateChanged(func(cbCtx context.Context, nodeID int64) {
		s.lifecycleMu.Lock()
		stopped := s.stopped
		schedCtx := s.ctx
		s.lifecycleMu.Unlock()

		if stopped || (schedCtx != nil && schedCtx.Err() != nil) || nodeID <= 0 {
			return
		}

		base := context.Background()
		if cbCtx != nil {
			base = context.WithoutCancel(cbCtx)
		}
		detachedCtx, cancel := context.WithTimeout(base, trafficCallbackTimeout)
		if schedCtx != nil {
			stopAfter := context.AfterFunc(schedCtx, cancel)
			defer stopAfter()
		}
		defer cancel()

		if err := s.EvaluateLBGroupForNode(detachedCtx, nodeID); err != nil {
			s.logger.Warn("scheduler: evaluate lb group on node state change failed", "node_id", nodeID, "err", err)
		}
	})
}

// Start wires the hub traffic callback and begins background periodic sweeps.
// Calling Start more than once is a no-op.
func (s *Scheduler) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	s.lifecycleMu.Lock()
	if s.started || s.stopped {
		s.lifecycleMu.Unlock()
		return
	}
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.started = true
	loopCtx := s.ctx
	s.lifecycleMu.Unlock()

	s.WireHub()

	s.wg.Add(1)
	go s.runLoop(loopCtx)
}

// Stop cancels the scheduler's internal context and waits for all background goroutines
// to exit cleanly. Stop is idempotent.
func (s *Scheduler) Stop() {
	s.lifecycleMu.Lock()
	if s.stopped {
		s.lifecycleMu.Unlock()
		s.wg.Wait()
		return
	}
	s.stopped = true
	cancel := s.cancel
	s.lifecycleMu.Unlock()

	if cancel != nil {
		cancel()
	}
	s.wg.Wait()
}

func (s *Scheduler) runLoop(ctx context.Context) {
	defer s.wg.Done()

	if ctx.Err() != nil {
		return
	}

	// Run an initial sweep so expired users, missed resets, or breached thresholds
	// are reconciled immediately on startup without waiting for the first tick.
	s.runSweep(ctx)

	sweepTicker := time.NewTicker(s.sweepInterval)
	defer sweepTicker.Stop()

	var pruneTicker *time.Ticker
	var pruneCh <-chan time.Time
	if s.trafficLogPruneInterval > 0 {
		pruneTicker = time.NewTicker(s.trafficLogPruneInterval)
		pruneCh = pruneTicker.C
		defer pruneTicker.Stop()
	}

	var kernelTicker *time.Ticker
	var kernelCh <-chan time.Time
	if s.kernelSyncInterval > 0 {
		kernelTicker = time.NewTicker(s.kernelSyncInterval)
		kernelCh = kernelTicker.C
		defer kernelTicker.Stop()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-sweepTicker.C:
			s.runSweep(ctx)
		case <-pruneCh:
			if s.store != nil {
				if _, err := s.store.PruneConfiguredTrafficUsageLogs(ctx); err != nil && ctx.Err() == nil {
					s.logger.Warn("scheduler: periodic traffic usage log prune failed", "err", err)
				}
			}
		case <-kernelCh:
			if _, err := s.SyncKernels(ctx); err != nil && ctx.Err() == nil {
				s.logger.Warn("scheduler: periodic kernel sync failed", "err", err)
			}
		}
	}
}

func (s *Scheduler) runSweep(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	if s.hub != nil {
		if err := s.hub.CheckHeartbeats(ctx, 0); err != nil && !errors.Is(err, hub.ErrHubClosed) && ctx.Err() == nil {
			s.logger.Warn("scheduler: check heartbeats failed", "err", err)
		}
	}
	if s.store == nil || ctx.Err() != nil {
		return
	}
	now := s.now()
	if err := s.RunBillingResets(ctx, now); err != nil && ctx.Err() == nil {
		s.logger.Warn("scheduler: billing resets failed", "err", err)
	}
	if ctx.Err() != nil {
		return
	}
	if err := s.SweepNodeThresholds(ctx); err != nil && ctx.Err() == nil {
		s.logger.Warn("scheduler: sweep node thresholds failed", "err", err)
	}
	if ctx.Err() != nil {
		return
	}
	if err := s.SweepUsers(ctx, now); err != nil && ctx.Err() == nil {
		s.logger.Warn("scheduler: sweep users failed", "err", err)
	}
	if ctx.Err() != nil {
		return
	}
	if err := s.SweepLBGroups(ctx); err != nil && ctx.Err() == nil {
		s.logger.Warn("scheduler: sweep lb groups failed", "err", err)
	}
}

func (s *Scheduler) nodeLock(nodeID int64) *sync.Mutex {
	s.nodeLocksMu.Lock()
	mu, ok := s.nodeLocks[nodeID]
	if !ok {
		mu = &sync.Mutex{}
		s.nodeLocks[nodeID] = mu
	}
	s.nodeLocksMu.Unlock()
	return mu
}

func (s *Scheduler) userLock(userID int64) *sync.Mutex {
	s.userLocksMu.Lock()
	mu, ok := s.userLocks[userID]
	if !ok {
		mu = &sync.Mutex{}
		s.userLocks[userID] = mu
	}
	s.userLocksMu.Unlock()
	return mu
}

func (s *Scheduler) groupLock(groupID int64) *sync.Mutex {
	s.groupLocksMu.Lock()
	mu, ok := s.groupLocks[groupID]
	if !ok {
		mu = &sync.Mutex{}
		s.groupLocks[groupID] = mu
	}
	s.groupLocksMu.Unlock()
	return mu
}

func (s *Scheduler) notify(ctx context.Context, evt webhook.AlertEvent) {
	if s.notifier == nil {
		return
	}
	s.notifier.Notify(ctx, evt)
}

func (s *Scheduler) syncNodeIgnoringOffline(ctx context.Context, nodeID int64) {
	if s.hub == nil {
		return
	}
	if err := s.hub.SyncNode(ctx, nodeID); err != nil &&
		!errors.Is(err, hub.ErrNodeOffline) &&
		!errors.Is(err, hub.ErrHubClosed) &&
		!errors.Is(err, store.ErrNotFound) {
		s.logger.Warn("scheduler: sync node failed", "node_id", nodeID, "err", err)
	}
}

func (s *Scheduler) hubConnectionState(nodeID int64) (bool, time.Time) {
	if s.hub == nil {
		return false, time.Time{}
	}
	if !s.hub.IsOnline(nodeID) {
		return false, time.Time{}
	}
	if tel, ok := s.hub.GetTelemetry(nodeID); ok && !tel.LastSeenAt.IsZero() {
		return true, tel.LastSeenAt.UTC()
	}
	return true, s.now().UTC()
}
