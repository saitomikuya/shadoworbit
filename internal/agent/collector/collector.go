package collector

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"

	"snell-panel/internal/protocol"
)

const (
	defaultDataDir          = "/var/lib/snell-panel-agent"
	defaultProcRoot         = "/proc"
	defaultProcNetDevPath   = "/proc/net/dev"
	defaultProcNetRoutePath = "/proc/net/route"
	defaultProcStatPath     = "/proc/stat"
	defaultProcMeminfoPath  = "/proc/meminfo"
	defaultProcUptimePath   = "/proc/uptime"
	defaultDiskPath         = "/"
	defaultNICInterval      = 5 * time.Second
	defaultStatsInterval    = 10 * time.Second
	defaultWALSyncInterval  = 30 * time.Second
)

// Options configures the dual-layer traffic collector and WAL.
type Options struct {
	DataDir             string
	WALPath             string
	ProcRoot            string
	ProcNetDevPath      string
	ProcNetRoutePath    string
	ProcStatPath        string
	ProcMeminfoPath     string
	ProcUptimePath      string
	DiskPath            string
	Interface           string
	StatsAddr           string
	SnellPIDFunc        func() int
	NICInterval         time.Duration
	StatsInterval       time.Duration
	WALSyncInterval     time.Duration
	PublicIPEndpointsV4 []string
	PublicIPEndpointsV6 []string
	HTTPClient          *http.Client
	Logger              *slog.Logger
}

// Collector implements Layer 1 NIC traffic polling, Layer 2 sing-box gRPC stats polling,
// Layer 3 atomic pending_traffic.json WAL, host telemetry, and public IP detection.
type Collector struct {
	opts    Options
	logger  *slog.Logger
	walPath string

	loopMu  sync.Mutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	nicMu       sync.Mutex
	hasLastNIC  bool
	lastIface   string
	lastNICRx   uint64
	lastNICTx   uint64
	lastNICTime time.Time
	lastRxBPS   uint64
	lastTxBPS   uint64

	snellMu        sync.Mutex
	lastSnellPID   int
	lastSnellRChar uint64
	lastSnellWChar uint64

	statsMu    sync.Mutex
	grpcConn   *grpc.ClientConn
	grpcTarget string

	cpuMu          sync.Mutex
	hasLastCPU     bool
	lastCPUTotal   uint64
	lastCPUIdle    uint64
	lastCPUPercent float64

	userMu       sync.RWMutex
	statsEnabled bool
	activeUsers  map[string]int64

	mu              sync.Mutex
	wal             walState
	stageSeq        uint64
	walSyncInterval time.Duration
	lastWALSync     time.Time
	walUnsynced     bool

	walWrites atomic.Int64
	walFsyncs atomic.Int64
}

// New constructs a Collector and loads or recovers its pending traffic WAL.
func New(opts Options) (*Collector, error) {
	if strings.TrimSpace(opts.DataDir) == "" && strings.TrimSpace(opts.WALPath) == "" {
		opts.DataDir = defaultDataDir
	}
	if strings.TrimSpace(opts.WALPath) == "" {
		opts.WALPath = filepath.Join(opts.DataDir, "pending_traffic.json")
	}
	if strings.TrimSpace(opts.ProcRoot) == "" {
		opts.ProcRoot = defaultProcRoot
	}
	if strings.TrimSpace(opts.ProcNetDevPath) == "" {
		opts.ProcNetDevPath = defaultProcNetDevPath
	}
	if strings.TrimSpace(opts.ProcNetRoutePath) == "" {
		opts.ProcNetRoutePath = defaultProcNetRoutePath
	}
	if strings.TrimSpace(opts.ProcStatPath) == "" {
		opts.ProcStatPath = defaultProcStatPath
	}
	if strings.TrimSpace(opts.ProcMeminfoPath) == "" {
		opts.ProcMeminfoPath = defaultProcMeminfoPath
	}
	if strings.TrimSpace(opts.ProcUptimePath) == "" {
		opts.ProcUptimePath = defaultProcUptimePath
	}
	if strings.TrimSpace(opts.DiskPath) == "" {
		opts.DiskPath = defaultDiskPath
	}
	opts.Interface = strings.TrimSpace(opts.Interface)
	if opts.Interface == "" {
		opts.Interface = strings.TrimSpace(os.Getenv("IFACE"))
	}
	opts.StatsAddr = strings.TrimSpace(opts.StatsAddr)
	if opts.NICInterval <= 0 {
		opts.NICInterval = defaultNICInterval
	}
	if opts.StatsInterval <= 0 {
		opts.StatsInterval = defaultStatsInterval
	}
	walSyncInterval := opts.WALSyncInterval
	if walSyncInterval == 0 {
		walSyncInterval = defaultWALSyncInterval
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	if err := os.MkdirAll(filepath.Dir(opts.WALPath), 0o750); err != nil {
		return nil, err
	}

	c := &Collector{
		opts:            opts,
		logger:          logger,
		walPath:         opts.WALPath,
		statsEnabled:    true,
		activeUsers:     make(map[string]int64),
		wal:             newEmptyWAL(),
		walSyncInterval: walSyncInterval,
	}
	if err := c.loadWAL(); err != nil {
		return nil, err
	}
	return c, nil
}

// SetActiveUsers updates the username -> user_id mapping and backfills any unattributed WAL entries.
func (c *Collector) SetActiveUsers(users []protocol.SSUserEntry) {
	newMap := make(map[string]int64, len(users))
	for _, u := range users {
		if u.Username == "" {
			continue
		}
		newMap[u.Username] = u.UserID
	}

	c.userMu.Lock()
	c.activeUsers = newMap
	c.userMu.Unlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.wal.UserDeltas) == 0 {
		return
	}
	next := c.wal.clone()
	changed := false
	for uname, entry := range next.UserDeltas {
		if entry.UserID == 0 {
			if uid, ok := newMap[uname]; ok && uid != 0 {
				entry.UserID = uid
				next.UserDeltas[uname] = entry
				changed = true
			}
		}
	}
	if changed {
		if err := c.commitWALWriteLocked(next, false); err != nil {
			c.logger.Warn("failed to persist backfilled user IDs to WAL", "error", err)
			return
		}
	}
}

// SetStatsEnabled toggles Layer 2 sing-box gRPC StatsService polling.
func (c *Collector) SetStatsEnabled(enabled bool) {
	c.userMu.Lock()
	c.statsEnabled = enabled
	c.userMu.Unlock()
}

// PollOnce performs one synchronous coalesced NIC, Snell process I/O, and gRPC Stats poll.
func (c *Collector) PollOnce(ctx context.Context) error {
	rxDelta, txDelta, commitNIC, nicErr := c.sampleNIC()
	snellDelta, commitSnell := c.sampleSnellIO()
	userDeltas, activeSnapshot, statsErr := c.fetchUserDeltas(ctx)

	walErr := c.addCombinedDeltas(rxDelta, txDelta, snellDelta, userDeltas, activeSnapshot)
	if walErr == nil {
		if commitNIC != nil {
			commitNIC()
		}
		if commitSnell != nil {
			commitSnell()
		}
	} else {
		walErr = fmt.Errorf("persist poll deltas: %w", walErr)
	}
	return errors.Join(nicErr, statsErr, walErr)
}

func (c *Collector) pollHostTraffic() error {
	rxDelta, txDelta, commitNIC, nicErr := c.sampleNIC()
	snellDelta, commitSnell := c.sampleSnellIO()

	walErr := c.addCombinedDeltas(rxDelta, txDelta, snellDelta, nil, nil)
	if walErr == nil {
		if commitNIC != nil {
			commitNIC()
		}
		if commitSnell != nil {
			commitSnell()
		}
	} else {
		walErr = fmt.Errorf("persist host traffic deltas: %w", walErr)
	}
	return errors.Join(nicErr, walErr)
}

// Start begins background NIC and Stats polling loops until ctx is cancelled or Stop is called.
func (c *Collector) Start(ctx context.Context) {
	c.loopMu.Lock()
	defer c.loopMu.Unlock()

	if c.running {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	loopCtx, cancel := context.WithCancel(ctx)
	c.cancel = cancel
	c.running = true

	c.wg.Add(2)
	go c.runNICLoop(loopCtx)
	go c.runStatsLoop(loopCtx)
}

// Stop halts background polling loops, waits for them to exit, and closes gRPC connections.
func (c *Collector) Stop() {
	c.loopMu.Lock()
	defer c.loopMu.Unlock()

	cancel := c.cancel
	wasRunning := c.running
	c.cancel = nil
	c.running = false

	if cancel != nil {
		cancel()
	}
	c.closeGRPC()
	if wasRunning {
		c.wg.Wait()
	}
	c.closeGRPC()
	if err := c.FlushWAL(); err != nil {
		c.logger.Warn("flush WAL on stop failed", "error", err)
	}
}

func (c *Collector) runNICLoop(ctx context.Context) {
	defer c.wg.Done()
	if err := c.pollHostTraffic(); err != nil && ctx.Err() == nil {
		c.logger.Warn("host traffic poll failed", "error", err)
	}
	ticker := time.NewTicker(c.opts.NICInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.pollHostTraffic(); err != nil && ctx.Err() == nil {
				c.logger.Warn("host traffic poll failed", "error", err)
			}
		}
	}
}

func (c *Collector) runStatsLoop(ctx context.Context) {
	defer c.wg.Done()
	if err := c.pollStats(ctx); err != nil && ctx.Err() == nil {
		c.logger.Warn("gRPC stats poll failed", "error", err)
	}
	ticker := time.NewTicker(c.opts.StatsInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.pollStats(ctx); err != nil && ctx.Err() == nil {
				c.logger.Warn("gRPC stats poll failed", "error", err)
			}
		}
	}
}

// StageMetrics collects live host telemetry and snapshots pending NIC and per-user WAL deltas.
// Calling the returned ack() subtracts only the snapshotted deltas atomically from the WAL.
func (c *Collector) StageMetrics(ctx context.Context, health protocol.AgentHealth) (protocol.AgentMetrics, func() error, error) {
	return c.stageMetrics(ctx, health, true)
}

// SnapshotAndStageMetrics returns a non-destructive snapshot of live telemetry and pending WAL deltas
// without clearing or advancing the WAL commit stage.
func (c *Collector) SnapshotAndStageMetrics(ctx context.Context, health protocol.AgentHealth) (protocol.AgentMetrics, error) {
	metrics, _, err := c.stageMetrics(ctx, health, false)
	return metrics, err
}

func (c *Collector) stageMetrics(ctx context.Context, health protocol.AgentHealth, advanceSeq bool) (protocol.AgentMetrics, func() error, error) {
	cpuPct := c.readCPUPercent(ctx)
	memUsed, memTotal := c.readMemory(ctx)
	diskPct := c.readDiskUsedPercent()
	uptime := c.readUptime()

	c.nicMu.Lock()
	rxBPS := c.lastRxBPS
	txBPS := c.lastTxBPS
	c.nicMu.Unlock()

	c.userMu.RLock()
	activeSnapshot := make(map[string]int64, len(c.activeUsers))
	for k, v := range c.activeUsers {
		activeSnapshot[k] = v
	}
	c.userMu.RUnlock()

	c.mu.Lock()
	stagedRx := c.wal.NICRxDelta
	stagedTx := c.wal.NICTxDelta
	stagedAdminSnell := c.wal.AdminSnellBytes
	stagedUsers := make(map[string]walUserDelta, len(c.wal.UserDeltas))
	userDeltas := make([]protocol.UserTrafficDelta, 0, len(c.wal.UserDeltas))

	for uname, entry := range c.wal.UserDeltas {
		if uname == "" || (entry.UpBytes == 0 && entry.DownBytes == 0) {
			continue
		}
		uid := entry.UserID
		if uid == 0 {
			if mapped, ok := activeSnapshot[uname]; ok && mapped != 0 {
				uid = mapped
				entry.UserID = mapped
				c.wal.UserDeltas[uname] = entry
			}
		}
		stagedUsers[uname] = entry
		userDeltas = append(userDeltas, protocol.UserTrafficDelta{
			Username:  uname,
			UserID:    uid,
			UpBytes:   entry.UpBytes,
			DownBytes: entry.DownBytes,
		})
	}
	sort.Slice(userDeltas, func(i, j int) bool {
		return userDeltas[i].Username < userDeltas[j].Username
	})

	if advanceSeq {
		c.stageSeq++
	}
	seq := c.stageSeq
	c.mu.Unlock()

	metrics := protocol.AgentMetrics{
		TS:              time.Now().Unix(),
		CPUPercent:      cpuPct,
		MemUsedBytes:    memUsed,
		MemTotalBytes:   memTotal,
		DiskUsedPercent: diskPct,
		UptimeSeconds:   uptime,
		RxBPS:           rxBPS,
		TxBPS:           txBPS,
		NicRxDelta:      stagedRx,
		NicTxDelta:      stagedTx,
		AdminSnellBytes: stagedAdminSnell,
		UserDeltas:      userDeltas,
		Health:          health,
	}

	if !advanceSeq {
		return metrics, func() error { return nil }, nil
	}

	var ackMu sync.Mutex
	acked := false
	ack := func() error {
		ackMu.Lock()
		defer ackMu.Unlock()
		if acked {
			return nil
		}

		c.mu.Lock()
		defer c.mu.Unlock()
		if seq != c.stageSeq {
			acked = true
			return nil
		}
		if stagedRx == 0 && stagedTx == 0 && stagedAdminSnell == 0 && len(stagedUsers) == 0 {
			acked = true
			return nil
		}

		next := c.wal.clone()
		next.NICRxDelta = subClamped(next.NICRxDelta, stagedRx)
		next.NICTxDelta = subClamped(next.NICTxDelta, stagedTx)
		next.AdminSnellBytes = subClamped(next.AdminSnellBytes, stagedAdminSnell)
		for uname, su := range stagedUsers {
			cur, ok := next.UserDeltas[uname]
			if !ok {
				continue
			}
			cur.UpBytes = subClamped(cur.UpBytes, su.UpBytes)
			cur.DownBytes = subClamped(cur.DownBytes, su.DownBytes)
			if cur.UpBytes == 0 && cur.DownBytes == 0 {
				delete(next.UserDeltas, uname)
			} else {
				next.UserDeltas[uname] = cur
			}
		}

		if err := c.commitWALWriteLocked(next, false); err != nil {
			return err
		}
		acked = true
		return nil
	}

	return metrics, ack, nil
}

func (c *Collector) pollSnellIO() {
	delta, commit := c.sampleSnellIO()
	if delta > 0 {
		if err := c.addAdminSnellDelta(delta); err != nil {
			c.logger.Warn("persist admin snell delta failed", "error", err)
			return
		}
	}
	if commit != nil {
		commit()
	}
}

func (c *Collector) sampleSnellIO() (uint64, func()) {
	if c.opts.SnellPIDFunc == nil {
		return 0, nil
	}
	pid := c.opts.SnellPIDFunc()
	if pid <= 0 {
		c.snellMu.Lock()
		c.lastSnellPID = 0
		c.snellMu.Unlock()
		return 0, nil
	}

	ioPath := filepath.Join(c.opts.ProcRoot, strconv.Itoa(pid), "io")
	raw, err := os.ReadFile(ioPath)
	if err != nil {
		return 0, nil
	}
	rchar, wchar, ok := parseProcPIDIO(raw)
	if !ok {
		return 0, nil
	}

	c.snellMu.Lock()
	if pid != c.lastSnellPID {
		c.lastSnellPID = pid
		c.lastSnellRChar = rchar
		c.lastSnellWChar = wchar
		c.snellMu.Unlock()
		return 0, nil
	}

	var rDelta, wDelta uint64
	if rchar >= c.lastSnellRChar {
		rDelta = rchar - c.lastSnellRChar
	}
	if wchar >= c.lastSnellWChar {
		wDelta = wchar - c.lastSnellWChar
	}
	c.snellMu.Unlock()

	delta := min(rDelta, wDelta)
	commit := func() {
		c.snellMu.Lock()
		if c.lastSnellPID == pid {
			c.lastSnellRChar = rchar
			c.lastSnellWChar = wchar
		}
		c.snellMu.Unlock()
	}
	return delta, commit
}

func parseProcPIDIO(raw []byte) (rchar, wchar uint64, ok bool) {
	var hasR, hasW bool
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		switch fields[0] {
		case "rchar:":
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				rchar = v
				hasR = true
			}
		case "wchar:":
			if v, err := strconv.ParseUint(fields[1], 10, 64); err == nil {
				wchar = v
				hasW = true
			}
		}
	}
	return rchar, wchar, hasR && hasW
}

// HostInfo returns OS, architecture, logical CPU count, and total RAM in bytes.
func (c *Collector) HostInfo() (osName, arch string, cpuCores int, totalRAM uint64) {
	_, totalRAM = c.readMemory(context.Background())
	return runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), totalRAM
}
