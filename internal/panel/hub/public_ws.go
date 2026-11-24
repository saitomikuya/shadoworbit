package hub

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/protocol"
)

type publicClient struct {
	id     uint64
	conn   *websocket.Conn
	sendCh chan []byte
	ctx    context.Context
	cancel context.CancelFunc
}

func (c *publicClient) enqueue(payload []byte) {
	select {
	case c.sendCh <- payload:
		return
	default:
	}

	// Drop oldest queued frame on overflow so slow clients never block Hub.
	select {
	case <-c.sendCh:
	default:
	}
	select {
	case c.sendCh <- payload:
	default:
	}
}

// BuildPublicSnapshot compiles a strictly redacted PublicStatusSnapshot from
// system_settings, nodes, and live telemetry cache.
func (h *Hub) BuildPublicSnapshot(ctx context.Context) (protocol.PublicStatusSnapshot, error) {
	if h.store == nil {
		return protocol.PublicStatusSnapshot{}, errors.New("hub: nil store")
	}
	if ctx == nil {
		ctx = h.baseCtx
	}

	settings, err := h.store.GetAllSettings(ctx)
	if err != nil {
		return protocol.PublicStatusSnapshot{}, err
	}

	nodes, err := h.store.ListNodes(ctx)
	if err != nil {
		return protocol.PublicStatusSnapshot{}, err
	}

	siteTitle := strings.TrimSpace(settings["site_title"])
	if siteTitle == "" {
		siteTitle = "ShadowOrbit"
	}
	announcement := settings["announcement"]
	percentageOnly := strings.EqualFold(strings.TrimSpace(settings["public_percentage_only"]), "true")

	h.mu.RLock()
	onlineSet := make(map[int64]struct{}, len(h.sessions))
	for id := range h.sessions {
		onlineSet[id] = struct{}{}
	}
	telSnapshot := make(map[int64]NodeTelemetry, len(h.telemetry))
	for id, tel := range h.telemetry {
		telSnapshot[id] = tel
	}
	h.mu.RUnlock()

	views := make([]protocol.PublicNodeView, 0, len(nodes))
	for _, n := range nodes {
		if !n.Enabled {
			continue
		}

		_, isLive := onlineSet[n.ID]
		status := protocol.NodeStatusOffline
		if n.IsTrafficPaused {
			status = protocol.NodeStatusTrafficPaused
		} else if isLive {
			status = protocol.NodeStatusOnline
		}

		cpuPercent := n.CPUPercent
		memUsed := n.MemUsedBytes
		memTotal := n.MemTotalBytes
		uptime := n.UptimeSeconds
		rxBPS := n.RxBPS
		txBPS := n.TxBPS
		coreA := n.CoreAHealthy
		coreB := n.CoreBHealthy

		if tel, ok := telSnapshot[n.ID]; ok {
			cpuPercent = tel.CPUPercent
			memUsed = tel.MemUsedBytes
			memTotal = tel.MemTotalBytes
			uptime = tel.UptimeSeconds
			rxBPS = tel.RxBPS
			txBPS = tel.TxBPS
			coreA = tel.Health.Snell && tel.Health.ShadowTLS
			coreB = tel.Health.SingBox
		}

		if !isLive {
			cpuPercent = 0
			memUsed = 0
			memTotal = 0
			uptime = 0
			rxBPS = 0
			txBPS = 0
			coreA = false
			coreB = false
		}

		usedBytes := calcCountedTraffic(n.CycleRxBytes, n.CycleTxBytes, n.TrafficCountMode)
		if usedBytes < 0 {
			usedBytes = 0
		}

		limitBytes := n.TrafficLimitBytes
		percentBase := limitBytes
		if percentBase <= 0 {
			percentBase = n.TrafficThresholdBytes
		}
		var trafficPercent float64
		if percentBase > 0 && usedBytes > 0 {
			pct := float64(usedBytes) / float64(percentBase) * 100
			if pct > 100 {
				pct = 100
			} else if pct < 0 {
				pct = 0
			}
			trafficPercent = math.Round(pct*100) / 100
		}

		totalRx := n.TotalRxBytes
		totalTx := n.TotalTxBytes
		if totalRx < 0 {
			totalRx = 0
		}
		if totalTx < 0 {
			totalTx = 0
		}

		pausedReason := n.PausedReason
		if percentageOnly {
			usedBytes = 0
			limitBytes = 0
			totalRx = 0
			totalTx = 0
			if pausedReason != "" {
				pausedReason = "traffic threshold reached"
			}
		}

		views = append(views, protocol.PublicNodeView{
			ID:                n.ID,
			Name:              n.Name,
			RegionTag:         n.RegionTag,
			SortOrder:         n.SortOrder,
			Status:            status,
			PausedReason:      pausedReason,
			BillingResetDay:   n.BillingResetDay,
			CPUPercent:        cpuPercent,
			MemUsedBytes:      memUsed,
			MemTotalBytes:     memTotal,
			UptimeSeconds:     uptime,
			RxBPS:             rxBPS,
			TxBPS:             txBPS,
			TotalRxBytes:      totalRx,
			TotalTxBytes:      totalTx,
			TrafficUsedBytes:  usedBytes,
			TrafficLimitBytes: limitBytes,
			TrafficPercent:    trafficPercent,
			PercentageOnly:    percentageOnly,
			CoreAHealthy:      coreA,
			CoreBHealthy:      coreB,
		})
	}

	return protocol.PublicStatusSnapshot{
		SiteTitle:      siteTitle,
		Announcement:   announcement,
		PercentageOnly: percentageOnly,
		Nodes:          views,
	}, nil
}

// ServePublicWS upgrades an unauthenticated visitor WebSocket, immediately pushes
// a redacted PublicStatusSnapshot, and streams debounced updates without blocking on slow clients.
func (h *Hub) ServePublicWS(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		http.Error(w, "hub store unavailable", http.StatusInternalServerError)
		return
	}

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		http.Error(w, "hub closed", http.StatusServiceUnavailable)
		return
	}
	h.wg.Add(1)
	h.mu.Unlock()
	defer h.wg.Done()

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		h.logger.Debug("hub: public ws accept failed", "err", err)
		return
	}
	conn.SetReadLimit(h.readLimit)

	ctx, cancel := context.WithCancel(h.baseCtx)
	client := &publicClient{
		id:     h.nextSessionID.Add(1),
		conn:   conn,
		sendCh: make(chan []byte, publicSendQueueCap),
		ctx:    ctx,
		cancel: cancel,
	}

	snap, err := h.BuildPublicSnapshot(ctx)
	if err == nil {
		if initialBytes, marshalErr := json.Marshal(snap); marshalErr == nil {
			client.enqueue(initialBytes)
		}
	}

	h.publicMu.Lock()
	if h.isClosed() {
		h.publicMu.Unlock()
		cancel()
		_ = conn.CloseNow()
		return
	}
	h.publicClients[client.id] = client
	h.publicMu.Unlock()

	defer func() {
		h.publicMu.Lock()
		delete(h.publicClients, client.id)
		h.publicMu.Unlock()
		cancel()
		_ = conn.CloseNow()
	}()

	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		defer cancel()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			_ = conn.CloseNow()
			<-readerDone
			return
		case payload := <-client.sendCh:
			wctx, wcancel := context.WithTimeout(ctx, h.writeTimeout)
			err := conn.Write(wctx, websocket.MessageText, payload)
			wcancel()
			if err != nil {
				cancel()
				_ = conn.CloseNow()
				<-readerDone
				return
			}
		}
	}
}

// BroadcastPublicStatus schedules a debounced public status snapshot broadcast
// to connected /api/v1/public/ws clients. It is thread-safe and non-blocking.
func (h *Hub) BroadcastPublicStatus() {
	h.triggerPublicBroadcast()
}

func (h *Hub) triggerPublicBroadcast() {
	if h.isClosed() {
		return
	}
	select {
	case h.publicDirtyCh <- struct{}{}:
	default:
	}
}

func (h *Hub) publicClientCount() int {
	h.publicMu.Lock()
	n := len(h.publicClients)
	h.publicMu.Unlock()
	return n
}

func (h *Hub) broadcastPublicBytes(payload []byte) {
	h.publicMu.Lock()
	clients := make([]*publicClient, 0, len(h.publicClients))
	for _, c := range h.publicClients {
		clients = append(clients, c)
	}
	h.publicMu.Unlock()

	for _, c := range clients {
		c.enqueue(payload)
	}
}

func (h *Hub) publicBroadcasterLoop() {
	defer h.wg.Done()
	for {
		select {
		case <-h.baseCtx.Done():
			return
		case <-h.publicDirtyCh:
		}

		if h.publicDebounce > 0 {
			timer := time.NewTimer(h.publicDebounce)
			for {
				select {
				case <-h.baseCtx.Done():
					timer.Stop()
					return
				case <-h.publicDirtyCh:
					// Coalesce burst updates within the debounce window.
				case <-timer.C:
					goto flush
				}
			}
		}

	flush:
		if h.publicClientCount() == 0 {
			continue
		}

		ctx, cancel := context.WithTimeout(h.baseCtx, 5*time.Second)
		snap, err := h.BuildPublicSnapshot(ctx)
		cancel()
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				h.logger.Warn("hub: build public snapshot failed", "err", err)
			}
			continue
		}
		payload, err := json.Marshal(snap)
		if err != nil {
			h.logger.Warn("hub: marshal public snapshot failed", "err", err)
			continue
		}
		h.broadcastPublicBytes(payload)
	}
}

func calcCountedTraffic(rx, tx int64, mode string) int64 {
	if rx < 0 {
		rx = 0
	}
	if tx < 0 {
		tx = 0
	}
	switch mode {
	case protocol.TrafficCountTxOnly:
		return tx
	case protocol.TrafficCountRxOnly:
		return rx
	case protocol.TrafficCountMaxDir:
		if rx > tx {
			return rx
		}
		return tx
	case protocol.TrafficCountBoth:
		fallthrough
	default:
		if rx > math.MaxInt64-tx {
			return math.MaxInt64
		}
		return rx + tx
	}
}
