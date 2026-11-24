package hub

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type agentSession struct {
	id                   uint64
	nodeID               int64
	conn                 *websocket.Conn
	ctx                  context.Context
	cancel               context.CancelFunc
	sendCh               chan []byte
	superseded           atomic.Bool
	connectedFromOffline atomic.Bool

	syncMu        sync.Mutex
	lastSyncedRev int64
}

func (s *agentSession) consumeConnectedFromOffline() bool {
	return s.connectedFromOffline.Swap(false)
}

func (s *agentSession) enqueue(payload []byte) error {
	select {
	case <-s.ctx.Done():
		return ErrNodeOffline
	default:
	}

	select {
	case s.sendCh <- payload:
		return nil
	case <-s.ctx.Done():
		return ErrNodeOffline
	default:
		// Slow/stalled socket: close session so it reconnects cleanly without blocking callers.
		s.cancel()
		_ = s.conn.CloseNow()
		return ErrNodeOffline
	}
}

// ServeAgentWS authenticates an agent via Bearer NODE_TOKEN, upgrades to WebSocket,
// manages session registration/replacement, pushes initial server.config_sync,
// and processes inbound agent frames until disconnect.
func (h *Hub) ServeAgentWS(w http.ResponseWriter, r *http.Request) {
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

	authCtx, cancelAuth := context.WithCancel(r.Context())
	stopAuth := context.AfterFunc(h.baseCtx, cancelAuth)
	if h.baseCtx.Err() != nil {
		cancelAuth()
	}
	node, statusCode, authErr := h.authenticateAgentRequest(authCtx, r)
	stopAuth()
	cancelAuth()
	if authErr != nil {
		if h.isClosed() {
			http.Error(w, "hub closed", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, authErr.Error(), statusCode)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		h.logger.Debug("hub: agent ws accept failed", "node_id", node.ID, "err", err)
		return
	}
	conn.SetReadLimit(h.readLimit)

	sessCtx, sessCancel := context.WithCancel(h.baseCtx)
	sess := &agentSession{
		id:            h.nextSessionID.Add(1),
		nodeID:        node.ID,
		conn:          conn,
		ctx:           sessCtx,
		cancel:        sessCancel,
		sendCh:        make(chan []byte, agentSendQueueCap),
		lastSyncedRev: -1,
	}

	now := h.now().UTC()
	var oldSess *agentSession
	var wasOfflinePending bool
	var wasOfflineAlerted bool

	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		sessCancel()
		_ = conn.CloseNow()
		return
	}

	oldSess = h.sessions[node.ID]
	if oldSess != nil {
		oldSess.superseded.Store(true)
	}

	_, wasOfflinePending = h.offlinePending[node.ID]
	wasOfflineAlerted = h.offlineAlerted[node.ID]

	h.sessions[node.ID] = sess
	delete(h.offlinePending, node.ID)

	tel, ok := h.telemetry[node.ID]
	if !ok {
		tel = NodeTelemetry{
			NodeID:                 node.ID,
			OS:                     node.AgentOS,
			Arch:                   node.AgentArch,
			CPUCores:               node.CPUCores,
			PublicIPv4:             node.PublicIP,
			PublicIPv6:             node.PublicIPv6,
			Versions:               node.ReportedVersions,
			ReportedConfigRevision: node.ReportedConfigRevision,
			CPUPercent:             node.CPUPercent,
			MemUsedBytes:           node.MemUsedBytes,
			MemTotalBytes:          node.MemTotalBytes,
			DiskUsedPercent:        node.DiskUsedPercent,
			UptimeSeconds:          node.UptimeSeconds,
			RxBPS:                  node.RxBPS,
			TxBPS:                  node.TxBPS,
			Health: protocol.AgentHealth{
				Snell:     node.CoreAHealthy,
				ShadowTLS: node.CoreAHealthy,
				SingBox:   node.CoreBHealthy,
			},
		}
	}
	tel.Online = true
	tel.LastSeenAt = now
	h.telemetry[node.ID] = tel
	h.mu.Unlock()

	if oldSess != nil {
		oldSess.cancel()
		_ = oldSess.conn.CloseNow()
	}

	nodeStatusMu := h.nodeStatusLock(node.ID)
	nodeStatusMu.Lock()
	h.mu.RLock()
	cur := h.sessions[node.ID]
	stillCurrent := !h.closed && cur != nil && cur.id == sess.id
	h.mu.RUnlock()

	if stillCurrent {
		prevNode := node
		if freshNode, getErr := h.store.GetNodeByID(sessCtx, node.ID); getErr != nil {
			if errors.Is(getErr, store.ErrNotFound) {
				nodeStatusMu.Unlock()
				h.EvictNode(node.ID)
				sessCancel()
				_ = conn.CloseNow()
				return
			}
		} else {
			prevNode = freshNode
		}
		if prevNode.Status == protocol.NodeStatusOffline && prevNode.LastSeenAt != nil && (!wasOfflinePending || wasOfflineAlerted) {
			sess.connectedFromOffline.Store(true)
		}

		statusNow := h.now().UTC()
		if err := h.store.SetNodeConnectionStatus(sessCtx, node.ID, true, statusNow); err != nil {
			h.logger.Warn("hub: set node online on connect failed", "node_id", node.ID, "err", err)
		} else {
			h.mu.Lock()
			if cur2 := h.sessions[node.ID]; !h.closed && cur2 != nil && cur2.id == sess.id {
				if t2, ok := h.telemetry[node.ID]; ok {
					t2.LastSeenAt = statusNow
					h.telemetry[node.ID] = t2
				}
			}
			h.mu.Unlock()
		}
	}
	nodeStatusMu.Unlock()

	if stillCurrent {
		sess.syncMu.Lock()
		h.mu.RLock()
		cur = h.sessions[node.ID]
		syncCurrent := !h.closed && cur != nil && cur.id == sess.id
		h.mu.RUnlock()
		if syncCurrent {
			if cfg, err := h.BuildConfigSync(sessCtx, node.ID); err != nil {
				h.logger.Warn("hub: initial config sync build failed", "node_id", node.ID, "err", err)
			} else if frame, err := protocol.MarshalEnvelope(protocol.MsgTypeServerConfigSync, h.nextReqID(), cfg); err != nil {
				h.logger.Warn("hub: initial config sync marshal failed", "node_id", node.ID, "err", err)
			} else if enqErr := sess.enqueue(frame); enqErr == nil {
				sess.lastSyncedRev = cfg.ConfigRevision
			}
		}
		sess.syncMu.Unlock()
	}

	h.triggerPublicBroadcast()

	var sessWg sync.WaitGroup
	sessWg.Add(2)
	go h.runAgentWriteLoop(sess, &sessWg)
	go h.runAgentPingLoop(sess, &sessWg)

	h.runAgentReadLoop(sess)

	sessCancel()
	_ = conn.CloseNow()
	sessWg.Wait()

	h.cleanupAgentSession(sess)
}

func (h *Hub) authenticateAgentRequest(ctx context.Context, r *http.Request) (*store.Node, int, error) {
	rawToken, err := auth.ExtractBearerToken(r.Header.Get("Authorization"))
	if err != nil {
		return nil, http.StatusUnauthorized, errors.New("unauthorized")
	}

	hash := auth.HashToken(rawToken)
	node, err := h.store.GetNodeByTokenHash(ctx, hash)
	if errors.Is(err, store.ErrNotFound) {
		nodes, listErr := h.store.ListNodes(ctx)
		if listErr != nil {
			return nil, http.StatusInternalServerError, errors.New("internal error")
		}
		var matched *store.Node
		for i := range nodes {
			if auth.VerifyTokenHash(rawToken, nodes[i].TokenHash) {
				cp := nodes[i]
				matched = &cp
			}
		}
		if matched == nil {
			return nil, http.StatusUnauthorized, errors.New("unauthorized")
		}
		node = matched
		err = nil
	}
	if err != nil {
		return nil, http.StatusInternalServerError, errors.New("internal error")
	}
	if node == nil || !auth.VerifyTokenHash(rawToken, node.TokenHash) {
		return nil, http.StatusUnauthorized, errors.New("unauthorized")
	}
	if !node.Enabled {
		return nil, http.StatusForbidden, errors.New("node disabled")
	}
	return node, http.StatusOK, nil
}

func (h *Hub) runAgentWriteLoop(s *agentSession, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		select {
		case <-s.ctx.Done():
			return
		case payload := <-s.sendCh:
			wctx, cancel := context.WithTimeout(s.ctx, h.writeTimeout)
			err := s.conn.Write(wctx, websocket.MessageText, payload)
			cancel()
			if err != nil {
				if s.ctx.Err() == nil {
					h.logger.Debug("hub: agent write failed", "node_id", s.nodeID, "err", err)
				}
				s.cancel()
				_ = s.conn.CloseNow()
				return
			}
		}
	}
}

func (h *Hub) runAgentPingLoop(s *agentSession, wg *sync.WaitGroup) {
	defer wg.Done()
	ticker := time.NewTicker(h.pingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			pctx, cancel := context.WithTimeout(s.ctx, h.pingTimeout)
			err := s.conn.Ping(pctx)
			cancel()
			if err != nil {
				if s.ctx.Err() == nil {
					h.logger.Debug("hub: agent ping failed", "node_id", s.nodeID, "err", err)
				}
				s.cancel()
				_ = s.conn.CloseNow()
				return
			}
		}
	}
}

func (h *Hub) runAgentReadLoop(s *agentSession) {
	for {
		msgType, data, err := s.conn.Read(s.ctx)
		if err != nil {
			return
		}
		if msgType != websocket.MessageText && msgType != websocket.MessageBinary {
			continue
		}
		h.handleAgentFrame(s, data)
	}
}

func (h *Hub) cleanupAgentSession(s *agentSession) {
	h.mu.Lock()
	isCurrent := false
	if cur, ok := h.sessions[s.nodeID]; ok && cur.id == s.id {
		delete(h.sessions, s.nodeID)
		isCurrent = true
	}

	genuineDisconnect := !s.superseded.Load() && isCurrent && !h.closed
	if genuineDisconnect {
		h.offlinePending[s.nodeID] = h.now().UTC()
		if tel, ok := h.telemetry[s.nodeID]; ok {
			tel.Online = false
			h.telemetry[s.nodeID] = tel
		}
	}
	h.mu.Unlock()

	if !genuineDisconnect {
		return
	}

	nodeStatusMu := h.nodeStatusLock(s.nodeID)
	nodeStatusMu.Lock()
	h.mu.RLock()
	stillOffline := !h.closed && h.sessions[s.nodeID] == nil
	h.mu.RUnlock()
	if stillOffline {
		cleanupCtx, cancel := context.WithTimeout(h.baseCtx, 2*time.Second)
		err := h.store.SetNodeConnectionStatus(cleanupCtx, s.nodeID, false, time.Time{})
		cancel()
		if err != nil && !errors.Is(err, store.ErrNotFound) && !errors.Is(err, context.Canceled) && !h.isClosed() {
			h.logger.Warn("hub: set node offline on disconnect failed", "node_id", s.nodeID, "err", err)
		}
	}
	nodeStatusMu.Unlock()

	if stillOffline {
		h.triggerPublicBroadcast()
	}
}

func (h *Hub) handleAgentFrame(s *agentSession, data []byte) {
	env, err := protocol.ParseEnvelope(data)
	if err != nil {
		h.logger.Warn("hub: ignoring invalid agent frame", "node_id", s.nodeID, "err", err)
		return
	}

	switch env.Type {
	case protocol.MsgTypeAgentHello:
		h.handleAgentHello(s, env)
	case protocol.MsgTypeAgentMetrics:
		h.handleAgentMetrics(s, env)
	case protocol.MsgTypeAgentEvent:
		h.handleAgentEvent(s, env)
	default:
		h.logger.Debug("hub: ignoring unknown agent message type", "node_id", s.nodeID, "type", env.Type)
	}
}

func (h *Hub) handleAgentHello(s *agentSession, env protocol.Envelope) {
	var hello protocol.AgentHello
	if err := env.DecodePayload(&hello); err != nil {
		h.logger.Warn("hub: invalid agent.hello payload", "node_id", s.nodeID, "err", err)
		return
	}

	now := h.now().UTC()
	nodeStatusMu := h.nodeStatusLock(s.nodeID)
	nodeStatusMu.Lock()

	h.mu.RLock()
	cur := h.sessions[s.nodeID]
	stillCurrent := !h.closed && cur != nil && cur.id == s.id
	h.mu.RUnlock()
	if !stillCurrent {
		nodeStatusMu.Unlock()
		return
	}

	prevNode, err := h.store.GetNodeByID(s.ctx, s.nodeID)
	if err != nil {
		nodeStatusMu.Unlock()
		h.logger.Warn("hub: agent.hello node lookup failed", "node_id", s.nodeID, "err", err)
		return
	}

	versions := normalizeAgentVersions(hello.Versions)
	if err := h.store.UpdateNodeVersions(s.ctx, s.nodeID, versions, hello.OS, hello.Arch, hello.CPUCores, hello.ConfigRevision); err != nil {
		h.logger.Warn("hub: update node versions failed", "node_id", s.nodeID, "err", err)
	}
	if err := h.store.UpdateNodePublicIPs(s.ctx, s.nodeID, hello.PublicIPv4, hello.PublicIPv6); err != nil {
		h.logger.Warn("hub: update node public ips failed", "node_id", s.nodeID, "err", err)
	}
	if err := h.store.SetNodeConnectionStatus(s.ctx, s.nodeID, true, now); err != nil {
		h.logger.Warn("hub: update node connection status on hello failed", "node_id", s.nodeID, "err", err)
	}

	h.mu.Lock()
	cur = h.sessions[s.nodeID]
	stillCurrent = !h.closed && cur != nil && cur.id == s.id
	var wasOfflineAlerted bool
	if stillCurrent {
		tel := h.telemetry[s.nodeID]
		tel.NodeID = s.nodeID
		tel.Online = true
		tel.OS = hello.OS
		tel.Arch = hello.Arch
		tel.CPUCores = hello.CPUCores
		tel.TotalRAMBytes = hello.TotalRAMBytes
		if hello.PublicIPv4 != "" {
			tel.PublicIPv4 = hello.PublicIPv4
		} else if tel.PublicIPv4 == "" {
			tel.PublicIPv4 = prevNode.PublicIP
		}
		if hello.PublicIPv6 != "" {
			tel.PublicIPv6 = hello.PublicIPv6
		} else if tel.PublicIPv6 == "" {
			tel.PublicIPv6 = prevNode.PublicIPv6
		}
		tel.Versions = versions
		tel.ReportedConfigRevision = hello.ConfigRevision
		tel.LastSeenAt = now
		h.telemetry[s.nodeID] = tel

		wasOfflineAlerted = h.offlineAlerted[s.nodeID]
		delete(h.offlineAlerted, s.nodeID)
		delete(h.offlinePending, s.nodeID)
	}
	h.mu.Unlock()
	nodeStatusMu.Unlock()

	if !stillCurrent {
		return
	}

	recoveredFromOffline := wasOfflineAlerted ||
		s.consumeConnectedFromOffline() ||
		(prevNode.Status == protocol.NodeStatusOffline && prevNode.LastSeenAt != nil)

	if recoveredFromOffline {
		h.notify(s.ctx, webhook.AlertEvent{
			Type:       webhook.EventNodeOnline,
			Severity:   webhook.SeverityInfo,
			TargetType: webhook.TargetTypeNode,
			TargetID:   s.nodeID,
			TargetName: prevNode.Name,
			Title:      "Node Online",
			Message:    fmt.Sprintf("Node %s reconnected", prevNode.Name),
			Resolved:   true,
			Timestamp:  now,
		})
	}

	s.syncMu.Lock()
	h.mu.RLock()
	cur = h.sessions[s.nodeID]
	syncCurrent := !h.closed && cur != nil && cur.id == s.id
	h.mu.RUnlock()
	if syncCurrent {
		latestNode, err := h.store.GetNodeByID(s.ctx, s.nodeID)
		if err == nil && hello.ConfigRevision != latestNode.ConfigRevision && latestNode.ConfigRevision != s.lastSyncedRev {
			if cfg, syncErr := h.BuildConfigSync(s.ctx, s.nodeID); syncErr != nil {
				h.logger.Warn("hub: build config_sync on hello failed", "node_id", s.nodeID, "err", syncErr)
			} else if frame, marshalErr := protocol.MarshalEnvelope(protocol.MsgTypeServerConfigSync, h.nextReqID(), cfg); marshalErr != nil {
				h.logger.Warn("hub: marshal config_sync on hello failed", "node_id", s.nodeID, "err", marshalErr)
			} else if enqErr := s.enqueue(frame); enqErr == nil {
				s.lastSyncedRev = cfg.ConfigRevision
			}
		}
	}
	s.syncMu.Unlock()

	h.triggerPublicBroadcast()
}

func (h *Hub) handleAgentMetrics(s *agentSession, env protocol.Envelope) {
	var m protocol.AgentMetrics
	if err := env.DecodePayload(&m); err != nil {
		h.logger.Warn("hub: invalid agent.metrics payload", "node_id", s.nodeID, "err", err)
		return
	}

	now := h.now().UTC()
	nicRx := clampUint64ToInt64(m.NicRxDelta)
	nicTx := clampUint64ToInt64(m.NicTxDelta)

	userDeltas := m.UserDeltas
	if len(userDeltas) > 0 {
		copied := make([]protocol.UserTrafficDelta, len(userDeltas))
		for i, ud := range userDeltas {
			ud.UpBytes = min(ud.UpBytes, uint64(math.MaxInt64))
			ud.DownBytes = min(ud.DownBytes, uint64(math.MaxInt64))
			copied[i] = ud
		}
		userDeltas = copied
	}

	res, err := h.store.ApplyTrafficDeltasAt(s.ctx, s.nodeID, nicRx, nicTx, userDeltas, now)
	if err != nil && !errors.Is(err, context.Canceled) && !s.superseded.Load() {
		h.logger.Warn("hub: apply traffic deltas failed", "node_id", s.nodeID, "err", err)
	}
	if adminBytes := clampUint64ToInt64(m.AdminSnellBytes); adminBytes > 0 {
		if err := h.store.RecordAdminSnellTraffic(s.ctx, s.nodeID, adminBytes, now); err != nil && !errors.Is(err, context.Canceled) && !s.superseded.Load() {
			h.logger.Warn("hub: record admin snell traffic failed", "node_id", s.nodeID, "err", err)
		}
	}

	coreAHealthy := m.Health.Snell && m.Health.ShadowTLS
	coreBHealthy := m.Health.SingBox
	if err := h.store.UpdateNodeTelemetry(s.ctx, s.nodeID, store.NodeTelemetryUpdate{
		CPUPercent:      m.CPUPercent,
		MemUsedBytes:    m.MemUsedBytes,
		MemTotalBytes:   m.MemTotalBytes,
		DiskUsedPercent: m.DiskUsedPercent,
		UptimeSeconds:   m.UptimeSeconds,
		RxBPS:           m.RxBPS,
		TxBPS:           m.TxBPS,
		CoreAHealthy:    coreAHealthy,
		CoreBHealthy:    coreBHealthy,
		LastSeenAt:      now,
	}); err != nil && !errors.Is(err, context.Canceled) && !s.superseded.Load() {
		h.logger.Warn("hub: update node telemetry failed", "node_id", s.nodeID, "err", err)
	}

	h.mu.Lock()
	cur := h.sessions[s.nodeID]
	stillCurrent := !h.closed && cur != nil && cur.id == s.id && !s.superseded.Load()
	if stillCurrent {
		tel := h.telemetry[s.nodeID]
		tel.NodeID = s.nodeID
		tel.Online = true
		tel.CPUPercent = m.CPUPercent
		tel.MemUsedBytes = m.MemUsedBytes
		tel.MemTotalBytes = m.MemTotalBytes
		tel.DiskUsedPercent = m.DiskUsedPercent
		tel.UptimeSeconds = m.UptimeSeconds
		tel.RxBPS = m.RxBPS
		tel.TxBPS = m.TxBPS
		tel.Health = m.Health
		tel.LastSeenAt = now
		h.telemetry[s.nodeID] = tel
		delete(h.offlinePending, s.nodeID)
		delete(h.offlineAlerted, s.nodeID)
	}
	h.mu.Unlock()

	if !stillCurrent {
		return
	}

	if res != nil && res.Node != nil {
		if fn := h.getOnTrafficUpdated(); fn != nil {
			uniqueUsers := dedupInt64(res.UpdatedUserIDs)
			fn(s.ctx, res.Node, uniqueUsers)
		}
	}

	h.triggerPublicBroadcast()
}

func (h *Hub) handleAgentEvent(s *agentSession, env protocol.Envelope) {
	var ev protocol.AgentEvent
	if err := env.DecodePayload(&ev); err != nil {
		h.logger.Warn("hub: invalid agent.event payload", "node_id", s.nodeID, "err", err)
		return
	}

	now := h.now().UTC()
	evCopy := ev

	h.mu.Lock()
	cur := h.sessions[s.nodeID]
	stillCurrent := !h.closed && cur != nil && cur.id == s.id && !s.superseded.Load()
	if stillCurrent {
		tel := h.telemetry[s.nodeID]
		tel.NodeID = s.nodeID
		tel.LastEvent = &evCopy
		h.telemetry[s.nodeID] = tel
	}
	h.mu.Unlock()
	if !stillCurrent {
		return
	}

	node, nodeErr := h.store.GetNodeByID(s.ctx, s.nodeID)
	nodeName := fmt.Sprintf("node-%d", s.nodeID)
	if nodeErr == nil && node != nil && node.Name != "" {
		nodeName = node.Name
	}

	switch ev.Event {
	case protocol.EventConfigApplied:
		if ev.ConfigRevision > 0 {
			if err := h.store.UpdateNodeReportedRevision(s.ctx, s.nodeID, ev.ConfigRevision); err != nil {
				h.logger.Warn("hub: update reported revision failed", "node_id", s.nodeID, "err", err)
			}
			h.mu.Lock()
			tel := h.telemetry[s.nodeID]
			tel.NodeID = s.nodeID
			tel.ReportedConfigRevision = ev.ConfigRevision
			h.telemetry[s.nodeID] = tel
			h.mu.Unlock()
		}

	case protocol.EventConfigError:
		h.notify(s.ctx, webhook.AlertEvent{
			Type:       webhook.EventConfigError,
			Severity:   webhook.SeverityCritical,
			TargetType: webhook.TargetTypeNode,
			TargetID:   s.nodeID,
			TargetName: nodeName,
			Title:      "Agent Config Error",
			Message:    ev.Message,
			Detail:     ev.Detail,
			Resolved:   false,
			Timestamp:  now,
		})

	case protocol.EventProcessCrashed:
		title := "Agent Process Crashed"
		if strings.TrimSpace(ev.Kernel) != "" {
			title = fmt.Sprintf("Kernel %s Crashed", ev.Kernel)
		}
		h.notify(s.ctx, webhook.AlertEvent{
			Type:       webhook.EventProcessCrashed,
			Severity:   webhook.SeverityCritical,
			TargetType: webhook.TargetTypeNode,
			TargetID:   s.nodeID,
			TargetName: nodeName,
			Title:      title,
			Message:    ev.Message,
			Detail:     ev.Detail,
			Resolved:   false,
			Timestamp:  now,
		})

	case protocol.EventKernelUpdateProgress:
		h.mu.Lock()
		h.kernelUpdates[s.nodeID] = KernelUpdateStatus{
			NodeID:    s.nodeID,
			Kernel:    ev.Kernel,
			Version:   ev.Version,
			Status:    ev.Status,
			Message:   ev.Message,
			Detail:    ev.Detail,
			UpdatedAt: now,
		}
		h.mu.Unlock()

	case protocol.EventKernelUpdateResult:
		h.mu.Lock()
		h.kernelUpdates[s.nodeID] = KernelUpdateStatus{
			NodeID:    s.nodeID,
			Kernel:    ev.Kernel,
			Version:   ev.Version,
			Status:    ev.Status,
			Message:   ev.Message,
			Detail:    ev.Detail,
			UpdatedAt: now,
		}
		h.mu.Unlock()

		statusNorm := strings.ToLower(strings.TrimSpace(ev.Status))
		switch statusNorm {
		case protocol.EventStatusSuccess, "update_success":
			if ev.Version != "" && node != nil {
				cleanVer := normalizeReportedVersion(ev.Version)
				versions := node.ReportedVersions
				switch ev.Kernel {
				case protocol.KernelSingBox:
					versions.SingBox = cleanVer
				case protocol.KernelSnellServer:
					versions.SnellServer = cleanVer
				case protocol.KernelShadowTLS:
					versions.ShadowTLS = cleanVer
				}
				if err := h.store.UpdateNodeVersions(s.ctx, s.nodeID, versions, node.AgentOS, node.AgentArch, node.CPUCores, node.ReportedConfigRevision); err != nil {
					h.logger.Warn("hub: update node versions after kernel update failed", "node_id", s.nodeID, "err", err)
				}
				h.mu.Lock()
				tel := h.telemetry[s.nodeID]
				tel.NodeID = s.nodeID
				tel.Versions = versions
				h.telemetry[s.nodeID] = tel
				h.mu.Unlock()
			}
			h.notify(s.ctx, webhook.AlertEvent{
				Type:       webhook.EventKernelUpdate,
				Severity:   webhook.SeverityInfo,
				TargetType: webhook.TargetTypeNode,
				TargetID:   s.nodeID,
				TargetName: nodeName,
				Title:      "Kernel Update Succeeded",
				Message:    ev.Message,
				Detail:     ev.Detail,
				Resolved:   true,
				Timestamp:  now,
			})

		case protocol.EventStatusFailed, "update_failed":
			h.notify(s.ctx, webhook.AlertEvent{
				Type:       webhook.EventKernelUpdate,
				Severity:   webhook.SeverityCritical,
				TargetType: webhook.TargetTypeNode,
				TargetID:   s.nodeID,
				TargetName: nodeName,
				Title:      "Kernel Update Failed",
				Message:    ev.Message,
				Detail:     ev.Detail,
				Resolved:   false,
				Timestamp:  now,
			})

		default:
			h.logger.Warn("hub: unknown kernel_update_result status", "node_id", s.nodeID, "status", ev.Status)
		}

	default:
		h.logger.Debug("hub: ignoring unknown agent.event type", "node_id", s.nodeID, "event", ev.Event)
	}
}

func clampUint64ToInt64(v uint64) int64 {
	if v > math.MaxInt64 {
		return math.MaxInt64
	}
	return int64(v)
}

func dedupInt64(in []int64) []int64 {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[int64]struct{}, len(in))
	out := make([]int64, 0, len(in))
	for _, v := range in {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

var reportedVersionRegex = regexp.MustCompile(`(?:^|[\s(])(v?\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?)(?:$|[\s),;])`)

func normalizeReportedVersion(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	firstLine := trimmed
	if idx := strings.IndexByte(firstLine, '\n'); idx >= 0 {
		firstLine = strings.TrimSpace(firstLine[:idx])
	}
	if m := reportedVersionRegex.FindStringSubmatch(firstLine); len(m) >= 2 && m[1] != "" {
		return m[1]
	}
	if m := reportedVersionRegex.FindStringSubmatch(trimmed); len(m) >= 2 && m[1] != "" {
		return m[1]
	}
	return firstLine
}

func normalizeAgentVersions(v protocol.AgentVersions) protocol.AgentVersions {
	return protocol.AgentVersions{
		SnellServer: normalizeReportedVersion(v.SnellServer),
		ShadowTLS:   normalizeReportedVersion(v.ShadowTLS),
		SingBox:     normalizeReportedVersion(v.SingBox),
	}
}
