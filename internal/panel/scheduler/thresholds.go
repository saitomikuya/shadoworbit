package scheduler

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"

	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

// CountedTraffic computes a node's counted cycle traffic according to mode,
// clamping negative inputs to 0 and preventing int64 overflow in "both" mode.
func CountedTraffic(rx, tx int64, mode string) int64 {
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

// EvaluateNodeThreshold evaluates a single node's traffic threshold state machine
// under a per-node mutex, re-reading authoritative state from the store.
func (s *Scheduler) EvaluateNodeThreshold(ctx context.Context, nodeID int64) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if nodeID <= 0 {
		return fmt.Errorf("%w: invalid node id %d", ErrInvalidArgument, nodeID)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	mu := s.nodeLock(nodeID)
	mu.Lock()
	defer mu.Unlock()

	node, err := s.store.GetNodeByID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			s.setNodeWarned(nodeID, false)
		}
		return err
	}
	err = s.evaluateNodeLocked(ctx, node)
	if errors.Is(err, store.ErrNotFound) {
		s.setNodeWarned(nodeID, false)
	}
	return err
}

// SweepNodeThresholds evaluates all nodes' traffic threshold state machines
// and prunes warning state for deleted nodes.
func (s *Scheduler) SweepNodeThresholds(ctx context.Context) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return err
	}

	present := make(map[int64]struct{}, len(nodes))
	for _, n := range nodes {
		present[n.ID] = struct{}{}
	}
	s.pruneNodeWarned(present)

	for _, n := range nodes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		mu := s.nodeLock(n.ID)
		mu.Lock()
		fresh, err := s.store.GetNodeByID(ctx, n.ID)
		if err != nil {
			mu.Unlock()
			if errors.Is(err, store.ErrNotFound) {
				s.setNodeWarned(n.ID, false)
				continue
			}
			return err
		}
		evalErr := s.evaluateNodeLocked(ctx, fresh)
		mu.Unlock()
		if evalErr != nil {
			if errors.Is(evalErr, store.ErrNotFound) {
				s.setNodeWarned(n.ID, false)
				continue
			}
			return evalErr
		}
	}
	return nil
}

func (s *Scheduler) evaluateNodeLocked(ctx context.Context, node *store.Node) error {
	counted := CountedTraffic(node.CycleRxBytes, node.CycleTxBytes, node.TrafficCountMode)
	nowUTC := s.now().UTC()

	// 1. Threshold reached or exceeded -> Pause.
	if node.TrafficThresholdBytes > 0 && counted >= node.TrafficThresholdBytes {
		if !node.IsTrafficPaused {
			reason := fmt.Sprintf("traffic threshold reached (%d / %d bytes, mode=%s)", counted, node.TrafficThresholdBytes, node.TrafficCountMode)
			if err := s.store.SetNodeTrafficPaused(ctx, node.ID, true, reason); err != nil {
				return err
			}
			if _, err := s.store.IncrementNodeConfigRevision(ctx, node.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
				return err
			}
			s.syncNodeIgnoringOffline(ctx, node.ID)
			if s.hub != nil {
				s.hub.BroadcastPublicStatus()
			}
			s.setNodeWarned(node.ID, true)

			if node.Enabled {
				s.notify(ctx, webhook.AlertEvent{
					Type:       webhook.EventTrafficPaused,
					Severity:   webhook.SeverityCritical,
					TargetType: webhook.TargetTypeNode,
					TargetID:   node.ID,
					TargetName: node.Name,
					Title:      fmt.Sprintf("节点流量超限暂停：%s", node.Name),
					Message:    fmt.Sprintf("节点 %s 本周期流量已达熔断阈值（%s / %s），已自动暂停服务", node.Name, webhook.FormatBytes(uint64(counted)), webhook.FormatBytes(uint64(node.TrafficThresholdBytes))),
					Detail:     fmt.Sprintf("执行动作：%s；统计方式：%s", formatThresholdActionCN(node.ThresholdAction), formatTrafficModeCN(node.TrafficCountMode)),
					Resolved:   false,
					Timestamp:  nowUTC,
				})
			}
		} else {
			s.setNodeWarned(node.ID, true)
		}
		return nil
	}

	// 2. Auto-recovery when previously paused and threshold raised/removed or traffic dropped.
	if node.IsTrafficPaused && (node.TrafficThresholdBytes <= 0 || counted < node.TrafficThresholdBytes) {
		if err := s.store.SetNodeTrafficPaused(ctx, node.ID, false, ""); err != nil {
			return err
		}
		online, lastSeen := s.hubConnectionState(node.ID)
		if err := s.store.SetNodeConnectionStatus(ctx, node.ID, online, lastSeen); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		if _, err := s.store.IncrementNodeConfigRevision(ctx, node.ID); err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}
		s.syncNodeIgnoringOffline(ctx, node.ID)
		if s.hub != nil {
			s.hub.BroadcastPublicStatus()
		}
		s.setNodeWarned(node.ID, false)

		s.notify(ctx, webhook.AlertEvent{
			Type:       webhook.EventTrafficRecovered,
			Severity:   webhook.SeverityInfo,
			TargetType: webhook.TargetTypeNode,
			TargetID:   node.ID,
			TargetName: node.Name,
			Title:      fmt.Sprintf("节点流量恢复：%s", node.Name),
			Message:    fmt.Sprintf("节点 %s 本周期流量（%s）已低于熔断阈值（%s），代理服务已自动恢复", node.Name, webhook.FormatBytes(uint64(counted)), webhook.FormatBytes(uint64(node.TrafficThresholdBytes))),
			Resolved:   true,
			Timestamp:  nowUTC,
		})
		return nil
	}

	// 3. Not paused and threshold disabled -> clear warning state.
	if node.TrafficThresholdBytes <= 0 {
		s.setNodeWarned(node.ID, false)
		return nil
	}

	// 4. Check warning threshold percentage.
	warnPct, warnEnabled := s.readWarningThresholdPercent(ctx)
	if !warnEnabled {
		s.setNodeWarned(node.ID, false)
		return nil
	}

	th := uint64(node.TrafficThresholdBytes)
	p := uint64(warnPct)
	warnBytes := int64((th/100)*p + ((th%100)*p)/100)

	if warnBytes > 0 && counted >= warnBytes {
		if node.Enabled && s.claimNodeWarned(node.ID) {
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventTrafficWarning,
				Severity:   webhook.SeverityWarning,
				TargetType: webhook.TargetTypeNode,
				TargetID:   node.ID,
				TargetName: node.Name,
				Title:      fmt.Sprintf("节点流量预警：%s", node.Name),
				Message:    fmt.Sprintf("节点 %s 本周期流量已达到 %d%% 预警阈值（%s / %s）", node.Name, warnPct, webhook.FormatBytes(uint64(counted)), webhook.FormatBytes(uint64(node.TrafficThresholdBytes))),
				Detail:     fmt.Sprintf("统计方式：%s", formatTrafficModeCN(node.TrafficCountMode)),
				Resolved:   false,
				Timestamp:  nowUTC,
			})
		}
	} else {
		s.setNodeWarned(node.ID, false)
	}

	return nil
}

func (s *Scheduler) readWarningThresholdPercent(ctx context.Context) (int, bool) {
	val, err := s.store.GetSettingOrDefault(ctx, settingWarningThresholdPercent, strconv.Itoa(defaultWarningThresholdPercent))
	if err != nil {
		return defaultWarningThresholdPercent, true
	}
	trimmed := strings.TrimSpace(val)
	if trimmed == "" {
		return defaultWarningThresholdPercent, true
	}
	pct, convErr := strconv.Atoi(trimmed)
	if convErr != nil {
		return defaultWarningThresholdPercent, true
	}
	if pct <= 0 || pct >= 100 {
		return 0, false
	}
	return pct, true
}

func (s *Scheduler) setNodeWarned(nodeID int64, warned bool) {
	s.mu.Lock()
	if warned {
		s.nodeWarned[nodeID] = true
	} else {
		delete(s.nodeWarned, nodeID)
	}
	s.mu.Unlock()
}

func (s *Scheduler) claimNodeWarned(nodeID int64) bool {
	s.mu.Lock()
	already := s.nodeWarned[nodeID]
	s.nodeWarned[nodeID] = true
	s.mu.Unlock()
	return !already
}

func (s *Scheduler) pruneNodeWarned(present map[int64]struct{}) {
	s.mu.Lock()
	for id := range s.nodeWarned {
		if _, ok := present[id]; !ok {
			delete(s.nodeWarned, id)
		}
	}
	s.mu.Unlock()
}

func formatThresholdActionCN(action string) string {
	switch action {
	case protocol.ThresholdActionStopSSOnly:
		return "仅停止 SS2022（保留管理员 Snell）"
	default:
		return "停止全部代理（Snell + SS2022）"
	}
}

func formatTrafficModeCN(mode string) string {
	switch mode {
	case protocol.TrafficCountTxOnly:
		return "仅统计上传"
	case protocol.TrafficCountRxOnly:
		return "仅统计下载"
	case protocol.TrafficCountMaxDir:
		return "取单向最大值"
	default:
		return "双向合计（上传+下载）"
	}
}
