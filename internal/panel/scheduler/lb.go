package scheduler

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"snell-panel/internal/panel/dnsprovider"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

// System settings keys for Huawei Cloud International DNS.
const (
	SettingHuaweiCloudDNSEndpoint = "huaweicloud_dns_endpoint"
	SettingHuaweiCloudDNSAK       = "huaweicloud_dns_ak"
	SettingHuaweiCloudDNSSK       = "huaweicloud_dns_sk"
)

// LBEvalOptions configures one LB group DNS evaluation pass.
type LBEvalOptions struct {
	ForceSync bool
	Trigger   string
}

// NodeEffectiveBudget returns the effective traffic budget for DNS load balancing:
// traffic_threshold_bytes takes precedence when > 0, otherwise traffic_limit_bytes.
func NodeEffectiveBudget(n *store.Node) int64 {
	if n == nil {
		return 0
	}
	if n.TrafficThresholdBytes > 0 {
		return n.TrafficThresholdBytes
	}
	if n.TrafficLimitBytes > 0 {
		return n.TrafficLimitBytes
	}
	return 0
}

// NodeRemainingTraffic computes remaining traffic bytes for n under its effective budget.
func NodeRemainingTraffic(n *store.Node) (remaining int64, hasBudget bool, used int64, budget int64) {
	if n == nil {
		return 0, false, 0, 0
	}
	used = CountedTraffic(n.CycleRxBytes, n.CycleTxBytes, n.TrafficCountMode)
	budget = NodeEffectiveBudget(n)
	if budget <= 0 {
		return 0, false, used, 0
	}
	rem := budget - used
	if rem < 0 {
		rem = 0
	}
	return rem, true, used, budget
}

// NewHuaweiCloudDNSProvider builds a Huawei Cloud DNS provider using overrides or saved system settings.
func (s *Scheduler) NewHuaweiCloudDNSProvider(ctx context.Context, endpointOverride, akOverride, skOverride string) (dnsprovider.Provider, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	endpoint := strings.TrimSpace(endpointOverride)
	if endpoint == "" {
		var err error
		endpoint, err = s.store.GetSettingOrDefault(ctx, SettingHuaweiCloudDNSEndpoint, dnsprovider.DefaultHuaweiCloudEndpoint)
		if err != nil {
			return nil, err
		}
		endpoint = strings.TrimSpace(endpoint)
		if endpoint == "" {
			endpoint = dnsprovider.DefaultHuaweiCloudEndpoint
		}
	}

	ak := strings.TrimSpace(akOverride)
	if ak == "" {
		var err error
		ak, err = s.store.GetSettingOrDefault(ctx, SettingHuaweiCloudDNSAK, "")
		if err != nil {
			return nil, err
		}
		ak = strings.TrimSpace(ak)
	}

	sk := strings.TrimSpace(skOverride)
	if sk == "" {
		var err error
		sk, err = s.store.GetSettingOrDefault(ctx, SettingHuaweiCloudDNSSK, "")
		if err != nil {
			return nil, err
		}
		sk = strings.TrimSpace(sk)
	}

	if ak == "" || sk == "" {
		return nil, errors.New("未配置华为云国际版 DNS AK/SK")
	}

	if s.dnsProviderFactory != nil {
		return s.dnsProviderFactory(endpoint, ak, sk)
	}
	return dnsprovider.NewHuaweiCloudClient(endpoint, ak, sk, dnsprovider.WithHTTPClient(s.httpClient))
}

// SweepLBGroups evaluates all enabled DNS load-balancing groups.
func (s *Scheduler) SweepLBGroups(ctx context.Context) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	groups, err := s.store.ListLBGroups(ctx)
	if err != nil {
		return err
	}
	for _, g := range groups {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if !g.Enabled {
			continue
		}
		if _, err := s.EvaluateLBGroup(ctx, g.ID, LBEvalOptions{Trigger: "sweep"}); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("scheduler: evaluate lb group failed", "group_id", g.ID, "err", err)
		}
	}
	return nil
}

// EvaluateLBGroupForNode evaluates the LB group containing nodeID (if any).
func (s *Scheduler) EvaluateLBGroupForNode(ctx context.Context, nodeID int64) error {
	if s.store == nil || nodeID <= 0 {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	grp, err := s.store.GetLBGroupByNodeID(ctx, nodeID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		return err
	}
	if !grp.Enabled {
		return nil
	}
	_, err = s.EvaluateLBGroup(ctx, grp.ID, LBEvalOptions{Trigger: "node_event"})
	if errors.Is(err, store.ErrNotFound) {
		return nil
	}
	return err
}

type lbMemberState struct {
	node      store.Node
	priority  int
	ipv4      string
	online    bool
	healthy   bool
	hasBudget bool
	remaining int64
	used      int64
	budget    int64
}

func (s *Scheduler) hydrateMemberState(g *store.LBGroup, n store.Node, priority int) lbMemberState {
	online := n.Status == protocol.NodeStatusOnline
	if s.hub != nil {
		online = s.hub.IsOnline(n.ID)
		if online {
			if tel, ok := s.hub.GetTelemetry(n.ID); ok {
				n.CoreAHealthy = tel.Health.Snell && tel.Health.ShadowTLS
				n.CoreBHealthy = tel.Health.SingBox
				if tel.PublicIPv4 != "" {
					n.PublicIP = tel.PublicIPv4
				}
			}
		}
	}

	ipv4 := strings.TrimSpace(n.PublicIP)
	parsedIP := net.ParseIP(ipv4)
	validIPv4 := parsedIP != nil && parsedIP.To4() != nil

	pausedBlocked := n.IsTrafficPaused && !(n.ThresholdAction == protocol.ThresholdActionStopSSOnly && !g.SSConfig.Enabled && g.SnellConfig.Enabled)
	coresHealthy := true
	if g.SnellConfig.Enabled && !n.CoreAHealthy {
		coresHealthy = false
	}
	if g.SSConfig.Enabled && !n.CoreBHealthy {
		coresHealthy = false
	}

	rem, hasBudget, used, budget := NodeRemainingTraffic(&n)
	healthy := n.Enabled && online && validIPv4 && !pausedBlocked && coresHealthy

	return lbMemberState{
		node:      n,
		priority:  priority,
		ipv4:      ipv4,
		online:    online,
		healthy:   healthy,
		hasBudget: hasBudget,
		remaining: rem,
		used:      used,
		budget:    budget,
	}
}

// EvaluateLBGroup runs the DNS load-balancing decision & synchronization pass for groupID.
func (s *Scheduler) EvaluateLBGroup(ctx context.Context, groupID int64, opts LBEvalOptions) (*store.LBGroup, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if groupID <= 0 {
		return nil, fmt.Errorf("%w: invalid lb group id %d", ErrInvalidArgument, groupID)
	}
	if ctx == nil {
		ctx = context.Background()
	}

	mu := s.groupLock(groupID)
	mu.Lock()
	defer mu.Unlock()

	g, err := s.store.GetLBGroupByID(ctx, groupID)
	if err != nil {
		return nil, err
	}
	if !g.Enabled && !opts.ForceSync {
		return g, nil
	}

	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	nodeByID := make(map[int64]store.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}

	members := make([]lbMemberState, 0, len(g.Members))
	memberByID := make(map[int64]lbMemberState, len(g.Members))
	healthy := make([]lbMemberState, 0, len(g.Members))
	for _, m := range g.Members {
		n, ok := nodeByID[m.NodeID]
		if !ok {
			continue
		}
		st := s.hydrateMemberState(g, n, m.Priority)
		members = append(members, st)
		memberByID[n.ID] = st
		if st.healthy {
			healthy = append(healthy, st)
		}
	}

	nowUTC := s.now().UTC()
	prevIPs := formatActiveIPs(g.ActiveRecords)
	prevActiveID := g.ActiveNodeID

	// Handle manual pin override first.
	if g.PinnedNodeID != nil {
		pinned, ok := memberByID[*g.PinnedNodeID]
		if !ok {
			return s.recordLBError(ctx, g, "锁定的成员节点不存在", opts.ForceSync)
		}
		if parsed := net.ParseIP(pinned.ipv4); parsed == nil || parsed.To4() == nil {
			return s.recordLBError(ctx, g, fmt.Sprintf("锁定节点 %s 无有效 IPv4 公网地址", pinned.node.Name), opts.ForceSync)
		}

		alreadySynced := !opts.ForceSync &&
			g.LastSyncError == "" &&
			!g.IsExhausted &&
			g.ActiveNodeID != nil && *g.ActiveNodeID == pinned.node.ID &&
			len(g.ActiveRecords) == 1 &&
			g.ActiveRecords[0].IP == pinned.ipv4
		if alreadySynced {
			return g, nil
		}

		desired := []dnsprovider.DesiredRecord{{IP: pinned.ipv4}}
		synced, syncErr := s.syncGroupDNS(ctx, g, false, desired)
		if syncErr != nil {
			return s.recordLBError(ctx, g, syncErr.Error(), opts.ForceSync)
		}

		toID := pinned.node.ID
		activeRecs := []store.LBActiveRecord{{
			NodeID:      pinned.node.ID,
			NodeName:    pinned.node.Name,
			IP:          pinned.ipv4,
			RecordSetID: synced[0].RecordSetID,
		}}
		toIPs := formatActiveIPs(activeRecs)
		switched := prevActiveID == nil || *prevActiveID != toID || prevIPs != toIPs

		lastSwitch := g.LastSwitchAt
		if switched {
			lastSwitch = &nowUTC
			_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
				GroupID:    g.ID,
				EventType:  "manual_pin",
				FromNodeID: prevActiveID,
				ToNodeID:   &toID,
				FromIPs:    prevIPs,
				ToIPs:      toIPs,
				Reason:     fmt.Sprintf("手动锁定解析到节点 %s (%s)", pinned.node.Name, pinned.ipv4),
				CreatedAt:  nowUTC,
			})
		}

		if g.IsExhausted {
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventDNSLBExhausted,
				Severity:   webhook.SeverityInfo,
				TargetType: webhook.TargetTypeLBGroup,
				TargetID:   g.ID,
				TargetName: g.Name,
				Title:      fmt.Sprintf("负载均衡分组恢复可用：%s", g.Name),
				Message:    fmt.Sprintf("分组 %s (%s) 已手动锁定并恢复解析至 %s (%s)", g.Name, g.DNSDomain, pinned.node.Name, pinned.ipv4),
				Resolved:   true,
				Timestamp:  nowUTC,
			})
		}

		if err := s.store.UpdateLBGroupSyncState(ctx, g.ID, store.LBGroupSyncState{
			ActiveNodeID:  &toID,
			ActiveRecords: activeRecs,
			LastSwitchAt:  lastSwitch,
			LastSyncAt:    &nowUTC,
			LastSyncError: "",
			IsExhausted:   false,
		}); err != nil {
			return nil, err
		}
		return s.store.GetLBGroupByID(ctx, g.ID)
	}

	// No healthy nodes available -> mark exhausted, keep existing DNS records, alert once on transition.
	if len(healthy) == 0 {
		reason := "分组内暂无健康可用节点"
		if len(members) == 0 {
			reason = "分组内未配置成员节点"
		}
		if !g.IsExhausted {
			_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
				GroupID:    g.ID,
				EventType:  "exhausted",
				FromNodeID: prevActiveID,
				FromIPs:    prevIPs,
				ToIPs:      prevIPs,
				Reason:     reason,
				CreatedAt:  nowUTC,
			})
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventDNSLBExhausted,
				Severity:   webhook.SeverityCritical,
				TargetType: webhook.TargetTypeLBGroup,
				TargetID:   g.ID,
				TargetName: g.Name,
				Title:      fmt.Sprintf("负载均衡分组全部不可用：%s", g.Name),
				Message:    fmt.Sprintf("分组 %s (%s) 内无可用健康节点（已保留原 DNS 解析记录）", g.Name, g.DNSDomain),
				Detail:     reason,
				Resolved:   false,
				Timestamp:  nowUTC,
			})
			if err := s.store.UpdateLBGroupSyncState(ctx, g.ID, store.LBGroupSyncState{
				ActiveNodeID:  g.ActiveNodeID,
				ActiveRecords: g.ActiveRecords,
				LastSwitchAt:  g.LastSwitchAt,
				LastSyncAt:    g.LastSyncAt,
				LastSyncError: reason,
				IsExhausted:   true,
			}); err != nil {
				return nil, err
			}
		} else if opts.ForceSync && g.LastSyncError != reason {
			if err := s.store.UpdateLBGroupSyncState(ctx, g.ID, store.LBGroupSyncState{
				ActiveNodeID:  g.ActiveNodeID,
				ActiveRecords: g.ActiveRecords,
				LastSwitchAt:  g.LastSwitchAt,
				LastSyncAt:    g.LastSyncAt,
				LastSyncError: reason,
				IsExhausted:   true,
			}); err != nil {
				return nil, err
			}
		}
		updated, err := s.store.GetLBGroupByID(ctx, g.ID)
		if err != nil {
			return nil, err
		}
		if opts.ForceSync {
			return updated, errors.New(reason)
		}
		return updated, nil
	}

	wasExhausted := g.IsExhausted
	if g.Strategy == protocol.LBStrategyWeightedMulti {
		return s.evaluateWeightedMulti(ctx, g, healthy, memberByID, wasExhausted, prevActiveID, prevIPs, nowUTC, opts)
	}

	// Single-IP strategies: remaining_balance or failover.
	var target lbMemberState
	var isFailover bool
	var reason string

	switch g.Strategy {
	case protocol.LBStrategyFailover:
		target, isFailover, reason = pickFailoverTarget(g, healthy, memberByID, prevActiveID)
	default:
		target, isFailover, reason = pickRemainingBalanceTarget(g, healthy, memberByID, prevActiveID, nowUTC)
	}

	alreadySynced := !opts.ForceSync &&
		g.LastSyncError == "" &&
		!wasExhausted &&
		g.ActiveNodeID != nil && *g.ActiveNodeID == target.node.ID &&
		len(g.ActiveRecords) == 1 &&
		g.ActiveRecords[0].IP == target.ipv4
	if alreadySynced {
		return g, nil
	}

	synced, syncErr := s.syncGroupDNS(ctx, g, false, []dnsprovider.DesiredRecord{{IP: target.ipv4}})
	if syncErr != nil {
		return s.recordLBError(ctx, g, syncErr.Error(), opts.ForceSync)
	}

	toID := target.node.ID
	activeRecs := []store.LBActiveRecord{{
		NodeID:      target.node.ID,
		NodeName:    target.node.Name,
		IP:          target.ipv4,
		RecordSetID: synced[0].RecordSetID,
	}}
	toIPs := formatActiveIPs(activeRecs)
	switched := prevActiveID == nil || *prevActiveID != toID || prevIPs != toIPs

	lastSwitch := g.LastSwitchAt
	if switched {
		lastSwitch = &nowUTC
		eventType := "balance_switch"
		if isFailover {
			eventType = "failover"
		}
		if prevActiveID == nil && !isFailover {
			reason = fmt.Sprintf("初始化 DNS 解析指向 %s (%s)", target.node.Name, target.ipv4)
		}
		_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
			GroupID:    g.ID,
			EventType:  eventType,
			FromNodeID: prevActiveID,
			ToNodeID:   &toID,
			FromIPs:    prevIPs,
			ToIPs:      toIPs,
			Reason:     reason,
			CreatedAt:  nowUTC,
		})

		if isFailover && prevActiveID != nil {
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventDNSLBFailover,
				Severity:   webhook.SeverityWarning,
				TargetType: webhook.TargetTypeLBGroup,
				TargetID:   g.ID,
				TargetName: g.Name,
				Title:      fmt.Sprintf("DNS 故障转移：%s → %s", g.Name, target.node.Name),
				Message:    fmt.Sprintf("分组 %s (%s) 已故障转移至 %s (%s)", g.Name, g.DNSDomain, target.node.Name, target.ipv4),
				Detail:     reason,
				Resolved:   false,
				Timestamp:  nowUTC,
			})
		} else if prevActiveID != nil && *prevActiveID != toID {
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventDNSLBSwitched,
				Severity:   webhook.SeverityInfo,
				TargetType: webhook.TargetTypeLBGroup,
				TargetID:   g.ID,
				TargetName: g.Name,
				Title:      fmt.Sprintf("DNS 负载均衡切换：%s → %s", g.Name, target.node.Name),
				Message:    fmt.Sprintf("分组 %s (%s) 已自动切换至 %s (%s)", g.Name, g.DNSDomain, target.node.Name, target.ipv4),
				Detail:     reason,
				Resolved:   true,
				Timestamp:  nowUTC,
			})
		}
	}

	if wasExhausted {
		_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
			GroupID:   g.ID,
			EventType: "recovered",
			ToNodeID:  &toID,
			FromIPs:   prevIPs,
			ToIPs:     toIPs,
			Reason:    fmt.Sprintf("分组恢复可用，已解析至 %s (%s)", target.node.Name, target.ipv4),
			CreatedAt: nowUTC,
		})
		s.notify(ctx, webhook.AlertEvent{
			Type:       webhook.EventDNSLBExhausted,
			Severity:   webhook.SeverityInfo,
			TargetType: webhook.TargetTypeLBGroup,
			TargetID:   g.ID,
			TargetName: g.Name,
			Title:      fmt.Sprintf("负载均衡分组恢复可用：%s", g.Name),
			Message:    fmt.Sprintf("分组 %s (%s) 已有健康节点，已恢复解析至 %s (%s)", g.Name, g.DNSDomain, target.node.Name, target.ipv4),
			Resolved:   true,
			Timestamp:  nowUTC,
		})
	}

	if err := s.store.UpdateLBGroupSyncState(ctx, g.ID, store.LBGroupSyncState{
		ActiveNodeID:  &toID,
		ActiveRecords: activeRecs,
		LastSwitchAt:  lastSwitch,
		LastSyncAt:    &nowUTC,
		LastSyncError: "",
		IsExhausted:   false,
	}); err != nil {
		return nil, err
	}
	return s.store.GetLBGroupByID(ctx, g.ID)
}

func (s *Scheduler) evaluateWeightedMulti(
	ctx context.Context,
	g *store.LBGroup,
	healthy []lbMemberState,
	memberByID map[int64]lbMemberState,
	wasExhausted bool,
	prevActiveID *int64,
	prevIPs string,
	nowUTC time.Time,
	opts LBEvalOptions,
) (*store.LBGroup, error) {
	eligible := make([]lbMemberState, 0, len(healthy))
	for _, st := range healthy {
		if !st.hasBudget || st.remaining > 0 {
			eligible = append(eligible, st)
		}
	}
	if len(eligible) == 0 {
		eligible = healthy
	}

	weights := computeProportionalWeights(eligible)
	desired := make([]dnsprovider.DesiredRecord, 0, len(eligible))
	for i, st := range eligible {
		desired = append(desired, dnsprovider.DesiredRecord{
			IP:     st.ipv4,
			Weight: weights[i],
		})
	}

	needsSync := opts.ForceSync || g.LastSyncError != "" || wasExhausted || len(g.ActiveRecords) != len(desired)
	prevMap := make(map[string]int, len(g.ActiveRecords))
	for _, r := range g.ActiveRecords {
		prevMap[r.IP] = r.Weight
	}
	ipRemoved := false
	for ip := range prevMap {
		found := false
		for _, d := range desired {
			if d.IP == ip {
				found = true
				break
			}
		}
		if !found {
			ipRemoved = true
			needsSync = true
		}
	}
	if !needsSync {
		for _, d := range desired {
			prevW, ok := prevMap[d.IP]
			if !ok {
				needsSync = true
				break
			}
			diff := prevW - d.Weight
			if diff < 0 {
				diff = -diff
			}
			if diff >= 5 {
				needsSync = true
				break
			}
		}
	}

	if !needsSync {
		return g, nil
	}

	synced, syncErr := s.syncGroupDNS(ctx, g, true, desired)
	if syncErr != nil {
		return s.recordLBError(ctx, g, syncErr.Error(), opts.ForceSync)
	}

	activeRecs := make([]store.LBActiveRecord, 0, len(eligible))
	for i, st := range eligible {
		rsID := ""
		if i < len(synced) {
			rsID = synced[i].RecordSetID
		}
		activeRecs = append(activeRecs, store.LBActiveRecord{
			NodeID:      st.node.ID,
			NodeName:    st.node.Name,
			IP:          st.ipv4,
			Weight:      weights[i],
			RecordSetID: rsID,
		})
	}
	toIPs := formatActiveIPs(activeRecs)
	primaryID := eligible[0].node.ID
	lastSwitch := g.LastSwitchAt

	if prevIPs != toIPs {
		lastSwitch = &nowUTC
		eventType := "weight_update"
		reason := fmt.Sprintf("更新多 IP 权重解析：%s", toIPs)
		if ipRemoved {
			eventType = "failover"
			reason = fmt.Sprintf("剔除不可用节点并更新权重解析：%s", toIPs)
		}
		_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
			GroupID:    g.ID,
			EventType:  eventType,
			FromNodeID: prevActiveID,
			ToNodeID:   &primaryID,
			FromIPs:    prevIPs,
			ToIPs:      toIPs,
			Reason:     reason,
			CreatedAt:  nowUTC,
		})
		if ipRemoved {
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventDNSLBFailover,
				Severity:   webhook.SeverityWarning,
				TargetType: webhook.TargetTypeLBGroup,
				TargetID:   g.ID,
				TargetName: g.Name,
				Title:      fmt.Sprintf("DNS 多 IP 节点剔除：%s", g.Name),
				Message:    fmt.Sprintf("分组 %s (%s) 已剔除不可用节点，当前解析：%s", g.Name, g.DNSDomain, toIPs),
				Resolved:   false,
				Timestamp:  nowUTC,
			})
		} else if len(g.ActiveRecords) > 0 {
			s.notify(ctx, webhook.AlertEvent{
				Type:       webhook.EventDNSLBSwitched,
				Severity:   webhook.SeverityInfo,
				TargetType: webhook.TargetTypeLBGroup,
				TargetID:   g.ID,
				TargetName: g.Name,
				Title:      fmt.Sprintf("DNS 权重解析调整：%s", g.Name),
				Message:    fmt.Sprintf("分组 %s (%s) 已调整各节点解析权重：%s", g.Name, g.DNSDomain, toIPs),
				Resolved:   true,
				Timestamp:  nowUTC,
			})
		}
	}

	if wasExhausted {
		_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
			GroupID:   g.ID,
			EventType: "recovered",
			ToNodeID:  &primaryID,
			FromIPs:   prevIPs,
			ToIPs:     toIPs,
			Reason:    fmt.Sprintf("分组恢复可用，当前权重解析：%s", toIPs),
			CreatedAt: nowUTC,
		})
		s.notify(ctx, webhook.AlertEvent{
			Type:       webhook.EventDNSLBExhausted,
			Severity:   webhook.SeverityInfo,
			TargetType: webhook.TargetTypeLBGroup,
			TargetID:   g.ID,
			TargetName: g.Name,
			Title:      fmt.Sprintf("负载均衡分组恢复可用：%s", g.Name),
			Message:    fmt.Sprintf("分组 %s (%s) 已有健康节点，当前解析：%s", g.Name, g.DNSDomain, toIPs),
			Resolved:   true,
			Timestamp:  nowUTC,
		})
	}

	if err := s.store.UpdateLBGroupSyncState(ctx, g.ID, store.LBGroupSyncState{
		ActiveNodeID:  &primaryID,
		ActiveRecords: activeRecs,
		LastSwitchAt:  lastSwitch,
		LastSyncAt:    &nowUTC,
		LastSyncError: "",
		IsExhausted:   false,
	}); err != nil {
		return nil, err
	}
	return s.store.GetLBGroupByID(ctx, g.ID)
}

func pickRemainingBalanceTarget(
	g *store.LBGroup,
	healthy []lbMemberState,
	memberByID map[int64]lbMemberState,
	prevActiveID *int64,
	nowUTC time.Time,
) (lbMemberState, bool, string) {
	best := healthy[0]
	for _, cand := range healthy[1:] {
		if compareRemainingBetter(cand, best) {
			best = cand
		}
	}

	if prevActiveID == nil {
		return best, false, fmt.Sprintf("选择剩余可用流量最多节点 %s", best.node.Name)
	}
	cur, exists := memberByID[*prevActiveID]
	if !exists || !cur.healthy {
		prevName := fmt.Sprintf("#%d", *prevActiveID)
		if exists {
			prevName = cur.node.Name
		}
		return best, true, fmt.Sprintf("原节点 %s 不可用，故障转移至 %s", prevName, best.node.Name)
	}
	if cur.hasBudget && cur.remaining <= 0 && (!best.hasBudget || best.remaining > 0) {
		return best, true, fmt.Sprintf("原节点 %s 可用流量耗尽，立即切换至 %s", cur.node.Name, best.node.Name)
	}
	if best.node.ID == cur.node.ID {
		return cur, false, ""
	}

	// Evaluate anti-flap lead diff and cooldown.
	leadSatisfied := false
	if !best.hasBudget && cur.hasBudget {
		leadSatisfied = true
	} else if best.hasBudget && cur.hasBudget && best.remaining-cur.remaining >= g.SwitchDiffBytes {
		leadSatisfied = true
	}
	if !leadSatisfied {
		return cur, false, ""
	}

	cooldown := time.Duration(g.SwitchCooldownMinutes) * time.Minute
	if cooldown > 0 && g.LastSwitchAt != nil && nowUTC.Sub(*g.LastSwitchAt) < cooldown {
		return cur, false, ""
	}

	return best, false, fmt.Sprintf(
		"节点 %s 剩余流量 (%s) 领先当前节点 %s (%s) 超过防抖差值",
		best.node.Name, formatRemainingText(best), cur.node.Name, formatRemainingText(cur),
	)
}

func pickFailoverTarget(
	g *store.LBGroup,
	healthy []lbMemberState,
	memberByID map[int64]lbMemberState,
	prevActiveID *int64,
) (lbMemberState, bool, string) {
	pct := int64(g.FailoverThresholdPercent)
	if pct <= 0 || pct > 100 {
		pct = 90
	}
	var chosen *lbMemberState
	for i := range healthy {
		st := &healthy[i]
		if !st.hasBudget || !isOverFailoverThreshold(st.used, st.budget, pct) {
			chosen = st
			break
		}
	}
	if chosen == nil {
		best := healthy[0]
		for _, cand := range healthy[1:] {
			if compareRemainingBetter(cand, best) {
				best = cand
			}
		}
		chosen = &best
	}

	if prevActiveID == nil || *prevActiveID == chosen.node.ID {
		return *chosen, false, fmt.Sprintf("主备策略选择节点 %s", chosen.node.Name)
	}
	cur, exists := memberByID[*prevActiveID]
	if !exists || !cur.healthy {
		prevName := fmt.Sprintf("#%d", *prevActiveID)
		if exists {
			prevName = cur.node.Name
		}
		return *chosen, true, fmt.Sprintf("主节点 %s 不可用，故障转移至备节点 %s", prevName, chosen.node.Name)
	}
	if cur.hasBudget && isOverFailoverThreshold(cur.used, cur.budget, pct) {
		return *chosen, true, fmt.Sprintf("节点 %s 已用流量达到 %d%% 切换阈值，切往 %s", cur.node.Name, pct, chosen.node.Name)
	}
	return *chosen, false, fmt.Sprintf("主备优先级恢复，切回节点 %s", chosen.node.Name)
}

func isOverFailoverThreshold(used, budget, pct int64) bool {
	if budget <= 0 {
		return false
	}
	threshold := (budget / 100) * pct + ((budget % 100) * pct) / 100
	return used >= threshold
}

func compareRemainingBetter(a, b lbMemberState) bool {
	if !a.hasBudget && b.hasBudget {
		return true
	}
	if a.hasBudget && !b.hasBudget {
		return false
	}
	if a.hasBudget && b.hasBudget && a.remaining != b.remaining {
		return a.remaining > b.remaining
	}
	if a.used != b.used {
		return a.used < b.used
	}
	if a.priority != b.priority {
		return a.priority < b.priority
	}
	return a.node.ID < b.node.ID
}

func computeProportionalWeights(eligible []lbMemberState) []int {
	scores := make([]int64, len(eligible))
	var maxRem int64
	for _, st := range eligible {
		if st.hasBudget && st.remaining > maxRem {
			maxRem = st.remaining
		}
	}
	if maxRem <= 0 {
		maxRem = 100 << 30
	}
	var total int64
	for i, st := range eligible {
		val := maxRem
		if st.hasBudget {
			val = st.remaining
		}
		if val <= 0 {
			val = 1
		}
		scores[i] = val
		total += val
	}
	weights := make([]int, len(eligible))
	for i, sc := range scores {
		w := int((sc * 100) / total)
		if w < 1 {
			w = 1
		}
		if w > 100 {
			w = 100
		}
		weights[i] = w
	}
	return weights
}

func (s *Scheduler) syncGroupDNS(
	ctx context.Context,
	g *store.LBGroup,
	weighted bool,
	desired []dnsprovider.DesiredRecord,
) ([]dnsprovider.SyncedRecord, error) {
	if strings.TrimSpace(g.DNSZoneID) == "" {
		return nil, errors.New("未选择华为云 DNS Zone")
	}
	prov, err := s.NewHuaweiCloudDNSProvider(ctx, "", "", "")
	if err != nil {
		return nil, err
	}
	return prov.SyncARecords(ctx, g.DNSZoneID, g.DNSDomain, g.DNSTTL, weighted, desired)
}

func (s *Scheduler) recordLBError(ctx context.Context, g *store.LBGroup, errMsg string, forceReturn bool) (*store.LBGroup, error) {
	nowUTC := s.now().UTC()
	if g.LastSyncError != errMsg || forceReturn {
		_ = s.store.AppendLBSwitchLog(ctx, &store.LBSwitchLog{
			GroupID:    g.ID,
			EventType:  "sync_error",
			FromNodeID: g.ActiveNodeID,
			FromIPs:    formatActiveIPs(g.ActiveRecords),
			ToIPs:      formatActiveIPs(g.ActiveRecords),
			Reason:     errMsg,
			CreatedAt:  nowUTC,
		})
	}
	if err := s.store.UpdateLBGroupSyncState(ctx, g.ID, store.LBGroupSyncState{
		ActiveNodeID:  g.ActiveNodeID,
		ActiveRecords: g.ActiveRecords,
		LastSwitchAt:  g.LastSwitchAt,
		LastSyncAt:    g.LastSyncAt,
		LastSyncError: errMsg,
		IsExhausted:   g.IsExhausted,
	}); err != nil {
		return nil, err
	}
	updated, err := s.store.GetLBGroupByID(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	if forceReturn {
		return updated, errors.New(errMsg)
	}
	return updated, nil
}

func formatActiveIPs(records []store.LBActiveRecord) string {
	if len(records) == 0 {
		return ""
	}
	parts := make([]string, 0, len(records))
	for _, r := range records {
		if r.Weight > 0 {
			parts = append(parts, fmt.Sprintf("%s(w=%d)", r.IP, r.Weight))
		} else {
			parts = append(parts, r.IP)
		}
	}
	return strings.Join(parts, ", ")
}

func formatRemainingText(st lbMemberState) string {
	if !st.hasBudget {
		return "无限制"
	}
	return webhook.FormatBytes(uint64(st.remaining))
}
