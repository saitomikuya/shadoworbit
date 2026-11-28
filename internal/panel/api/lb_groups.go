package api

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/dnsprovider"
	"snell-panel/internal/panel/scheduler"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

type lbGroupMemberViewDTO struct {
	NodeID                int64  `json:"node_id"`
	Priority              int    `json:"priority"`
	NodeName              string `json:"node_name"`
	RegionTag             string `json:"region_tag"`
	Enabled               bool   `json:"enabled"`
	Online                bool   `json:"online"`
	Status                string `json:"status"`
	PublicIP              string `json:"public_ip"`
	CoreAHealthy          bool   `json:"core_a_healthy"`
	CoreBHealthy          bool   `json:"core_b_healthy"`
	IsTrafficPaused       bool   `json:"is_traffic_paused"`
	CountedBytes          int64  `json:"counted_bytes"`
	BudgetBytes           int64  `json:"budget_bytes"`
	RemainingBytes        int64  `json:"remaining_bytes"`
	TrafficLimitBytes     int64  `json:"traffic_limit_bytes"`
	TrafficThresholdBytes int64  `json:"traffic_threshold_bytes"`
	TrafficCountMode      string `json:"traffic_count_mode"`
}

type lbGroupDTO struct {
	ID                       int64                  `json:"id"`
	Name                     string                 `json:"name"`
	RegionTag                string                 `json:"region_tag"`
	Enabled                  bool                   `json:"enabled"`
	SortOrder                int                    `json:"sort_order"`
	DNSZoneID                string                 `json:"dns_zone_id"`
	DNSZoneName              string                 `json:"dns_zone_name"`
	DNSDomain                string                 `json:"dns_domain"`
	DNSTTL                   int                    `json:"dns_ttl"`
	Strategy                 string                 `json:"strategy"`
	SwitchDiffBytes          int64                  `json:"switch_diff_bytes"`
	SwitchCooldownMinutes    int                    `json:"switch_cooldown_minutes"`
	FailoverThresholdPercent int                    `json:"failover_threshold_percent"`
	SnellConfig              protocol.SnellConfig   `json:"snell_config"`
	SSConfig                 protocol.SSConfig      `json:"ss_config"`
	PinnedNodeID             *int64                 `json:"pinned_node_id"`
	ActiveNodeID             *int64                 `json:"active_node_id"`
	ActiveNodeName           string                 `json:"active_node_name"`
	ActiveRecords            []store.LBActiveRecord `json:"active_records"`
	LastSwitchAt             *time.Time             `json:"last_switch_at"`
	LastSyncAt               *time.Time             `json:"last_sync_at"`
	LastSyncError            string                 `json:"last_sync_error"`
	IsExhausted              bool                   `json:"is_exhausted"`
	MemberNodeIDs            []int64                `json:"member_node_ids"`
	Members                  []lbGroupMemberViewDTO `json:"members"`
	CreatedAt                time.Time              `json:"created_at"`
	UpdatedAt                time.Time              `json:"updated_at"`
}

type lbGroupUpsertRequest struct {
	Name                     string               `json:"name"`
	RegionTag                string               `json:"region_tag"`
	Enabled                  *bool                `json:"enabled"`
	SortOrder                int                  `json:"sort_order"`
	DNSZoneID                string               `json:"dns_zone_id"`
	DNSZoneName              string               `json:"dns_zone_name"`
	DNSDomain                string               `json:"dns_domain"`
	DNSTTL                   int                  `json:"dns_ttl"`
	Strategy                 string               `json:"strategy"`
	SwitchDiffBytes          *int64               `json:"switch_diff_bytes"`
	SwitchCooldownMinutes    *int                 `json:"switch_cooldown_minutes"`
	FailoverThresholdPercent *int                 `json:"failover_threshold_percent"`
	SnellConfig              protocol.SnellConfig `json:"snell_config"`
	SSConfig                 protocol.SSConfig    `json:"ss_config"`
	MemberNodeIDs            []int64              `json:"member_node_ids"`
}

type lbGroupPinRequest struct {
	NodeID *int64 `json:"node_id"`
}

type huaweiCloudTestRequest struct {
	Endpoint string `json:"endpoint"`
	AK       string `json:"ak"`
	SK       string `json:"sk"`
}

func (s *server) handleTestHuaweiCloudDNS(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req huaweiCloudTestRequest
	if err := decodeOptionalJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	prov, err := s.sched.NewHuaweiCloudDNSProvider(r.Context(), req.Endpoint, req.AK, req.SK)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	zones, err := prov.ListPublicZones(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if zones == nil {
		zones = []dnsprovider.Zone{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":          true,
		"zones_count": len(zones),
		"zones":       zones,
	})
}

func (s *server) handleListHuaweiCloudZones(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	prov, err := s.sched.NewHuaweiCloudDNSProvider(r.Context(), "", "", "")
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	zones, err := prov.ListPublicZones(r.Context())
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if zones == nil {
		zones = []dnsprovider.Zone{}
	}
	writeJSON(w, http.StatusOK, zones)
}

func (s *server) handleListLBGroups(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	groups, err := s.store.ListLBGroups(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list lb groups")
		return
	}
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load nodes")
		return
	}
	nodeByID := make(map[int64]store.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}

	out := make([]lbGroupDTO, 0, len(groups))
	for _, g := range groups {
		out = append(out, s.buildLBGroupDTO(g, nodeByID))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleGetLBGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lb group id")
		return
	}
	grp, err := s.store.GetLBGroupByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lb group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get lb group")
		return
	}
	dto, err := s.hydrateSingleLBGroupDTO(r.Context(), *grp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hydrate lb group")
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (s *server) handleCreateLBGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req lbGroupUpsertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	grp, memberIDs, err := parseAndValidateLBGroupRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	affected, err := s.store.CreateLBGroup(r.Context(), grp, memberIDs)
	if err != nil {
		writeLBGroupStoreErr(w, err, "create")
		return
	}

	if len(affected) > 0 {
		s.syncNodeIDs(r.Context(), affected)
	}
	if _, evalErr := s.sched.EvaluateLBGroup(r.Context(), grp.ID, scheduler.LBEvalOptions{Trigger: "group_create"}); evalErr != nil {
		s.logger.Warn("evaluate lb group after create failed", "group_id", grp.ID, "err", evalErr)
	}
	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}

	latest, err := s.store.GetLBGroupByID(r.Context(), grp.ID)
	if err != nil {
		latest = grp
	}
	dto, err := s.hydrateSingleLBGroupDTO(r.Context(), *latest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load created lb group")
		return
	}
	writeJSON(w, http.StatusCreated, dto)
}

func (s *server) handleUpdateLBGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lb group id")
		return
	}
	var req lbGroupUpsertRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	grp, memberIDs, err := parseAndValidateLBGroupRequest(req)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	grp.ID = id

	affected, err := s.store.UpdateLBGroup(r.Context(), grp, memberIDs)
	if err != nil {
		writeLBGroupStoreErr(w, err, "update")
		return
	}

	if len(affected) > 0 {
		s.syncNodeIDs(r.Context(), affected)
	}
	if _, evalErr := s.sched.EvaluateLBGroup(r.Context(), grp.ID, scheduler.LBEvalOptions{Trigger: "group_update"}); evalErr != nil {
		s.logger.Warn("evaluate lb group after update failed", "group_id", grp.ID, "err", evalErr)
	}
	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}

	latest, err := s.store.GetLBGroupByID(r.Context(), id)
	if err != nil {
		latest = grp
	}
	dto, err := s.hydrateSingleLBGroupDTO(r.Context(), *latest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load updated lb group")
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (s *server) handleDeleteLBGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lb group id")
		return
	}
	if err := s.store.DeleteLBGroup(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lb group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete lb group")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) handleSyncLBGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lb group id")
		return
	}
	grp, evalErr := s.sched.EvaluateLBGroup(r.Context(), id, scheduler.LBEvalOptions{
		ForceSync: true,
		Trigger:   "manual_sync",
	})
	if evalErr != nil {
		if errors.Is(evalErr, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lb group not found")
			return
		}
		writeError(w, http.StatusBadGateway, evalErr.Error())
		return
	}
	dto, err := s.hydrateSingleLBGroupDTO(r.Context(), *grp)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hydrate lb group")
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (s *server) handlePinLBGroup(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lb group id")
		return
	}
	var req lbGroupPinRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	var pinID *int64
	if req.NodeID != nil && *req.NodeID > 0 {
		v := *req.NodeID
		pinID = &v
	}
	if err := s.store.SetLBGroupPinnedNode(r.Context(), id, pinID); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "lb group not found")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update pinned node")
		}
		return
	}

	_, evalErr := s.sched.EvaluateLBGroup(r.Context(), id, scheduler.LBEvalOptions{
		ForceSync: true,
		Trigger:   "manual_pin",
	})
	if evalErr != nil {
		s.logger.Warn("evaluate lb group after pin failed", "group_id", id, "err", evalErr)
	}
	latest, err := s.store.GetLBGroupByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to reload lb group")
		return
	}
	dto, err := s.hydrateSingleLBGroupDTO(r.Context(), *latest)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to hydrate lb group")
		return
	}
	writeJSON(w, http.StatusOK, dto)
}

func (s *server) handleListLBGroupLogs(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid lb group id")
		return
	}
	if _, err := s.store.GetLBGroupByID(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "lb group not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load lb group")
		return
	}
	limit := 50
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, convErr := strconv.Atoi(raw); convErr == nil && n > 0 {
			limit = n
		}
	}
	logs, err := s.store.ListLBSwitchLogs(r.Context(), id, limit)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list lb switch logs")
		return
	}
	if logs == nil {
		logs = []store.LBSwitchLog{}
	}
	writeJSON(w, http.StatusOK, logs)
}

func writeLBGroupStoreErr(w http.ResponseWriter, err error, action string) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "lb group not found")
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "分组名称、绑定域名或成员节点已被其他分组占用")
	case errors.Is(err, store.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, err.Error())
	default:
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("failed to %s lb group", action))
	}
}

func parseAndValidateLBGroupRequest(req lbGroupUpsertRequest) (*store.LBGroup, []int64, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, nil, errors.New("name cannot be empty")
	}

	domain := strings.TrimSuffix(strings.TrimSpace(strings.ToLower(req.DNSDomain)), ".")
	if err := validateLBDomain(domain); err != nil {
		return nil, nil, err
	}

	ttl := req.DNSTTL
	if ttl == 0 {
		ttl = 60
	}
	if ttl < 1 || ttl > 86400 {
		return nil, nil, errors.New("dns_ttl must be between 1 and 86400")
	}

	strategy := strings.TrimSpace(req.Strategy)
	if strategy == "" {
		strategy = protocol.LBStrategyRemainingBalance
	}
	if !protocol.IsValidLBStrategy(strategy) {
		return nil, nil, fmt.Errorf("invalid strategy %q", strategy)
	}

	switchDiffBytes := int64(10) << 30 // default 10 GiB
	if req.SwitchDiffBytes != nil {
		switchDiffBytes = *req.SwitchDiffBytes
	}
	if switchDiffBytes < 0 {
		return nil, nil, errors.New("switch_diff_bytes must be >= 0")
	}

	cooldownMins := 10
	if req.SwitchCooldownMinutes != nil {
		cooldownMins = *req.SwitchCooldownMinutes
	}
	if cooldownMins < 0 {
		return nil, nil, errors.New("switch_cooldown_minutes must be >= 0")
	}

	failoverPct := 90
	if req.FailoverThresholdPercent != nil {
		failoverPct = *req.FailoverThresholdPercent
	}
	if failoverPct < 1 || failoverPct > 100 {
		return nil, nil, errors.New("failover_threshold_percent must be between 1 and 100")
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	snell := req.SnellConfig
	snell.InnerPort = 0 // never overwritten by LB group
	snell.DNSIPPreference = ""
	if snell.Enabled {
		if snell.Version == "" {
			snell.Version = protocol.SnellVersionV5
		}
		if snell.Obfs == "" {
			snell.Obfs = protocol.SnellObfsOff
		}
		if snell.PublicPort < 1 || snell.PublicPort > 65535 {
			return nil, nil, errors.New("snell_config.public_port must be between 1 and 65535")
		}
		if strings.TrimSpace(snell.PSK) == "" {
			return nil, nil, errors.New("snell_config.psk cannot be empty when snell is enabled")
		}
		if strings.TrimSpace(snell.STLSPassword) == "" {
			return nil, nil, errors.New("snell_config.stls_password cannot be empty when snell is enabled")
		}
		if err := validateSTLSSNI(snell.STLSSNI); err != nil {
			return nil, nil, fmt.Errorf("invalid snell_config.stls_sni: %w", err)
		}
	}

	ss := req.SSConfig
	ss.Users = nil
	if ss.Enabled {
		if ss.TCPPort < 1 || ss.TCPPort > 65535 {
			return nil, nil, errors.New("ss_config.tcp_port must be between 1 and 65535")
		}
		if ss.UDPPort == 0 {
			ss.UDPPort = ss.TCPPort
		}
	}

	// Reuse node protocol config validator for PSK, cipher, iPSK, SNI, and port collision checks.
	tmpNode := store.Node{
		Name:             name,
		TrafficCountMode: protocol.TrafficCountBoth,
		ThresholdAction:  protocol.ThresholdActionStopAll,
		BillingResetDay:  1,
		SnellConfig:      snell,
		SSConfig:         ss,
	}
	if err := validateNodeConfig(&tmpNode); err != nil {
		return nil, nil, err
	}

	return &store.LBGroup{
		Name:                     name,
		RegionTag:                strings.TrimSpace(req.RegionTag),
		Enabled:                  enabled,
		SortOrder:                req.SortOrder,
		DNSZoneID:                strings.TrimSpace(req.DNSZoneID),
		DNSZoneName:              strings.TrimSuffix(strings.TrimSpace(strings.ToLower(req.DNSZoneName)), "."),
		DNSDomain:                domain,
		DNSTTL:                   ttl,
		Strategy:                 strategy,
		SwitchDiffBytes:          switchDiffBytes,
		SwitchCooldownMinutes:    cooldownMins,
		FailoverThresholdPercent: failoverPct,
		SnellConfig:              snell,
		SSConfig:                 ss,
	}, req.MemberNodeIDs, nil
}

func validateLBDomain(domain string) error {
	if domain == "" {
		return errors.New("dns_domain cannot be empty")
	}
	if hasControlChars(domain) || strings.IndexFunc(domain, unicode.IsSpace) != -1 || strings.ContainsAny(domain, ",=#;[]/?@\\:") {
		return fmt.Errorf("invalid dns_domain %q", domain)
	}
	if net.ParseIP(domain) != nil {
		return errors.New("dns_domain must be a domain name, not an IP address")
	}
	if !strings.Contains(domain, ".") {
		return errors.New("dns_domain must be a valid FQDN (e.g. ali.example.com)")
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 {
			return fmt.Errorf("invalid dns_domain %q", domain)
		}
	}
	return nil
}

func (s *server) hydrateSingleLBGroupDTO(ctx context.Context, g store.LBGroup) (lbGroupDTO, error) {
	nodes, err := s.store.ListNodes(ctx)
	if err != nil {
		return lbGroupDTO{}, err
	}
	nodeByID := make(map[int64]store.Node, len(nodes))
	for _, n := range nodes {
		nodeByID[n.ID] = n
	}
	return s.buildLBGroupDTO(g, nodeByID), nil
}

func (s *server) buildLBGroupDTO(g store.LBGroup, nodeByID map[int64]store.Node) lbGroupDTO {
	if g.ActiveRecords == nil {
		g.ActiveRecords = []store.LBActiveRecord{}
	}
	memberIDs := make([]int64, 0, len(g.Members))
	members := make([]lbGroupMemberViewDTO, 0, len(g.Members))

	for _, m := range g.Members {
		memberIDs = append(memberIDs, m.NodeID)
		n, ok := nodeByID[m.NodeID]
		if !ok {
			continue
		}
		dto := s.toNodeDTO(n, "")
		online := dto.Status == protocol.NodeStatusOnline || s.hub.IsOnline(n.ID)
		rem, hasBudget, used, budget := scheduler.NodeRemainingTraffic(&dto.Node)
		if !hasBudget {
			rem = -1
		}
		members = append(members, lbGroupMemberViewDTO{
			NodeID:                dto.ID,
			Priority:              m.Priority,
			NodeName:              dto.Name,
			RegionTag:             dto.RegionTag,
			Enabled:               dto.Enabled,
			Online:                online,
			Status:                dto.Status,
			PublicIP:              dto.PublicIP,
			CoreAHealthy:          dto.CoreAHealthy,
			CoreBHealthy:          dto.CoreBHealthy,
			IsTrafficPaused:       dto.IsTrafficPaused,
			CountedBytes:          used,
			BudgetBytes:           budget,
			RemainingBytes:        rem,
			TrafficLimitBytes:     dto.TrafficLimitBytes,
			TrafficThresholdBytes: dto.TrafficThresholdBytes,
			TrafficCountMode:      dto.TrafficCountMode,
		})
	}

	activeName := ""
	if g.ActiveNodeID != nil {
		if n, ok := nodeByID[*g.ActiveNodeID]; ok {
			activeName = n.Name
		}
	}

	return lbGroupDTO{
		ID:                       g.ID,
		Name:                     g.Name,
		RegionTag:                g.RegionTag,
		Enabled:                  g.Enabled,
		SortOrder:                g.SortOrder,
		DNSZoneID:                g.DNSZoneID,
		DNSZoneName:              g.DNSZoneName,
		DNSDomain:                g.DNSDomain,
		DNSTTL:                   g.DNSTTL,
		Strategy:                 g.Strategy,
		SwitchDiffBytes:          g.SwitchDiffBytes,
		SwitchCooldownMinutes:    g.SwitchCooldownMinutes,
		FailoverThresholdPercent: g.FailoverThresholdPercent,
		SnellConfig:              g.SnellConfig,
		SSConfig:                 g.SSConfig,
		PinnedNodeID:             g.PinnedNodeID,
		ActiveNodeID:             g.ActiveNodeID,
		ActiveNodeName:           activeName,
		ActiveRecords:            g.ActiveRecords,
		LastSwitchAt:             g.LastSwitchAt,
		LastSyncAt:               g.LastSyncAt,
		LastSyncError:            g.LastSyncError,
		IsExhausted:              g.IsExhausted,
		MemberNodeIDs:            memberIDs,
		Members:                  members,
		CreatedAt:                g.CreatedAt,
		UpdatedAt:                g.UpdatedAt,
	}
}
