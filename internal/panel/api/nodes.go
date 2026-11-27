package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"snell-panel/internal/panel/auth"
	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/panel/webhook"
	"snell-panel/internal/protocol"
)

type nodeDTO struct {
	store.Node
	NodeToken string `json:"node_token,omitempty"`
}

type createSnellConfigRequest struct {
	Enabled         bool   `json:"enabled"`
	Version         string `json:"version"`
	PublicPort      int    `json:"public_port"`
	InnerPort       int    `json:"inner_port"`
	PSK             string `json:"psk"`
	Obfs            string `json:"obfs"`
	TFO             *bool  `json:"tfo"`
	DNSIPPreference string `json:"dns_ip_preference"`
	STLSPassword    string `json:"stls_password"`
	STLSSNI         string `json:"stls_sni"`
}

type createSSConfigRequest struct {
	Enabled bool   `json:"enabled"`
	TCPPort int    `json:"tcp_port"`
	UDPPort int    `json:"udp_port"`
	Cipher  string `json:"cipher"`
	IPSK    string `json:"ipsk"`
	STLSSNI string `json:"stls_sni"`
	TFO     *bool  `json:"tfo"`
}

type createNodeRequest struct {
	Name                  string                    `json:"name"`
	RegionTag             string                    `json:"region_tag"`
	PublicIP              string                    `json:"public_ip"`
	PublicIPv6            string                    `json:"public_ipv6"`
	CustomEntryHost       string                    `json:"custom_entry_host"`
	CustomEntryPort       int                       `json:"custom_entry_port"`
	SortOrder             int                       `json:"sort_order"`
	Enabled               *bool                     `json:"enabled"`
	SnellConfig           *createSnellConfigRequest `json:"snell_config"`
	SSConfig              *createSSConfigRequest    `json:"ss_config"`
	DNSUnlockEnabled      bool                      `json:"dns_unlock_enabled"`
	DNSUnlockServer       string                    `json:"dns_unlock_server"`
	DNSRuleGroupID        *int64                    `json:"dns_rule_group_id"`
	DNSExtraRules         []string                  `json:"dns_extra_rules"`
	TrafficLimitBytes     int64                     `json:"traffic_limit_bytes"`
	TrafficThresholdBytes int64                     `json:"traffic_threshold_bytes"`
	TrafficCountMode      string                    `json:"traffic_count_mode"`
	ThresholdAction       string                    `json:"threshold_action"`
	BillingResetDay       *int                      `json:"billing_reset_day"`
}

type optionalInt64 struct {
	set   bool
	value *int64
}

func (o *optionalInt64) UnmarshalJSON(data []byte) error {
	o.set = true
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		o.value = nil
		return nil
	}
	var v int64
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	o.value = &v
	return nil
}

type updateSnellConfigRequest struct {
	Enabled         *bool   `json:"enabled"`
	Version         *string `json:"version"`
	PublicPort      *int    `json:"public_port"`
	InnerPort       *int    `json:"inner_port"`
	PSK             *string `json:"psk"`
	Obfs            *string `json:"obfs"`
	TFO             *bool   `json:"tfo"`
	DNSIPPreference *string `json:"dns_ip_preference"`
	STLSPassword    *string `json:"stls_password"`
	STLSSNI         *string `json:"stls_sni"`
}

type updateSSConfigRequest struct {
	Enabled *bool   `json:"enabled"`
	TCPPort *int    `json:"tcp_port"`
	UDPPort *int    `json:"udp_port"`
	Cipher  *string `json:"cipher"`
	IPSK    *string `json:"ipsk"`
	STLSSNI *string `json:"stls_sni"`
	TFO     *bool   `json:"tfo"`
}

type updateNodeRequest struct {
	Name                  *string                   `json:"name"`
	RegionTag             *string                   `json:"region_tag"`
	PublicIP              *string                   `json:"public_ip"`
	PublicIPv6            *string                   `json:"public_ipv6"`
	CustomEntryHost       *string                   `json:"custom_entry_host"`
	CustomEntryPort       *int                      `json:"custom_entry_port"`
	SortOrder             *int                      `json:"sort_order"`
	Enabled               *bool                     `json:"enabled"`
	SnellConfig           *updateSnellConfigRequest `json:"snell_config"`
	SSConfig              *updateSSConfigRequest    `json:"ss_config"`
	DNSUnlockEnabled      *bool                     `json:"dns_unlock_enabled"`
	DNSUnlockServer       *string                   `json:"dns_unlock_server"`
	DNSRuleGroupID        optionalInt64             `json:"dns_rule_group_id"`
	DNSExtraRules         *[]string                 `json:"dns_extra_rules"`
	TrafficLimitBytes     *int64                    `json:"traffic_limit_bytes"`
	TrafficThresholdBytes *int64                    `json:"traffic_threshold_bytes"`
	TrafficCountMode      *string                   `json:"traffic_count_mode"`
	ThresholdAction       *string                   `json:"threshold_action"`
	BillingResetDay       *int                      `json:"billing_reset_day"`
}

type calibrateTrafficRequest struct {
	CycleRxBytes *int64 `json:"cycle_rx_bytes"`
	CycleTxBytes *int64 `json:"cycle_tx_bytes"`
}

type serviceCtlRequest struct {
	Action string `json:"action"`
}

type reorderNodesRequest struct {
	IDs     []int64 `json:"ids"`
	NodeIDs []int64 `json:"node_ids"`
}

func (s *server) toNodeDTO(n store.Node, rawToken string) nodeDTO {
	if n.DNSExtraRules == nil {
		n.DNSExtraRules = []string{}
	}
	n.SSConfig.Users = nil

	if tel, ok := s.hub.GetTelemetry(n.ID); ok && s.hub.IsOnline(n.ID) {
		if !n.IsTrafficPaused {
			n.Status = protocol.NodeStatusOnline
		}
		n.CPUPercent = tel.CPUPercent
		n.MemUsedBytes = tel.MemUsedBytes
		n.MemTotalBytes = tel.MemTotalBytes
		n.DiskUsedPercent = tel.DiskUsedPercent
		n.UptimeSeconds = tel.UptimeSeconds
		n.RxBPS = tel.RxBPS
		n.TxBPS = tel.TxBPS
		n.CoreAHealthy = tel.Health.Snell && tel.Health.ShadowTLS
		n.CoreBHealthy = tel.Health.SingBox
		n.ReportedConfigRevision = tel.ReportedConfigRevision
		n.ReportedVersions = tel.Versions
		if tel.OS != "" {
			n.AgentOS = tel.OS
		}
		if tel.Arch != "" {
			n.AgentArch = tel.Arch
		}
		if tel.CPUCores > 0 {
			n.CPUCores = tel.CPUCores
		}
		if tel.PublicIPv4 != "" {
			n.PublicIP = tel.PublicIPv4
		}
		if tel.PublicIPv6 != "" {
			n.PublicIPv6 = tel.PublicIPv6
		}
		if !tel.LastSeenAt.IsZero() {
			t := tel.LastSeenAt
			n.LastSeenAt = &t
		}
	}

	return nodeDTO{
		Node:      n,
		NodeToken: rawToken,
	}
}

func validateNodeConfig(n *store.Node) error {
	if strings.TrimSpace(n.Name) == "" {
		return errors.New("name cannot be empty")
	}
	if n.BillingResetDay < 1 || n.BillingResetDay > 31 {
		return errors.New("billing_reset_day must be between 1 and 31")
	}
	if n.CustomEntryPort < 0 || n.CustomEntryPort > 65535 {
		return errors.New("custom_entry_port must be between 0 and 65535")
	}
	if n.TrafficLimitBytes < 0 {
		return errors.New("traffic_limit_bytes cannot be negative")
	}
	if n.TrafficThresholdBytes < 0 {
		return errors.New("traffic_threshold_bytes cannot be negative")
	}
	if !protocol.IsValidTrafficCountMode(n.TrafficCountMode) {
		return fmt.Errorf("invalid traffic_count_mode %q", n.TrafficCountMode)
	}
	if !protocol.IsValidThresholdAction(n.ThresholdAction) {
		return fmt.Errorf("invalid threshold_action %q", n.ThresholdAction)
	}
	if n.SnellConfig.PublicPort < 0 || n.SnellConfig.PublicPort > 65535 {
		return errors.New("snell_config.public_port must be between 0 and 65535")
	}
	if n.SnellConfig.InnerPort < 0 || n.SnellConfig.InnerPort > 65535 {
		return errors.New("snell_config.inner_port must be between 0 and 65535")
	}
	if n.SnellConfig.Version != "" && !protocol.IsValidSnellVersion(n.SnellConfig.Version) {
		return fmt.Errorf("invalid snell_config.version %q", n.SnellConfig.Version)
	}
	if n.SnellConfig.Obfs != "" && !protocol.IsValidSnellObfs(n.SnellConfig.Obfs) {
		return fmt.Errorf("invalid snell_config.obfs %q", n.SnellConfig.Obfs)
	}
	switch n.SnellConfig.DNSIPPreference {
	case "", protocol.DNSIPPrefPreferIPv4, protocol.DNSIPPrefPreferIPv6, protocol.DNSIPPrefIPv4Only, protocol.DNSIPPrefAuto:
	default:
		return fmt.Errorf("invalid snell_config.dns_ip_preference %q", n.SnellConfig.DNSIPPreference)
	}
	if n.SnellConfig.PSK != "" {
		for _, r := range n.SnellConfig.PSK {
			if unicode.IsControl(r) || unicode.IsSpace(r) || r == ';' || r == '#' {
				return errors.New("snell_config.psk cannot contain whitespace, control characters, ';' or '#'")
			}
		}
	}
	if n.SnellConfig.STLSPassword != "" {
		if strings.TrimSpace(n.SnellConfig.STLSPassword) == "" || hasControlChars(n.SnellConfig.STLSPassword) {
			return errors.New("snell_config.stls_password cannot be blank or contain control characters")
		}
	}
	if n.SnellConfig.STLSSNI != "" {
		if err := validateSTLSSNI(n.SnellConfig.STLSSNI); err != nil {
			return fmt.Errorf("invalid snell_config.stls_sni: %w", err)
		}
	}
	if n.SSConfig.TCPPort < 0 || n.SSConfig.TCPPort > 65535 {
		return errors.New("ss_config.tcp_port must be between 0 and 65535")
	}
	if n.SSConfig.UDPPort < 0 || n.SSConfig.UDPPort > 65535 {
		return errors.New("ss_config.udp_port must be between 0 and 65535")
	}
	if n.SSConfig.STLSSNI != "" {
		if err := validateSTLSSNI(n.SSConfig.STLSSNI); err != nil {
			return fmt.Errorf("invalid ss_config.stls_sni: %w", err)
		}
	}
	if n.SnellConfig.Enabled && n.SnellConfig.PublicPort > 0 && n.SnellConfig.InnerPort > 0 &&
		n.SnellConfig.PublicPort == n.SnellConfig.InnerPort {
		return fmt.Errorf("snell_config.public_port (%d) cannot equal snell_config.inner_port", n.SnellConfig.PublicPort)
	}
	if n.SnellConfig.Enabled && n.SSConfig.Enabled && n.SSConfig.TCPPort > 0 {
		if n.SnellConfig.PublicPort > 0 && n.SSConfig.TCPPort == n.SnellConfig.PublicPort {
			return fmt.Errorf("ss_config.tcp_port (%d) cannot collide with snell_config.public_port", n.SSConfig.TCPPort)
		}
		if n.SnellConfig.InnerPort > 0 && n.SSConfig.TCPPort == n.SnellConfig.InnerPort {
			return fmt.Errorf("ss_config.tcp_port (%d) cannot collide with snell_config.inner_port", n.SSConfig.TCPPort)
		}
	}
	if n.SSConfig.Cipher != "" && !protocol.IsValidCipher(n.SSConfig.Cipher) {
		return fmt.Errorf("invalid ss_config.cipher %q", n.SSConfig.Cipher)
	}
	if n.SSConfig.Enabled {
		if !protocol.IsValidCipher(n.SSConfig.Cipher) {
			return fmt.Errorf("invalid ss_config.cipher %q", n.SSConfig.Cipher)
		}
		if err := auth.ValidateSS2022Key(n.SSConfig.IPSK, n.SSConfig.Cipher); err != nil {
			return fmt.Errorf("invalid ss_config.ipsk: %w", err)
		}
	} else if n.SSConfig.IPSK != "" && n.SSConfig.Cipher != "" {
		if err := auth.ValidateSS2022Key(n.SSConfig.IPSK, n.SSConfig.Cipher); err != nil {
			return fmt.Errorf("invalid ss_config.ipsk: %w", err)
		}
	}
	return nil
}

func (s *server) handleListNodes(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	nodes, err := s.store.ListNodes(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list nodes")
		return
	}
	out := make([]nodeDTO, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, s.toNodeDTO(n, ""))
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handleCreateNode(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req createNodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	billingResetDay := 1
	if req.BillingResetDay != nil {
		billingResetDay = *req.BillingResetDay
	}
	countMode := strings.TrimSpace(req.TrafficCountMode)
	if countMode == "" {
		countMode = protocol.TrafficCountBoth
	}
	thresholdAction := strings.TrimSpace(req.ThresholdAction)
	if thresholdAction == "" {
		thresholdAction = protocol.ThresholdActionStopAll
	}

	snellCfg := protocol.SnellConfig{TFO: true}
	if req.SnellConfig != nil {
		tfo := true
		if req.SnellConfig.TFO != nil {
			tfo = *req.SnellConfig.TFO
		}
		snellCfg = protocol.SnellConfig{
			Enabled:         req.SnellConfig.Enabled,
			Version:         req.SnellConfig.Version,
			PublicPort:      req.SnellConfig.PublicPort,
			InnerPort:       req.SnellConfig.InnerPort,
			PSK:             req.SnellConfig.PSK,
			Obfs:            req.SnellConfig.Obfs,
			TFO:             tfo,
			DNSIPPreference: req.SnellConfig.DNSIPPreference,
			STLSPassword:    req.SnellConfig.STLSPassword,
			STLSSNI:         req.SnellConfig.STLSSNI,
		}
		if snellCfg.Enabled && snellCfg.Version == "" {
			snellCfg.Version = protocol.SnellVersionV5
		}
	}
	ssCfg := protocol.SSConfig{TFO: true}
	if req.SSConfig != nil {
		tfo := true
		if req.SSConfig.TFO != nil {
			tfo = *req.SSConfig.TFO
		}
		ssCfg = protocol.SSConfig{
			Enabled: req.SSConfig.Enabled,
			TCPPort: req.SSConfig.TCPPort,
			UDPPort: req.SSConfig.UDPPort,
			Cipher:  req.SSConfig.Cipher,
			IPSK:    req.SSConfig.IPSK,
			STLSSNI: req.SSConfig.STLSSNI,
			TFO:     tfo,
			Users:   nil,
		}
	}
	extraRules := req.DNSExtraRules
	if extraRules == nil {
		extraRules = []string{}
	}

	node := &store.Node{
		Name:                  strings.TrimSpace(req.Name),
		RegionTag:             req.RegionTag,
		PublicIP:              req.PublicIP,
		PublicIPv6:            req.PublicIPv6,
		CustomEntryHost:       req.CustomEntryHost,
		CustomEntryPort:       req.CustomEntryPort,
		SortOrder:             req.SortOrder,
		Enabled:               enabled,
		Status:                protocol.NodeStatusOffline,
		SnellConfig:           snellCfg,
		SSConfig:              ssCfg,
		DNSUnlockEnabled:      req.DNSUnlockEnabled,
		DNSUnlockServer:       req.DNSUnlockServer,
		DNSRuleGroupID:        req.DNSRuleGroupID,
		DNSExtraRules:         extraRules,
		TrafficLimitBytes:     req.TrafficLimitBytes,
		TrafficThresholdBytes: req.TrafficThresholdBytes,
		TrafficCountMode:      countMode,
		ThresholdAction:       thresholdAction,
		BillingResetDay:       billingResetDay,
		ConfigRevision:        1,
	}

	if err := validateNodeConfig(node); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	rawToken, tokenHash, err := auth.GenerateNodeTokenPair()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to generate node token")
		return
	}
	node.TokenHash = tokenHash

	if err := s.store.CreateNode(r.Context(), node); err != nil {
		switch {
		case errors.Is(err, store.ErrForeignKey), errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to create node")
		}
		return
	}

	if err := s.auth.SaveNodeToken(r.Context(), node.ID, rawToken); err != nil {
		_ = s.store.DeleteNode(r.Context(), node.ID)
		writeError(w, http.StatusInternalServerError, "failed to persist encrypted node token")
		return
	}

	if node.SSConfig.Enabled {
		if _, err := s.store.GrantNodeToAllUsers(r.Context(), node.ID); err != nil {
			s.logger.Warn("grant new SS node to existing users failed", "node_id", node.ID, "err", err)
		}
	}

	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}

	created, err := s.store.GetNodeByID(r.Context(), node.ID)
	if err != nil {
		writeJSON(w, http.StatusCreated, s.toNodeDTO(*node, rawToken))
		return
	}
	writeJSON(w, http.StatusCreated, s.toNodeDTO(*created, rawToken))
}

func (s *server) handleGetNode(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	node, err := s.store.GetNodeByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get node")
		return
	}

	writeJSON(w, http.StatusOK, s.toNodeDTO(*node, ""))
}

func (s *server) handleUpdateNode(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	var req updateNodeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var valErr error
	committed, err := s.store.UpdateNodeTx(r.Context(), id, func(existing *store.Node) (*store.Node, error) {
		updated := *existing
		if req.Name != nil {
			updated.Name = strings.TrimSpace(*req.Name)
		}
		if req.RegionTag != nil {
			updated.RegionTag = *req.RegionTag
		}
		if req.PublicIP != nil {
			updated.PublicIP = *req.PublicIP
		}
		if req.PublicIPv6 != nil {
			updated.PublicIPv6 = *req.PublicIPv6
		}
		if req.CustomEntryHost != nil {
			updated.CustomEntryHost = *req.CustomEntryHost
		}
		if req.CustomEntryPort != nil {
			updated.CustomEntryPort = *req.CustomEntryPort
		}
		if req.SortOrder != nil {
			updated.SortOrder = *req.SortOrder
		}
		if req.Enabled != nil {
			updated.Enabled = *req.Enabled
		}
		if req.SnellConfig != nil {
			if req.SnellConfig.Enabled != nil {
				updated.SnellConfig.Enabled = *req.SnellConfig.Enabled
			}
			if req.SnellConfig.Version != nil {
				updated.SnellConfig.Version = *req.SnellConfig.Version
			}
			if req.SnellConfig.PublicPort != nil {
				updated.SnellConfig.PublicPort = *req.SnellConfig.PublicPort
			}
			if req.SnellConfig.InnerPort != nil {
				updated.SnellConfig.InnerPort = *req.SnellConfig.InnerPort
			}
			if req.SnellConfig.PSK != nil {
				updated.SnellConfig.PSK = *req.SnellConfig.PSK
			}
			if req.SnellConfig.Obfs != nil {
				updated.SnellConfig.Obfs = *req.SnellConfig.Obfs
			}
			if req.SnellConfig.TFO != nil {
				updated.SnellConfig.TFO = *req.SnellConfig.TFO
			}
			if req.SnellConfig.DNSIPPreference != nil {
				updated.SnellConfig.DNSIPPreference = *req.SnellConfig.DNSIPPreference
			}
			if req.SnellConfig.STLSPassword != nil {
				updated.SnellConfig.STLSPassword = *req.SnellConfig.STLSPassword
			}
			if req.SnellConfig.STLSSNI != nil {
				updated.SnellConfig.STLSSNI = *req.SnellConfig.STLSSNI
			}
			if updated.SnellConfig.Enabled && updated.SnellConfig.Version == "" {
				updated.SnellConfig.Version = protocol.SnellVersionV5
			}
		}
		if req.SSConfig != nil {
			if req.SSConfig.Enabled != nil {
				updated.SSConfig.Enabled = *req.SSConfig.Enabled
			}
			if req.SSConfig.TCPPort != nil {
				updated.SSConfig.TCPPort = *req.SSConfig.TCPPort
			}
			if req.SSConfig.UDPPort != nil {
				updated.SSConfig.UDPPort = *req.SSConfig.UDPPort
			}
			if req.SSConfig.Cipher != nil {
				updated.SSConfig.Cipher = *req.SSConfig.Cipher
			}
			if req.SSConfig.IPSK != nil {
				updated.SSConfig.IPSK = *req.SSConfig.IPSK
			}
			if req.SSConfig.STLSSNI != nil {
				updated.SSConfig.STLSSNI = *req.SSConfig.STLSSNI
			}
			if req.SSConfig.TFO != nil {
				updated.SSConfig.TFO = *req.SSConfig.TFO
			}
			updated.SSConfig.Users = nil
		}
		if req.DNSUnlockEnabled != nil {
			updated.DNSUnlockEnabled = *req.DNSUnlockEnabled
		}
		if req.DNSUnlockServer != nil {
			updated.DNSUnlockServer = *req.DNSUnlockServer
		}
		if req.DNSRuleGroupID.set {
			updated.DNSRuleGroupID = req.DNSRuleGroupID.value
		}
		if req.DNSExtraRules != nil {
			if *req.DNSExtraRules == nil {
				updated.DNSExtraRules = []string{}
			} else {
				updated.DNSExtraRules = append([]string(nil), (*req.DNSExtraRules)...)
			}
		}
		if req.TrafficLimitBytes != nil {
			updated.TrafficLimitBytes = *req.TrafficLimitBytes
		}
		if req.TrafficThresholdBytes != nil {
			updated.TrafficThresholdBytes = *req.TrafficThresholdBytes
		}
		if req.TrafficCountMode != nil {
			updated.TrafficCountMode = strings.TrimSpace(*req.TrafficCountMode)
		}
		if req.ThresholdAction != nil {
			updated.ThresholdAction = strings.TrimSpace(*req.ThresholdAction)
		}
		if req.BillingResetDay != nil {
			updated.BillingResetDay = *req.BillingResetDay
		}

		if err := validateNodeConfig(&updated); err != nil {
			valErr = err
			return nil, err
		}

		updated.ConfigRevision = existing.ConfigRevision + 1
		return &updated, nil
	})
	if valErr != nil {
		writeError(w, http.StatusBadRequest, valErr.Error())
		return
	}
	if err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "node not found")
		case errors.Is(err, store.ErrForeignKey), errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		case errors.Is(err, store.ErrConflict):
			writeError(w, http.StatusConflict, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to update node")
		}
		return
	}

	if err := s.sched.EvaluateNodeThreshold(r.Context(), id); err != nil {
		s.logger.Warn("evaluate node threshold after update failed", "node_id", id, "err", err)
	}
	if err := s.hub.SyncNode(r.Context(), id); err != nil && !errors.Is(err, hub.ErrNodeOffline) && !errors.Is(err, hub.ErrHubClosed) {
		s.logger.Warn("sync node after update failed", "node_id", id, "err", err)
	}
	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}

	respNode := *committed
	if latest, err := s.store.GetNodeByID(r.Context(), id); err == nil {
		if latest.ConfigRevision == committed.ConfigRevision || latest.IsTrafficPaused != committed.IsTrafficPaused {
			respNode = *latest
		}
	}
	writeJSON(w, http.StatusOK, s.toNodeDTO(respNode, ""))
}

func (s *server) handleDeleteNode(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	if err := s.store.DeleteNode(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to delete node")
		return
	}

	s.hub.EvictNode(id)

	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (s *server) handleResetNodeTraffic(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	node, err := s.store.GetNodeByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to load node")
		return
	}

	wasPaused := node.IsTrafficPaused
	now := time.Now().UTC()

	if err := s.store.ResetNodeCycleTraffic(r.Context(), id, now); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to reset node traffic")
		return
	}

	if s.hub.IsOnline(id) {
		if err := s.store.SetNodeConnectionStatus(r.Context(), id, true, now); err != nil && !errors.Is(err, store.ErrNotFound) {
			s.logger.Warn("restore online status after traffic reset failed", "node_id", id, "err", err)
		}
	}

	if err := s.sched.EvaluateNodeThreshold(r.Context(), id); err != nil {
		s.logger.Warn("evaluate node threshold after reset failed", "node_id", id, "err", err)
	}

	if wasPaused {
		if _, err := s.store.IncrementNodeConfigRevision(r.Context(), id); err != nil {
			s.logger.Warn("increment config_revision after traffic reset failed", "node_id", id, "err", err)
		}
		if err := s.hub.SyncNode(r.Context(), id); err != nil && !errors.Is(err, hub.ErrNodeOffline) && !errors.Is(err, hub.ErrHubClosed) {
			s.logger.Warn("sync node after traffic reset failed", "node_id", id, "err", err)
		}
		s.webhook.Notify(context.Background(), webhook.AlertEvent{
			Type:       webhook.EventTrafficRecovered,
			Severity:   webhook.SeverityInfo,
			TargetType: webhook.TargetTypeNode,
			TargetID:   id,
			TargetName: node.Name,
			Title:      fmt.Sprintf("节点流量重置恢复：%s", node.Name),
			Message:    fmt.Sprintf("节点 %s 周期流量已手动清零，代理服务已恢复正常", node.Name),
			Resolved:   true,
			Timestamp:  now,
		})
	}

	latest, err := s.store.GetNodeByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load updated node")
		return
	}
	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}
	writeJSON(w, http.StatusOK, s.toNodeDTO(*latest, ""))
}

func (s *server) handleCalibrateNodeTraffic(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	var req calibrateTrafficRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	var rx, tx int64
	if req.CycleRxBytes != nil {
		rx = *req.CycleRxBytes
	}
	if req.CycleTxBytes != nil {
		tx = *req.CycleTxBytes
	}
	if rx < 0 || tx < 0 {
		writeError(w, http.StatusBadRequest, "traffic bytes cannot be negative")
		return
	}

	if err := s.store.CalibrateNodeTraffic(r.Context(), id, rx, tx); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "node not found")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to calibrate node traffic")
		}
		return
	}

	if err := s.sched.EvaluateNodeThreshold(r.Context(), id); err != nil {
		s.logger.Warn("evaluate node threshold after calibration failed", "node_id", id, "err", err)
	}

	latest, err := s.store.GetNodeByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to load calibrated node")
		return
	}
	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}
	writeJSON(w, http.StatusOK, s.toNodeDTO(*latest, ""))
}

func (s *server) handleNodeServiceCtl(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	if _, err := s.store.GetNodeByID(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to check node")
		return
	}

	var req serviceCtlRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}
	action := strings.TrimSpace(req.Action)
	if !protocol.IsValidServiceAction(action) {
		writeError(w, http.StatusBadRequest, "invalid service action")
		return
	}

	err = s.hub.SendServiceCtl(r.Context(), id, protocol.ServerServiceCtl{Action: action})
	if err != nil {
		switch {
		case errors.Is(err, hub.ErrNodeOffline):
			writeError(w, http.StatusConflict, "node is offline")
		case errors.Is(err, hub.ErrInvalidCommand):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to send service control command")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status": "dispatched",
		"action": action,
	})
}

func (s *server) handleSyncNode(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	if _, err := s.store.GetNodeByID(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to check node")
		return
	}

	rev, err := s.store.IncrementNodeConfigRevision(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to increment config revision")
		return
	}

	err = s.hub.SyncNode(r.Context(), id)
	if err != nil {
		if errors.Is(err, hub.ErrNodeOffline) {
			writeJSON(w, http.StatusOK, map[string]any{
				"status":          "offline",
				"synced":          false,
				"config_revision": rev,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to sync node")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":          "synced",
		"synced":          true,
		"config_revision": rev,
	})
}

func (s *server) handleNodeInstallCmd(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	id, err := parseID(r.PathValue("id"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid node id")
		return
	}

	node, err := s.store.GetNodeByID(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to get node")
		return
	}

	rawToken, err := s.auth.GetNodeToken(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "node token not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "failed to recover node token")
		return
	}
	if !auth.VerifyTokenHash(rawToken, node.TokenHash) {
		writeError(w, http.StatusConflict, "stored node token does not match node hash")
		return
	}

	panelURL := deriveWSBaseURL(r)
	if panelURL == "" {
		panelURL = "ws://127.0.0.1:8080"
	}

	agentImage, _ := s.store.GetSettingOrDefault(r.Context(), "agent_docker_image", "saitomikuya/shadoworbit-agent:latest")
	agentImage = strings.TrimSpace(agentImage)
	if agentImage == "" {
		agentImage = "saitomikuya/shadoworbit-agent:latest"
	}
	dockerRun := fmt.Sprintf(
		"docker run -d --name node-agent --restart always --network host -v /opt/node-agent:/var/lib/node-agent -e PANEL_URL=%q -e NODE_TOKEN=%q -e TZ=Asia/Shanghai %s",
		panelURL, rawToken, agentImage,
	)
	dockerCompose := fmt.Sprintf(`services:
  node-agent:
    image: %s
    container_name: node-agent
    restart: always
    network_mode: host
    volumes:
      - /opt/node-agent:/var/lib/node-agent
    environment:
      - PANEL_URL=%s
      - NODE_TOKEN=%s
      - TZ=Asia/Shanghai
`, agentImage, panelURL, rawToken)

	writeJSON(w, http.StatusOK, map[string]any{
		"node_id":        id,
		"panel_url":      panelURL,
		"node_token":     rawToken,
		"docker_image":   agentImage,
		"docker_run":     dockerRun,
		"docker_compose": dockerCompose,
	})
}

func (s *server) handleReorderNodes(w http.ResponseWriter, r *http.Request, _ *auth.AdminClaims) {
	var req reorderNodesRequest
	if err := decodeJSON(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON payload")
		return
	}

	ids := req.IDs
	if len(ids) == 0 {
		ids = req.NodeIDs
	}
	if len(ids) == 0 {
		writeError(w, http.StatusBadRequest, "ids cannot be empty")
		return
	}

	seen := make(map[int64]struct{}, len(ids))
	for _, id := range ids {
		if id <= 0 {
			writeError(w, http.StatusBadRequest, "node id must be positive")
			return
		}
		if _, dup := seen[id]; dup {
			writeError(w, http.StatusBadRequest, "duplicate node id in reorder list")
			return
		}
		seen[id] = struct{}{}
	}

	if err := s.store.ReorderNodes(r.Context(), ids); err != nil {
		switch {
		case errors.Is(err, store.ErrNotFound):
			writeError(w, http.StatusNotFound, "node not found")
		case errors.Is(err, store.ErrInvalidArgument):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "failed to reorder nodes")
		}
		return
	}

	if s.hub != nil {
		s.hub.BroadcastPublicStatus()
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"ids":    ids,
	})
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func validateSTLSSNI(raw string) error {
	if raw == "" {
		return errors.New("stls_sni cannot be empty")
	}
	if hasControlChars(raw) || strings.IndexFunc(raw, unicode.IsSpace) != -1 || strings.ContainsAny(raw, ",=#;/?@\\") {
		return fmt.Errorf("stls_sni %q contains invalid characters", raw)
	}
	if h, pStr, splitErr := net.SplitHostPort(raw); splitErr == nil {
		if h == "" || strings.ContainsAny(h, "[]") {
			return fmt.Errorf("invalid stls_sni host in %q", raw)
		}
		if strings.HasPrefix(raw, "[") && net.ParseIP(h) == nil {
			return fmt.Errorf("invalid bracketed stls_sni %q: interior must be an IP address", raw)
		}
		if strings.Contains(h, ":") && net.ParseIP(h) == nil {
			return fmt.Errorf("invalid stls_sni host in %q", raw)
		}
		p, err := strconv.Atoi(pStr)
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid stls_sni port in %q: must be 1..65535", raw)
		}
		return nil
	} else if !strings.Contains(splitErr.Error(), "missing port in address") {
		return fmt.Errorf("invalid stls_sni %q: %w", raw, splitErr)
	}
	h := raw
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		inner := h[1 : len(h)-1]
		if net.ParseIP(inner) == nil {
			return fmt.Errorf("invalid bracketed stls_sni %q: interior must be an IP address", raw)
		}
		h = inner
	}
	if h == "" || strings.ContainsAny(h, "[]") || (strings.Contains(h, ":") && net.ParseIP(h) == nil) {
		return fmt.Errorf("invalid stls_sni %q", raw)
	}
	return nil
}

func unionInt64(a, b []int64) []int64 {
	seen := make(map[int64]struct{}, len(a)+len(b))
	out := make([]int64, 0, len(a)+len(b))
	for _, id := range a {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	for _, id := range b {
		if id <= 0 {
			continue
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func (s *server) syncNodeIDs(ctx context.Context, nodeIDs []int64) {
	for _, nid := range nodeIDs {
		if err := s.hub.SyncNode(ctx, nid); err != nil && !errors.Is(err, hub.ErrNodeOffline) && !errors.Is(err, hub.ErrHubClosed) {
			s.logger.Warn("sync node failed", "node_id", nid, "err", err)
		}
	}
}
