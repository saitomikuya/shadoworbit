package store

import (
	"time"

	"snell-panel/internal/protocol"
)

// Node represents a managed VPS node persisted in SQLite.
type Node struct {
	ID                     int64                  `json:"id"`
	Name                   string                 `json:"name"`
	RegionTag              string                 `json:"region_tag"`
	TokenHash              string                 `json:"-"`
	PublicIP               string                 `json:"public_ip"`
	PublicIPv6             string                 `json:"public_ipv6"`
	CustomEntryHost        string                 `json:"custom_entry_host"`
	CustomEntryPort        int                    `json:"custom_entry_port"`
	SortOrder              int                    `json:"sort_order"`
	Enabled                bool                   `json:"enabled"`
	Status                 string                 `json:"status"`
	PausedReason           string                 `json:"paused_reason"`
	SnellConfig            protocol.SnellConfig   `json:"snell_config"`
	SSConfig               protocol.SSConfig      `json:"ss_config"`
	DNSUnlockEnabled       bool                   `json:"dns_unlock_enabled"`
	DNSUnlockServer        string                 `json:"dns_unlock_server"`
	DNSRuleGroupID         *int64                 `json:"dns_rule_group_id"`
	DNSExtraRules          []string               `json:"dns_extra_rules"`
	TrafficLimitBytes      int64                  `json:"traffic_limit_bytes"`
	TrafficThresholdBytes  int64                  `json:"traffic_threshold_bytes"`
	TrafficCountMode       string                 `json:"traffic_count_mode"`
	ThresholdAction        string                 `json:"threshold_action"`
	BillingResetDay        int                    `json:"billing_reset_day"`
	CycleRxBytes           int64                  `json:"cycle_rx_bytes"`
	CycleTxBytes           int64                  `json:"cycle_tx_bytes"`
	TotalRxBytes           int64                  `json:"total_rx_bytes"`
	TotalTxBytes           int64                  `json:"total_tx_bytes"`
	LastResetAt            *time.Time             `json:"last_reset_at"`
	IsTrafficPaused        bool                   `json:"is_traffic_paused"`
	ConfigRevision         int64                  `json:"config_revision"`
	ReportedConfigRevision int64                  `json:"reported_config_revision"`
	ReportedVersions       protocol.AgentVersions `json:"reported_versions"`
	AgentOS                string                 `json:"agent_os"`
	AgentArch              string                 `json:"agent_arch"`
	CPUCores               int                    `json:"cpu_cores"`
	LastSeenAt             *time.Time             `json:"last_seen_at"`
	CPUPercent             float64                `json:"cpu_percent"`
	MemUsedBytes           uint64                 `json:"mem_used_bytes"`
	MemTotalBytes          uint64                 `json:"mem_total_bytes"`
	DiskUsedPercent        float64                `json:"disk_used_percent"`
	UptimeSeconds          uint64                 `json:"uptime_seconds"`
	RxBPS                  uint64                 `json:"rx_bps"`
	TxBPS                  uint64                 `json:"tx_bps"`
	CoreAHealthy           bool                   `json:"core_a_healthy"`
	CoreBHealthy           bool                   `json:"core_b_healthy"`
	CreatedAt              time.Time              `json:"created_at"`
	UpdatedAt              time.Time              `json:"updated_at"`
}

// NodeTelemetryUpdate holds live telemetry fields reported via agent.metrics.
type NodeTelemetryUpdate struct {
	PublicIP        string
	PublicIPv6      string
	CPUPercent      float64
	MemUsedBytes    uint64
	MemTotalBytes   uint64
	DiskUsedPercent float64
	UptimeSeconds   uint64
	RxBPS           uint64
	TxBPS           uint64
	CoreAHealthy    bool
	CoreBHealthy    bool
	LastSeenAt      time.Time
}

// User represents a multi-user SS2022 + ShadowTLS v3 subscriber.
type User struct {
	ID                int64      `json:"id"`
	Username          string     `json:"username"`
	Enabled           bool       `json:"enabled"`
	SubToken          string     `json:"sub_token"`
	SSUPSK16          string     `json:"ss_upsk_16"`
	SSUPSK32          string     `json:"ss_upsk_32"`
	STLSPassword      string     `json:"stls_password"`
	TrafficQuotaBytes int64      `json:"traffic_quota_bytes"`
	BillingResetDay   int        `json:"billing_reset_day"`
	UsedUpBytes       int64      `json:"used_up_bytes"`
	UsedDownBytes     int64      `json:"used_down_bytes"`
	LastResetAt       *time.Time `json:"last_reset_at"`
	ExpireAt          *time.Time `json:"expire_at"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
}

// IsQuotaExhausted reports whether the user has a positive traffic quota and
// their cumulative upload+download traffic has reached or exceeded it, using
// uint64 arithmetic to prevent signed int64 overflow.
func (u *User) IsQuotaExhausted() bool {
	if u == nil || u.TrafficQuotaBytes <= 0 {
		return false
	}
	up := max(int64(0), u.UsedUpBytes)
	down := max(int64(0), u.UsedDownBytes)
	return uint64(up)+uint64(down) >= uint64(u.TrafficQuotaBytes)
}

// DNSRuleGroup represents a reusable DNS unlock domain rule set.
type DNSRuleGroup struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Rules       []string  `json:"rules"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// TrafficLogDaily represents one daily traffic record for a node or user.
type TrafficLogDaily struct {
	ID         int64  `json:"id"`
	TargetType string `json:"target_type"`
	TargetID   int64  `json:"target_id"`
	LogDate    string `json:"log_date"`
	RxBytes    int64  `json:"rx_bytes"`
	TxBytes    int64  `json:"tx_bytes"`
}

// DailyTrafficFilter filters QueryDailyTraffic results.
type DailyTrafficFilter struct {
	TargetType string
	TargetID   int64
	FromDate   string
	ToDate     string
}

// TrafficUsageLog represents one per-minute aggregated user+node usage record.
type TrafficUsageLog struct {
	ID        int64  `json:"id"`
	NodeID    int64  `json:"node_id"`
	NodeName  string `json:"node_name"`
	RegionTag string `json:"region_tag"`
	UserID    int64  `json:"user_id"`
	Username  string `json:"username"`
	LogMinute string `json:"log_minute"`
	StartTime string `json:"start_time,omitempty"`
	EndTime   string `json:"end_time,omitempty"`
	RxBytes   int64  `json:"rx_bytes"`
	TxBytes   int64  `json:"tx_bytes"`
	UpdatedAt string `json:"updated_at"`
}

// TrafficUsageLogFilter filters QueryTrafficUsageLogs results.
type TrafficUsageLogFilter struct {
	NodeID          int64
	UserID          *int64
	From            string
	To              string
	Limit           int
	Merge           bool
	MergeGapMinutes int
}

// UserNodeTrafficEntry represents cumulative traffic recorded for a user on one node.
type UserNodeTrafficEntry struct {
	NodeID     int64  `json:"node_id"`
	NodeName   string `json:"node_name"`
	RegionTag  string `json:"region_tag"`
	UpBytes    int64  `json:"up_bytes"`
	DownBytes  int64  `json:"down_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

// AdminNodeTrafficEntry represents cumulative Snell admin traffic recorded on one node.
type AdminNodeTrafficEntry struct {
	NodeID     int64  `json:"node_id"`
	NodeName   string `json:"node_name"`
	RegionTag  string `json:"region_tag"`
	TotalBytes int64  `json:"total_bytes"`
}

// SubTemplate represents an editable Surge or Mihomo subscription template.
type SubTemplate struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	ClientType string    `json:"client_type"`
	Content    string    `json:"content"`
	IsDefault  bool      `json:"is_default"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// WebhookChannel represents an alert notification target.
type WebhookChannel struct {
	ID               int64     `json:"id"`
	Name             string    `json:"name"`
	Provider         string    `json:"provider"`
	URL              string    `json:"url"`
	Secret           string    `json:"secret"`
	SubscribedEvents []string  `json:"subscribed_events"`
	Enabled          bool      `json:"enabled"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// LBActiveRecord describes one DNS A record currently synced for an LB group.
type LBActiveRecord struct {
	NodeID      int64  `json:"node_id"`
	NodeName    string `json:"node_name"`
	IP          string `json:"ip"`
	Weight      int    `json:"weight,omitempty"`
	RecordSetID string `json:"recordset_id,omitempty"`
}

// LBGroupMember links a node into a load-balancing group with an explicit priority order.
type LBGroupMember struct {
	GroupID   int64     `json:"group_id"`
	NodeID    int64     `json:"node_id"`
	Priority  int       `json:"priority"`
	CreatedAt time.Time `json:"created_at"`
}

// LBGroupSummary holds lightweight group metadata for node/user views.
type LBGroupSummary struct {
	ID      int64  `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
}

// LBGroup represents a DNS load-balancing group sharing one unified domain entry.
type LBGroup struct {
	ID                       int64                `json:"id"`
	Name                     string               `json:"name"`
	RegionTag                string               `json:"region_tag"`
	Enabled                  bool                 `json:"enabled"`
	SortOrder                int                  `json:"sort_order"`
	DNSZoneID                string               `json:"dns_zone_id"`
	DNSZoneName              string               `json:"dns_zone_name"`
	DNSDomain                string               `json:"dns_domain"`
	DNSTTL                   int                  `json:"dns_ttl"`
	Strategy                 string               `json:"strategy"`
	SwitchDiffBytes          int64                `json:"switch_diff_bytes"`
	SwitchCooldownMinutes    int                  `json:"switch_cooldown_minutes"`
	FailoverThresholdPercent int                  `json:"failover_threshold_percent"`
	SnellConfig              protocol.SnellConfig `json:"snell_config"`
	SSConfig                 protocol.SSConfig    `json:"ss_config"`
	PinnedNodeID             *int64               `json:"pinned_node_id"`
	ActiveNodeID             *int64               `json:"active_node_id"`
	ActiveRecords            []LBActiveRecord     `json:"active_records"`
	LastSwitchAt             *time.Time           `json:"last_switch_at"`
	LastSyncAt               *time.Time           `json:"last_sync_at"`
	LastSyncError            string               `json:"last_sync_error"`
	IsExhausted              bool                 `json:"is_exhausted"`
	Members                  []LBGroupMember      `json:"members"`
	CreatedAt                time.Time            `json:"created_at"`
	UpdatedAt                time.Time            `json:"updated_at"`
}

// LBGroupSyncState captures DNS synchronization state persisted after an LB evaluation.
type LBGroupSyncState struct {
	ActiveNodeID  *int64
	ActiveRecords []LBActiveRecord
	LastSwitchAt  *time.Time
	LastSyncAt    *time.Time
	LastSyncError string
	IsExhausted   bool
}

// LBSwitchLog records a DNS load-balancing switch, failover, pin, or error event.
type LBSwitchLog struct {
	ID         int64     `json:"id"`
	GroupID    int64     `json:"group_id"`
	EventType  string    `json:"event_type"`
	FromNodeID *int64    `json:"from_node_id"`
	ToNodeID   *int64    `json:"to_node_id"`
	FromIPs    string    `json:"from_ips"`
	ToIPs      string    `json:"to_ips"`
	Reason     string    `json:"reason"`
	CreatedAt  time.Time `json:"created_at"`
}
