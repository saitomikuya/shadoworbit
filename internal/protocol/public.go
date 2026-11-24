package protocol

// PublicNodeView is a strictly redacted read-only node projection for unauthenticated endpoints.
// Compile-time safety: it must NEVER contain PublicIP, CustomEntryHost, CustomEntryPort,
// SnellConfig, SSConfig, DNSUnlockServer, Token, TokenHash, or any user PII.
type PublicNodeView struct {
	ID                int64   `json:"id"`
	Name              string  `json:"name"`
	RegionTag         string  `json:"region_tag"`
	SortOrder         int     `json:"sort_order"`
	Status            string  `json:"status"`
	PausedReason      string  `json:"paused_reason"`
	BillingResetDay   int     `json:"billing_reset_day"`
	CPUPercent        float64 `json:"cpu_percent"`
	MemUsedBytes      uint64  `json:"mem_used_bytes"`
	MemTotalBytes     uint64  `json:"mem_total_bytes"`
	UptimeSeconds     uint64  `json:"uptime_seconds"`
	RxBPS             uint64  `json:"rx_bps"`
	TxBPS             uint64  `json:"tx_bps"`
	TotalRxBytes      int64   `json:"total_rx_bytes"`
	TotalTxBytes      int64   `json:"total_tx_bytes"`
	TrafficUsedBytes  int64   `json:"traffic_used_bytes"`
	TrafficLimitBytes int64   `json:"traffic_limit_bytes"`
	TrafficPercent    float64 `json:"traffic_percent"`
	PercentageOnly    bool    `json:"percentage_only"`
	CoreAHealthy      bool    `json:"core_a_healthy"`
	CoreBHealthy      bool    `json:"core_b_healthy"`
}

// PublicStatusSnapshot is returned by GET /api/v1/public/status and pushed via /api/v1/public/ws.
type PublicStatusSnapshot struct {
	SiteTitle      string           `json:"site_title"`
	Announcement   string           `json:"announcement"`
	PercentageOnly bool             `json:"percentage_only"`
	Nodes          []PublicNodeView `json:"nodes"`
}
