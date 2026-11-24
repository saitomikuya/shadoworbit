package protocol

// AgentVersions reports installed binary versions on the node.
type AgentVersions struct {
	SingBox     string `json:"sing_box"`
	SnellServer string `json:"snell_server"`
	ShadowTLS   string `json:"shadow_tls"`
}

// AgentHello is sent by the agent after WS handshake (type: "agent.hello").
type AgentHello struct {
	OS             string        `json:"os"`
	Arch           string        `json:"arch"`
	CPUCores       int           `json:"cpu_cores"`
	TotalRAMBytes  uint64        `json:"total_ram_bytes"`
	PublicIPv4     string        `json:"public_ipv4"`
	PublicIPv6     string        `json:"public_ipv6"`
	Versions       AgentVersions `json:"versions"`
	ConfigRevision int64         `json:"config_revision"`
}

// UserTrafficDelta holds per-user incremental traffic from sing-box Stats API.
type UserTrafficDelta struct {
	Username  string `json:"username"`
	UserID    int64  `json:"user_id"`
	UpBytes   uint64 `json:"up_bytes"`
	DownBytes uint64 `json:"down_bytes"`
}

// AgentHealth reports liveness of each isolated kernel process.
type AgentHealth struct {
	Snell     bool `json:"snell"`
	ShadowTLS bool `json:"shadow_tls"`
	SingBox   bool `json:"sing_box"`
}

// AgentMetrics is periodically sent by the agent (type: "agent.metrics").
type AgentMetrics struct {
	TS              int64              `json:"ts"`
	CPUPercent      float64            `json:"cpu_percent"`
	MemUsedBytes    uint64             `json:"mem_used_bytes"`
	MemTotalBytes   uint64             `json:"mem_total_bytes"`
	DiskUsedPercent float64            `json:"disk_used_percent"`
	UptimeSeconds   uint64             `json:"uptime_seconds"`
	RxBPS           uint64             `json:"rx_bps"`
	TxBPS           uint64             `json:"tx_bps"`
	NicRxDelta      uint64             `json:"nic_rx_delta"`
	NicTxDelta      uint64             `json:"nic_tx_delta"`
	AdminSnellBytes uint64             `json:"admin_snell_bytes,omitempty"`
	UserDeltas      []UserTrafficDelta `json:"user_deltas"`
	Health          AgentHealth        `json:"health"`
}

// AgentEvent reports async lifecycle, config, or kernel update events (type: "agent.event").
type AgentEvent struct {
	Event          string `json:"event"`
	ConfigRevision int64  `json:"config_revision"`
	Kernel         string `json:"kernel"`
	Status         string `json:"status"`
	Version        string `json:"version"`
	Message        string `json:"message"`
	Detail         string `json:"detail"`
}

// SnellConfig defines the admin-only Snell + ShadowTLS v3 channel configuration.
type SnellConfig struct {
	Enabled         bool   `json:"enabled"`
	Version         string `json:"version"`
	PublicPort      int    `json:"public_port"`
	InnerPort       int    `json:"inner_port"`
	PSK             string `json:"psk"`
	Obfs            string `json:"obfs"`
	TFO             bool   `json:"tfo"`
	DNSIPPreference string `json:"dns_ip_preference"`
	STLSPassword    string `json:"stls_password"`
	STLSSNI         string `json:"stls_sni"`
}

// SSUserEntry defines a single authorized user in sing-box multi-user SS2022 + ShadowTLS v3.
type SSUserEntry struct {
	UserID       int64  `json:"user_id"`
	Username     string `json:"username"`
	UPSK         string `json:"upsk"`
	STLSPassword string `json:"stls_password"`
}

// SSConfig defines the multi-user SS2022 + ShadowTLS v3 channel configuration.
type SSConfig struct {
	Enabled bool          `json:"enabled"`
	TCPPort int           `json:"tcp_port"`
	UDPPort int           `json:"udp_port"`
	Cipher  string        `json:"cipher"`
	IPSK    string        `json:"ipsk"`
	STLSSNI string        `json:"stls_sni"`
	Users   []SSUserEntry `json:"users"`
}

// DNSConfig defines the built-in miekg/dns loopback unlock dispatcher settings.
type DNSConfig struct {
	UnlockEnabled bool     `json:"unlock_enabled"`
	UnlockServer  string   `json:"unlock_server"`
	Rules         []string `json:"rules"`
	UpstreamDNS   string   `json:"upstream_dns"`
	LocalPort     int      `json:"local_port"`
}

// ServerConfigSync delivers the desired node state snapshot (type: "server.config_sync").
type ServerConfigSync struct {
	ConfigRevision int64       `json:"config_revision"`
	Snell          SnellConfig `json:"snell"`
	SS             SSConfig    `json:"ss"`
	DNS            DNSConfig   `json:"dns"`
}

// ServerKernelUpdate instructs the agent to update/rollback a kernel binary (type: "server.kernel_update").
type ServerKernelUpdate struct {
	Kernel      string `json:"kernel"`
	Version     string `json:"version"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256"`
}

// ServerServiceCtl instructs the agent to restart isolated proxy services (type: "server.service_ctl").
type ServerServiceCtl struct {
	Action string `json:"action"`
}
