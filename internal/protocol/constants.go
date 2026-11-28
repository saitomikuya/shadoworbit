package protocol

// WebSocket message types (Envelope.Type).
const (
	MsgTypeAgentHello         = "agent.hello"
	MsgTypeAgentMetrics       = "agent.metrics"
	MsgTypeAgentEvent         = "agent.event"
	MsgTypeServerConfigSync   = "server.config_sync"
	MsgTypeServerKernelUpdate = "server.kernel_update"
	MsgTypeServerServiceCtl   = "server.service_ctl"
)

// Node runtime status values.
const (
	NodeStatusOnline        = "online"
	NodeStatusOffline       = "offline"
	NodeStatusTrafficPaused = "traffic_paused"
)

// Snell protocol versions, obfuscation modes, and DNS IP preferences.
const (
	SnellVersionV4 = "v4"
	SnellVersionV5 = "v5"

	SnellObfsOff  = "off"
	SnellObfsHTTP = "http"
	SnellObfsTLS  = "tls"

	DNSIPPrefPreferIPv4 = "prefer-ipv4"
	DNSIPPrefPreferIPv6 = "prefer-ipv6"
	DNSIPPrefIPv4Only   = "ipv4-only"
	DNSIPPrefAuto       = "auto"
)

// Shadowsocks 2022 ciphers.
const (
	CipherAES128GCM = "2022-blake3-aes-128-gcm"
	CipherAES256GCM = "2022-blake3-aes-256-gcm"
)

// Node traffic accounting count modes.
const (
	TrafficCountBoth   = "both"
	TrafficCountTxOnly = "tx_only"
	TrafficCountRxOnly = "rx_only"
	TrafficCountMaxDir = "max_dir"
)

// Node traffic threshold pause actions.
const (
	ThresholdActionStopAll    = "stop_all"
	ThresholdActionStopSSOnly = "stop_ss_only"
)

// Managed proxy kernels.
const (
	KernelSingBox     = "sing-box"
	KernelSnellServer = "snell-server"
	KernelShadowTLS   = "shadow-tls"
)

// Service control actions (ServerServiceCtl.Action).
const (
	ServiceActionRestartSnell   = "restart_snell"
	ServiceActionRestartSingBox = "restart_singbox"
	ServiceActionRestartAll     = "restart_all"
)

// Agent event types and statuses (AgentEvent.Event / AgentEvent.Status).
const (
	EventConfigApplied        = "config_applied"
	EventConfigError          = "config_error"
	EventProcessCrashed       = "process_crashed"
	EventKernelUpdateProgress = "kernel_update_progress"
	EventKernelUpdateResult   = "kernel_update_result"

	EventStatusSuccess    = "success"
	EventStatusFailed     = "failed"
	EventStatusInProgress = "in_progress"
)

// Subscription client types & targets.
const (
	ClientTypeSurgeAdmin = "surge_admin"
	ClientTypeMihomoUser = "mihomo_user"
	ClientTypeSurgeUser  = "surge_user"

	SubTargetMihomo       = "mihomo"
	SubTargetSurge        = "surge"
	SubTargetShadowrocket = "shadowrocket"
)

// Webhook provider identifiers.
const (
	WebhookProviderFeishu     = "feishu"
	WebhookProviderDingTalk   = "dingtalk"
	WebhookProviderWeCom      = "wecom"
	WebhookProviderServerChan = "serverchan"
	WebhookProviderCustom     = "custom"
)

// DNS Load-Balancing Group strategies.
const (
	LBStrategyRemainingBalance = "remaining_balance"
	LBStrategyFailover         = "failover"
	LBStrategyWeightedMulti    = "weighted_multi"
)

// IsValidNodeStatus reports whether s is a valid node status.
func IsValidNodeStatus(s string) bool {
	return s == NodeStatusOnline || s == NodeStatusOffline || s == NodeStatusTrafficPaused
}

// IsValidSnellVersion reports whether v is a supported Snell version.
func IsValidSnellVersion(v string) bool {
	return v == SnellVersionV4 || v == SnellVersionV5
}

// IsValidSnellObfs reports whether o is a supported Snell obfs mode.
func IsValidSnellObfs(o string) bool {
	return o == SnellObfsOff || o == SnellObfsHTTP || o == SnellObfsTLS
}

// IsValidCipher reports whether c is a supported SS2022 cipher.
func IsValidCipher(c string) bool {
	return c == CipherAES128GCM || c == CipherAES256GCM
}

// IsValidTrafficCountMode reports whether m is a valid traffic accounting mode.
func IsValidTrafficCountMode(m string) bool {
	return m == TrafficCountBoth || m == TrafficCountTxOnly || m == TrafficCountRxOnly || m == TrafficCountMaxDir
}

// IsValidThresholdAction reports whether a is a valid pause action.
func IsValidThresholdAction(a string) bool {
	return a == ThresholdActionStopAll || a == ThresholdActionStopSSOnly
}

// IsValidKernel reports whether k is a managed proxy kernel name.
func IsValidKernel(k string) bool {
	return k == KernelSingBox || k == KernelSnellServer || k == KernelShadowTLS
}

// IsValidServiceAction reports whether a is a valid service control action.
func IsValidServiceAction(a string) bool {
	return a == ServiceActionRestartSnell || a == ServiceActionRestartSingBox || a == ServiceActionRestartAll
}

// IsValidAgentEvent reports whether e is a recognized agent event type.
func IsValidAgentEvent(e string) bool {
	switch e {
	case EventConfigApplied, EventConfigError, EventProcessCrashed, EventKernelUpdateProgress, EventKernelUpdateResult:
		return true
	default:
		return false
	}
}

// IsValidClientType reports whether c is a supported subscription template client type.
func IsValidClientType(c string) bool {
	return c == ClientTypeSurgeAdmin || c == ClientTypeMihomoUser || c == ClientTypeSurgeUser
}

// IsValidWebhookProvider reports whether p is a supported webhook provider.
func IsValidWebhookProvider(p string) bool {
	return p == WebhookProviderFeishu || p == WebhookProviderDingTalk || p == WebhookProviderWeCom || p == WebhookProviderServerChan || p == WebhookProviderCustom
}

// IsValidLBStrategy reports whether s is a supported load-balancing group strategy.
func IsValidLBStrategy(s string) bool {
	return s == LBStrategyRemainingBalance || s == LBStrategyFailover || s == LBStrategyWeightedMulti
}
