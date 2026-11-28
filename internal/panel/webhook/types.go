package webhook

import (
	"errors"
	"strings"
	"time"
)

// Canonical alert event types.
const (
	EventNodeOffline        = "node_offline"
	EventNodeOnline         = "node_online"
	EventProcessCrashed     = "process_crashed"
	EventKernelUpdate       = "kernel_update"
	EventConfigError        = "config_error"
	EventTrafficWarning     = "traffic_warning"
	EventTrafficPaused      = "traffic_paused"
	EventTrafficRecovered   = "traffic_recovered"
	EventUserQuotaExhausted = "user_quota_exhausted"
	EventUserExpired        = "user_expired"
	EventHighResourceUsage  = "high_resource_usage"
	EventDNSLBSwitched      = "dns_lb_switched"
	EventDNSLBFailover      = "dns_lb_failover"
	EventDNSLBExhausted     = "dns_lb_exhausted"
	EventTest               = "test" // synthetic event used by SendTest
)

// Canonical severity levels.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Target types used in AlertEvent.TargetType.
const (
	TargetTypeNode    = "node"
	TargetTypeUser    = "user"
	TargetTypeSystem  = "system"
	TargetTypeLBGroup = "lb_group"
)

// Sentinel errors returned by webhook validation and delivery.
var (
	ErrInvalidURL          = errors.New("webhook: invalid webhook url")
	ErrUnsupportedProvider = errors.New("webhook: unsupported provider")
	ErrInvalidSecretConfig = errors.New("webhook: invalid custom secret/header/template config")
	ErrProviderResponse    = errors.New("webhook: provider returned error response")
	ErrPrivateIPBlocked    = errors.New("webhook: private or loopback IP blocked")
)

// AlertEvent represents a normalized panel or agent alert notification.
type AlertEvent struct {
	Type       string    `json:"type"`
	Severity   string    `json:"severity"`
	TargetType string    `json:"target_type"`
	TargetID   int64     `json:"target_id"`
	TargetName string    `json:"target_name"`
	Title      string    `json:"title"`
	Message    string    `json:"message"`
	Detail     string    `json:"detail"`
	Resolved   bool      `json:"resolved"`
	Timestamp  time.Time `json:"timestamp"`
}

// AllEventTypes returns the 14 canonical subscribable alert event types.
func AllEventTypes() []string {
	return []string{
		EventNodeOffline,
		EventNodeOnline,
		EventProcessCrashed,
		EventKernelUpdate,
		EventConfigError,
		EventTrafficWarning,
		EventTrafficPaused,
		EventTrafficRecovered,
		EventUserQuotaExhausted,
		EventUserExpired,
		EventHighResourceUsage,
		EventDNSLBSwitched,
		EventDNSLBFailover,
		EventDNSLBExhausted,
	}
}

// IsValidEventType reports whether t is one of the 14 canonical alert event types.
func IsValidEventType(t string) bool {
	switch t {
	case EventNodeOffline,
		EventNodeOnline,
		EventProcessCrashed,
		EventKernelUpdate,
		EventConfigError,
		EventTrafficWarning,
		EventTrafficPaused,
		EventTrafficRecovered,
		EventUserQuotaExhausted,
		EventUserExpired,
		EventHighResourceUsage,
		EventDNSLBSwitched,
		EventDNSLBFailover,
		EventDNSLBExhausted:
		return true
	default:
		return false
	}
}

// IsValidSubscriptionEvent reports whether t is a valid subscription entry ("*", "all", or canonical event).
func IsValidSubscriptionEvent(t string) bool {
	s := strings.ToLower(strings.TrimSpace(t))
	return s == "*" || s == "all" || IsValidEventType(s)
}

// IsValidSeverity reports whether s is a valid alert severity.
func IsValidSeverity(s string) bool {
	switch s {
	case SeverityInfo, SeverityWarning, SeverityCritical:
		return true
	default:
		return false
	}
}

func normalizeEvent(evt AlertEvent, now func() time.Time) AlertEvent {
	evt.Type = strings.TrimSpace(evt.Type)
	evt.Severity = strings.ToLower(strings.TrimSpace(evt.Severity))
	if !IsValidSeverity(evt.Severity) {
		switch {
		case evt.Resolved:
			evt.Severity = SeverityInfo
		case evt.Type == EventNodeOffline || evt.Type == EventProcessCrashed || evt.Type == EventTrafficPaused || evt.Type == EventDNSLBExhausted:
			evt.Severity = SeverityCritical
		default:
			evt.Severity = SeverityWarning
		}
	}
	evt.TargetType = strings.TrimSpace(evt.TargetType)
	evt.TargetName = strings.TrimSpace(evt.TargetName)
	if evt.Title == "" {
		evt.Title = evt.Type
	}
	if evt.Timestamp.IsZero() {
		if now != nil {
			evt.Timestamp = now().UTC()
		} else {
			evt.Timestamp = time.Now().UTC()
		}
	} else {
		evt.Timestamp = evt.Timestamp.UTC()
	}
	return evt
}
