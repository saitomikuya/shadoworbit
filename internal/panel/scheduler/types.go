package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"snell-panel/internal/panel/webhook"
)

const (
	defaultSweepInterval           = 15 * time.Second
	defaultGitHubAPIBaseURL        = "https://api.github.com"
	defaultHTTPTimeout             = 20 * time.Second
	defaultWarningThresholdPercent = 85
	trafficCallbackTimeout         = 10 * time.Second

	settingKernelVersionsCache     = "kernel_versions_cache"
	settingCustomSnellVersions     = "custom_snell_versions"
	settingWarningThresholdPercent = "warning_threshold_percent"
	settingAlertUserExpired        = "alert_user_expired"
	settingAlertUserQuotaExhausted = "alert_user_quota_exhausted"

	nodeResetMonthPrefix = "last_node_reset_month:"
	userResetMonthPrefix = "last_user_reset_month:"
)

// Sentinel errors returned by scheduler operations.
var (
	ErrInvalidArgument = errors.New("scheduler: invalid argument")
	ErrNotFound        = errors.New("scheduler: not found")
)

// AlertNotifier dispatches alert events (satisfied directly by *webhook.Engine).
type AlertNotifier interface {
	Notify(ctx context.Context, evt webhook.AlertEvent)
}

// Option configures Scheduler behavior.
type Option func(*Scheduler)

// WithLogger overrides the structured logger used by Scheduler.
func WithLogger(logger *slog.Logger) Option {
	return func(s *Scheduler) {
		if logger != nil {
			s.logger = logger
		}
	}
}

// WithNow overrides the clock function used by Scheduler (defaults to time.Now).
func WithNow(now func() time.Time) Option {
	return func(s *Scheduler) {
		if now != nil {
			s.now = now
		}
	}
}

// WithSweepInterval sets the periodic sweep interval for heartbeats, resets, thresholds, and users.
func WithSweepInterval(d time.Duration) Option {
	return func(s *Scheduler) {
		if d > 0 {
			s.sweepInterval = d
		}
	}
}

// WithKernelSyncInterval sets the periodic GitHub kernel sync interval.
// Default is 0 (disabled) so startup never triggers unsolicited HTTP requests unless configured.
func WithKernelSyncInterval(d time.Duration) Option {
	return func(s *Scheduler) {
		if d >= 0 {
			s.kernelSyncInterval = d
		}
	}
}

// WithGitHubAPIBaseURL overrides the GitHub API base URL (defaults to https://api.github.com).
func WithGitHubAPIBaseURL(baseURL string) Option {
	return func(s *Scheduler) {
		trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
		if trimmed != "" {
			s.githubAPIBaseURL = trimmed
		}
	}
}

// WithHTTPClient overrides the HTTP client used for GitHub API requests.
func WithHTTPClient(client *http.Client) Option {
	return func(s *Scheduler) {
		if client != nil {
			s.httpClient = client
		}
	}
}

// KernelAsset describes a single downloadable Linux kernel binary or archive for a target arch.
type KernelAsset struct {
	Arch        string `json:"arch"`
	Name        string `json:"name"`
	DownloadURL string `json:"download_url"`
	SHA256      string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
}

// KernelRelease represents one upstream kernel release and its Linux amd64/arm64 assets.
type KernelRelease struct {
	Version     string                 `json:"version"`
	TagName     string                 `json:"tag_name"`
	PublishedAt string                 `json:"published_at,omitempty"`
	Assets      map[string]KernelAsset `json:"assets"`
}

// SnellVersionEntry represents a built-in or custom snell-server version URL map.
type SnellVersionEntry struct {
	Version string            `json:"version"`
	Major   string            `json:"major,omitempty"`
	BuiltIn bool              `json:"built_in"`
	URLs    map[string]string `json:"urls"`
}

// KernelVersionsCache is persisted under system_settings["kernel_versions_cache"].
type KernelVersionsCache struct {
	SyncedAt  string          `json:"synced_at,omitempty"`
	SingBox   []KernelRelease `json:"sing_box"`
	ShadowTLS []KernelRelease `json:"shadow_tls"`
}

// KernelCatalog is returned by ListKernels and SyncKernels.
type KernelCatalog struct {
	SyncedAt    string              `json:"synced_at,omitempty"`
	SingBox     []KernelRelease     `json:"sing-box"`
	ShadowTLS   []KernelRelease     `json:"shadow-tls"`
	SnellServer []SnellVersionEntry `json:"snell-server"`
}

// KernelUpdateRequest specifies a single or batch kernel update dispatch request.
type KernelUpdateRequest struct {
	NodeIDs     []int64 `json:"node_ids"`
	Kernel      string  `json:"kernel"`
	Version     string  `json:"version"`
	DownloadURL string  `json:"download_url"`
	SHA256      string  `json:"sha256"`
}

// KernelUpdateNodeResult describes the dispatch outcome for a single node.
type KernelUpdateNodeResult struct {
	NodeID int64  `json:"node_id"`
	Status string `json:"status"` // "dispatched" | "offline" | "failed"
	Error  string `json:"error,omitempty"`
}

// KernelUpdateBatchResult summarizes a single/batch kernel update dispatch.
type KernelUpdateBatchResult struct {
	Dispatched []int64                  `json:"dispatched"`
	Failed     []KernelUpdateNodeResult `json:"failed"`
	Results    []KernelUpdateNodeResult `json:"results"`
}
