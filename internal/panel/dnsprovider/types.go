package dnsprovider

import (
	"context"
	"strings"
)

// DefaultHuaweiCloudEndpoint is the default Huawei Cloud International DNS API endpoint (Hong Kong).
const DefaultHuaweiCloudEndpoint = "https://dns.ap-southeast-1.myhuaweicloud.com"

// Zone describes a public DNS hosted zone returned by the DNS provider.
type Zone struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Status    string `json:"status"`
	TTL       int    `json:"ttl"`
	RecordNum int    `json:"record_num"`
}

// RecordSet represents an existing DNS recordset on the provider.
type RecordSet struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Type        string   `json:"type"`
	TTL         int      `json:"ttl"`
	Records     []string `json:"records"`
	Line        string   `json:"line"`
	Weight      *int     `json:"weight,omitempty"`
	Status      string   `json:"status"`
	Description string   `json:"description,omitempty"`
}

// DesiredRecord specifies one target IPv4 address (and optional weight) to sync.
type DesiredRecord struct {
	IP     string
	Weight int
}

// SyncedRecord describes a resulting provider recordset after synchronization.
type SyncedRecord struct {
	IP          string `json:"ip"`
	Weight      int    `json:"weight,omitempty"`
	RecordSetID string `json:"recordset_id,omitempty"`
}

// Provider abstracts DNS zone listing and A-record synchronization operations.
type Provider interface {
	ListPublicZones(ctx context.Context) ([]Zone, error)
	ListRecordSets(ctx context.Context, zoneID, fqdn, recordType string) ([]RecordSet, error)
	SyncARecords(ctx context.Context, zoneID, fqdn string, ttl int, weighted bool, desired []DesiredRecord) ([]SyncedRecord, error)
}

// EnsureTrailingDot normalizes a domain name to lowercase with a trailing dot.
func EnsureTrailingDot(domain string) string {
	trimmed := strings.TrimSpace(strings.ToLower(domain))
	if trimmed == "" {
		return ""
	}
	if !strings.HasSuffix(trimmed, ".") {
		return trimmed + "."
	}
	return trimmed
}

// StripTrailingDot normalizes a domain name to lowercase without a trailing dot.
func StripTrailingDot(domain string) string {
	trimmed := strings.TrimSpace(strings.ToLower(domain))
	return strings.TrimSuffix(trimmed, ".")
}
