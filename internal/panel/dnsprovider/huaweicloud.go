package dnsprovider

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	huaweiSignAlgorithm = "SDK-HMAC-SHA256"
	huaweiHeaderDate    = "X-Sdk-Date"
	huaweiDefaultLine   = "default_view"
	huaweiRecordDesc    = "Managed by ShadowOrbit DNS LB"
)

// HuaweiCloudClient implements Provider against Huawei Cloud International DNS API v2/v2.1
// using SDK-HMAC-SHA256 AK/SK request signing.
type HuaweiCloudClient struct {
	baseURL    string
	host       string
	ak         string
	sk         string
	httpClient *http.Client
	now        func() time.Time
}

// HuaweiCloudOption configures HuaweiCloudClient.
type HuaweiCloudOption func(*HuaweiCloudClient)

// WithHTTPClient overrides the HTTP client used by HuaweiCloudClient.
func WithHTTPClient(c *http.Client) HuaweiCloudOption {
	return func(cl *HuaweiCloudClient) {
		if c != nil {
			cl.httpClient = c
		}
	}
}

// WithNow overrides the clock function used for X-Sdk-Date signing headers.
func WithNow(fn func() time.Time) HuaweiCloudOption {
	return func(cl *HuaweiCloudClient) {
		if fn != nil {
			cl.now = fn
		}
	}
}

// NewHuaweiCloudClient constructs a Huawei Cloud DNS API client.
func NewHuaweiCloudClient(endpoint, ak, sk string, opts ...HuaweiCloudOption) (*HuaweiCloudClient, error) {
	ep := strings.TrimSpace(endpoint)
	if ep == "" {
		ep = DefaultHuaweiCloudEndpoint
	}
	ep = strings.TrimRight(ep, "/")
	u, err := url.Parse(ep)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("dnsprovider: invalid huaweicloud endpoint %q", endpoint)
	}
	ak = strings.TrimSpace(ak)
	sk = strings.TrimSpace(sk)
	if ak == "" || sk == "" {
		return nil, errors.New("dnsprovider: huaweicloud AK and SK are required")
	}

	cl := &HuaweiCloudClient{
		baseURL:    ep,
		host:       u.Host,
		ak:         ak,
		sk:         sk,
		httpClient: &http.Client{Timeout: 15 * time.Second},
		now:        time.Now,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(cl)
		}
	}
	return cl, nil
}

// ListPublicZones fetches all public hosted zones visible under the AK/SK account.
func (c *HuaweiCloudClient) ListPublicZones(ctx context.Context) ([]Zone, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var out []Zone
	marker := ""
	for page := 0; page < 20; page++ {
		q := url.Values{}
		q.Set("type", "public")
		q.Set("limit", "500")
		if marker != "" {
			q.Set("marker", marker)
		}

		var resp struct {
			Zones []struct {
				ID        string `json:"id"`
				Name      string `json:"name"`
				Status    string `json:"status"`
				TTL       int    `json:"ttl"`
				RecordNum int    `json:"record_num"`
			} `json:"zones"`
		}
		if err := c.doJSON(ctx, http.MethodGet, "/v2/zones", q, nil, &resp); err != nil {
			return nil, err
		}
		for _, z := range resp.Zones {
			out = append(out, Zone{
				ID:        z.ID,
				Name:      StripTrailingDot(z.Name),
				Status:    z.Status,
				TTL:       z.TTL,
				RecordNum: z.RecordNum,
			})
		}
		if len(resp.Zones) < 500 {
			break
		}
		marker = resp.Zones[len(resp.Zones)-1].ID
		if marker == "" {
			break
		}
	}
	return out, nil
}

// ListRecordSets lists recordsets in zoneID matching fqdn and recordType.
func (c *HuaweiCloudClient) ListRecordSets(ctx context.Context, zoneID, fqdn, recordType string) ([]RecordSet, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	zoneID = strings.TrimSpace(zoneID)
	if zoneID == "" {
		return nil, errors.New("dnsprovider: zone_id is required")
	}
	targetFQDN := EnsureTrailingDot(fqdn)
	if targetFQDN == "" {
		return nil, errors.New("dnsprovider: fqdn is required")
	}
	recordType = strings.ToUpper(strings.TrimSpace(recordType))
	if recordType == "" {
		recordType = "A"
	}

	q := url.Values{}
	q.Set("name", targetFQDN)
	q.Set("type", recordType)
	q.Set("search_mode", "equal")
	q.Set("limit", "500")

	var resp struct {
		Recordsets []RecordSet `json:"recordsets"`
	}
	if err := c.doJSON(ctx, http.MethodGet, "/v2.1/zones/"+url.PathEscape(zoneID)+"/recordsets", q, nil, &resp); err != nil {
		return nil, err
	}

	filtered := make([]RecordSet, 0, len(resp.Recordsets))
	for _, rs := range resp.Recordsets {
		if strings.EqualFold(EnsureTrailingDot(rs.Name), targetFQDN) && strings.EqualFold(rs.Type, recordType) {
			filtered = append(filtered, rs)
		}
	}
	return filtered, nil
}

// SyncARecords reconciles the zone's A recordsets for fqdn against desired targets.
// When weighted is false, a single non-weighted A recordset is maintained.
// When weighted is true, one weighted A recordset per IP on default_view is maintained.
func (c *HuaweiCloudClient) SyncARecords(
	ctx context.Context,
	zoneID, fqdn string,
	ttl int,
	weighted bool,
	desired []DesiredRecord,
) ([]SyncedRecord, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	zoneID = strings.TrimSpace(zoneID)
	if zoneID == "" {
		return nil, errors.New("dnsprovider: zone_id is required")
	}
	targetFQDN := EnsureTrailingDot(fqdn)
	if targetFQDN == "" {
		return nil, errors.New("dnsprovider: fqdn is required")
	}
	if ttl <= 0 {
		ttl = 60
	}
	if len(desired) == 0 {
		return nil, errors.New("dnsprovider: desired records cannot be empty")
	}

	existing, err := c.ListRecordSets(ctx, zoneID, targetFQDN, "A")
	if err != nil {
		return nil, err
	}

	if !weighted {
		targetIP := strings.TrimSpace(desired[0].IP)
		if targetIP == "" {
			return nil, errors.New("dnsprovider: desired IP cannot be empty")
		}

		// Filter default_view or empty-line A recordsets.
		var matching []RecordSet
		for _, rs := range existing {
			if rs.Line == "" || rs.Line == huaweiDefaultLine || rs.Line == "default" {
				matching = append(matching, rs)
			}
		}

		if len(matching) == 1 && matching[0].Weight == nil {
			rs := matching[0]
			if len(rs.Records) == 1 && rs.Records[0] == targetIP && rs.TTL == ttl {
				return []SyncedRecord{{
					IP:          targetIP,
					RecordSetID: rs.ID,
				}}, nil
			}
			updated, err := c.updateRecordSet(ctx, zoneID, rs.ID, targetFQDN, ttl, []string{targetIP}, nil)
			if err != nil {
				return nil, err
			}
			return []SyncedRecord{{
				IP:          targetIP,
				RecordSetID: updated.ID,
			}}, nil
		}

		for _, rs := range matching {
			if err := c.deleteRecordSet(ctx, zoneID, rs.ID); err != nil {
				return nil, err
			}
		}
		created, err := c.createRecordSet(ctx, zoneID, targetFQDN, ttl, []string{targetIP}, nil)
		if err != nil {
			return nil, err
		}
		return []SyncedRecord{{
			IP:          targetIP,
			RecordSetID: created.ID,
		}}, nil
	}

	// Weighted multi-IP mode: maintain one weighted recordset per desired IP on default_view.
	desiredByIP := make(map[string]int, len(desired))
	orderedIPs := make([]string, 0, len(desired))
	for _, d := range desired {
		ip := strings.TrimSpace(d.IP)
		if ip == "" {
			continue
		}
		w := d.Weight
		if w < 1 {
			w = 1
		}
		if w > 1000 {
			w = 1000
		}
		if _, exists := desiredByIP[ip]; !exists {
			orderedIPs = append(orderedIPs, ip)
		}
		desiredByIP[ip] = w
	}
	if len(orderedIPs) == 0 {
		return nil, errors.New("dnsprovider: desired weighted records contain no valid IPs")
	}

	keptByIP := make(map[string]RecordSet, len(orderedIPs))
	for _, rs := range existing {
		if rs.Line != "" && rs.Line != huaweiDefaultLine && rs.Line != "default" {
			continue
		}
		if rs.Weight == nil || len(rs.Records) != 1 {
			if err := c.deleteRecordSet(ctx, zoneID, rs.ID); err != nil {
				return nil, err
			}
			continue
		}
		ip := rs.Records[0]
		if _, want := desiredByIP[ip]; !want {
			if err := c.deleteRecordSet(ctx, zoneID, rs.ID); err != nil {
				return nil, err
			}
			continue
		}
		if _, dup := keptByIP[ip]; dup {
			if err := c.deleteRecordSet(ctx, zoneID, rs.ID); err != nil {
				return nil, err
			}
			continue
		}
		keptByIP[ip] = rs
	}

	result := make([]SyncedRecord, 0, len(orderedIPs))
	for _, ip := range orderedIPs {
		w := desiredByIP[ip]
		if cur, ok := keptByIP[ip]; ok {
			if cur.TTL == ttl && cur.Weight != nil && *cur.Weight == w {
				result = append(result, SyncedRecord{
					IP:          ip,
					Weight:      w,
					RecordSetID: cur.ID,
				})
				continue
			}
			updated, err := c.updateRecordSet(ctx, zoneID, cur.ID, targetFQDN, ttl, []string{ip}, &w)
			if err != nil {
				return nil, err
			}
			result = append(result, SyncedRecord{
				IP:          ip,
				Weight:      w,
				RecordSetID: updated.ID,
			})
			continue
		}
		created, err := c.createRecordSet(ctx, zoneID, targetFQDN, ttl, []string{ip}, &w)
		if err != nil {
			return nil, err
		}
		result = append(result, SyncedRecord{
			IP:          ip,
			Weight:      w,
			RecordSetID: created.ID,
		})
	}
	return result, nil
}

type recordSetMutateBody struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Type        string   `json:"type"`
	TTL         int      `json:"ttl"`
	Records     []string `json:"records"`
	Line        string   `json:"line,omitempty"`
	Weight      *int     `json:"weight,omitempty"`
}

func (c *HuaweiCloudClient) createRecordSet(
	ctx context.Context,
	zoneID, fqdn string,
	ttl int,
	records []string,
	weight *int,
) (*RecordSet, error) {
	body := recordSetMutateBody{
		Name:        fqdn,
		Description: huaweiRecordDesc,
		Type:        "A",
		TTL:         ttl,
		Records:     records,
		Line:        huaweiDefaultLine,
		Weight:      weight,
	}
	var rs RecordSet
	if err := c.doJSON(ctx, http.MethodPost, "/v2.1/zones/"+url.PathEscape(zoneID)+"/recordsets", nil, body, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *HuaweiCloudClient) updateRecordSet(
	ctx context.Context,
	zoneID, recordSetID, fqdn string,
	ttl int,
	records []string,
	weight *int,
) (*RecordSet, error) {
	body := recordSetMutateBody{
		Name:        fqdn,
		Description: huaweiRecordDesc,
		Type:        "A",
		TTL:         ttl,
		Records:     records,
		Weight:      weight,
	}
	var rs RecordSet
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(recordSetID)
	if err := c.doJSON(ctx, http.MethodPut, path, nil, body, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

func (c *HuaweiCloudClient) deleteRecordSet(ctx context.Context, zoneID, recordSetID string) error {
	path := "/v2.1/zones/" + url.PathEscape(zoneID) + "/recordsets/" + url.PathEscape(recordSetID)
	return c.doJSON(ctx, http.MethodDelete, path, nil, nil, nil)
}

func (c *HuaweiCloudClient) doJSON(
	ctx context.Context,
	method, path string,
	query url.Values,
	reqBody any,
	respBody any,
) error {
	var bodyBytes []byte
	if reqBody != nil {
		b, err := json.Marshal(reqBody)
		if err != nil {
			return fmt.Errorf("dnsprovider: marshal request: %w", err)
		}
		bodyBytes = b
	}

	fullURL := c.baseURL + path
	if len(query) > 0 {
		fullURL += "?" + query.Encode()
	}

	var bodyReader io.Reader
	if len(bodyBytes) > 0 {
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return fmt.Errorf("dnsprovider: build request: %w", err)
	}

	c.signRequest(req, bodyBytes, c.now().UTC())

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("dnsprovider: huaweicloud request failed: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return fmt.Errorf("dnsprovider: read huaweicloud response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return formatHuaweiError(resp.StatusCode, raw)
	}

	if respBody != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, respBody); err != nil {
			return fmt.Errorf("dnsprovider: decode huaweicloud response: %w", err)
		}
	}
	return nil
}

func formatHuaweiError(status int, raw []byte) error {
	var errPayload struct {
		ErrorCode string `json:"error_code"`
		ErrorMsg  string `json:"error_msg"`
		Message   string `json:"message"`
		Code      string `json:"code"`
	}
	if json.Unmarshal(raw, &errPayload) == nil {
		code := errPayload.ErrorCode
		if code == "" {
			code = errPayload.Code
		}
		msg := errPayload.ErrorMsg
		if msg == "" {
			msg = errPayload.Message
		}
		if code != "" || msg != "" {
			return fmt.Errorf("huaweicloud dns api HTTP %d (%s): %s", status, code, msg)
		}
	}
	snippet := strings.TrimSpace(string(raw))
	if len(snippet) > 300 {
		snippet = snippet[:300] + "..."
	}
	if snippet == "" {
		snippet = http.StatusText(status)
	}
	return fmt.Errorf("huaweicloud dns api HTTP %d: %s", status, snippet)
}

func (c *HuaweiCloudClient) signRequest(req *http.Request, body []byte, now time.Time) {
	sdkDate := now.UTC().Format("20060102T150405Z")
	req.Host = c.host
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Host", c.host)
	req.Header.Set(huaweiHeaderDate, sdkDate)

	canonicalURI := buildCanonicalURI(req.URL.Path)
	canonicalQuery := buildCanonicalQuery(req.URL.Query())
	canonicalHeaders, signedHeaders := buildCanonicalHeaders(req.Header)
	payloadHash := sha256Hex(body)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		payloadHash,
	}, "\n")

	stringToSign := strings.Join([]string{
		huaweiSignAlgorithm,
		sdkDate,
		sha256Hex([]byte(canonicalRequest)),
	}, "\n")

	mac := hmac.New(sha256.New, []byte(c.sk))
	_, _ = mac.Write([]byte(stringToSign))
	sig := hex.EncodeToString(mac.Sum(nil))

	authHeader := fmt.Sprintf("%s Access=%s, SignedHeaders=%s, Signature=%s",
		huaweiSignAlgorithm, c.ak, signedHeaders, sig,
	)
	req.Header.Set("Authorization", authHeader)
}

func buildCanonicalURI(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	rawSegs := strings.Split(path, "/")
	escaped := make([]string, 0, len(rawSegs))
	for _, seg := range rawSegs {
		if seg == "" {
			continue
		}
		escaped = append(escaped, rfc3986Escape(seg))
	}
	if len(escaped) == 0 {
		return "/"
	}
	return "/" + strings.Join(escaped, "/") + "/"
}

func buildCanonicalQuery(values url.Values) string {
	if len(values) == 0 {
		return ""
	}
	type kv struct {
		k string
		v string
	}
	pairs := make([]kv, 0, len(values))
	for k, vs := range values {
		ek := rfc3986Escape(k)
		if len(vs) == 0 {
			pairs = append(pairs, kv{k: ek, v: ""})
			continue
		}
		for _, v := range vs {
			pairs = append(pairs, kv{k: ek, v: rfc3986Escape(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	parts := make([]string, len(pairs))
	for i, p := range pairs {
		parts[i] = p.k + "=" + p.v
	}
	return strings.Join(parts, "&")
}

func buildCanonicalHeaders(h http.Header) (string, string) {
	keys := []string{"content-type", "host", "x-sdk-date"}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		val := strings.TrimSpace(h.Get(k))
		b.WriteString(k)
		b.WriteByte(':')
		b.WriteString(val)
		b.WriteByte('\n')
	}
	return b.String(), strings.Join(keys, ";")
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func rfc3986Escape(s string) string {
	const hexDigits = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexDigits[c>>4])
			b.WriteByte(hexDigits[c&0x0F])
		}
	}
	return b.String()
}
