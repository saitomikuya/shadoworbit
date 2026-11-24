package collector

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"time"
)

var (
	defaultPublicIPEndpointsV4 = []string{
		"https://api4.ipify.org",
		"https://ipv4.icanhazip.com",
		"https://v4.ident.me",
	}
	defaultPublicIPEndpointsV6 = []string{
		"https://api6.ipify.org",
		"https://ipv6.icanhazip.com",
		"https://v6.ident.me",
	}
)

const (
	publicIPFamilyTimeout   = 3 * time.Second
	publicIPEndpointTimeout = 1500 * time.Millisecond
)

// DetectPublicIPs concurrently queries IPv4 and IPv6 endpoints and returns validated addresses.
// Failures or timeouts are non-blocking and return empty strings.
func (c *Collector) DetectPublicIPs(ctx context.Context) (ipv4 string, ipv6 string) {
	v4Endpoints := c.opts.PublicIPEndpointsV4
	if v4Endpoints == nil {
		v4Endpoints = defaultPublicIPEndpointsV4
	}
	v6Endpoints := c.opts.PublicIPEndpointsV6
	if v6Endpoints == nil {
		v6Endpoints = defaultPublicIPEndpointsV6
	}

	var wg sync.WaitGroup
	if len(v4Endpoints) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipv4 = c.detectFamilyPublicIP(ctx, v4Endpoints, false)
		}()
	}
	if len(v6Endpoints) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ipv6 = c.detectFamilyPublicIP(ctx, v6Endpoints, true)
		}()
	}
	wg.Wait()
	return ipv4, ipv6
}

func (c *Collector) detectFamilyPublicIP(ctx context.Context, endpoints []string, wantV6 bool) string {
	familyCtx, cancel := context.WithTimeout(ctx, publicIPFamilyTimeout)
	defer cancel()

	client, cleanup := c.publicIPClient(wantV6)
	if cleanup != nil {
		defer cleanup()
	}

	for _, ep := range endpoints {
		if familyCtx.Err() != nil {
			return ""
		}
		ep = strings.TrimSpace(ep)
		if ep == "" {
			continue
		}
		if ip := querySinglePublicIP(familyCtx, client, ep, wantV6); ip != "" {
			return ip
		}
	}
	return ""
}

func (c *Collector) publicIPClient(wantV6 bool) (*http.Client, func()) {
	if c.opts.HTTPClient != nil {
		return c.opts.HTTPClient, nil
	}

	dialer := &net.Dialer{Timeout: publicIPEndpointTimeout}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			// Only force tcp4/tcp6 when dialing a hostname; keep "tcp" for IP literals
			// so IPv4 loopback test servers work in IPv6 detection unit tests.
			if _, parseErr := netip.ParseAddr(host); parseErr != nil {
				if wantV6 {
					network = "tcp6"
				} else {
					network = "tcp4"
				}
			}
			return dialer.DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout:   publicIPEndpointTimeout,
		ResponseHeaderTimeout: publicIPEndpointTimeout,
		DisableKeepAlives:     true,
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   publicIPEndpointTimeout,
	}
	return client, tr.CloseIdleConnections
}

func querySinglePublicIP(ctx context.Context, client *http.Client, endpoint string, wantV6 bool) string {
	u, err := url.Parse(endpoint)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}

	reqCtx, cancel := context.WithTimeout(ctx, publicIPEndpointTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "snell-panel-agent/1.0")

	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ""
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256))
	if err != nil {
		return ""
	}
	return validatePublicIP(string(body), wantV6)
}

func validatePublicIP(raw string, wantV6 bool) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil || !addr.IsValid() ||
		addr.IsUnspecified() ||
		addr.IsMulticast() ||
		addr.IsLoopback() ||
		addr.IsPrivate() ||
		addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() ||
		addr.IsInterfaceLocalMulticast() ||
		!addr.IsGlobalUnicast() ||
		addr.Zone() != "" {
		return ""
	}
	if wantV6 {
		if !addr.Is6() || addr.Is4In6() {
			return ""
		}
		return addr.String()
	}
	if !addr.Is4() {
		return ""
	}
	return addr.String()
}
