package scheduler

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"snell-panel/internal/panel/hub"
	"snell-panel/internal/panel/store"
	"snell-panel/internal/protocol"
)

const maxGitHubResponseBytes = 16 << 20 // 16 MiB

var builtInSnellVersions = []SnellVersionEntry{
	{
		Version: "v5.0.0",
		Major:   protocol.SnellVersionV5,
		BuiltIn: true,
		URLs: map[string]string{
			"amd64": "https://dl.nssurge.com/snell/snell-server-v5.0.0-linux-amd64.zip",
			"arm64": "https://dl.nssurge.com/snell/snell-server-v5.0.0-linux-aarch64.zip",
		},
	},
	{
		Version: "v4.1.1",
		Major:   protocol.SnellVersionV4,
		BuiltIn: true,
		URLs: map[string]string{
			"amd64": "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-amd64.zip",
			"arm64": "https://dl.nssurge.com/snell/snell-server-v4.1.1-linux-aarch64.zip",
		},
	},
}

func builtInSnellList() []SnellVersionEntry {
	out := make([]SnellVersionEntry, 0, len(builtInSnellVersions))
	for _, entry := range builtInSnellVersions {
		urls := make(map[string]string, len(entry.URLs))
		for k, v := range entry.URLs {
			urls[k] = v
		}
		out = append(out, SnellVersionEntry{
			Version: entry.Version,
			Major:   entry.Major,
			BuiltIn: true,
			URLs:    urls,
		})
	}
	return out
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Draft       bool      `json:"draft"`
	Prerelease  bool      `json:"prerelease"`
	PublishedAt string    `json:"published_at"`
	Assets      []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	Size               int64  `json:"size"`
	Digest             string `json:"digest"`
}

// ListKernels reads the cached GitHub kernel releases and built-in/custom snell-server
// version maps from system_settings.
func (s *Scheduler) ListKernels(ctx context.Context) (*KernelCatalog, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	cache, err := s.readKernelCache(ctx)
	if err != nil {
		return nil, err
	}
	snellList, err := s.ListSnellVersions(ctx)
	if err != nil {
		return nil, err
	}

	return &KernelCatalog{
		SyncedAt:    cache.SyncedAt,
		SingBox:     cache.SingBox,
		ShadowTLS:   cache.ShadowTLS,
		SnellServer: snellList,
	}, nil
}

// SyncKernels fetches the latest GitHub releases for SagerNet/sing-box and ihciah/shadow-tls,
// parses Linux amd64/arm64 assets in memory, and atomically updates kernel_versions_cache
// only when both repository fetches and parses succeed.
func (s *Scheduler) SyncKernels(ctx context.Context) (*KernelCatalog, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	singBox, err := s.fetchGitHubReleases(ctx, "SagerNet", "sing-box")
	if err != nil {
		return nil, fmt.Errorf("sync sing-box releases: %w", err)
	}
	shadowTLS, err := s.fetchGitHubReleases(ctx, "ihciah", "shadow-tls")
	if err != nil {
		return nil, fmt.Errorf("sync shadow-tls releases: %w", err)
	}

	cache := KernelVersionsCache{
		SyncedAt:  s.now().UTC().Format(time.RFC3339),
		SingBox:   singBox,
		ShadowTLS: shadowTLS,
	}
	raw, err := json.Marshal(cache)
	if err != nil {
		return nil, err
	}
	if err := s.store.SetSetting(ctx, settingKernelVersionsCache, string(raw)); err != nil {
		return nil, err
	}

	snellList, err := s.ListSnellVersions(ctx)
	if err != nil {
		return nil, err
	}

	return &KernelCatalog{
		SyncedAt:    cache.SyncedAt,
		SingBox:     cache.SingBox,
		ShadowTLS:   cache.ShadowTLS,
		SnellServer: snellList,
	}, nil
}

// ListSnellVersions returns built-in snell-server v4/v5 entries followed by custom versions.
func (s *Scheduler) ListSnellVersions(ctx context.Context) ([]SnellVersionEntry, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	custom, err := s.readCustomSnellVersions(ctx)
	if err != nil {
		return nil, err
	}

	out := builtInSnellList()
	out = append(out, custom...)
	return out, nil
}

// AddCustomSnellVersion validates and persists a custom snell-server version URL map.
func (s *Scheduler) AddCustomSnellVersion(ctx context.Context, version string, urls map[string]string) (*SnellVersionEntry, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if hasControlChar(version) {
		return nil, fmt.Errorf("%w: invalid version %q", ErrInvalidArgument, version)
	}
	cleanVer := strings.TrimSpace(version)
	normVer := normalizeVersionKey(cleanVer)
	if cleanVer == "" || normVer == "" || hasControlOrWhitespace(cleanVer) {
		return nil, fmt.Errorf("%w: invalid version %q", ErrInvalidArgument, version)
	}
	for _, b := range builtInSnellVersions {
		if versionMatches(b.Version, b.Version, normVer) {
			return nil, fmt.Errorf("%w: cannot overwrite built-in snell version %q", ErrInvalidArgument, b.Version)
		}
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("%w: urls map cannot be empty", ErrInvalidArgument)
	}
	normURLs := make(map[string]string, len(urls))
	for rawArch, rawURL := range urls {
		arch, ok := normalizeStrictArch(rawArch)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported arch %q", ErrInvalidArgument, rawArch)
		}
		cleanURL := strings.TrimSpace(rawURL)
		if !isValidHTTPURL(cleanURL) {
			return nil, fmt.Errorf("%w: invalid download url %q", ErrInvalidArgument, rawURL)
		}
		if _, dup := normURLs[arch]; dup {
			return nil, fmt.Errorf("%w: duplicate normalized arch %q", ErrInvalidArgument, arch)
		}
		normURLs[arch] = cleanURL
	}

	entry := SnellVersionEntry{
		Version: cleanVer,
		Major:   inferSnellMajor(cleanVer),
		BuiltIn: false,
		URLs:    normURLs,
	}

	s.kernelsMu.Lock()
	defer s.kernelsMu.Unlock()

	custom, err := s.readCustomSnellVersions(ctx)
	if err != nil {
		return nil, err
	}

	filtered := make([]SnellVersionEntry, 0, len(custom)+1)
	replaced := false
	for _, item := range custom {
		if versionMatches(item.Version, item.Version, normVer) {
			if !replaced {
				filtered = append(filtered, entry)
				replaced = true
			}
			continue
		}
		filtered = append(filtered, item)
	}
	if !replaced {
		filtered = append(filtered, entry)
	}
	custom = filtered
	slices.SortFunc(custom, func(a, b SnellVersionEntry) int {
		return strings.Compare(a.Version, b.Version)
	})

	if err := s.writeCustomSnellVersions(ctx, custom); err != nil {
		return nil, err
	}

	copyEntry := entry
	copyEntry.URLs = mapsClone(entry.URLs)
	return &copyEntry, nil
}

// DeleteCustomSnellVersion deletes a custom snell-server version from system_settings.
func (s *Scheduler) DeleteCustomSnellVersion(ctx context.Context, version string) error {
	if s.store == nil {
		return errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if hasControlChar(version) {
		return fmt.Errorf("%w: invalid version %q", ErrInvalidArgument, version)
	}
	cleanVer := strings.TrimSpace(version)
	normVer := normalizeVersionKey(cleanVer)
	if cleanVer == "" || normVer == "" || hasControlOrWhitespace(cleanVer) {
		return fmt.Errorf("%w: invalid version %q", ErrInvalidArgument, version)
	}
	for _, b := range builtInSnellVersions {
		if versionMatches(b.Version, b.Version, normVer) {
			return fmt.Errorf("%w: cannot delete built-in snell version %q", ErrInvalidArgument, b.Version)
		}
	}

	s.kernelsMu.Lock()
	defer s.kernelsMu.Unlock()

	custom, err := s.readCustomSnellVersions(ctx)
	if err != nil {
		return err
	}

	filtered := make([]SnellVersionEntry, 0, len(custom))
	found := false
	for _, item := range custom {
		if versionMatches(item.Version, item.Version, normVer) {
			found = true
			continue
		}
		filtered = append(filtered, item)
	}
	if !found {
		return fmt.Errorf("%w: custom snell version %q", ErrNotFound, cleanVer)
	}

	return s.writeCustomSnellVersions(ctx, filtered)
}

// DispatchKernelUpdate validates req, resolves per-node download URLs when DownloadURL is omitted,
// dispatches server.kernel_update to each unique node via Hub, and returns structured per-node results
// without aborting the batch when individual nodes are offline.
func (s *Scheduler) DispatchKernelUpdate(ctx context.Context, req KernelUpdateRequest) (*KernelUpdateBatchResult, error) {
	if s.store == nil {
		return nil, errors.New("scheduler: nil store")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if len(req.NodeIDs) == 0 {
		return nil, fmt.Errorf("%w: node_ids cannot be empty", ErrInvalidArgument)
	}
	if !protocol.IsValidKernel(req.Kernel) {
		return nil, fmt.Errorf("%w: invalid kernel %q", ErrInvalidArgument, req.Kernel)
	}
	if hasControlChar(req.Version) {
		return nil, fmt.Errorf("%w: invalid version %q", ErrInvalidArgument, req.Version)
	}
	version := strings.TrimSpace(req.Version)
	if version == "" || hasControlOrWhitespace(version) {
		return nil, fmt.Errorf("%w: invalid version %q", ErrInvalidArgument, req.Version)
	}

	sha := strings.ToLower(strings.TrimSpace(req.SHA256))
	if sha != "" && !isValidSHA256Hex(sha) {
		return nil, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidArgument)
	}

	explicitURL := strings.TrimSpace(req.DownloadURL)
	if explicitURL != "" && !isValidHTTPURL(explicitURL) {
		return nil, fmt.Errorf("%w: invalid download_url %q", ErrInvalidArgument, req.DownloadURL)
	}

	seen := make(map[int64]struct{}, len(req.NodeIDs))
	uniqueNodeIDs := make([]int64, 0, len(req.NodeIDs))
	for _, nid := range req.NodeIDs {
		if nid <= 0 {
			return nil, fmt.Errorf("%w: invalid node id %d", ErrInvalidArgument, nid)
		}
		if _, ok := seen[nid]; ok {
			continue
		}
		seen[nid] = struct{}{}
		uniqueNodeIDs = append(uniqueNodeIDs, nid)
	}

	var catalog *KernelCatalog
	if explicitURL == "" {
		var err error
		catalog, err = s.ListKernels(ctx)
		if err != nil {
			return nil, err
		}
	}

	res := &KernelUpdateBatchResult{
		Dispatched: []int64{},
		Failed:     []KernelUpdateNodeResult{},
		Results:    []KernelUpdateNodeResult{},
	}

	for _, nid := range uniqueNodeIDs {
		node, err := s.store.GetNodeByID(ctx, nid)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				nr := KernelUpdateNodeResult{NodeID: nid, Status: "failed", Error: "node not found"}
				res.Failed = append(res.Failed, nr)
				res.Results = append(res.Results, nr)
				continue
			}
			return nil, err
		}

		downloadURL := explicitURL
		resolvedSHA := sha
		if downloadURL == "" {
			arch := s.resolveNodeArch(node)
			var autoSHA string
			var found bool
			downloadURL, autoSHA, found = resolveCatalogDownload(catalog, req.Kernel, version, arch)
			if !found {
				nr := KernelUpdateNodeResult{
					NodeID: nid,
					Status: "failed",
					Error:  fmt.Sprintf("no %s %s artifact found for arch %s", req.Kernel, version, arch),
				}
				res.Failed = append(res.Failed, nr)
				res.Results = append(res.Results, nr)
				continue
			}
			if resolvedSHA == "" {
				resolvedSHA = autoSHA
			}
		}

		if s.hub == nil {
			nr := KernelUpdateNodeResult{NodeID: nid, Status: "offline", Error: hub.ErrNodeOffline.Error()}
			res.Failed = append(res.Failed, nr)
			res.Results = append(res.Results, nr)
			continue
		}

		cmd := protocol.ServerKernelUpdate{
			Kernel:      req.Kernel,
			Version:     version,
			DownloadURL: downloadURL,
			SHA256:      resolvedSHA,
		}
		err = s.hub.SendKernelUpdate(ctx, nid, cmd)
		switch {
		case err == nil:
			res.Dispatched = append(res.Dispatched, nid)
			res.Results = append(res.Results, KernelUpdateNodeResult{NodeID: nid, Status: "dispatched"})
		case errors.Is(err, hub.ErrNodeOffline):
			nr := KernelUpdateNodeResult{NodeID: nid, Status: "offline", Error: err.Error()}
			res.Failed = append(res.Failed, nr)
			res.Results = append(res.Results, nr)
		default:
			nr := KernelUpdateNodeResult{NodeID: nid, Status: "failed", Error: err.Error()}
			res.Failed = append(res.Failed, nr)
			res.Results = append(res.Results, nr)
		}
	}

	return res, nil
}

func (s *Scheduler) resolveNodeArch(node *store.Node) string {
	if s.hub != nil {
		if tel, ok := s.hub.GetTelemetry(node.ID); ok && strings.TrimSpace(tel.Arch) != "" {
			if norm := normalizeTelemetryArch(tel.Arch); norm != "" {
				return norm
			}
		}
	}
	if norm := normalizeTelemetryArch(node.AgentArch); norm != "" {
		return norm
	}
	return "amd64"
}

func normalizeVersionKey(version string) string {
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
}

func resolveCatalogDownload(catalog *KernelCatalog, kernel, version, arch string) (string, string, bool) {
	if catalog == nil {
		return "", "", false
	}
	normTarget := normalizeVersionKey(version)

	switch kernel {
	case protocol.KernelSingBox:
		for _, rel := range catalog.SingBox {
			if versionMatches(rel.Version, rel.TagName, normTarget) {
				if asset, ok := rel.Assets[arch]; ok && asset.DownloadURL != "" {
					return asset.DownloadURL, asset.SHA256, true
				}
			}
		}
	case protocol.KernelShadowTLS:
		for _, rel := range catalog.ShadowTLS {
			if versionMatches(rel.Version, rel.TagName, normTarget) {
				if asset, ok := rel.Assets[arch]; ok && asset.DownloadURL != "" {
					return asset.DownloadURL, asset.SHA256, true
				}
			}
		}
	case protocol.KernelSnellServer:
		for _, entry := range catalog.SnellServer {
			if versionMatches(entry.Version, entry.Version, normTarget) {
				if u, ok := entry.URLs[arch]; ok && u != "" {
					return u, "", true
				}
			}
		}
	}
	return "", "", false
}

func versionMatches(version, tagName, normTarget string) bool {
	v1 := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(version)), "v")
	v2 := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(tagName)), "v")
	return (v1 != "" && v1 == normTarget) || (v2 != "" && v2 == normTarget)
}

func (s *Scheduler) fetchGitHubReleases(ctx context.Context, owner, repo string) ([]KernelRelease, error) {
	endpoint := fmt.Sprintf("%s/repos/%s/%s/releases?per_page=20", s.githubAPIBaseURL, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "snell-panel/1.0")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGitHubResponseBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 256 {
			msg = msg[:256]
		}
		return nil, fmt.Errorf("github api %s/%s returned HTTP %d: %s", owner, repo, resp.StatusCode, msg)
	}

	var ghReleases []ghRelease
	if err := json.Unmarshal(body, &ghReleases); err != nil {
		return nil, fmt.Errorf("decode %s/%s releases: %w", owner, repo, err)
	}

	releases := make([]KernelRelease, 0, len(ghReleases))
	for _, r := range ghReleases {
		if r.Draft || r.Prerelease {
			continue
		}
		tag := strings.TrimSpace(r.TagName)
		if tag == "" {
			tag = strings.TrimSpace(r.Name)
		}
		ver := strings.TrimPrefix(tag, "v")
		if ver == "" {
			continue
		}

		assets := make(map[string]KernelAsset)
		for _, a := range r.Assets {
			arch, ok := matchLinuxArchAsset(a.Name, a.BrowserDownloadURL)
			if !ok {
				continue
			}
			candidate := KernelAsset{
				Arch:        arch,
				Name:        strings.TrimSpace(a.Name),
				DownloadURL: strings.TrimSpace(a.BrowserDownloadURL),
				SHA256:      extractSHA256Digest(a.Digest),
				Size:        a.Size,
			}
			if existing, exists := assets[arch]; !exists || preferCandidateAsset(candidate.Name, existing.Name) {
				assets[arch] = candidate
			}
		}

		if len(assets) == 0 {
			continue
		}
		releases = append(releases, KernelRelease{
			Version:     ver,
			TagName:     tag,
			PublishedAt: strings.TrimSpace(r.PublishedAt),
			Assets:      assets,
		})
	}

	return releases, nil
}

func matchLinuxArchAsset(name, downloadURL string) (string, bool) {
	if !isValidHTTPURL(strings.TrimSpace(downloadURL)) {
		return "", false
	}
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "" {
		return "", false
	}

	// Exclude metadata, checksums, signatures, and unsupported archive/package formats.
	excludedSuffixes := []string{
		".sha256", ".sha512", ".sig", ".asc",
		".deb", ".rpm", ".apk",
		".tar.xz", ".txz", ".tar.bz2", ".tbz2", ".7z", ".rar",
		".txt", ".md", ".json", ".yaml", ".yml",
		".exe", ".msi", ".dmg", ".pkg", ".appimage", ".ipk",
	}
	for _, suf := range excludedSuffixes {
		if strings.HasSuffix(lower, suf) {
			return "", false
		}
	}
	if strings.HasSuffix(lower, ".tar") || (strings.HasSuffix(lower, ".gz") && !strings.HasSuffix(lower, ".tar.gz")) {
		return "", false
	}

	// Exclude non-Linux OS targets.
	nonLinuxTokens := []string{
		"windows", "win32", "win64",
		"darwin", "macos", "osx",
		"freebsd", "openbsd", "netbsd", "dragonfly",
		"android", "ios", "solaris", "illumos",
	}
	for _, tok := range nonLinuxTokens {
		if strings.Contains(lower, tok) {
			return "", false
		}
	}
	if !strings.Contains(lower, "linux") {
		return "", false
	}

	// Exclude non-amd64/arm64 CPU architectures and x86-64 micro-architecture variants
	// (e.g., amd64v3) that require newer ISA extensions and SIGILL on older VPS CPUs.
	excludedArches := []string{
		"386", "i386", "i686", "armv5", "armv6", "armv7", "armhf", "mips", "ppc64", "s390x", "riscv64", "loong64",
		"amd64v2", "amd64-v2", "amd64_v2",
		"amd64v3", "amd64-v3", "amd64_v3",
		"amd64v4", "amd64-v4", "amd64_v4",
		"x86_64v2", "x86_64-v2", "x86_64_v2",
		"x86_64v3", "x86_64-v3", "x86_64_v3",
		"x86_64v4", "x86_64-v4", "x86_64_v4",
		"x86-64v2", "x86-64-v2", "x86-64_v2",
		"x86-64v3", "x86-64-v3", "x86-64_v3",
		"x86-64v4", "x86-64-v4", "x86-64_v4",
		"x64v2", "x64-v2", "x64_v2",
		"x64v3", "x64-v3", "x64_v3",
		"x64v4", "x64-v4", "x64_v4",
	}
	for _, tok := range excludedArches {
		if strings.Contains(lower, tok) {
			return "", false
		}
	}

	isAMD64 := strings.Contains(lower, "amd64") || strings.Contains(lower, "x86_64") || strings.Contains(lower, "x64")
	isARM64 := strings.Contains(lower, "arm64") || strings.Contains(lower, "aarch64")
	if isAMD64 && !isARM64 {
		return "amd64", true
	}
	if isARM64 && !isAMD64 {
		return "arm64", true
	}
	return "", false
}

func preferCandidateAsset(candidateName, existingName string) bool {
	cLower := strings.ToLower(candidateName)
	eLower := strings.ToLower(existingName)

	cMusl := strings.Contains(cLower, "musl")
	eMusl := strings.Contains(eLower, "musl")
	if eMusl && !cMusl {
		return true
	}
	if cMusl && !eMusl {
		return false
	}

	cArchive := strings.HasSuffix(cLower, ".tar.gz") || strings.HasSuffix(cLower, ".tgz") || strings.HasSuffix(cLower, ".zip")
	eArchive := strings.HasSuffix(eLower, ".tar.gz") || strings.HasSuffix(eLower, ".tgz") || strings.HasSuffix(eLower, ".zip")
	return cArchive && !eArchive
}

func extractSHA256Digest(digest string) string {
	trimmed := strings.TrimSpace(digest)
	if len(trimmed) == 0 {
		return ""
	}
	lower := strings.ToLower(trimmed)
	if !strings.HasPrefix(lower, "sha256:") {
		return ""
	}
	hexPart := strings.TrimPrefix(lower, "sha256:")
	if !isValidSHA256Hex(hexPart) {
		return ""
	}
	return hexPart
}

func (s *Scheduler) readKernelCache(ctx context.Context) (KernelVersionsCache, error) {
	raw, err := s.store.GetSettingOrDefault(ctx, settingKernelVersionsCache, "{}")
	if err != nil {
		return KernelVersionsCache{}, err
	}
	var cache KernelVersionsCache
	trimmed := strings.TrimSpace(raw)
	if trimmed != "" && trimmed != "{}" {
		if err := json.Unmarshal([]byte(trimmed), &cache); err != nil {
			return KernelVersionsCache{}, fmt.Errorf("parse %s: %w", settingKernelVersionsCache, err)
		}
	}
	if cache.SingBox == nil {
		cache.SingBox = []KernelRelease{}
	}
	if cache.ShadowTLS == nil {
		cache.ShadowTLS = []KernelRelease{}
	}
	return cache, nil
}

func (s *Scheduler) readCustomSnellVersions(ctx context.Context) ([]SnellVersionEntry, error) {
	raw, err := s.store.GetSettingOrDefault(ctx, settingCustomSnellVersions, "[]")
	if err != nil {
		return nil, err
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || trimmed == "{}" {
		return []SnellVersionEntry{}, nil
	}
	var entries []SnellVersionEntry
	if err := json.Unmarshal([]byte(trimmed), &entries); err != nil {
		return nil, fmt.Errorf("parse %s: %w", settingCustomSnellVersions, err)
	}
	if entries == nil {
		entries = []SnellVersionEntry{}
	}
	return entries, nil
}

func (s *Scheduler) writeCustomSnellVersions(ctx context.Context, entries []SnellVersionEntry) error {
	if entries == nil {
		entries = []SnellVersionEntry{}
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	return s.store.SetSetting(ctx, settingCustomSnellVersions, string(raw))
}

func normalizeStrictArch(raw string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "amd64", "linux/amd64":
		return "amd64", true
	case "arm64", "linux/arm64":
		return "arm64", true
	default:
		return "", false
	}
}

func normalizeTelemetryArch(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "amd64", "linux/amd64", "x86_64", "x64":
		return "amd64"
	case "arm64", "linux/arm64", "aarch64":
		return "arm64"
	default:
		return ""
	}
}

func inferSnellMajor(version string) string {
	lower := strings.ToLower(strings.TrimSpace(version))
	if strings.HasPrefix(lower, "v4") || strings.HasPrefix(lower, "4.") {
		return protocol.SnellVersionV4
	}
	if strings.HasPrefix(lower, "v5") || strings.HasPrefix(lower, "5.") {
		return protocol.SnellVersionV5
	}
	return ""
}

func isValidHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func isValidSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func hasControlChar(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func hasControlOrWhitespace(s string) bool {
	for _, r := range s {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return true
		}
	}
	return false
}

func mapsClone(src map[string]string) map[string]string {
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
