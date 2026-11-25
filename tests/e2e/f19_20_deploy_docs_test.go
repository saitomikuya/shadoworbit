//go:build e2e

package e2e_test

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

var (
	f19_stubWordRe      = regexp.MustCompile(`\b(TODO|FIXME|TBD|XXX|PLACEHOLDER)\b|\[(?i:TODO|FIXME|TBD|XXX|PLACEHOLDER)\]|<(?i:TODO|FIXME|TBD|XXX|PLACEHOLDER)>`)
	f19_envExtractRe    = regexp.MustCompile(`(?:os\.Getenv|os\.LookupEnv|getenvDefault|getenvBool|envOrDefault|\bgetenv)\(\s*"([A-Z0-9_]+)"`)
	f19_secretPatternRe = regexp.MustCompile(`(?i)(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|BEGIN (?:RSA|EC|OPENSSH) PRIVATE KEY|nd_live_[A-Za-z0-9]{16,})`)
	f20_goVetLineRe     = regexp.MustCompile(`\bgo\s+vet\b[^\n]*\./\.\.\.`)
)

func f19_readRepoFile(t *testing.T, relPath string) string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	b, err := os.ReadFile(filepath.Join(repoRoot, relPath))
	if err != nil {
		t.Fatalf("read %s: %v", relPath, err)
	}
	if len(strings.TrimSpace(string(b))) == 0 {
		t.Fatalf("%s is empty", relPath)
	}
	return string(b)
}

type f19_composeDoc struct {
	Services map[string]f19_composeService `yaml:"services"`
}

type f19_composeService struct {
	Image       string   `yaml:"image"`
	Build       any      `yaml:"build"`
	Container   string   `yaml:"container_name"`
	Restart     string   `yaml:"restart"`
	NetworkMode string   `yaml:"network_mode"`
	Ports       []string `yaml:"ports"`
	Volumes     []string `yaml:"volumes"`
	Environment any      `yaml:"environment"`
}

func f19_parseComposeEnvMap(envField any) map[string]string {
	out := map[string]string{}
	switch v := envField.(type) {
	case map[string]any:
		for k, val := range v {
			out[k] = strings.TrimSpace(f19_toString(val))
		}
	case []any:
		for _, item := range v {
			s := f19_toString(item)
			if idx := strings.IndexByte(s, '='); idx > 0 {
				out[strings.TrimSpace(s[:idx])] = strings.TrimSpace(s[idx+1:])
			} else if strings.TrimSpace(s) != "" {
				out[strings.TrimSpace(s)] = ""
			}
		}
	}
	return out
}

func f19_toString(v any) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func f19_parseWorkflows(t *testing.T) map[string]string {
	t.Helper()
	repoRoot := findRepoRoot(t)
	wfDir := filepath.Join(repoRoot, ".github", "workflows")
	entries, err := os.ReadDir(wfDir)
	if err != nil {
		t.Fatalf("read .github/workflows: %v", err)
	}
	files := map[string]string{}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yml") || strings.HasSuffix(name, ".yaml") {
			b, err := os.ReadFile(filepath.Join(wfDir, name))
			if err != nil {
				t.Fatalf("read workflow %s: %v", name, err)
			}
			files[filepath.Join(".github", "workflows", name)] = string(b)
		}
	}
	if len(files) == 0 {
		t.Fatalf("no .yml/.yaml files found in .github/workflows")
	}
	return files
}

func f19_allowedCmdEnvVars(t *testing.T) map[string]bool {
	t.Helper()
	allowed := map[string]bool{
		"TZ":             true,
		"GITHUB_API_URL": true,
	}
	for _, srcRel := range []string{"cmd/panel/main.go", "cmd/agent/main.go"} {
		src := f19_readRepoFile(t, srcRel)
		matches := f19_envExtractRe.FindAllStringSubmatch(src, -1)
		if len(matches) == 0 {
			t.Fatalf("f19_envExtractRe extracted 0 env vars from %s; regex out of sync with source", srcRel)
		}
		for _, m := range matches {
			allowed[m[1]] = true
		}
	}
	return allowed
}

func f19_stripDockerfileComments(df string) string {
	norm := strings.ReplaceAll(df, "\r\n", "\n")
	var sb strings.Builder
	for _, line := range strings.Split(norm, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		sb.WriteString(line)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func f19_dockerfileLogicalInstructions(df string) []string {
	norm := strings.ReplaceAll(df, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	var instructions []string
	var cur strings.Builder
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		rtrimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(rtrimmed, `\`) {
			part := strings.TrimSpace(strings.TrimSuffix(rtrimmed, `\`))
			if part != "" {
				if cur.Len() > 0 {
					cur.WriteByte(' ')
				}
				cur.WriteString(part)
			}
			continue
		}
		if cur.Len() > 0 {
			cur.WriteByte(' ')
		}
		cur.WriteString(trimmed)
		instructions = append(instructions, cur.String())
		cur.Reset()
	}
	if cur.Len() > 0 {
		instructions = append(instructions, cur.String())
	}
	return instructions
}

func f19_tokenizeDockerfileArgs(s string) []string {
	var tokens []string
	var cur strings.Builder
	var quote byte
	inTok := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && quote == '"' && i+1 < len(s) {
				i++
				cur.WriteByte(s[i])
				continue
			}
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == ' ' || c == '\t' {
			if inTok {
				tokens = append(tokens, cur.String())
				cur.Reset()
				inTok = false
			}
			continue
		}
		inTok = true
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		if c == '\\' && i+1 < len(s) {
			i++
			cur.WriteByte(s[i])
			continue
		}
		cur.WriteByte(c)
	}
	if inTok {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func f19_parseDockerfileEnvKeys(df string) (envKeys []string, argKeys []string) {
	for _, instr := range f19_dockerfileLogicalInstructions(df) {
		trimmed := strings.TrimSpace(instr)
		sp := strings.IndexAny(trimmed, " \t")
		if sp <= 0 {
			continue
		}
		op := strings.ToUpper(trimmed[:sp])
		rest := strings.TrimSpace(trimmed[sp+1:])
		if rest == "" {
			continue
		}
		tokens := f19_tokenizeDockerfileArgs(rest)
		switch op {
		case "ENV":
			if len(tokens) == 0 {
				continue
			}
			if strings.Contains(tokens[0], "=") {
				for _, tok := range tokens {
					if eq := strings.IndexByte(tok, '='); eq > 0 {
						envKeys = append(envKeys, tok[:eq])
					}
				}
			} else {
				envKeys = append(envKeys, tokens[0])
			}
		case "ARG":
			for _, tok := range tokens {
				if eq := strings.IndexByte(tok, '='); eq > 0 {
					argKeys = append(argKeys, tok[:eq])
				} else if tok != "" {
					argKeys = append(argKeys, tok)
				}
			}
		}
	}
	return envKeys, argKeys
}

// =====================================================================
// Feature 19: Multi-Arch Docker & Compose Deployment (5 Tier 1 + 5 Tier 2)
// =====================================================================

func TestF19_Tier1_DockerfilePanelMultiStageAndRuntimeContract(t *testing.T) {
	df := f19_readRepoFile(t, "deploy/Dockerfile.panel")
	stripped := f19_stripDockerfileComments(df)
	lower := strings.ToLower(stripped)

	fromCount := 0
	for _, line := range strings.Split(stripped, "\n") {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(line)), "FROM ") {
			fromCount++
		}
	}
	if fromCount < 2 {
		t.Fatalf("deploy/Dockerfile.panel must be multi-stage (>=2 FROM), got %d", fromCount)
	}
	for _, req := range []string{
		"node", "npm", "golang", "1.24", "cgo_enabled=0",
		"./cmd/panel", "ca-certificates", "tzdata", "/app", "8080",
	} {
		if !strings.Contains(lower, req) {
			t.Fatalf("deploy/Dockerfile.panel missing required directive/token %q", req)
		}
	}
	if !strings.Contains(lower, "entrypoint") && !strings.Contains(lower, "cmd ") {
		t.Fatalf("deploy/Dockerfile.panel missing ENTRYPOINT/CMD")
	}
}

func TestF19_Tier1_DockerfileAgentMultiArchTiniAnd3Kernels(t *testing.T) {
	df := f19_readRepoFile(t, "deploy/Dockerfile.agent")
	lower := strings.ToLower(f19_stripDockerfileComments(df))

	for _, req := range []string{
		"golang", "1.26", "cgo_enabled=0", "./cmd/agent",
		"tini", "ca-certificates",
		"snell-server", "shadow-tls", "sing-box",
		"/var/lib/snell-panel-agent",
	} {
		if !strings.Contains(lower, req) {
			t.Fatalf("deploy/Dockerfile.agent missing required multi-arch/kernel/tini token %q", req)
		}
	}
	if !strings.Contains(lower, "targetarch") && !strings.Contains(lower, "targetplatform") {
		t.Fatalf("deploy/Dockerfile.agent must reference TARGETARCH or TARGETPLATFORM")
	}
	if (!strings.Contains(lower, "amd64") && !strings.Contains(lower, "x86_64")) ||
		(!strings.Contains(lower, "arm64") && !strings.Contains(lower, "aarch64")) {
		t.Fatalf("deploy/Dockerfile.agent must explicitly handle both amd64/x86_64 and arm64/aarch64")
	}
	if !strings.Contains(lower, "entrypoint") || !strings.Contains(lower, "tini") {
		t.Fatalf("deploy/Dockerfile.agent must configure tini as ENTRYPOINT")
	}
}

func TestF19_Tier1_DockerComposeValidYAMLAndPanelService(t *testing.T) {
	raw := f19_readRepoFile(t, "deploy/docker-compose.yml")
	var doc f19_composeDoc
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("deploy/docker-compose.yml invalid YAML: %v", err)
	}
	if len(doc.Services) == 0 {
		t.Fatalf("deploy/docker-compose.yml has no services")
	}

	var foundPanel bool
	for name, svc := range doc.Services {
		envMap := f19_parseComposeEnvMap(svc.Environment)
		hasPort8080 := false
		for _, p := range svc.Ports {
			if strings.Contains(p, "8080") {
				hasPort8080 = true
			}
		}
		hasDataVol := false
		for _, v := range svc.Volumes {
			if strings.Contains(v, "./data:/app/data") {
				hasDataVol = true
			}
		}
		if hasPort8080 && hasDataVol {
			foundPanel = true
			if svc.Restart != "always" && svc.Restart != "unless-stopped" {
				t.Fatalf("panel service %q must set restart policy always/unless-stopped, got %q", name, svc.Restart)
			}
			for _, envKey := range []string{"ADMIN_USER", "ADMIN_INITIAL_PASS", "TZ"} {
				if _, ok := envMap[envKey]; !ok {
					t.Fatalf("panel service %q missing env var %q in %+v", name, envKey, envMap)
				}
			}
		}
	}
	if !foundPanel {
		t.Fatalf("deploy/docker-compose.yml missing panel service with port 8080 and ./data:/app/data volume")
	}
}

func TestF19_Tier1_DockerComposeNetworkAndAgentGuidance(t *testing.T) {
	raw := f19_readRepoFile(t, "deploy/docker-compose.yml")
	if !strings.Contains(raw, "./data:/app/data") || !strings.Contains(raw, "8080") {
		t.Fatalf("deploy/docker-compose.yml missing ./data:/app/data or port 8080")
	}

	var doc f19_composeDoc
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatalf("deploy/docker-compose.yml invalid YAML: %v", err)
	}
	for name, svc := range doc.Services {
		envMap := f19_parseComposeEnvMap(svc.Environment)
		_, hasPanelURL := envMap["PANEL_URL"]
		_, hasNodeTok := envMap["NODE_TOKEN"]
		isAgent := strings.Contains(strings.ToLower(name), "agent") ||
			strings.Contains(strings.ToLower(svc.Image), "agent") ||
			hasPanelURL || hasNodeTok
		if isAgent && svc.NetworkMode != "host" {
			t.Fatalf("agent service %q in deploy/docker-compose.yml must set network_mode: host, got %q", name, svc.NetworkMode)
		}
	}

	hasHostGuidance := (strings.Contains(raw, "network_mode") && strings.Contains(raw, "host")) ||
		strings.Contains(raw, "--network host")
	if !hasHostGuidance {
		repoRoot := findRepoRoot(t)
		for _, rel := range []string{"deploy/Dockerfile.agent", "README.md"} {
			if b, err := os.ReadFile(filepath.Join(repoRoot, rel)); err == nil {
				s := string(b)
				if (strings.Contains(s, "network_mode") && strings.Contains(s, "host")) ||
					strings.Contains(s, "--network host") {
					hasHostGuidance = true
					break
				}
			}
		}
	}
	if !hasHostGuidance {
		t.Fatalf("expected host-network agent deployment guidance (network_mode: host or --network host) in deploy/docker-compose.yml, deploy/Dockerfile.agent, or README.md")
	}
}

func TestF19_Tier1_DockerfilesWireWebDistAndExecutableKernels(t *testing.T) {
	panelDF := f19_readRepoFile(t, "deploy/Dockerfile.panel")
	panelLower := strings.ToLower(f19_stripDockerfileComments(panelDF))
	if !strings.Contains(panelLower, "web/dist") && !strings.Contains(panelLower, "dist") {
		t.Fatalf("deploy/Dockerfile.panel must copy/build web/dist into Go builder stage for //go:embed")
	}
	if !strings.Contains(panelLower, "/app/data") {
		t.Fatalf("deploy/Dockerfile.panel should ensure /app/data directory exists")
	}

	agentDF := f19_readRepoFile(t, "deploy/Dockerfile.agent")
	agentLower := strings.ToLower(f19_stripDockerfileComments(agentDF))
	if !strings.Contains(agentLower, "chmod +x") && !strings.Contains(agentLower, "chmod 755") && !strings.Contains(agentLower, "chmod 0755") {
		t.Fatalf("deploy/Dockerfile.agent must chmod +x downloaded kernel binaries")
	}
}

func TestF19_Tier2_NoPlaceholdersOrStubsInDeployFiles(t *testing.T) {
	for _, rel := range []string{
		"deploy/Dockerfile.panel",
		"deploy/Dockerfile.agent",
		"deploy/docker-compose.yml",
	} {
		txt := f19_readRepoFile(t, rel)
		if m := f19_stubWordRe.FindString(txt); m != "" {
			t.Fatalf("%s contains placeholder/stub marker %q", rel, m)
		}
	}
}

func TestF19_Tier2_NoHardcodedRealSecretsOrTokensInDeployFiles(t *testing.T) {
	for _, rel := range []string{
		"deploy/Dockerfile.panel",
		"deploy/Dockerfile.agent",
		"deploy/docker-compose.yml",
	} {
		txt := f19_readRepoFile(t, rel)
		if m := f19_secretPatternRe.FindString(txt); m != "" {
			t.Fatalf("%s appears to contain a hardcoded real secret/token %q", rel, m)
		}
	}
}

func TestF19_Tier2_EnvVarConsistencyWithCmdPanelAndCmdAgent(t *testing.T) {
	allowed := f19_allowedCmdEnvVars(t)
	composeRaw := f19_readRepoFile(t, "deploy/docker-compose.yml")

	var doc f19_composeDoc
	if err := yaml.Unmarshal([]byte(composeRaw), &doc); err != nil {
		t.Fatal(err)
	}
	for svcName, svc := range doc.Services {
		for k := range f19_parseComposeEnvMap(svc.Environment) {
			if !allowed[k] {
				t.Fatalf("docker-compose.yml service %q references unknown env var %q not supported by cmd/panel or cmd/agent", svcName, k)
			}
		}
	}

	// Guard against common misspelled env vars in deploy/*
	for _, rel := range []string{"deploy/Dockerfile.panel", "deploy/Dockerfile.agent", "deploy/docker-compose.yml"} {
		txt := f19_readRepoFile(t, rel)
		for _, bad := range []string{"ADMIN_PASS=", "AGENT_TOKEN=", "SNELL_PANEL_TOKEN="} {
			if strings.Contains(txt, bad) {
				t.Fatalf("%s uses incorrect env var %q", rel, bad)
			}
		}
	}

	standardContainerEnv := map[string]bool{
		"CGO_ENABLED": true, "GOOS": true, "GOARCH": true,
		"DEBIAN_FRONTEND": true, "PATH": true, "LANG": true,
		"LC_ALL": true, "HOME": true, "GOPROXY": true, "GOTOOLCHAIN": true,
	}
	badArgVars := map[string]bool{
		"ADMIN_PASS": true, "AGENT_TOKEN": true, "SNELL_PANEL_TOKEN": true,
	}
	for _, rel := range []string{"deploy/Dockerfile.panel", "deploy/Dockerfile.agent"} {
		df := f19_readRepoFile(t, rel)
		envKeys, argKeys := f19_parseDockerfileEnvKeys(df)
		for _, k := range envKeys {
			if !standardContainerEnv[k] && !allowed[k] {
				t.Fatalf("%s ENV sets unrecognized env var %q", rel, k)
			}
		}
		for _, k := range argKeys {
			if badArgVars[k] {
				t.Fatalf("%s ARG uses incorrect env var %q", rel, k)
			}
		}
	}
}

func TestF19_Tier2_DockerfileAgentBothArchBranchesAndValidInstructions(t *testing.T) {
	for _, rel := range []string{"deploy/Dockerfile.panel", "deploy/Dockerfile.agent"} {
		df := f19_readRepoFile(t, rel)
		trimmed := strings.TrimRight(df, " \t\r\n")
		if strings.HasSuffix(trimmed, `\`) {
			t.Fatalf("%s ends with dangling line continuation '\\'", rel)
		}
		for idx, line := range strings.Split(df, "\n") {
			tline := strings.TrimSpace(line)
			if strings.HasPrefix(tline, "#") {
				continue
			}
			for _, instr := range []string{"FROM", "RUN", "COPY", "ADD", "WORKDIR", "EXPOSE", "ENTRYPOINT", "CMD"} {
				if strings.EqualFold(tline, instr) {
					t.Fatalf("%s:%d has empty Dockerfile instruction %q", rel, idx+1, tline)
				}
			}
		}
	}

	agentDF := f19_readRepoFile(t, "deploy/Dockerfile.agent")
	lower := strings.ToLower(f19_stripDockerfileComments(agentDF))
	if (!strings.Contains(lower, "amd64") && !strings.Contains(lower, "x86_64")) ||
		(!strings.Contains(lower, "arm64") && !strings.Contains(lower, "aarch64")) {
		t.Fatalf("deploy/Dockerfile.agent must explicitly handle both amd64/x86_64 and arm64/aarch64")
	}
	if !strings.Contains(lower, "sing-box") || !strings.Contains(lower, "shadow-tls") || !strings.Contains(lower, "snell-server") {
		t.Fatalf("deploy/Dockerfile.agent must install all 3 kernels")
	}
}

func TestF19_Tier2_DockerComposeValidPortVolumeAndRestartSpecs(t *testing.T) {
	raw := f19_readRepoFile(t, "deploy/docker-compose.yml")
	var doc f19_composeDoc
	if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
		t.Fatal(err)
	}
	for name, svc := range doc.Services {
		if svc.Image == "" && svc.Build == nil {
			t.Fatalf("service %q must define image or build", name)
		}
		for _, p := range svc.Ports {
			if !strings.Contains(p, ":") {
				t.Fatalf("service %q has invalid port mapping %q", name, p)
			}
		}
		for _, v := range svc.Volumes {
			if !strings.Contains(v, ":") {
				t.Fatalf("service %q has invalid volume mapping %q", name, v)
			}
		}
		if svc.Restart != "" {
			switch svc.Restart {
			case "no", "always", "on-failure", "unless-stopped":
			default:
				t.Fatalf("service %q has invalid restart policy %q", name, svc.Restart)
			}
		}
	}
}

// =====================================================================
// Feature 20: GitHub Actions CI/CD & Documentation (5 Tier 1 + 5 Tier 2)
// =====================================================================

type f20_workflowDoc struct {
	Name string             `yaml:"name"`
	On   any                `yaml:"on"`
	Jobs map[string]f20_job `yaml:"jobs"`
}

type f20_job struct {
	RunsOn any        `yaml:"runs-on"`
	Steps  []f20_step `yaml:"steps"`
}

type f20_step struct {
	Name string         `yaml:"name"`
	Uses string         `yaml:"uses"`
	Run  string         `yaml:"run"`
	With map[string]any `yaml:"with"`
	Work string         `yaml:"working-directory"`
}

func TestF20_Tier1_GitHubWorkflowExistsAndValidYAML(t *testing.T) {
	files := f19_parseWorkflows(t)
	for path, raw := range files {
		var doc f20_workflowDoc
		if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("workflow %s invalid YAML: %v", path, err)
		}
		if doc.Name == "" || doc.On == nil || len(doc.Jobs) == 0 {
			t.Fatalf("workflow %s missing name, on trigger, or jobs: %+v", path, doc)
		}
		for jName, j := range doc.Jobs {
			if j.RunsOn == nil || len(j.Steps) == 0 {
				t.Fatalf("workflow %s job %q missing runs-on or steps", path, jName)
			}
		}
	}
}

func TestF20_Tier1_WorkflowRunsGoVetGoTestRaceAndWebBuild(t *testing.T) {
	files := f19_parseWorkflows(t)
	var all strings.Builder
	var hasGoVet, hasGoTestRace, hasWebBuild bool
	for wfPath, raw := range files {
		all.WriteString(raw)
		all.WriteString("\n")
		var doc f20_workflowDoc
		if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatalf("workflow %s invalid YAML: %v", wfPath, err)
		}
		for _, job := range doc.Jobs {
			for _, step := range job.Steps {
				if f20_goVetLineRe.MatchString(step.Run) {
					hasGoVet = true
				}
				for _, line := range strings.Split(step.Run, "\n") {
					if strings.Contains(line, "go test") && strings.Contains(line, "-race") && strings.Contains(line, "./...") {
						hasGoTestRace = true
					}
				}
				if strings.Contains(step.Run, "npm run build") || strings.Contains(step.Run, "vite build") {
					hasWebBuild = true
				}
			}
		}
	}
	combined := all.String()
	if !strings.Contains(combined, "1.24") {
		t.Fatalf("GitHub Actions workflows missing Go 1.24 version")
	}
	if !hasGoVet {
		t.Fatalf("GitHub Actions workflows missing `go vet ./...` step")
	}
	if !hasGoTestRace {
		t.Fatalf("GitHub Actions workflows missing `go test -race ./...` step")
	}
	if !hasWebBuild {
		t.Fatalf("GitHub Actions workflows missing `npm run build` (or `vite build`) step")
	}
}

func TestF20_Tier1_WorkflowMultiArchDockerBuildxBothImages(t *testing.T) {
	files := f19_parseWorkflows(t)
	var all strings.Builder
	for _, raw := range files {
		all.WriteString(raw)
		all.WriteString("\n")
	}
	combined := all.String()
	for _, req := range []string{
		"docker/setup-qemu-action",
		"docker/setup-buildx-action",
		"docker/build-push-action",
		"linux/amd64",
		"linux/arm64",
	} {
		if !strings.Contains(combined, req) {
			t.Fatalf("GitHub Actions workflows missing multi-arch Docker buildx requirement %q", req)
		}
	}
	hasDirect := strings.Contains(combined, "deploy/Dockerfile.panel") && strings.Contains(combined, "deploy/Dockerfile.agent")
	hasMatrix := strings.Contains(combined, "Dockerfile.panel") && strings.Contains(combined, "Dockerfile.agent") && strings.Contains(combined, "deploy/")
	hasTemplateMatrix := strings.Contains(combined, "deploy/Dockerfile.${{") && strings.Contains(combined, "panel") && strings.Contains(combined, "agent")
	if !hasDirect && !hasMatrix && !hasTemplateMatrix {
		t.Fatalf("GitHub Actions workflows must build both deploy/Dockerfile.panel and deploy/Dockerfile.agent (direct or matrixed)")
	}
}

func TestF20_Tier1_READMEExistsWithPanelAndAgentDeployDocs(t *testing.T) {
	readme := f19_readRepoFile(t, "README.md")
	for _, req := range []string{
		"docker-compose.yml",
		"8080",
		"./data",
		"ADMIN_USER",
		"ADMIN_INITIAL_PASS",
		"PANEL_URL",
		"NODE_TOKEN",
		"--network host",
		"/var/lib/snell-panel-agent",
		"snell-server",
		"shadow-tls",
		"sing-box",
	} {
		if !strings.Contains(readme, req) {
			t.Fatalf("README.md missing deployment documentation requirement %q", req)
		}
	}
}

func TestF20_Tier1_READMEDocumentsDualTrackSubsDNSUnlockAndBackup(t *testing.T) {
	readme := f19_readRepoFile(t, "README.md")
	for _, req := range []string{
		"/s/admin/",
		"/s/u/",
		"Surge",
		"Mihomo",
		"Shadowrocket",
		"MoeClub/haproxy_docker",
		"abc.com",
		"^abc.com",
		"*.abc.com",
		"panel.db",
	} {
		if !strings.Contains(readme, req) {
			t.Fatalf("README.md missing subscription/DNS-unlock/backup documentation %q", req)
		}
	}
}

func TestF20_Tier2_NoPlaceholdersOrStubsInCIAndREADME(t *testing.T) {
	files := f19_parseWorkflows(t)
	files["README.md"] = f19_readRepoFile(t, "README.md")
	for path, txt := range files {
		if m := f19_stubWordRe.FindString(txt); m != "" {
			t.Fatalf("%s contains placeholder/stub marker %q", path, m)
		}
	}
}

func TestF20_Tier2_WorkflowReferencedPathsExistInRepo(t *testing.T) {
	repoRoot := findRepoRoot(t)
	files := f19_parseWorkflows(t)

	for wfPath, raw := range files {
		var doc f20_workflowDoc
		if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		for jobName, job := range doc.Jobs {
			for _, step := range job.Steps {
				if step.Work != "" {
					cleanWork := strings.TrimPrefix(step.Work, "./")
					if idx := strings.Index(cleanWork, "${{"); idx >= 0 {
						prefix := strings.TrimRight(cleanWork[:idx], "/")
						if prefix != "" {
							if _, err := os.Stat(filepath.Join(repoRoot, prefix)); err != nil {
								t.Fatalf("%s job %q step working-directory prefix %q does not exist in repo: %v", wfPath, jobName, prefix, err)
							}
						}
					} else if _, err := os.Stat(filepath.Join(repoRoot, cleanWork)); err != nil {
						t.Fatalf("%s job %q step working-directory %q does not exist in repo: %v", wfPath, jobName, step.Work, err)
					}
				}
				if fVal, ok := step.With["file"]; ok {
					df := strings.TrimPrefix(f19_toString(fVal), "./")
					if df != "" {
						if idx := strings.Index(df, "${{"); idx >= 0 {
							prefix := strings.TrimRight(filepath.Dir(df[:idx]+"x"), "/")
							if prefix != "" && prefix != "." {
								if _, err := os.Stat(filepath.Join(repoRoot, prefix)); err != nil {
									t.Fatalf("%s job %q step with.file dir prefix %q does not exist in repo: %v", wfPath, jobName, prefix, err)
								}
							}
							if strings.Contains(df, "deploy/") && (strings.Contains(df, "Dockerfile") || strings.Contains(df, "matrix.")) {
								for _, cand := range []string{"deploy/Dockerfile.panel", "deploy/Dockerfile.agent"} {
									if _, err := os.Stat(filepath.Join(repoRoot, cand)); err != nil {
										t.Fatalf("%s job %q step with.file %q requires %s in repo: %v", wfPath, jobName, df, cand, err)
									}
								}
							}
						} else if _, err := os.Stat(filepath.Join(repoRoot, df)); err != nil {
							t.Fatalf("%s job %q step with.file %q does not exist in repo: %v", wfPath, jobName, df, err)
						}
					}
				}
			}
		}
	}
}

func TestF20_Tier2_READMEEnvVarsConsistentWithCmdBinaries(t *testing.T) {
	readme := f19_readRepoFile(t, "README.md")
	for _, requiredEnv := range []string{
		"ADMIN_USER", "ADMIN_INITIAL_PASS", "PANEL_URL", "NODE_TOKEN", "TZ",
	} {
		if !strings.Contains(readme, requiredEnv) {
			t.Fatalf("README.md missing canonical env var %q", requiredEnv)
		}
	}
	for _, wrongEnv := range []string{"ADMIN_PASS=", "AGENT_TOKEN=", "SNELL_PANEL_TOKEN="} {
		if strings.Contains(readme, wrongEnv) {
			t.Fatalf("README.md documents incorrect/non-existent env var %q", wrongEnv)
		}
	}
}

func f20_parseFenceMarker(trimmed string) (byte, int, string) {
	if len(trimmed) < 3 {
		return 0, 0, ""
	}
	ch := trimmed[0]
	if ch != '`' && ch != '~' {
		return 0, 0, ""
	}
	count := 0
	for count < len(trimmed) && trimmed[count] == ch {
		count++
	}
	if count < 3 {
		return 0, 0, ""
	}
	return ch, count, trimmed[count:]
}

func f20_markdownHeadingLevel(trimmed string) int {
	level := 0
	for level < len(trimmed) && trimmed[level] == '#' {
		level++
	}
	if level == 0 || level > 6 {
		return 0
	}
	if level == len(trimmed) || trimmed[level] == ' ' || trimmed[level] == '\t' {
		return level
	}
	return 0
}

func TestF20_Tier2_READMEStructureBalancedFencesAndNonEmptySections(t *testing.T) {
	readme := f19_readRepoFile(t, "README.md")
	if len(readme) < 1500 {
		t.Fatalf("README.md unexpectedly short (%d bytes); expected comprehensive documentation", len(readme))
	}

	norm := strings.ReplaceAll(readme, "\r\n", "\n")
	lines := strings.Split(norm, "\n")
	inFenceLine := make([]bool, len(lines))
	inFence := false
	var fenceChar byte
	fenceLen := 0
	fenceBlocks := 0

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		ch, cnt, rest := f20_parseFenceMarker(trimmed)
		if !inFence {
			if ch != 0 && (ch != '`' || !strings.ContainsRune(rest, '`')) {
				inFence = true
				fenceChar = ch
				fenceLen = cnt
				fenceBlocks++
				inFenceLine[i] = true
				continue
			}
		} else {
			inFenceLine[i] = true
			if ch == fenceChar && cnt >= fenceLen && strings.TrimSpace(rest) == "" {
				inFence = false
				fenceChar = 0
				fenceLen = 0
			}
			continue
		}
	}
	if fenceBlocks == 0 || inFence {
		t.Fatalf("README.md has unbalanced or missing markdown code fences (blocks=%d unclosed=%v)", fenceBlocks, inFence)
	}

	headingCount := 0
	for i, line := range lines {
		if inFenceLine[i] {
			continue
		}
		trimmed := strings.TrimSpace(line)
		currLevel := f20_markdownHeadingLevel(trimmed)
		if currLevel == 0 {
			continue
		}
		headingCount++
		hasBody := false
		for j := i + 1; j < len(lines); j++ {
			next := strings.TrimSpace(lines[j])
			if next == "" {
				continue
			}
			if inFenceLine[j] {
				hasBody = true
				break
			}
			nextLevel := f20_markdownHeadingLevel(next)
			if nextLevel > 0 {
				if nextLevel > currLevel {
					hasBody = true
					break
				}
				t.Fatalf("README.md:%d heading %q has empty body before next heading %q", i+1, line, next)
			}
			hasBody = true
			break
		}
		if !hasBody {
			t.Fatalf("README.md:%d heading %q has empty body at end of file", i+1, line)
		}
	}
	if headingCount < 4 {
		t.Fatalf("README.md should have >=4 structured markdown headings, got %d", headingCount)
	}
}

func TestF20_Tier2_WorkflowJobsHaveValidTriggersAndNoSecretLeaks(t *testing.T) {
	files := f19_parseWorkflows(t)
	for wfPath, raw := range files {
		if m := f19_secretPatternRe.FindString(raw); m != "" {
			t.Fatalf("workflow %s leaked credential pattern %q", wfPath, m)
		}
		var doc f20_workflowDoc
		if err := yaml.Unmarshal([]byte(raw), &doc); err != nil {
			t.Fatal(err)
		}
		onMap, ok := doc.On.(map[string]any)
		if ok {
			validTrigger := false
			for k := range onMap {
				switch k {
				case "push", "pull_request", "workflow_dispatch", "release", "schedule", "tag":
					validTrigger = true
				}
			}
			if !validTrigger {
				t.Fatalf("workflow %s has no standard trigger in 'on': %+v", wfPath, onMap)
			}
		}
		for jobName, job := range doc.Jobs {
			for idx, step := range job.Steps {
				if strings.TrimSpace(step.Uses) == "" && strings.TrimSpace(step.Run) == "" {
					t.Fatalf("workflow %s job %q step[%d] has neither 'uses' nor 'run'", wfPath, jobName, idx)
				}
			}
		}
	}
}
