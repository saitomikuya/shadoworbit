package dnsproxy

import "strings"

type ruleKey struct {
	exactOnly bool
	subOnly   bool
	domain    string
}

// RuleMatcher implements MoeClub/haproxy_docker domain rule matching:
//   - "abc.com": matches root "abc.com" and all subdomains ("sub.abc.com", "a.b.abc.com")
//   - "^abc.com" or "@abc.com": matches exact root "abc.com" only
//   - "*.abc.com" or ".abc.com": matches subdomains only ("www.abc.com", "a.b.abc.com"), excluding root
type RuleMatcher struct {
	exact     map[string]struct{}
	wildcard  map[string]struct{}
	ruleCount int
}

// ParseRules compiles MoeClub-style rule lines into an immutable RuleMatcher.
// Slice elements may contain embedded newlines; comments (# or //), surrounding
// whitespace, and invalid/empty tokens are stripped or skipped cleanly.
func ParseRules(lines []string) *RuleMatcher {
	m := &RuleMatcher{
		exact:    make(map[string]struct{}),
		wildcard: make(map[string]struct{}),
	}
	seen := make(map[ruleKey]struct{})

	for _, raw := range lines {
		for _, part := range strings.Split(raw, "\n") {
			part = strings.TrimRight(part, "\r")
			if idx := earliestCommentIndex(part); idx >= 0 {
				part = part[:idx]
			}
			token := strings.TrimSpace(part)
			if token == "" {
				continue
			}

			var exactOnly, subOnly bool
			switch {
			case strings.HasPrefix(token, "^") || strings.HasPrefix(token, "@"):
				exactOnly = true
				token = token[1:]
			case strings.HasPrefix(token, "*."):
				subOnly = true
				token = token[2:]
			case strings.HasPrefix(token, "."):
				subOnly = true
				token = token[1:]
			}

			norm, ok := normalizeRuleDomain(token)
			if !ok {
				continue
			}

			key := ruleKey{
				exactOnly: exactOnly,
				subOnly:   subOnly,
				domain:    norm,
			}
			if _, exists := seen[key]; !exists {
				seen[key] = struct{}{}
				m.ruleCount++
			}

			switch {
			case exactOnly:
				m.exact[norm] = struct{}{}
			case subOnly:
				m.wildcard[norm] = struct{}{}
			default:
				m.exact[norm] = struct{}{}
				m.wildcard[norm] = struct{}{}
			}
		}
	}

	return m
}

// Len returns the number of distinct valid rules loaded in the matcher.
func (m *RuleMatcher) Len() int {
	if m == nil {
		return 0
	}
	return m.ruleCount
}

// MatchDomain reports whether domain matches any configured unlock rule.
// Matching is case-insensitive and ignores a single trailing root dot.
func (m *RuleMatcher) MatchDomain(domain string) bool {
	if m == nil || (len(m.exact) == 0 && len(m.wildcard) == 0) {
		return false
	}

	norm, ok := normalizeQueryDomain(domain)
	if !ok {
		return false
	}

	if _, hit := m.exact[norm]; hit {
		return true
	}

	for i := 0; i < len(norm); i++ {
		if norm[i] == '.' {
			parent := norm[i+1:]
			if _, hit := m.wildcard[parent]; hit {
				return true
			}
		}
	}
	return false
}

func earliestCommentIndex(s string) int {
	hashIdx := strings.IndexByte(s, '#')
	slashIdx := strings.Index(s, "//")
	switch {
	case hashIdx >= 0 && slashIdx >= 0:
		if hashIdx < slashIdx {
			return hashIdx
		}
		return slashIdx
	case hashIdx >= 0:
		return hashIdx
	default:
		return slashIdx
	}
}

func normalizeRuleDomain(raw string) (string, bool) {
	if raw == "" {
		return "", false
	}
	if strings.HasSuffix(raw, ".") {
		raw = raw[:len(raw)-1]
	}
	if raw == "" || len(raw) > 253 {
		return "", false
	}
	if strings.HasPrefix(raw, ".") || strings.HasSuffix(raw, ".") || strings.Contains(raw, "..") {
		return "", false
	}

	var buf [253]byte
	labelLen := 0
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		if c == '.' {
			if labelLen == 0 || labelLen > 63 || buf[i-1] == '-' {
				return "", false
			}
			labelLen = 0
			buf[i] = '.'
			continue
		}
		if labelLen == 0 && c == '-' {
			return "", false
		}
		if !isRuleHostChar(c) {
			return "", false
		}
		labelLen++
		if labelLen > 63 {
			return "", false
		}
		buf[i] = c
	}
	if labelLen == 0 || buf[len(raw)-1] == '-' {
		return "", false
	}
	return string(buf[:len(raw)]), true
}

func normalizeQueryDomain(raw string) (string, bool) {
	// Fast trim only if needed so canonical queries stay zero-alloc.
	if len(raw) > 0 && (isASCIIWhitespace(raw[0]) || isASCIIWhitespace(raw[len(raw)-1])) {
		raw = strings.TrimSpace(raw)
	}
	if raw == "" {
		return "", false
	}
	if raw[len(raw)-1] == '.' {
		raw = raw[:len(raw)-1]
	}
	if raw == "" || len(raw) > 253 {
		return "", false
	}
	if raw[0] == '.' || raw[len(raw)-1] == '.' {
		return "", false
	}

	hasUpper := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			hasUpper = true
		} else if c == '.' && i+1 < len(raw) && raw[i+1] == '.' {
			return "", false
		} else if isASCIIWhitespace(c) {
			return "", false
		}
	}
	if !hasUpper {
		return raw, true
	}

	var buf [253]byte
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c >= 'A' && c <= 'Z' {
			c += 'a' - 'A'
		}
		buf[i] = c
	}
	return string(buf[:len(raw)]), true
}

func isRuleHostChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func isASCIIWhitespace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
