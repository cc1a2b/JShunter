package main

import (
	"strings"
)

// ParseCSPOrigins extracts host origins from a Content-Security-Policy
// header (or http-equiv meta value). Recon use-case: the allow-list of
// hosts a site loads from is a fast list of subdomains and third-party
// vendors to investigate. We only return scheme://host[:port] tokens —
// keywords (`'self'`, `'unsafe-inline'`), data:, blob:, mediastream:,
// filesystem: are filtered out.
func ParseCSPOrigins(policy string) []string {
	if policy == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, dir := range strings.Split(policy, ";") {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}
		fields := strings.Fields(dir)
		if len(fields) < 2 {
			continue
		}
		// Skip directive name (default-src, script-src, …); iterate sources.
		for _, src := range fields[1:] {
			src = strings.Trim(src, "\"'")
			if src == "" {
				continue
			}
			if strings.HasPrefix(src, "'") || strings.HasPrefix(src, "*") {
				continue
			}
			low := strings.ToLower(src)
			if strings.HasPrefix(low, "data:") || strings.HasPrefix(low, "blob:") ||
				strings.HasPrefix(low, "mediastream:") || strings.HasPrefix(low, "filesystem:") ||
				strings.HasPrefix(low, "ws:") || strings.HasPrefix(low, "wss:") ||
				strings.HasPrefix(low, "self") || strings.HasPrefix(low, "none") ||
				strings.HasPrefix(low, "nonce-") || strings.HasPrefix(low, "sha256-") ||
				strings.HasPrefix(low, "sha384-") || strings.HasPrefix(low, "sha512-") ||
				strings.HasPrefix(low, "strict-dynamic") || strings.HasPrefix(low, "report-sample") ||
				strings.HasPrefix(low, "unsafe-") {
				continue
			}
			if _, ok := seen[src]; !ok {
				seen[src] = struct{}{}
				out = append(out, src)
			}
		}
	}
	return out
}
