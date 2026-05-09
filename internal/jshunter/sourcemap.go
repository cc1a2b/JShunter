package jshunter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Source-map ingestion. v0.5's `--sourcemap` flag was a stub — it found
// the `//# sourceMappingURL=` reference and did nothing with it. v0.6+
// fetches the map (or decodes the inline data URI), parses the JSON, and
// scans every entry in `sourcesContent[]` as its own source. Modern
// bundlers (Vite, esbuild, webpack 5, Turbopack, Rspack) ship the
// pre-minification source verbatim in this array — including comments,
// dev-only branches, and the original variable names — which is the
// single highest-leverage signal for secret recon on production sites.
//
// Specs:
//   https://sourcemaps.info/spec.html
//   https://tc39.es/ecma426/

type sourceMap struct {
	Version        int      `json:"version"`
	File           string   `json:"file,omitempty"`
	SourceRoot     string   `json:"sourceRoot,omitempty"`
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent,omitempty"`
}

// sourceMappingURL captures both header form and inline-data form. The
// `//#` and the older `//@` markers are equivalent per the spec.
var sourceMappingURLRe = regexp.MustCompile(`(?m)^[\t ]*//[#@]\s*sourceMappingURL=([^\s]+)\s*$`)

// FetchAndScanSourceMap looks for a sourceMappingURL marker in `body`,
// resolves it relative to `baseURL`, fetches (or decodes) the map, and
// runs the v0.6 detection pipeline against every entry in
// sourcesContent[]. Returns the count of original sources scanned.
//
// data: URI inlining is supported. http(s): is fetched via the same
// hardened client (host limiter, max-bytes, SSRF guard).
func FetchAndScanSourceMap(client *http.Client, baseURL string, body []byte, config *Config) (int, error) {
	m := sourceMappingURLRe.FindSubmatch(body)
	if m == nil {
		return 0, nil
	}
	mapRef := strings.TrimSpace(string(m[1]))
	if mapRef == "" {
		return 0, nil
	}

	mapBytes, err := fetchSourceMapPayload(client, baseURL, mapRef, config)
	if err != nil {
		return 0, fmt.Errorf("fetch sourcemap: %w", err)
	}
	if config.MaxBytes > 0 && int64(len(mapBytes)) > config.MaxBytes {
		mapBytes = mapBytes[:config.MaxBytes]
	}

	var sm sourceMap
	if err := json.Unmarshal(mapBytes, &sm); err != nil {
		return 0, fmt.Errorf("parse sourcemap: %w", err)
	}
	if sm.Version != 3 {
		// Source-map v3 is the only deployed version; v1/v2 were proposals.
		// Treat unknown as best-effort.
	}

	scanned := 0
	for i, content := range sm.SourcesContent {
		if content == "" {
			continue
		}
		src := sourceLabel(baseURL, &sm, i)
		if globalStats != nil {
			statAdd(&globalStats.BytesParsed, int64(len(content)))
		}
		processed := processJSAnalysis([]byte(content), config)
		reportMatchesWithConfig(src, processed, config)
		scanned++
	}
	return scanned, nil
}

// sourceLabel builds a stable identifier for an in-map source so the
// operator can locate it from the output (`vim` won't open it, but the
// hash and path are consistent across runs).
func sourceLabel(baseURL string, sm *sourceMap, idx int) string {
	if idx < len(sm.Sources) && sm.Sources[idx] != "" {
		s := sm.Sources[idx]
		if sm.SourceRoot != "" && !strings.HasPrefix(s, "/") && !strings.Contains(s, "://") {
			s = strings.TrimRight(sm.SourceRoot, "/") + "/" + s
		}
		return baseURL + ".map#" + s
	}
	return fmt.Sprintf("%s.map#sources[%d]", baseURL, idx)
}

// fetchSourceMapPayload resolves the map reference. Three forms supported:
//   1. data:application/json[;base64],{...}  — inline (Vite dev, webpack devtool)
//   2. /static/app.js.map  — root-relative
//   3. https://cdn/app.js.map  — absolute
func fetchSourceMapPayload(client *http.Client, baseURL, ref string, config *Config) ([]byte, error) {
	if strings.HasPrefix(ref, "data:") {
		return decodeDataURI(ref)
	}

	mapURL := ref
	if !strings.Contains(ref, "://") {
		base, err := url.Parse(baseURL)
		if err != nil {
			return nil, fmt.Errorf("parse base url: %w", err)
		}
		rel, err := url.Parse(ref)
		if err != nil {
			return nil, fmt.Errorf("parse map ref: %w", err)
		}
		mapURL = base.ResolveReference(rel).String()
	}

	if err := validateTargetURL(mapURL, config.AllowInternal); err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", mapURL, nil)
	if err != nil {
		return nil, err
	}
	if config.UserAgent != "" {
		req.Header.Set("User-Agent", config.UserAgent)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("sourcemap fetch returned %d", resp.StatusCode)
	}

	limit := config.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxBytes
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit))
}

// decodeDataURI handles both base64 and percent-encoded data: URIs.
// data:[<mediatype>][;base64],<data>
func decodeDataURI(uri string) ([]byte, error) {
	const prefix = "data:"
	if !strings.HasPrefix(uri, prefix) {
		return nil, fmt.Errorf("not a data URI")
	}
	rest := uri[len(prefix):]
	comma := strings.Index(rest, ",")
	if comma < 0 {
		return nil, fmt.Errorf("data URI missing comma")
	}
	meta, body := rest[:comma], rest[comma+1:]
	if strings.Contains(meta, ";base64") {
		dec, err := harBase64Decode([]byte(body))
		if err != nil {
			return nil, fmt.Errorf("data URI base64: %w", err)
		}
		return dec, nil
	}
	// percent-encoded
	out, err := url.QueryUnescape(body)
	if err != nil {
		return nil, fmt.Errorf("data URI url-unescape: %w", err)
	}
	return []byte(out), nil
}
