package jshunter

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// robots.txt is recon gold: targets explicitly list their non-crawlable
// paths. JSHunter's `--robots` mode fetches the file, returns the
// disallowed paths, and the operator can feed those back as targets.
//
// We don't honor robots.txt for our own crawling by default — that's a
// recon-tool decision, not a library decision — but operators on
// engagements with explicit rules-of-engagement can pipe the disallow
// list into the URL queue.
//
// Spec: https://www.rfc-editor.org/rfc/rfc9309

type RobotsResult struct {
	URL       string
	Disallow  []string
	Allow     []string
	Sitemaps  []string
	UserAgent string
}

// FetchRobots fetches `<base>/robots.txt` and parses the rules for the
// configured user-agent (or `*` if none). Returns nil result when the
// file is absent or unreachable — robots.txt absence is the most common
// case and not an error.
func FetchRobots(client *http.Client, baseURL string, ua string) (*RobotsResult, error) {
	target := strings.TrimRight(baseURL, "/") + "/robots.txt"
	if err := validateTargetURL(target, false); err != nil {
		return nil, fmt.Errorf("robots: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return nil, err
	}
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("robots fetch returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil, err
	}
	return parseRobots(target, ua, raw), nil
}

// parseRobots implements a defensive subset of RFC 9309. We don't model
// `Crawl-delay` or wildcard groups perfectly — operators wanting strict
// compliance should use a dedicated robots library — but for "give me
// the disallow paths" the simple group walk is correct.
func parseRobots(target, ua string, body []byte) *RobotsResult {
	res := &RobotsResult{URL: target, UserAgent: ua}
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	currentGroup := []string{}
	matchActive := false
	defaultMatch := false
	if ua == "" {
		ua = "*"
	}
	uaLower := strings.ToLower(ua)

	flush := func() {
		// A blank line ends a group; commit if current group applies.
		currentGroup = currentGroup[:0]
		matchActive = false
	}

	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			flush()
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			continue
		}
		field := strings.TrimSpace(strings.ToLower(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])

		switch field {
		case "user-agent":
			currentGroup = append(currentGroup, strings.ToLower(val))
			matchActive = false
			for _, g := range currentGroup {
				if g == uaLower || g == "*" {
					matchActive = true
					if g == "*" {
						defaultMatch = true
					}
					break
				}
			}
		case "disallow":
			if matchActive && val != "" {
				res.Disallow = append(res.Disallow, val)
			}
		case "allow":
			if matchActive && val != "" {
				res.Allow = append(res.Allow, val)
			}
		case "sitemap":
			res.Sitemaps = append(res.Sitemaps, val)
		}
	}
	_ = defaultMatch
	return res
}
