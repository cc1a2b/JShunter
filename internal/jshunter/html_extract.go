package jshunter

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/html"
)

// HTMLArtifacts is the structured slice of recon-relevant payloads
// extracted from one HTML response. Inline scripts and SRI hashes are not
// available in JS-only crawls — operators routinely miss secrets that live
// in the homepage's `<script>` tag rather than an external bundle.
type HTMLArtifacts struct {
	InlineScripts []InlineScript
	ExternalJS    []ExternalJS
	CSPOrigins    []string
	Sourcemaps    []string
}

type InlineScript struct {
	// Index is the zero-based position of the script tag in the document
	// so we can synthesize a stable per-script source id (`page#script[3]`).
	Index    int
	Body     string
	Type     string // "module" | "" | "application/json" | …
	Nonce    string
	IsLDJSON bool
}

type ExternalJS struct {
	URL       string
	Integrity string // SRI: "sha384-..."
	Async     bool
	Defer     bool
	Type      string
}

// ExtractFromHTML parses an HTML body and returns the extractable
// artifacts. Robust to malformed input — `golang.org/x/net/html` recovers
// from broken markup the way browsers do.
func ExtractFromHTML(body []byte) (*HTMLArtifacts, error) {
	out := &HTMLArtifacts{}
	z := html.NewTokenizer(bytes.NewReader(body))
	scriptIdx := 0

	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			if err := z.Err(); err != nil && err != io.EOF {
				return out, fmt.Errorf("html tokenizer: %w", err)
			}
			return out, nil

		case html.StartTagToken, html.SelfClosingTagToken:
			t := z.Token()
			switch strings.ToLower(t.Data) {
			case "script":
				attrs := tagAttrs(t)
				src := attrs["src"]
				if src != "" {
					out.ExternalJS = append(out.ExternalJS, ExternalJS{
						URL:       src,
						Integrity: attrs["integrity"],
						Async:     hasAttr(t, "async"),
						Defer:     hasAttr(t, "defer"),
						Type:      attrs["type"],
					})
				} else if tt == html.StartTagToken {
					// Capture inline script body up to </script>.
					body, err := readUntilEndTag(z, "script")
					if err == nil && strings.TrimSpace(body) != "" {
						script := InlineScript{
							Index: scriptIdx,
							Body:  body,
							Type:  attrs["type"],
							Nonce: attrs["nonce"],
						}
						script.IsLDJSON = strings.EqualFold(script.Type, "application/ld+json")
						out.InlineScripts = append(out.InlineScripts, script)
					}
					scriptIdx++
				}

			case "meta":
				// CSP via http-equiv (some sites prefer this over header).
				if strings.EqualFold(tagAttrs(t)["http-equiv"], "Content-Security-Policy") {
					content := tagAttrs(t)["content"]
					out.CSPOrigins = append(out.CSPOrigins, ParseCSPOrigins(content)...)
				}

			case "link":
				attrs := tagAttrs(t)
				rel := strings.ToLower(attrs["rel"])
				href := attrs["href"]
				if href != "" {
					switch rel {
					case "preload", "modulepreload", "prefetch":
						if strings.EqualFold(attrs["as"], "script") || rel == "modulepreload" {
							out.ExternalJS = append(out.ExternalJS, ExternalJS{
								URL:       href,
								Integrity: attrs["integrity"],
								Type:      "module",
							})
						}
					}
				}
			}
		}
	}
}

// readUntilEndTag consumes tokens up to and including the closing tag,
// returning the concatenated text content. Used to capture inline script
// bodies which the tokenizer reports as a separate Text token.
func readUntilEndTag(z *html.Tokenizer, tag string) (string, error) {
	var buf bytes.Buffer
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			return buf.String(), z.Err()
		case html.TextToken:
			buf.Write(z.Text())
		case html.EndTagToken:
			t := z.Token()
			if strings.EqualFold(t.Data, tag) {
				return buf.String(), nil
			}
		}
	}
}

func tagAttrs(t html.Token) map[string]string {
	m := make(map[string]string, len(t.Attr))
	for _, a := range t.Attr {
		m[strings.ToLower(a.Key)] = a.Val
	}
	return m
}

func hasAttr(t html.Token, name string) bool {
	for _, a := range t.Attr {
		if strings.EqualFold(a.Key, name) {
			return true
		}
	}
	return false
}

// looksLikeHTML returns true when the response body is HTML rather than JS.
// We use a tiny prefix sniff rather than the full encoding/sniff implementation
// because the body is already bounded by --max-bytes.
func looksLikeHTML(body []byte, contentType string) bool {
	if strings.Contains(strings.ToLower(contentType), "html") {
		return true
	}
	head := body
	if len(head) > 512 {
		head = head[:512]
	}
	low := strings.ToLower(string(head))
	low = strings.TrimSpace(low)
	return strings.HasPrefix(low, "<!doctype html") ||
		strings.HasPrefix(low, "<html") ||
		strings.HasPrefix(low, "<head") ||
		strings.HasPrefix(low, "<body")
}
