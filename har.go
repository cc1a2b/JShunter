package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// HAR (HTTP Archive) ingestion. Operators who already have a Burp/Chrome
// devtools archive don't need JSHunter to re-fetch — feeding the HAR
// directly is faster and reproducible.

type harFile struct {
	Log struct {
		Entries []harEntry `json:"entries"`
	} `json:"log"`
}

type harEntry struct {
	Request struct {
		URL string `json:"url"`
	} `json:"request"`
	Response struct {
		Status  int `json:"status"`
		Content struct {
			MimeType string `json:"mimeType"`
			Text     string `json:"text"`
			Encoding string `json:"encoding"`
		} `json:"content"`
	} `json:"response"`
}

// IngestHAR reads a HAR file and runs the v0.6 detection pipeline against
// every JS-typed response within it. Non-JS entries are silently skipped.
// Returns the number of entries scanned (useful for --stats and CI gating).
func IngestHAR(path string, config *Config) (int, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read har: %w", err)
	}
	var h harFile
	if err := json.Unmarshal(raw, &h); err != nil {
		return 0, fmt.Errorf("parse har: %w", err)
	}

	scanned := 0
	for _, e := range h.Log.Entries {
		if e.Response.Status < 200 || e.Response.Status >= 400 {
			continue
		}
		mt := strings.ToLower(e.Response.Content.MimeType)
		urlLower := strings.ToLower(e.Request.URL)
		isJS := strings.Contains(mt, "javascript") ||
			strings.Contains(mt, "ecmascript") ||
			strings.HasSuffix(urlLower, ".js") ||
			strings.Contains(urlLower, ".js?")
		if !isJS {
			continue
		}

		body := []byte(e.Response.Content.Text)
		if e.Response.Content.Encoding == "base64" {
			if dec, derr := harBase64Decode(body); derr == nil {
				body = dec
			}
		}
		if config.MaxBytes > 0 && int64(len(body)) > config.MaxBytes {
			body = body[:config.MaxBytes]
			if globalStats != nil {
				statInc(&globalStats.BytesTruncated)
			}
		}
		if globalStats != nil {
			statInc(&globalStats.URLsFetched)
			statAdd(&globalStats.BytesParsed, int64(len(body)))
		}
		processed := processJSAnalysis(body, config)
		reportMatchesWithConfig(e.Request.URL, processed, config)
		scanned++
	}
	return scanned, nil
}

// harBase64Decode is tolerant of std/URL/raw base64 variants (HAR exporters
// disagree). We try each in order and return the first decode that succeeds.
func harBase64Decode(b []byte) ([]byte, error) {
	s := strings.TrimSpace(string(b))
	for _, dec := range []func(string) ([]byte, error){
		base64.StdEncoding.DecodeString,
		base64.URLEncoding.DecodeString,
		base64.RawStdEncoding.DecodeString,
		base64.RawURLEncoding.DecodeString,
	} {
		if out, err := dec(s); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("har: not decodable as any base64 variant")
}
