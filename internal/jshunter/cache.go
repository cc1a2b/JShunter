package jshunter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// On-disk cache for HTTP responses, keyed by URL hash. The point is twofold:
//
//  1. Re-running JSHunter on the same target during triage shouldn't
//     re-pull megabytes of bundles we already saw.
//  2. With ETag / Last-Modified, the second run becomes mostly 304s on
//     the wire — kinder to targets, faster on the operator's laptop.
//
// On disk:
//   <cache-dir>/<sha256(url)>.body  — response body
//   <cache-dir>/<sha256(url)>.meta  — JSON metadata (Etag, Last-Modified, status, fetchedAt, contentType)
//
// We do NOT cache responses with set-cookie or auth headers — those are
// session-specific and caching them is a security hazard.

type cacheMeta struct {
	URL          string    `json:"url"`
	Status       int       `json:"status"`
	ContentType  string    `json:"content_type,omitempty"`
	ETag         string    `json:"etag,omitempty"`
	LastModified string    `json:"last_modified,omitempty"`
	FetchedAt    time.Time `json:"fetched_at"`
	Size         int       `json:"size"`
}

type DiskCache struct {
	dir string
	mu  sync.Mutex
}

func NewDiskCache(dir string) (*DiskCache, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create cache dir: %w", err)
	}
	return &DiskCache{dir: dir}, nil
}

func (c *DiskCache) keyFor(u string) string {
	h := sha256.Sum256([]byte(u))
	return hex.EncodeToString(h[:])
}

func (c *DiskCache) bodyPath(u string) string {
	return filepath.Join(c.dir, c.keyFor(u)+".body")
}

func (c *DiskCache) metaPath(u string) string {
	return filepath.Join(c.dir, c.keyFor(u)+".meta")
}

// Lookup returns the cached entry if present. Caller decides whether to
// short-circuit (use as-is) or revalidate via If-None-Match.
func (c *DiskCache) Lookup(u string) (body []byte, meta *cacheMeta, ok bool) {
	if c == nil {
		return nil, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	rawMeta, err := os.ReadFile(c.metaPath(u))
	if err != nil {
		return nil, nil, false
	}
	var m cacheMeta
	if err := json.Unmarshal(rawMeta, &m); err != nil {
		return nil, nil, false
	}
	body, err = os.ReadFile(c.bodyPath(u))
	if err != nil {
		return nil, nil, false
	}
	return body, &m, true
}

// Store writes body + metadata. Skipped silently when the response carries
// `Set-Cookie` or `Authorization` (security hazard) or when `body` is empty.
func (c *DiskCache) Store(u string, resp *http.Response, body []byte) error {
	if c == nil || len(body) == 0 {
		return nil
	}
	if resp.Header.Get("Set-Cookie") != "" {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	meta := cacheMeta{
		URL:          u,
		Status:       resp.StatusCode,
		ContentType:  resp.Header.Get("Content-Type"),
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
		FetchedAt:    time.Now().UTC(),
		Size:         len(body),
	}
	rawMeta, err := json.Marshal(meta)
	if err != nil {
		return fmt.Errorf("cache: marshal meta: %w", err)
	}
	// Write body first, then meta. Lookup requires a valid .meta before it
	// trusts the .body, so the meta acts as the commit marker: writing it
	// last means a crash — or a competing writer — can never leave a valid
	// meta pointing at a partially written body. Both writes go through a
	// temp-file-then-rename so a concurrent reader (or a second JSHunter
	// process sharing --cache-dir, where our in-process mutex offers no
	// protection) never observes a half-written or interleaved file.
	if err := writeFileAtomic(c.bodyPath(u), body, 0o600); err != nil {
		return fmt.Errorf("cache: write body: %w", err)
	}
	if err := writeFileAtomic(c.metaPath(u), rawMeta, 0o600); err != nil {
		return fmt.Errorf("cache: write meta: %w", err)
	}
	return nil
}

// writeFileAtomic writes data to a temporary file in the same directory as
// path and atomically renames it into place. rename(2) is atomic within a
// filesystem, so a reader — including a second JSHunter process pointed at
// the same --cache-dir — always sees either the previous complete file or
// the new complete one, never a truncated or interleaved write. The fsync
// before rename makes the payload durable so a crash can't leave a
// zero-length entry that Lookup would treat as a valid cache hit.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	// Best-effort cleanup if we bail before the rename commits.
	defer func() {
		if tmpName != "" {
			os.Remove(tmpName)
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	tmpName = "" // rename committed; nothing left to clean up
	return nil
}

// AttachConditional sets If-None-Match / If-Modified-Since on a request when
// we have a cached entry. The caller observes a 304 in makeRequestWithRetry
// and substitutes the cached body.
func (c *DiskCache) AttachConditional(req *http.Request) {
	if c == nil {
		return
	}
	_, m, ok := c.Lookup(req.URL.String())
	if !ok {
		return
	}
	if m.ETag != "" {
		req.Header.Set("If-None-Match", m.ETag)
	}
	if m.LastModified != "" {
		req.Header.Set("If-Modified-Since", m.LastModified)
	}
}
