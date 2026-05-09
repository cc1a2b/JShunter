package jshunter

import (
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Per-host concurrency cap. Recon tools that hit one host with N parallel
// goroutines get banned. The default is intentionally conservative; operators
// who own the target can raise it via --threads (which becomes a global cap)
// without changing the per-host floor.
const (
	defaultPerHostConcurrency = 4
	defaultBreakerThreshold   = 5
	defaultBreakerCooldown    = 30 * time.Second
)

// hostController bounds outbound concurrency per host AND tracks consecutive
// 429/5xx responses for a circuit breaker. When the breaker trips, all
// subsequent requests to that host are dropped until cooldown elapses.
type hostController struct {
	perHost int
	mu      sync.Mutex
	state   map[string]*hostState
}

type hostState struct {
	sem        chan struct{}
	failStreak int
	tripUntil  time.Time
}

var (
	globalHostController *hostController
	hostControllerOnce   sync.Once
)

func getHostController() *hostController {
	hostControllerOnce.Do(func() {
		globalHostController = &hostController{
			perHost: defaultPerHostConcurrency,
			state:   map[string]*hostState{},
		}
	})
	return globalHostController
}

// host returns or creates the per-host bookkeeping struct.
func (c *hostController) host(h string) *hostState {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.state[h]
	if !ok {
		s = &hostState{sem: make(chan struct{}, c.perHost)}
		c.state[h] = s
	}
	return s
}

// acquire blocks until a token is available for the host. Returns a release
// closure and a bool — false means the breaker is tripped and the caller
// should NOT make the request.
func (c *hostController) acquire(host string) (release func(), allowed bool) {
	if host == "" {
		return func() {}, true
	}
	s := c.host(host)
	c.mu.Lock()
	if !s.tripUntil.IsZero() && time.Now().Before(s.tripUntil) {
		c.mu.Unlock()
		return func() {}, false
	}
	c.mu.Unlock()
	s.sem <- struct{}{}
	return func() { <-s.sem }, true
}

// recordOutcome teaches the circuit breaker. 200/2xx clears the streak; 429
// or 5xx increments it; once we've crossed the threshold the host is benched
// for the cooldown duration.
func (c *hostController) recordOutcome(host string, status int, retryAfter time.Duration) {
	if host == "" {
		return
	}
	s := c.host(host)
	c.mu.Lock()
	defer c.mu.Unlock()
	if status >= 200 && status < 400 {
		s.failStreak = 0
		return
	}
	if status == http.StatusTooManyRequests || status >= 500 {
		s.failStreak++
		if s.failStreak >= defaultBreakerThreshold {
			cd := defaultBreakerCooldown
			if retryAfter > cd {
				cd = retryAfter
			}
			s.tripUntil = time.Now().Add(cd)
			s.failStreak = 0
		}
	}
}

// parseRetryAfter returns the duration the server asked us to wait. Honors
// both seconds-form ("Retry-After: 30") and HTTP-date form. Returns 0 when
// absent or unparseable.
func parseRetryAfter(h http.Header) time.Duration {
	v := h.Get("Retry-After")
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d > 0 {
			return d
		}
	}
	return 0
}

// backoffWithJitter returns the v0.6 retry sleep — exponential base with
// ±25% jitter to avoid thundering-herd when many concurrent crawlers hit the
// same backoff schedule on the same host.
func backoffWithJitter(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 6 {
		attempt = 6
	}
	base := time.Duration(1<<uint(attempt)) * time.Second
	jitter := time.Duration(rand.Int63n(int64(base) / 2))
	return base + jitter - time.Duration(int64(base)/4)
}

// hostOf is a tiny helper for the controller; tolerates malformed URLs.
func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u == nil {
		return ""
	}
	return u.Host
}

// describeBreaker is used by --verbose to explain why a request was dropped.
func describeBreaker(host string) string {
	c := getHostController()
	c.mu.Lock()
	defer c.mu.Unlock()
	s, ok := c.state[host]
	if !ok || s.tripUntil.IsZero() {
		return ""
	}
	left := time.Until(s.tripUntil).Round(time.Second)
	return fmt.Sprintf("breaker tripped for %s, %s remaining", host, left)
}
