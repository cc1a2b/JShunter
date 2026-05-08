package main

import (
	"context"
	"net/http"
	"sync"
	"time"
)

// VerifyAllConcurrent runs liveness probes against every Finding that has
// a registered verifier, using a bounded worker pool. Per-host concurrency
// is still capped by `verifyHostLimiter`; the worker pool here is a
// global ceiling on simultaneous outbound HTTP calls so a scan with 200
// findings doesn't open 200 sockets at once.
//
// Each probe is bounded by `timeout`. Findings missing a verifier are
// silently skipped. Mutates findings in place (sets Verified, Verify,
// Confidence).
func VerifyAllConcurrent(findings []*Finding, client *http.Client, timeout time.Duration, workers int) {
	if workers <= 0 {
		workers = 8
	}
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	registerVerifiers()

	jobs := make(chan *Finding)
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for f := range jobs {
				v, ok := verifierRegistry[f.RuleID]
				if !ok {
					continue
				}
				if globalStats != nil {
					statInc(&globalStats.VerifyAttempts)
				}
				ctx, cancel := context.WithTimeout(context.Background(), timeout)
				res := v(ctx, client, f.Value)
				cancel()
				findingsMutex.Lock()
				f.Verify = &res
				if res.Alive {
					f.Verified = true
					f.Confidence = 1.0
				}
				findingsMutex.Unlock()
				switch {
				case res.Alive && globalStats != nil:
					statInc(&globalStats.VerifyAlive)
				case res.Error != "" && globalStats != nil:
					statInc(&globalStats.VerifyError)
				case globalStats != nil:
					statInc(&globalStats.VerifyDead)
				}
			}
		}()
	}
	for _, f := range findings {
		jobs <- f
	}
	close(jobs)
	wg.Wait()
}
