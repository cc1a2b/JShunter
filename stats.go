package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// Stats is the operator's audit trail for a JSHunter run. Without these
// counters, "the FP filter dropped 800 things" is opaque; with them, the
// operator can answer "did the filter eat a real key?" by re-running with
// --no-fp-filter and diffing.
type Stats struct {
	RunID                string
	StartedAt            time.Time
	URLsQueued           int64
	URLsFetched          int64
	URLsBlocked          int64
	BytesParsed          int64
	BytesTruncated       int64
	RegistryHits         int64
	LegacyMatchesRaw     int64
	DroppedVendorNoise   int64
	DroppedFixture       int64
	DroppedSourcemap     int64
	DroppedLowEntropy    int64
	DroppedNoContext     int64
	DroppedBelowConf     int64
	DroppedRegistryDup   int64
	FindingsAfterFilter  int64
	FindingsAfterDedupe  int64
	VerifyAttempts       int64
	VerifyAlive          int64
	VerifyDead           int64
	VerifyError          int64
}

var globalStats *Stats

// initStats creates a stats struct with a freshly minted run-id; safe to call
// once per process. The run-id makes log lines correlatable across stages.
func initStats() *Stats {
	if globalStats != nil {
		return globalStats
	}
	globalStats = &Stats{
		RunID:     newRunID(),
		StartedAt: time.Now(),
	}
	return globalStats
}

func newRunID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("rid-%d", time.Now().UnixNano())
	}
	return "rid-" + hex.EncodeToString(b)
}

// Inc adds 1 to a named counter via atomic ops. The counter pointer is passed
// directly so callers can use it freely from goroutines without contention.
func statInc(p *int64) {
	if p != nil {
		atomic.AddInt64(p, 1)
	}
}

func statAdd(p *int64, n int64) {
	if p != nil {
		atomic.AddInt64(p, n)
	}
}

// printStats emits a human-friendly summary to stderr (so it doesn't pollute
// the stdout pipeline operators feed into other tools). When --json is set,
// the same numbers ride the JSON envelope under "stats".
func printStats(s *Stats) {
	if s == nil {
		return
	}
	dur := time.Since(s.StartedAt).Round(time.Millisecond)
	fmt.Fprintf(os.Stderr, "\n[%sSTATS%s] run=%s duration=%s\n", colors["BLUE"], colors["NC"], s.RunID, dur)
	fmt.Fprintf(os.Stderr, "  fetched         : %d (%d blocked, %d truncated)\n",
		atomic.LoadInt64(&s.URLsFetched),
		atomic.LoadInt64(&s.URLsBlocked),
		atomic.LoadInt64(&s.BytesTruncated))
	fmt.Fprintf(os.Stderr, "  bytes parsed    : %d\n", atomic.LoadInt64(&s.BytesParsed))
	fmt.Fprintf(os.Stderr, "  registry hits   : %d\n", atomic.LoadInt64(&s.RegistryHits))
	fmt.Fprintf(os.Stderr, "  legacy raw      : %d\n", atomic.LoadInt64(&s.LegacyMatchesRaw))
	fmt.Fprintf(os.Stderr, "  dropped/vendor  : %d\n", atomic.LoadInt64(&s.DroppedVendorNoise))
	fmt.Fprintf(os.Stderr, "  dropped/fixture : %d\n", atomic.LoadInt64(&s.DroppedFixture))
	fmt.Fprintf(os.Stderr, "  dropped/srcmap  : %d\n", atomic.LoadInt64(&s.DroppedSourcemap))
	fmt.Fprintf(os.Stderr, "  dropped/entropy : %d\n", atomic.LoadInt64(&s.DroppedLowEntropy))
	fmt.Fprintf(os.Stderr, "  dropped/context : %d\n", atomic.LoadInt64(&s.DroppedNoContext))
	fmt.Fprintf(os.Stderr, "  dropped/conf    : %d\n", atomic.LoadInt64(&s.DroppedBelowConf))
	fmt.Fprintf(os.Stderr, "  dropped/dup     : %d\n", atomic.LoadInt64(&s.DroppedRegistryDup))
	fmt.Fprintf(os.Stderr, "  findings post   : %d (after dedupe %d)\n",
		atomic.LoadInt64(&s.FindingsAfterFilter),
		atomic.LoadInt64(&s.FindingsAfterDedupe))
	if atomic.LoadInt64(&s.VerifyAttempts) > 0 {
		fmt.Fprintf(os.Stderr, "  verify          : %d alive / %d dead / %d error\n",
			atomic.LoadInt64(&s.VerifyAlive),
			atomic.LoadInt64(&s.VerifyDead),
			atomic.LoadInt64(&s.VerifyError))
	}
}
