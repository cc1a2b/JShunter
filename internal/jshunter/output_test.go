package jshunter

// Serialization / output-format contract tests.
//
// These validate that the package renderers (JSON envelope, SARIF 2.1.0,
// NDJSON) and the --diff consumer honour the documented output contract
// (schema_version 2, redaction that never leaks the raw secret, stable
// value_hash, per-location SARIF results, new-only diff semantics).
//
// The renderers all read the process-global dedupe table populated by
// recordFinding and drained by flushFindings, so each test seeds that table
// from constructed *Finding values through the real ingestion path and, where
// a renderer only writes to os.Stdout, captures stdout via an os.Pipe. No
// product code is modified.

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Test fixtures / helpers (all package-level identifiers prefixed ot_).
// ---------------------------------------------------------------------------

// ot_sample is a constructed finding plus the raw fragments we assert never
// leak into redacted output.
type ot_sample struct {
	ruleID     string
	name       string
	provider   string
	secretType string
	severity   Severity
	raw        string // full raw secret value
	middle     string // a substring from the interior that must be masked
	source     string
	line       int
	column     int
}

// ot_makeFinding builds a *Finding exactly as analyzeBody would: redacted,
// value_hash and entropy are produced by the real product helpers so the
// redaction/hashing assertions exercise product behaviour, not a re-implement.
func ot_makeFinding(s ot_sample) *Finding {
	return &Finding{
		SchemaVersion: SchemaVersion,
		RuleID:        s.ruleID,
		Name:          s.name,
		Provider:      s.provider,
		SecretType:    s.secretType,
		Severity:      s.severity,
		Value:         s.raw,
		Redacted:      redactValue(s.raw),
		ValueHash:     hashValue(s.raw),
		Source:        s.source,
		Line:          s.line,
		Column:        s.column,
		Confidence:    0.91,
		Entropy:       shannonEntropy(s.raw),
		Reasons:       []string{"unit-test constructed finding"},
	}
}

// ot_samples is a small, distinct corpus. Distinct raw values guarantee
// distinct value_hash|secret_type keys, so recordFinding never merges them and
// finding-count == result-count invariants hold. None are real credentials;
// the fragment layout only needs len > 16 so redactValue keeps head+tail.
func ot_samples() []ot_sample {
	return []ot_sample{
		{
			ruleID: "aws.access_key_id", name: "AWS Access Key ID",
			provider: "AWS", secretType: "access_key_id", severity: SevCritical,
			raw: "tokAA_" + "HEADAAAABBBBCCCCDDDD" + "_ZZ01", middle: "AAAABBBB",
			source: "https://cdn.example.com/app.js", line: 12, column: 7,
		},
		{
			ruleID: "stripe.secret_key", name: "Stripe Secret Key",
			provider: "Stripe", secretType: "api_key", severity: SevCritical,
			raw: "tokBB_" + "HEADEEEEFFFFGGGGHHHH" + "_ZZ02", middle: "EEEEFFFF",
			source: "https://cdn.example.com/vendor.js", line: 340, column: 19,
		},
		{
			ruleID: "github.pat_classic", name: "GitHub Personal Access Token",
			provider: "GitHub", secretType: "pat", severity: SevHigh,
			raw: "tokCC_" + "HEADIIIIJJJJKKKKLLLL" + "_ZZ03", middle: "IIIIJJJJ",
			source: "/opt/site/static/main.min.js", line: 1, column: 4055,
		},
		{
			ruleID: "slack.webhook", name: "Slack Incoming Webhook",
			provider: "Slack", secretType: "webhook", severity: SevMedium,
			raw: "tokDD_" + "HEADMMMMNNNNOOOOPPPP" + "_ZZ04", middle: "MMMMNNNN",
			source: "https://assets.example.com/chunk.42.js", line: 88, column: 3,
		},
	}
}

// ot_withCleanState snapshots and restores the process-global suppression
// hooks and empties the dedupe table around fn, so subtests are hermetic
// regardless of execution order relative to any sibling test.
func ot_withCleanState(t *testing.T, fn func()) {
	t.Helper()
	prevIgnore := activeIgnoreList
	prevDiff := activeDiffSeen
	activeIgnoreList = nil
	activeDiffSeen = nil
	resetFindings()
	defer func() {
		resetFindings()
		activeIgnoreList = prevIgnore
		activeDiffSeen = prevDiff
	}()
	fn()
}

// ot_seed records every finding through the real ingestion path. It fails the
// test if any insert is unexpectedly suppressed or merged (which would break
// the count invariants the format assertions rely on).
func ot_seed(t *testing.T, findings []*Finding) {
	t.Helper()
	for _, f := range findings {
		if rec := recordFinding(f); rec == nil {
			t.Fatalf("recordFinding unexpectedly suppressed finding rule=%s hash=%s", f.RuleID, f.ValueHash)
		}
	}
}

// ot_captureStdout redirects os.Stdout to a pipe for the duration of fn and
// returns everything written. A concurrent reader drains the pipe so large
// payloads cannot deadlock on the pipe buffer, and os.Stdout is always
// restored (even if fn panics).
func ot_captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w

	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()

	func() {
		defer func() {
			os.Stdout = orig
			_ = w.Close()
		}()
		fn()
	}()

	out := <-done
	_ = r.Close()
	return out
}

// ot_isHex16 reports whether s is exactly 16 lowercase hex chars, matching
// hashValue's hex.EncodeToString(sha256[:8]) output shape.
func ot_isHex16(s string) bool {
	if len(s) != 16 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// JSON envelope (outputJSON -> stdout)
// ---------------------------------------------------------------------------

// ot_jsonEnvelope mirrors the top-level shape emitted by outputJSON.
type ot_jsonEnvelope struct {
	SchemaVersion int       `json:"schema_version"`
	Source        string    `json:"source"`
	Findings      []Finding `json:"findings"`
	Tool          struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"tool"`
}

func TestOutput_JSONEnvelope(t *testing.T) {
	ot_withCleanState(t, func() {
		samples := ot_samples()
		byHash := make(map[string]ot_sample, len(samples))
		findings := make([]*Finding, 0, len(samples))
		for _, s := range samples {
			f := ot_makeFinding(s)
			findings = append(findings, f)
			byHash[f.ValueHash] = s
		}
		ot_seed(t, findings)

		raw := ot_captureStdout(t, func() {
			outputJSON("https://scan.example.com/target", map[string][]string{
				"Emails": {"ops@example.com"},
			})
		})

		// Round-trips via json.Unmarshal.
		var env ot_jsonEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err != nil {
			t.Fatalf("envelope did not round-trip through json.Unmarshal: %v\npayload:\n%s", err, raw)
		}

		// Top-level schema_version == 2.
		if env.SchemaVersion != SchemaVersion {
			t.Errorf("top-level schema_version = %d, want %d", env.SchemaVersion, SchemaVersion)
		}
		if env.SchemaVersion != 2 {
			t.Errorf("top-level schema_version = %d, want literal 2", env.SchemaVersion)
		}
		if env.Tool.Name != "jshunter" {
			t.Errorf("tool.name = %q, want %q", env.Tool.Name, "jshunter")
		}
		if env.Tool.Version == "" {
			t.Error("tool.version is empty; want the build version string")
		}
		if len(env.Findings) != len(samples) {
			t.Fatalf("findings length = %d, want %d", len(env.Findings), len(samples))
		}

		seenHashes := make(map[string]bool, len(env.Findings))
		for i := range env.Findings {
			fn := env.Findings[i]
			want, ok := byHash[fn.ValueHash]
			if !ok {
				t.Errorf("finding[%d] has unexpected value_hash %q", i, fn.ValueHash)
				continue
			}
			seenHashes[fn.ValueHash] = true

			// Each finding carries schema_version.
			if fn.SchemaVersion != SchemaVersion {
				t.Errorf("finding %s: schema_version = %d, want %d", fn.RuleID, fn.SchemaVersion, SchemaVersion)
			}
			// value_hash is 16 lowercase hex chars and matches the product hash.
			if !ot_isHex16(fn.ValueHash) {
				t.Errorf("finding %s: value_hash %q is not 16 hex chars", fn.RuleID, fn.ValueHash)
			}
			if fn.ValueHash != hashValue(want.raw) {
				t.Errorf("finding %s: value_hash %q != hashValue(raw) %q", fn.RuleID, fn.ValueHash, hashValue(want.raw))
			}
			// Redaction must never expose the raw secret or its interior.
			if fn.Redacted == "" {
				t.Errorf("finding %s: redacted is empty", fn.RuleID)
			}
			if fn.Redacted == want.raw {
				t.Errorf("finding %s: redacted equals the raw secret", fn.RuleID)
			}
			if strings.Contains(fn.Redacted, want.raw) {
				t.Errorf("finding %s: redacted %q contains the raw secret", fn.RuleID, fn.Redacted)
			}
			if strings.Contains(fn.Redacted, want.middle) {
				t.Errorf("finding %s: redacted %q leaks interior fragment %q", fn.RuleID, fn.Redacted, want.middle)
			}
			if !strings.Contains(fn.Redacted, "*") {
				t.Errorf("finding %s: redacted %q is not masked", fn.RuleID, fn.Redacted)
			}
			// The raw secret must not appear anywhere in the redacted string; a
			// stronger cross-check: the serialized envelope keeps `value`
			// separate, and redacted is derived by redactValue.
			if fn.Redacted != redactValue(want.raw) {
				t.Errorf("finding %s: redacted %q != redactValue(raw) %q", fn.RuleID, fn.Redacted, redactValue(want.raw))
			}
			// source / line / column preserved verbatim.
			if fn.Source != want.source {
				t.Errorf("finding %s: source = %q, want %q", fn.RuleID, fn.Source, want.source)
			}
			if fn.Line != want.line {
				t.Errorf("finding %s: line = %d, want %d", fn.RuleID, fn.Line, want.line)
			}
			if fn.Column != want.column {
				t.Errorf("finding %s: column = %d, want %d", fn.RuleID, fn.Column, want.column)
			}
		}
		if len(seenHashes) != len(samples) {
			t.Errorf("distinct findings by value_hash = %d, want %d", len(seenHashes), len(samples))
		}
	})
}

// ---------------------------------------------------------------------------
// SARIF 2.1.0 (ToSARIF -> struct, marshalled and re-parsed independently)
// ---------------------------------------------------------------------------

// ot_sarifDoc is an independent view of the SARIF JSON. It deliberately does
// NOT reuse the product SARIF structs so the assertions validate the real
// serialized field names ($schema, ruleId, uri, ...).
type ot_sarifDoc struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name           string `json:"name"`
				Version        string `json:"version"`
				InformationURI string `json:"informationUri"`
				Rules          []struct {
					ID string `json:"id"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			Level     string `json:"level"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region *struct {
						StartLine   int `json:"startLine"`
						StartColumn int `json:"startColumn"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func TestOutput_SARIF(t *testing.T) {
	ot_withCleanState(t, func() {
		samples := ot_samples()
		findings := make([]*Finding, 0, len(samples))
		wantRuleIDs := make(map[string]bool, len(samples))
		for _, s := range samples {
			f := ot_makeFinding(s)
			findings = append(findings, f)
			wantRuleIDs[s.ruleID] = true
		}
		ot_seed(t, findings)

		env := ToSARIF()
		if env == nil {
			t.Fatal("ToSARIF returned nil")
		}

		// Valid JSON: marshal then re-parse through an independent struct.
		b, err := json.Marshal(env)
		if err != nil {
			t.Fatalf("SARIF envelope failed to marshal: %v", err)
		}
		if !json.Valid(b) {
			t.Fatal("SARIF output is not valid JSON")
		}
		var doc ot_sarifDoc
		if err := json.Unmarshal(b, &doc); err != nil {
			t.Fatalf("SARIF did not round-trip: %v", err)
		}

		if doc.Schema == "" {
			t.Error("$schema is empty")
		}
		if !strings.Contains(doc.Schema, "sarif") {
			t.Errorf("$schema = %q, expected a sarif schema URI", doc.Schema)
		}
		if doc.Version != "2.1.0" {
			t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
		}
		if len(doc.Runs) != 1 {
			t.Fatalf("runs length = %d, want 1", len(doc.Runs))
		}
		run := doc.Runs[0]

		// runs[0].tool.driver present and identified.
		if run.Tool.Driver.Name == "" {
			t.Error("runs[0].tool.driver.name is empty")
		}
		if run.Tool.Driver.Version == "" {
			t.Error("runs[0].tool.driver.version is empty")
		}
		if len(run.Tool.Driver.Rules) == 0 {
			t.Error("runs[0].tool.driver.rules is empty; driver should advertise its rule set")
		}

		// results[] length matches findings (each finding has exactly one
		// Location after recordFinding, so one SARIF result per finding).
		if len(run.Results) != len(findings) {
			t.Fatalf("results length = %d, want %d (one per finding location)", len(run.Results), len(findings))
		}

		// Each result has a ruleId and at least one usable location.
		for i, res := range run.Results {
			if res.RuleID == "" {
				t.Errorf("results[%d].ruleId is empty", i)
			}
			if !wantRuleIDs[res.RuleID] {
				t.Errorf("results[%d].ruleId = %q, not one of the seeded rules", i, res.RuleID)
			}
			if len(res.Locations) == 0 {
				t.Errorf("results[%d] has no locations", i)
				continue
			}
			uri := res.Locations[0].PhysicalLocation.ArtifactLocation.URI
			if uri == "" {
				t.Errorf("results[%d] location has empty artifactLocation.uri", i)
			}
			if res.Level == "" {
				t.Errorf("results[%d].level is empty", i)
			}
		}
	})
}

// ---------------------------------------------------------------------------
// NDJSON (outputNDJSON -> stdout, one finding per line)
// ---------------------------------------------------------------------------

func TestOutput_NDJSON(t *testing.T) {
	ot_withCleanState(t, func() {
		samples := ot_samples()
		findings := make([]*Finding, 0, len(samples))
		wantHashes := make(map[string]bool, len(samples))
		for _, s := range samples {
			f := ot_makeFinding(s)
			findings = append(findings, f)
			wantHashes[f.ValueHash] = true
		}
		ot_seed(t, findings)

		raw := ot_captureStdout(t, outputNDJSON)

		// N findings -> N non-empty lines.
		lines := make([]string, 0, len(samples))
		for _, ln := range strings.Split(raw, "\n") {
			if strings.TrimSpace(ln) != "" {
				lines = append(lines, ln)
			}
		}
		if len(lines) != len(samples) {
			t.Fatalf("NDJSON produced %d non-empty lines, want %d\npayload:\n%s", len(lines), len(samples), raw)
		}

		gotHashes := make(map[string]bool, len(lines))
		for i, ln := range lines {
			// Each line is independently json.Unmarshal-able into a Finding.
			var f Finding
			if err := json.Unmarshal([]byte(ln), &f); err != nil {
				t.Errorf("line %d is not valid JSON: %v\nline: %s", i, err, ln)
				continue
			}
			if f.SchemaVersion != SchemaVersion {
				t.Errorf("line %d: schema_version = %d, want %d", i, f.SchemaVersion, SchemaVersion)
			}
			if !ot_isHex16(f.ValueHash) {
				t.Errorf("line %d: value_hash %q is not 16 hex chars", i, f.ValueHash)
			}
			if f.Redacted == "" || strings.Contains(f.Redacted, f.Value) {
				t.Errorf("line %d: redacted %q leaks raw value %q", i, f.Redacted, f.Value)
			}
			gotHashes[f.ValueHash] = true
		}
		for h := range wantHashes {
			if !gotHashes[h] {
				t.Errorf("NDJSON missing seeded finding with value_hash %q", h)
			}
		}
		if len(gotHashes) != len(wantHashes) {
			t.Errorf("NDJSON emitted %d distinct hashes, want %d", len(gotHashes), len(wantHashes))
		}
	})
}

// ---------------------------------------------------------------------------
// Diff envelope (DiffPrevious + activeDiffSeen suppression path)
// ---------------------------------------------------------------------------

func TestOutput_DiffNewOnly(t *testing.T) {
	ot_withCleanState(t, func() {
		samples := ot_samples() // [0],[1] are the baseline; [2],[3] are new.
		if len(samples) < 4 {
			t.Fatalf("need >=4 samples, have %d", len(samples))
		}
		oldA := samples[0]
		oldB := samples[1]
		newC := samples[2]
		newD := samples[3]

		// Phase 1: produce a real previous envelope via outputJSON, containing
		// only the baseline findings, and persist it to disk.
		ot_seed(t, []*Finding{ot_makeFinding(oldA), ot_makeFinding(oldB)})
		prevJSON := ot_captureStdout(t, func() {
			outputJSON("https://scan.example.com/yesterday", nil)
		})
		resetFindings() // start the "current" run from a clean table

		prevPath := filepath.Join(t.TempDir(), "yesterday.json")
		if err := os.WriteFile(prevPath, []byte(prevJSON), 0o600); err != nil {
			t.Fatalf("write previous envelope: %v", err)
		}

		// Phase 2: DiffPrevious parses the envelope and returns the baseline
		// value_hash set.
		seen, err := DiffPrevious(prevPath)
		if err != nil {
			t.Fatalf("DiffPrevious returned error: %v", err)
		}
		if len(seen) != 2 {
			t.Fatalf("baseline seen set size = %d, want 2", len(seen))
		}
		if !seen[hashValue(oldA.raw)] || !seen[hashValue(oldB.raw)] {
			t.Fatalf("baseline seen set missing an expected hash: %v", seen)
		}

		// Phase 3: wire the baseline into the live suppression hook and record
		// the current set (old A,B + new C,D). Only NEW findings survive.
		activeDiffSeen = seen

		if got := recordFinding(ot_makeFinding(oldA)); got != nil {
			t.Errorf("baseline finding A was reported; want suppressed by --diff")
		}
		if got := recordFinding(ot_makeFinding(oldB)); got != nil {
			t.Errorf("baseline finding B was reported; want suppressed by --diff")
		}
		if got := recordFinding(ot_makeFinding(newC)); got == nil {
			t.Errorf("new finding C was suppressed; want reported")
		}
		if got := recordFinding(ot_makeFinding(newD)); got == nil {
			t.Errorf("new finding D was suppressed; want reported")
		}

		out := flushFindings()
		if len(out) != 2 {
			t.Fatalf("post-diff findings = %d, want 2 (only new)", len(out))
		}
		gotHashes := map[string]bool{}
		for _, f := range out {
			gotHashes[f.ValueHash] = true
		}
		if !gotHashes[hashValue(newC.raw)] || !gotHashes[hashValue(newD.raw)] {
			t.Errorf("post-diff set missing a new finding: %v", gotHashes)
		}
		if gotHashes[hashValue(oldA.raw)] || gotHashes[hashValue(oldB.raw)] {
			t.Errorf("post-diff set leaked a baseline finding: %v", gotHashes)
		}
	})
}

// ot_diffEnvelope is used to hand-craft previous envelopes with a chosen
// schema_version for the compatibility-check tests.
type ot_diffEnvelope struct {
	SchemaVersion int       `json:"schema_version"`
	Findings      []Finding `json:"findings"`
}

func TestOutput_DiffSchemaCompat(t *testing.T) {
	ot_withCleanState(t, func() {
		dir := t.TempDir()

		writeEnvelope := func(name string, v int) string {
			p := filepath.Join(dir, name)
			env := ot_diffEnvelope{
				SchemaVersion: v,
				Findings: []Finding{
					*ot_makeFinding(ot_samples()[0]),
				},
			}
			b, err := json.Marshal(env)
			if err != nil {
				t.Fatalf("marshal envelope: %v", err)
			}
			if err := os.WriteFile(p, b, 0o600); err != nil {
				t.Fatalf("write envelope: %v", err)
			}
			return p
		}

		// Matching schema version parses cleanly and yields the hash set.
		okPath := writeEnvelope("match.json", SchemaVersion)
		seen, err := DiffPrevious(okPath)
		if err != nil {
			t.Fatalf("DiffPrevious(matching schema) error: %v", err)
		}
		if len(seen) != 1 {
			t.Errorf("matching-schema seen size = %d, want 1", len(seen))
		}

		// Mismatched schema version is a hard error mentioning schema_version.
		badPath := writeEnvelope("mismatch.json", SchemaVersion+1)
		if _, err := DiffPrevious(badPath); err == nil {
			t.Error("DiffPrevious accepted a mismatched schema_version; want error")
		} else if !strings.Contains(err.Error(), "schema_version") {
			t.Errorf("mismatch error = %q, want it to mention schema_version", err.Error())
		}

		// A zero/absent schema_version (e.g. a pre-v2 or hand-rolled file) also
		// fails the compatibility gate.
		legacyPath := writeEnvelope("legacy.json", 0)
		if _, err := DiffPrevious(legacyPath); err == nil {
			t.Error("DiffPrevious accepted schema_version=0; want error")
		}

		// Empty path is a documented no-op: (nil, nil).
		seen, err = DiffPrevious("")
		if err != nil || seen != nil {
			t.Errorf("DiffPrevious(\"\") = (%v, %v), want (nil, nil)", seen, err)
		}

		// Missing file surfaces a read error.
		if _, err := DiffPrevious(filepath.Join(dir, "does-not-exist.json")); err == nil {
			t.Error("DiffPrevious(missing file) returned nil error; want a read error")
		} else if !strings.Contains(err.Error(), "read previous") {
			t.Errorf("missing-file error = %q, want it to mention \"read previous\"", err.Error())
		}

		// Malformed JSON surfaces a parse error.
		malformed := filepath.Join(dir, "malformed.json")
		if err := os.WriteFile(malformed, []byte("{ this is not json"), 0o600); err != nil {
			t.Fatalf("write malformed: %v", err)
		}
		if _, err := DiffPrevious(malformed); err == nil {
			t.Error("DiffPrevious(malformed) returned nil error; want a parse error")
		} else if !strings.Contains(err.Error(), "parse previous") {
			t.Errorf("malformed error = %q, want it to mention \"parse previous\"", err.Error())
		}
	})
}
