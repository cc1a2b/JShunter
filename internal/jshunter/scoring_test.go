package jshunter

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// Shared test helpers. Every non-Test top-level identifier in this file is
// prefixed with st_ to avoid clashes with other test files in this package.
// ---------------------------------------------------------------------------

const st_eps = 1e-9

// st_almostEqual compares two floats within a small epsilon so that binary
// rounding of sums like 0.5+0.05 does not make an otherwise-correct score fail.
func st_almostEqual(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d <= st_eps
}

// st_validatorTrue is a stand-in provider validator that always accepts and
// contributes a recognisable reason string.
func st_validatorTrue(string) (bool, []string) {
	return true, []string{"custom-validator-ok"}
}

// st_validatorFalse always rejects with a recognisable reason string.
func st_validatorFalse(string) (bool, []string) {
	return false, []string{"custom-validator-no"}
}

// st_isHexLower reports whether s is entirely lowercase hex digits.
func st_isHexLower(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// st_joinReasons flattens a reasons slice for substring assertions.
func st_joinReasons(rs []string) string {
	return strings.Join(rs, " | ")
}

// st_findByValue returns the first finding whose Value matches, or nil.
func st_findByValue(fs []*Finding, value string) *Finding {
	for _, f := range fs {
		if f.Value == value {
			return f
		}
	}
	return nil
}

// st_akiaExample is a canonical AWS documentation sample that lives in the
// exact-match vendor-noise denylist. Assembled from fragments so this test
// file does not itself trip upstream secret scanners.
var st_akiaExample = "AKIA" + "IOSFODNN7EXAMPLE"

// st_highEntropyDiverse is a 40-char value with entropy 4.82 and 3 character
// classes (lower+upper+digit): it triggers both the entropy and diversity
// bonuses in scoreFinding.
const st_highEntropyDiverse = "A1b2C3d4E5f6G7h8I9" + "j0K1l2M3n4O5p6Q7r8S9t0"

// ---------------------------------------------------------------------------
// scoreFinding: full false-positive pipeline.
// ---------------------------------------------------------------------------

type st_scoreCase struct {
	name       string
	rule       *Rule
	value      string
	context    string
	source     string
	wantKeep   bool
	wantScore  float64  // asserted for every row; drops return 0
	reasonSubs []string // substrings that must appear in the joined reasons
}

func TestScoring_ScoreFindingPipeline(t *testing.T) {
	cases := []st_scoreCase{
		{
			name:       "vendor-noise-exact-match-drops",
			rule:       &Rule{ID: "t.exact", ConfidencePrior: 0.9},
			value:      st_akiaExample,
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"exact-match"},
		},
		{
			name:       "vendor-noise-substring-drops",
			rule:       &Rule{ID: "t.substr", ConfidencePrior: 0.9},
			value:      "xxxPLACEHOLDERxxx",
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"placeholder fragment"},
		},
		{
			name:       "minlen-drops",
			rule:       &Rule{ID: "t.minlen", ConfidencePrior: 0.9, MinLen: 20},
			value:      "tooShort", // 8 chars
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"< MinLen"},
		},
		{
			name:       "maxlen-drops",
			rule:       &Rule{ID: "t.maxlen", ConfidencePrior: 0.9, MaxLen: 8},
			value:      "waytoolongvalue123", // 18 chars
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"> MaxLen"},
		},
		{
			name:       "minentropy-drops",
			rule:       &Rule{ID: "t.minent", ConfidencePrior: 0.9, MinEntropy: 4.0},
			value:      strings.Repeat("a", 30), // entropy 0
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"< required"},
		},
		{
			name:       "highfp-low-diversity-drops",
			rule:       &Rule{ID: "t.hfp.div", ConfidencePrior: 0.9, HighFPProne: true},
			value:      "abcdefghijklmnop", // diversity 1
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"character-class diversity"},
		},
		{
			name:       "highfp-low-entropy-drops",
			rule:       &Rule{ID: "t.hfp.ent", ConfidencePrior: 0.9, HighFPProne: true},
			value:      strings.Repeat("a", 19) + "B", // diversity 2, entropy 0.29
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"too low for high-FP"},
		},
		{
			name:       "requires-context-present-adds-0.05",
			rule:       &Rule{ID: "t.ctx.ok", ConfidencePrior: 0.5, RequiresContext: true, ContextKeywords: []string{"github"}},
			value:      "abcdefghijklmnop", // div 1, entropy 4.0 -> no bonuses
			context:    "wired into github config",
			wantKeep:   true,
			wantScore:  0.55,
			reasonSubs: []string{"context keyword present"},
		},
		{
			name:       "requires-context-absent-drops",
			rule:       &Rule{ID: "t.ctx.no", ConfidencePrior: 0.5, RequiresContext: true, ContextKeywords: []string{"github"}},
			value:      "abcdefghijklmnop",
			context:    "nothing relevant nearby",
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"missing required context"},
		},
		{
			name:       "validate-pass-adds-0.10",
			rule:       &Rule{ID: "t.val.ok", ConfidencePrior: 0.5, Validate: st_validatorTrue},
			value:      "abcdefghijklmnop",
			wantKeep:   true,
			wantScore:  0.60,
			reasonSubs: []string{"custom-validator-ok"},
		},
		{
			name:       "validate-fail-drops",
			rule:       &Rule{ID: "t.val.no", ConfidencePrior: 0.5, Validate: st_validatorFalse},
			value:      "abcdefghijklmnop",
			wantKeep:   false,
			wantScore:  0,
			reasonSubs: []string{"provider validator rejected", "custom-validator-no"},
		},
		{
			name:       "fixture-wording-subtracts-0.30",
			rule:       &Rule{ID: "t.fix", ConfidencePrior: 0.9},
			value:      "abcdefghijklmnop",
			context:    "this is just an example",
			wantKeep:   true,
			wantScore:  0.60,
			reasonSubs: []string{"fixture/example wording"},
		},
		{
			name:       "high-entropy-adds-0.05",
			rule:       &Rule{ID: "t.ent", ConfidencePrior: 0.5},
			value:      "abcdefghijklmnopqrstuvwxyz", // entropy 4.70, diversity 1
			wantKeep:   true,
			wantScore:  0.55,
			reasonSubs: []string{"high entropy"},
		},
		{
			name:       "diverse-classes-adds-0.05",
			rule:       &Rule{ID: "t.div", ConfidencePrior: 0.5},
			value:      "aA1aA1aA1aA1", // diversity 3, entropy 1.585
			wantKeep:   true,
			wantScore:  0.55,
			reasonSubs: []string{"diverse character classes"},
		},
		{
			name:       "vendor-chunk-source-subtracts-0.15",
			rule:       &Rule{ID: "t.chunk", ConfidencePrior: 0.8},
			value:      "abcdefghijklmnop",
			source:     "assets/vendor/main.js",
			wantKeep:   true,
			wantScore:  0.65,
			reasonSubs: []string{"vendor/chunk bundle"},
		},
		{
			name: "score-clamped-to-upper-1.0",
			rule: &Rule{
				ID: "t.clamp.hi", ConfidencePrior: 0.95,
				RequiresContext: true, ContextKeywords: []string{"token"},
				Validate: st_validatorTrue,
			},
			value:      st_highEntropyDiverse, // entropy 4.82, diversity 3
			context:    "service token here",
			wantKeep:   true,
			wantScore:  1.0, // 0.95+0.05+0.10+0.05+0.05 = 1.20 -> clamped
			reasonSubs: []string{"context keyword present", "custom-validator-ok", "high entropy", "diverse character classes"},
		},
		{
			name:       "score-clamped-to-lower-0.0",
			rule:       &Rule{ID: "t.clamp.lo", ConfidencePrior: 0.10},
			value:      "abcdefghijklmnop",
			context:    "just an example placeholder-free line",
			source:     "static/vendor/app.js",
			wantKeep:   true,
			wantScore:  0.0, // 0.10-0.15-0.30 = -0.35 -> clamped
			reasonSubs: []string{"vendor/chunk bundle", "fixture/example wording"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			keep, score, reasons := scoreFinding(tc.rule, tc.value, tc.context, tc.source)
			if keep != tc.wantKeep {
				t.Fatalf("keep = %v, want %v (score=%.4f reasons=%q)", keep, tc.wantKeep, score, reasons)
			}
			if !st_almostEqual(score, tc.wantScore) {
				t.Errorf("score = %.6f, want %.6f (reasons=%q)", score, tc.wantScore, reasons)
			}
			joined := st_joinReasons(reasons)
			for _, sub := range tc.reasonSubs {
				if !strings.Contains(joined, sub) {
					t.Errorf("reasons %q missing substring %q", joined, sub)
				}
			}
		})
	}
}

// TestScoring_ScoreFindingZeroPriorDefaults verifies the ConfidencePrior==0
// fallback to the 0.5 baseline documented in scoreFinding.
func TestScoring_ScoreFindingZeroPriorDefaults(t *testing.T) {
	keep, score, _ := scoreFinding(&Rule{ID: "t.zero"}, "abcdefghijklmnop", "", "")
	if !keep {
		t.Fatalf("keep = false, want true")
	}
	if !st_almostEqual(score, 0.5) {
		t.Errorf("zero-prior baseline score = %.6f, want 0.5", score)
	}
}

// ---------------------------------------------------------------------------
// shannonEntropy
// ---------------------------------------------------------------------------

func TestScoring_ShannonEntropy(t *testing.T) {
	if got := shannonEntropy(""); got != 0 {
		t.Errorf("entropy(empty) = %v, want 0", got)
	}
	if got := shannonEntropy("aaaaaaaa"); got != 0 {
		t.Errorf("entropy(all-same) = %v, want 0", got)
	}

	// Known closed-form values.
	if got := shannonEntropy("aabb"); !st_almostEqual(got, 1.0) {
		t.Errorf("entropy(aabb) = %v, want 1.0", got)
	}
	if got := shannonEntropy("abcd"); !st_almostEqual(got, 2.0) {
		t.Errorf("entropy(abcd) = %v, want 2.0", got)
	}

	// Random-looking beats repeated.
	repeated := shannonEntropy(strings.Repeat("a", 32))
	random := shannonEntropy("aB3dE5fG7hJ9kL1mN2pQ4rS6tU8vWxYz")
	if !(random > repeated) {
		t.Errorf("expected random entropy %.4f > repeated entropy %.4f", random, repeated)
	}
	if repeated != 0 {
		t.Errorf("entropy(repeated) = %v, want 0", repeated)
	}
}

// ---------------------------------------------------------------------------
// charClassDiversity
// ---------------------------------------------------------------------------

func TestScoring_CharClassDiversity(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abcdef", 1},      // lower only
		{"ABCDEF", 1},      // upper only
		{"012345", 1},      // digit only
		{"-_./+=", 1},      // symbol only
		{"abcDEF", 2},      // lower+upper
		{"abc123", 2},      // lower+digit
		{"abcDEF123", 3},   // lower+upper+digit
		{"abcDEF123-_", 4}, // all four classes
		{"héllo", 1},       // non-ASCII letters ignored, only ASCII lower counts
	}
	for _, c := range cases {
		if got := charClassDiversity(c.in); got != c.want {
			t.Errorf("charClassDiversity(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// ---------------------------------------------------------------------------
// redactValue
// ---------------------------------------------------------------------------

func TestScoring_RedactValue(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"abcd", "****"},                           // n<=8 -> all stars
		{"abcdefgh", "********"},                   // boundary n==8
		{"abcdefghi", "ab*****hi"},                 // n==9 -> head2+tail2
		{"abcdefghijklmnop", "ab************op"},   // boundary n==16
		{"abcdefghijklmnopq", "abcd*********nopq"}, // boundary n==17 -> head4+tail4
	}
	for _, c := range cases {
		got := redactValue(c.in)
		if got != c.want {
			t.Errorf("redactValue(%q) = %q, want %q", c.in, got, c.want)
		}
		if len(got) != len(c.in) {
			t.Errorf("redactValue(%q) length = %d, want %d (mask must preserve length)", c.in, len(got), len(c.in))
		}
	}

	// Head/tail must be preserved for the long form; middle fully masked.
	long := "SECRETprefix_middle_body_suffixTAIL"
	red := redactValue(long)
	if !strings.HasPrefix(red, long[:4]) {
		t.Errorf("redactValue kept wrong head: %q", red)
	}
	if !strings.HasSuffix(red, long[len(long)-4:]) {
		t.Errorf("redactValue kept wrong tail: %q", red)
	}
	if strings.Contains(red[4:len(red)-4], long[10:15]) {
		t.Errorf("redactValue leaked middle bytes: %q", red)
	}
}

// ---------------------------------------------------------------------------
// hashValue
// ---------------------------------------------------------------------------

func TestScoring_HashValue(t *testing.T) {
	// Stability: same input -> same output.
	if hashValue("jshunter") != hashValue("jshunter") {
		t.Errorf("hashValue not stable for identical input")
	}
	// Distinct inputs -> distinct hashes (overwhelmingly likely).
	if hashValue("a") == hashValue("b") {
		t.Errorf("hashValue collided on distinct inputs")
	}
	// Shape: exactly 16 lowercase hex characters.
	for _, in := range []string{"", "jshunter", strings.Repeat("z", 500)} {
		h := hashValue(in)
		if len(h) != 16 {
			t.Errorf("hashValue(%q) length = %d, want 16", in, len(h))
		}
		if !st_isHexLower(h) {
			t.Errorf("hashValue(%q) = %q, not lowercase hex", in, h)
		}
	}
	// Known SHA-256 prefixes (first 8 bytes) pin the algorithm.
	if got := hashValue(""); got != "e3b0c44298fc1c14" {
		t.Errorf("hashValue(empty) = %q, want e3b0c44298fc1c14", got)
	}
	if got := hashValue("jshunter"); got != "d4aaaf60058e3eb7" {
		t.Errorf("hashValue(jshunter) = %q, want d4aaaf60058e3eb7", got)
	}
}

// ---------------------------------------------------------------------------
// positionAt
// ---------------------------------------------------------------------------

func TestScoring_PositionAt(t *testing.T) {
	const body = "abc\ndef\nghij"
	cases := []struct {
		idx      int
		wantLine int
		wantCol  int
	}{
		{0, 1, 1},              // start of file
		{1, 1, 2},              // second char, same line
		{2, 1, 3},              // 'c'
		{4, 2, 1},              // first char after first newline -> 'd'
		{5, 2, 2},              // 'e'
		{8, 3, 1},              // start of third line -> 'g'
		{-5, 1, 1},             // negative clamps to 0
		{len(body), 3, 5},      // idx == len clamps to len (end of "ghij")
		{len(body) + 99, 3, 5}, // beyond end clamps to len
	}
	for _, c := range cases {
		line, col := positionAt(body, c.idx)
		if line != c.wantLine || col != c.wantCol {
			t.Errorf("positionAt(idx=%d) = (%d,%d), want (%d,%d)", c.idx, line, col, c.wantLine, c.wantCol)
		}
	}

	// Multi-line walk: second 'c' in "a\nbb\nccc".
	line, col := positionAt("a\nbb\nccc", 6)
	if line != 3 || col != 2 {
		t.Errorf("positionAt second-c = (%d,%d), want (3,2)", line, col)
	}
}

// ---------------------------------------------------------------------------
// extractContextWindow
// ---------------------------------------------------------------------------

func TestScoring_ExtractContextWindow(t *testing.T) {
	// Whole small body is returned when the window over-reaches both ends.
	body := "hello world"
	if got := extractContextWindow(body, 0, 5); got != body {
		t.Errorf("small body window = %q, want %q", got, body)
	}

	// Both sides clipped: contextWindow==96 on each side of a 3-char match.
	clip := strings.Repeat("L", 120) + "MID" + strings.Repeat("R", 120)
	win := extractContextWindow(clip, 120, 123)
	if len(win) != 96+3+96 {
		t.Errorf("clipped window length = %d, want %d", len(win), 96+3+96)
	}
	if win[96:99] != "MID" {
		t.Errorf("clipped window centre = %q, want MID", win[96:99])
	}

	// Bounds-safe at the very start of the body.
	startBody := "abc" + strings.Repeat("z", 300)
	sw := extractContextWindow(startBody, 0, 3)
	if !strings.HasPrefix(sw, "abc") {
		t.Errorf("start window = %q, want prefix abc", sw[:8])
	}
	if len(sw) != 3+96 {
		t.Errorf("start window length = %d, want %d", len(sw), 3+96)
	}

	// Bounds-safe at the very end of the body.
	endBody := strings.Repeat("z", 300) + "xyz"
	ew := extractContextWindow(endBody, 300, 303)
	if !strings.HasSuffix(ew, "xyz") {
		t.Errorf("end window = %q, want suffix xyz", ew[len(ew)-8:])
	}
	if len(ew) != 96+3 {
		t.Errorf("end window length = %d, want %d", len(ew), 96+3)
	}

	// Degenerate: empty body cannot panic.
	if got := extractContextWindow("", 0, 0); got != "" {
		t.Errorf("empty body window = %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// isInVendorNoise
// ---------------------------------------------------------------------------

func TestScoring_IsInVendorNoise(t *testing.T) {
	// Exact-match corpus entry.
	if drop, why := isInVendorNoise(st_akiaExample); !drop || !strings.Contains(why, "exact-match") {
		t.Errorf("isInVendorNoise(exact) = (%v,%q), want (true, exact-match...)", drop, why)
	}
	// Substring placeholder fragment.
	if drop, why := isInVendorNoise("prefix_YOUR_API_KEY_suffix"); !drop || !strings.Contains(why, "placeholder fragment") {
		t.Errorf("isInVendorNoise(substr) = (%v,%q), want (true, ...placeholder fragment...)", drop, why)
	}
	if drop, _ := isInVendorNoise("xxPLACEHOLDERxx"); !drop {
		t.Errorf("isInVendorNoise(PLACEHOLDER) = false, want true")
	}
	// A real, non-sample key must not be flagged.
	if drop, why := isInVendorNoise("AKIA" + "2OGYBAH6STMMNXWG"); drop {
		t.Errorf("isInVendorNoise(real key) = (true,%q), want false", why)
	}
	if drop, _ := isInVendorNoise("totally-unique-value-42"); drop {
		t.Errorf("isInVendorNoise(unique) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// looksLikeFixture
// ---------------------------------------------------------------------------

func TestScoring_LooksLikeFixture(t *testing.T) {
	truthy := []string{
		"here is an example value",
		"loaded from fixture data",
		"just a dummy token",
		"sample credentials",
		"placeholder goes here",
		"FIXME rotate this",
		"TODO remove before prod",
		"for example, use this",
		"UPPER EXAMPLE CASE", // case-insensitive
	}
	for _, c := range truthy {
		if !looksLikeFixture(c) {
			t.Errorf("looksLikeFixture(%q) = false, want true", c)
		}
	}
	falsy := []string{
		"",
		"production credential in use",
		"live secret loaded at boot",
		"nothing suspicious on this line",
	}
	for _, c := range falsy {
		if looksLikeFixture(c) {
			t.Errorf("looksLikeFixture(%q) = true, want false", c)
		}
	}
}

// ---------------------------------------------------------------------------
// hasContextKeyword
// ---------------------------------------------------------------------------

func TestScoring_HasContextKeyword(t *testing.T) {
	// Empty keyword list is a wildcard: always true.
	if !hasContextKeyword("anything at all", nil) {
		t.Errorf("hasContextKeyword(nil kws) = false, want true")
	}
	if !hasContextKeyword("anything at all", []string{}) {
		t.Errorf("hasContextKeyword(empty kws) = false, want true")
	}
	// Present (case-insensitive).
	if !hasContextKeyword("the API Key value", []string{"api"}) {
		t.Errorf("hasContextKeyword(present) = false, want true")
	}
	if !hasContextKeyword("Bearer TOKEN header", []string{"token"}) {
		t.Errorf("hasContextKeyword(case-insensitive) = false, want true")
	}
	// One of several present.
	if !hasContextKeyword("session cookie set", []string{"nope", "session", "other"}) {
		t.Errorf("hasContextKeyword(one-of) = false, want true")
	}
	// Absent.
	if hasContextKeyword("nothing relevant nearby", []string{"token", "secret"}) {
		t.Errorf("hasContextKeyword(absent) = true, want false")
	}
}

// ---------------------------------------------------------------------------
// analyzeBody end-to-end: dedupe + resetFindings isolation + vendor-noise drop.
// ---------------------------------------------------------------------------

func TestScoring_AnalyzeBodyResetAndDedupe(t *testing.T) {
	const src = "https://example.test/app.js"

	// 1) A real AWS access key id survives the pipeline and is recorded.
	resetFindings()
	tp := "AKIA" + "2OGYBAH6STMMNXWG"
	got := analyzeBody(src, []byte(`const key = "`+tp+`";`), 0.0)
	f := st_findByValue(got, tp)
	if f == nil {
		t.Fatalf("expected a finding for %q, got %d findings", tp, len(got))
	}
	if f.RuleID != "aws.access_key_id" {
		t.Errorf("finding RuleID = %q, want aws.access_key_id", f.RuleID)
	}
	if f.Line != 1 || f.Column != 14 {
		t.Errorf("finding position = (%d,%d), want (1,14)", f.Line, f.Column)
	}
	if f.Redacted != redactValue(tp) || f.ValueHash != hashValue(tp) {
		t.Errorf("finding redaction/hash not wired: redacted=%q hash=%q", f.Redacted, f.ValueHash)
	}

	// 2) resetFindings isolates runs; the vendor-noise sample is dropped.
	resetFindings()
	noise := analyzeBody(src, []byte(`const key = "`+st_akiaExample+`";`), 0.0)
	if st_findByValue(noise, st_akiaExample) != nil {
		t.Errorf("vendor-noise sample %q leaked a finding", st_akiaExample)
	}

	// 3) The same secret twice in one body dedupes into a single Finding
	//    carrying two Locations.
	resetFindings()
	dupBody := `a = "` + tp + `";` + "\n" + `b = "` + tp + `";`
	dup := analyzeBody(src, []byte(dupBody), 0.0)
	merged := st_findByValue(dup, tp)
	if merged == nil {
		t.Fatalf("expected a merged finding for %q", tp)
	}
	if len(merged.Locations) != 2 {
		t.Errorf("merged Locations = %d, want 2 (dedupe should collapse both hits)", len(merged.Locations))
	}

	// Leave global dedupe state clean for any sibling tests.
	resetFindings()
}
