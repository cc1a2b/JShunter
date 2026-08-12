package jshunter

// registry_test.go is the regression lock for the curated secret-detection
// registry. It pins three things that must never silently regress:
//
//   1. Registry invariants — every rule self-tests green, IDs are unique,
//      patterns compile, length bounds are sane, and the ID index is a faithful
//      mirror of the registry slice.
//   2. A hostile false-positive corpus of REAL non-secrets (git SHAs, digests,
//      UUIDs, SRI/base64 blobs, credential-free and templated connection
//      strings, JWT-shaped-but-invalid tokens). analyzeBody must return ZERO
//      findings on it. This is the most important assertion in the repo: it is
//      what lets us keep precision high while adding rules.
//   3. A true-positive smoke set proving the high-precision prefixed rules still
//      fire on genuine-format tokens at the default confidence gate.
//
// All identifiers that are not tests are prefixed rt_ per the package test
// convention. Tests never run in parallel: analyzeBody/runSelfTest mutate the
// package-global dedupe map, so every analyzeBody call is preceded by
// resetFindings() and the suite relies on Go's sequential in-file ordering.

import (
	"strings"
	"testing"
)

// rt_expectedRuleCount pins the size of the curated registry (detection.go's
// first wave + rules_ext.go's extendedRules). If a rule is intentionally added
// or removed, update this constant in the same commit — the failure is the
// point, it forces a conscious review of the registry surface.
const rt_expectedRuleCount = 87

// TestRegistry_SelfTestAllPass runs every rule against its embedded TP/FP
// fixtures and asserts a clean sweep. On any failure it prints the offending
// RuleID together with the diagnostic Notes runSelfTest collected.
func TestRegistry_SelfTestAllPass(t *testing.T) {
	results := runSelfTest()

	if len(results) != rt_expectedRuleCount {
		t.Fatalf("self-test covered %d rules; expected %d (registry changed — update rt_expectedRuleCount if intentional)",
			len(results), rt_expectedRuleCount)
	}

	failed := 0
	for _, r := range results {
		if !r.OK {
			failed++
			t.Errorf("rule %q (%s) failed self-test: TP %d/%d, FP caught %d/%d, notes=%v",
				r.RuleID, r.Name, r.TPPassed, r.TPTotal, r.FPCaught, r.FPTotal, r.Notes)
		}
	}
	if failed > 0 {
		t.Fatalf("%d/%d registry rules failed self-test", failed, len(results))
	}
}

// TestRegistry_UniqueIDs asserts no two rules share an ID. A collision would
// let one rule silently shadow another in rulesIndex and in --only/--disable.
func TestRegistry_UniqueIDs(t *testing.T) {
	registerRules()

	counts := make(map[string]int, len(rulesRegistry))
	order := make([]string, 0, len(rulesRegistry))
	for i := range rulesRegistry {
		id := rulesRegistry[i].ID
		if counts[id] == 0 {
			order = append(order, id)
		}
		counts[id]++
	}

	for _, id := range order {
		if counts[id] > 1 {
			t.Errorf("duplicate rule ID %q registered %d times", id, counts[id])
		}
	}
	if len(rulesRegistry) != rt_expectedRuleCount {
		t.Errorf("registry holds %d rules; expected %d", len(rulesRegistry), rt_expectedRuleCount)
	}
}

// TestRegistry_PatternsCompile asserts every rule carries a compiled pattern, a
// non-empty ID, and sane length bounds (MinLen <= MaxLen whenever MaxLen is set,
// and no negative bounds).
func TestRegistry_PatternsCompile(t *testing.T) {
	registerRules()

	for i := range rulesRegistry {
		r := &rulesRegistry[i]
		if strings.TrimSpace(r.ID) == "" {
			t.Errorf("rule at index %d has an empty ID", i)
		}
		if r.Pattern == nil {
			t.Errorf("rule %q has a nil Pattern", r.ID)
			continue
		}
		if r.MinLen < 0 || r.MaxLen < 0 {
			t.Errorf("rule %q has a negative length bound (MinLen=%d, MaxLen=%d)", r.ID, r.MinLen, r.MaxLen)
		}
		if r.MaxLen > 0 && r.MinLen > r.MaxLen {
			t.Errorf("rule %q has MinLen %d > MaxLen %d", r.ID, r.MinLen, r.MaxLen)
		}
	}
}

// TestRegistry_IndexConsistent asserts rulesIndex is a faithful mirror of
// rulesRegistry: one entry per rule ID, each pointing at the rule that owns it.
func TestRegistry_IndexConsistent(t *testing.T) {
	registerRules()

	for i := range rulesRegistry {
		id := rulesRegistry[i].ID
		p, ok := rulesIndex[id]
		if !ok {
			t.Errorf("rulesIndex is missing an entry for rule ID %q", id)
			continue
		}
		if p == nil {
			t.Errorf("rulesIndex[%q] is nil", id)
			continue
		}
		if p.ID != id {
			t.Errorf("rulesIndex[%q] points at a rule whose ID is %q", id, p.ID)
		}
	}

	if len(rulesIndex) != len(rulesRegistry) {
		t.Errorf("rulesIndex has %d entries but the registry has %d rules (stray or missing index entry)",
			len(rulesIndex), len(rulesRegistry))
	}
}

// TestRegistry_NoFalsePositives is the precision lock. It feeds analyzeBody two
// corpora of genuine non-secrets and asserts ZERO findings survive the default
// 0.50 confidence gate. Any leak is printed with its RuleID and value so the
// regression is immediately actionable.
func TestRegistry_NoFalsePositives(t *testing.T) {
	corpora := []struct {
		name string
		body string
	}{
		{"hostile", rt_hostileCorpus},
		{"proximity", rt_proximityCorpus},
	}

	for _, c := range corpora {
		resetFindings()
		findings := analyzeBody("corpus://"+c.name, []byte(c.body), 0.50)
		if len(findings) == 0 {
			continue
		}
		for _, f := range findings {
			t.Errorf("[%s] false positive leaked: rule=%s value=%q redacted=%s confidence=%.2f line=%d col=%d",
				c.name, f.RuleID, f.Value, f.Redacted, f.Confidence, f.Line, f.Column)
		}
		t.Fatalf("[%s] corpus of real non-secrets produced %d finding(s); expected 0", c.name, len(findings))
	}
}

// TestRegistry_TruePositivesFire proves the high-precision prefixed rules still
// detect genuine-format tokens at the 0.50 gate. Token literals are stored as
// concatenated fragments so no contiguous secret ever appears in this source
// file (Go folds the constants at compile time; analyzeBody sees the whole
// value). The tokens reuse each rule's own vetted TPExample.
func TestRegistry_TruePositivesFire(t *testing.T) {
	for _, tc := range rt_truePositives {
		resetFindings()
		body := "const k = \"" + tc.token + "\";"
		findings := analyzeBody("tp://"+tc.ruleID, []byte(body), 0.50)

		fired := false
		got := make([]string, 0, len(findings))
		for _, f := range findings {
			got = append(got, f.RuleID)
			if f.RuleID == tc.ruleID {
				fired = true
			}
		}
		if !fired {
			t.Errorf("rule %q did not fire on a genuine-format token (redacted %s) at min-confidence 0.50; got findings=%v",
				tc.ruleID, redactValue(tc.token), got)
		}
	}
}

// rt_truePositives pairs a rule ID with a genuine-format token for that rule,
// each split into fragments so the contiguous secret never appears in source.
var rt_truePositives = []struct {
	ruleID string
	token  string
}{
	{"groq.api_key", "gsk_L2m" + "69I7wDdQGnMo6sFSYnvCeqmkfCXIxmEYupOYzBneBDtnhP0NR"},
	{"openrouter.api_key", "sk-or-v" + "1-067ca04053432ab168ca59d1ee785131358da2b631ef474551c14e56e2142047"},
	{"notion.integration_token", "ntn_985" + "99256546sNwq36XGb0oZ5EgsqW4ZZzvzTqB1WmHdP9K"},
	{"postman.api_key", "PMAK-56" + "5771eec9a0db3520965632-5c71d7daef62224b8c00713c8940d9fb1a"},
	{"grafana.service_account_token", "glsa_Rz" + "izFr7ReQJuGwN45JtsKJCqADPyWHTM_2dcc265b"},
}

// rt_hostileCorpus is a curated pile of real, non-secret strings that shallow
// regex scanners routinely misfire on. Every line here MUST score zero findings.
// It deliberately mixes git object IDs, content digests, UUIDs, Subresource
// Integrity / base64 asset blobs, minified bundle soup, credential-free and
// templated database URIs, JWT-shaped-but-invalid tokens, and PUBLIC (not
// private) key headers.
const rt_hostileCorpus = `
// --- git object identifiers: 40-hex SHA-1, not secrets ---------------------
commit 5f2e8a9c1d3b4e6f7a8b9c0d1e2f3a4b5c6d7e8f
parent 9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b
tree   e3b0c44298fc1c149afbf4c8996fb92427ae41e4
blob   da39a3ee5e6b4b0d3255bfef95601890afd80709

// --- content digests: 32-hex md5 and 64-hex sha256 -------------------------
md5    = d41d8cd98f00b204e9800998ecf8427e
etag   = "1f3870be274f6c49b3e31a0c6728957f"
sha256 = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
digest = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

// --- RFC-4122 UUIDs: request / correlation / span identifiers --------------
requestId = 123e4567-e89b-12d3-a456-426614174000
traceId   = 550e8400-e29b-41d4-a716-446655440000
spanId    = f47ac10b-58cc-4372-a567-0e02b2c3d479

// --- Subresource Integrity / lockfile integrity: base64 sha512 (== pad) ----
<script src="/vendor.js" integrity="sha512-2+1d312Gv/F0ka3L+WanxnvPQ93+m+j2HLOWk54rzWk/lAPxKcimaVSC+kRml1k+lqAEalcc0tQie4/Wubz/Zg=="></script>
"lodash-es":  { "integrity": "sha512-XSr9Mh++0EfIoxa8f08FovgmfZnC9S3Wu5cGGXLKtqurs7eIGuc69n+gTRYYq4fldrustqc/zTJf1Gp9hWSDgw==" }
"typescript": { "integrity": "sha512-htlLATSLqu5cO4qg4RPVw4yspdxSI+xLFXAsAnViNEdZGovJNcjowMDJGUtqJjYwvXw9WWj+VaFY6Uqc14jEBQ==" }

// --- inline base64 asset payloads (data URIs) ------------------------------
const pngPixel = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==";
const gifPixel = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

// --- framework-generated 24-char identifiers (React keys, asset hashes) ----
const fiberKey  = "a1B2c3D4e5F6g7H8i9J0k1L2";
const assetKey  = "Zm9vYmFyYmF6cXV4MTIzNDU2";
const chunkName = "main.7d3f9a2b8c1e4056.js";

// --- minified vendor bundle soup -------------------------------------------
!function(e,t){"object"==typeof exports?module.exports=t():"function"==typeof define&&define.amd?define([],t):e.LZ=t()}(this,function(){var e=String.fromCharCode,o="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";var r={compress:function(n){if(null==n)return"";var t=_c(n,6,function(i){return o.charAt(i)});switch(t.length%4){default:case 0:return t;case 1:return t+"===";case 2:return t+"==";case 3:return t+"="}}};return r});

// --- database connection strings: no credentials present -------------------
DATABASE_URL=postgres://localhost:5432/appdb
READONLY_URL=postgresql://readonly@db.internal/reports
REDIS_URL=redis://127.0.0.1:6379/0
MONGO_URL=mongodb://mongo:27017/records
AMQP_URL=amqp://guest@rabbitmq:5672/

// --- database connection strings: templated / interpolated passwords -------
PROD_DB=mongodb://appuser:${DB_PASSWORD}@cluster0.example.net/main
STAGE_DB=postgres://admin:{{POSTGRES_PASSWORD}}@10.0.0.5:5432/db
CI_DB=mysql://root:%MYSQL_PWD%@127.0.0.1:3306/sys

// --- JWT-shaped strings that FAIL structural JWT validation ----------------
header_no_alg  = eyJmb28iOiJiYXIifQ.eyJiYXoiOiJxdXgxMjM0NTY.c2lnbmF0dXJlX2Jsb2JfeHl6
bad_base64_len = eyJABCDEFGHIJ.eyJKLMNOPQRST.zzzzzzzzzzzz

// --- PUBLIC key material and certificates (NOT private keys) ---------------
-----BEGIN PUBLIC KEY-----
-----BEGIN CERTIFICATE-----
`

// rt_proximityCorpus places a common brand / config word (appId, cloudflare,
// datadog, postmark, cohere) immediately next to a coincidental 32- or 40-hex
// hash. It locks in the deliberate design decision (see rules_ext.go's header
// comment) to DROP bare hex/base64 shapes gated only by a nearby brand word:
// analyzeBody must still return ZERO findings here.
const rt_proximityCorpus = `
const appId          = "d41d8cd98f00b204e9800998ecf8427e";
let   cloudflareRay  = "5f2e8a9c1d3b4e6f7a8b9c0d1e2f3a4b5c6d7e8f";
const datadogTraceId = "9f86d081884c7d659a2feaa0c55ad0157f3870be";
window.postmark      = { messageId: "1f3870be274f6c49b3e31a0c6728957f" };
export const cohere  = "827ccb0eea8a706c4c34a16891f84e7b1a2b3c4d";
`
