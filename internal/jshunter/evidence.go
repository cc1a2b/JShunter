package jshunter

import (
	"fmt"
	"strings"
)

// Evidence accumulation and the structural gate.
//
// scoreFinding answers "does this value look like what the rule describes".
// This file answers the question that actually decides whether an operator
// wastes an afternoon: "is this a credential at all, and does disclosing it
// cost anything". The two are kept separate on purpose — rule-intrinsic scoring
// is stable and unit-tested against fixed constants, while the structural stage
// is free to grow without rewriting those expectations.

// Signal is one named contribution to a finding's confidence.
type Signal struct {
	Name   string  `json:"name"`
	Delta  float64 `json:"delta,omitempty"`
	Detail string  `json:"detail,omitempty"`
}

// Evidence is the structural and statistical record behind a finding. It is an
// optional, additive member of the v2 output schema: absent on legacy-path
// findings and on bodies the scanner could not confidently classify.
type Evidence struct {
	Region       string   `json:"region,omitempty"`
	Role         string   `json:"role,omitempty"`
	BoundTo      string   `json:"bound_to,omitempty"`
	Callee       string   `json:"callee,omitempty"`
	Shape        string   `json:"shape,omitempty"`
	Charset      string   `json:"charset,omitempty"`
	Exposure     Exposure `json:"exposure,omitempty"`
	ExposureNote string   `json:"exposure_note,omitempty"`
	Surprisal    float64  `json:"surprisal,omitempty"`
	Signals      []Signal `json:"signals,omitempty"`
}

// structuralVerdict is the gate's decision for one candidate match.
type structuralVerdict struct {
	Keep     bool
	Delta    float64
	Reason   string
	Evidence *Evidence
}

// structuralGateEnabled is the operator kill switch behind --no-structural. It
// is written once during flag parsing, before any worker starts.
var structuralGateEnabled = true

// ruleNeedsBinding reports whether a rule carries so little provider-specific
// information that a match must be bound to a credential-named identifier to
// count as evidence.
//
// A rule with a real validator has already earned its keep — the value passed a
// checksum, a decode, or a structural test. A low-prior rule with no validator
// has matched a shape, and a shape alone is not a finding.
func ruleNeedsBinding(rule *Rule) bool {
	if rule == nil || rule.Validate != nil {
		return false
	}
	return rule.HighFPProne || rule.RequiresContext || rule.ConfidencePrior < 0.70
}

// evaluateStructure runs the structural gate for one match and returns the
// verdict plus the evidence to attach to the finding.
func evaluateStructure(rule *Rule, needsBinding bool, value, body, source string, start, end int, st *Structure) structuralVerdict {
	ev := &Evidence{}
	v := structuralVerdict{Keep: true, Evidence: ev}
	if !structuralGateEnabled || st == nil {
		ev.Exposure = ExposureSecret
		return v
	}

	hasValidator := rule != nil && rule.Validate != nil

	cls := st.Classify(start, end)
	lit := st.LiteralAt(start, end)
	// Rules that deliberately match the key as well as the value span the
	// binding and the literal. Narrowing to the literal they enclose recovers
	// the real value region without weakening the boundary test.
	if lit == nil && (cls == ClassStraddle || cls == ClassCode) {
		if ns, ne, ok := st.NarrowToLiteral(start, end); ok {
			if inner := st.LiteralAt(ns, ne); inner != nil {
				lit, cls = inner, inner.Kind
				if inner_v := st.LiteralValue(inner); inner_v != "" &&
					len(inner_v) < len(value) && strings.Contains(value, inner_v) {
					value = inner_v
				}
			}
		}
	}
	ev.Region = cls.String()

	var bound, callee string
	if lit != nil {
		bound = st.BindingName(lit)
		callee = st.CalleeName(lit)
		ev.Role = lit.Role.String()
		ev.BoundTo = bound
		ev.Callee = callee
	}
	credName, benignName := nameSignal(bound)

	shape := AnalyzeValue(value)
	ev.Shape = shape.Shape.String()
	ev.Charset = shape.Charset
	if s := st.Surprisal(value); s > 0 {
		ev.Surprisal = round2(s)
	}

	exposure := ClassifyExposure(rule, value, st, lit)
	ev.Exposure = exposure.Class
	ev.ExposureNote = exposure.Reason

	add := func(name string, delta float64, detail string) {
		ev.Signals = append(ev.Signals, Signal{Name: name, Delta: round2(delta), Detail: detail})
		v.Delta += delta
	}
	reject := func(reason string) structuralVerdict {
		return structuralVerdict{Keep: false, Reason: reason, Evidence: ev}
	}

	// --- rejections, all conditional on the body being confidently JavaScript
	if st.Reliable {
		switch cls {
		case ClassRegex:
			return reject("match lies inside a regular-expression literal, which is a pattern rather than a value")
		case ClassStraddle:
			return reject("match crosses a token boundary, so it is not a single literal value")
		case ClassCode:
			return reject("match lies in code rather than in a string literal, template literal or comment")
		}
		if lit != nil && literalRunFragment(st.LiteralValue(lit), value) {
			return reject("match is a slice of a longer uninterrupted token run in the same literal")
		}
		if lit != nil && pemHeaderWithoutBody(st.LiteralValue(lit), value) {
			return reject("PEM banner with no key body; this is a format constant, not a key")
		}
		if lit != nil && isMockResponseFixture(body, st, lit) {
			return reject("value is fixture data inside a mock HTTP response handler")
		}
		// A credential is a value. Manifests keyed by content hash are the
		// dominant source of property-key matches, and the few token-keyed maps
		// that exist are fixtures. A rule with a passing provider validator is
		// exempt, so a checksum-verified key stays visible wherever it appears.
		if lit != nil && lit.Role == RolePropertyKey && !hasValidator {
			return reject("match is an object property key, not a value")
		}
		if pw, placeholder := uriPasswordIsPlaceholder(value); placeholder {
			return reject("connection URI password is the placeholder '" + pw + "'")
		}
		if needsBinding && !credName {
			if lit == nil {
				return reject("shape-only rule with no credential-named binding to corroborate it")
			}
			if benignName {
				return reject("bound to '" + bound + "', which names a build artifact rather than a credential")
			}
			if !lit.Role.Binding() {
				return reject("shape-only rule matched in a position that binds no name to the value")
			}
			return reject("shape-only rule bound to '" + bound + "', which does not name a credential")
		}
		switch shape.Shape {
		case ShapeEncodedAsset:
			return reject("value " + shape.Detail)
		case ShapeEncodedText:
			if !credName {
				return reject("value " + shape.Detail)
			}
		case ShapeNaturalLanguage:
			return reject("value reads as prose rather than as an opaque credential")
		case ShapeRepetitive:
			return reject("value is a sequential or repeated pattern, not a generated credential")
		case ShapePathLike:
			if !credName {
				return reject("value is a path or URL rather than a credential")
			}
		case ShapeHexDigest, ShapeUUID:
			// Genuinely random, and therefore invisible to entropy. Only a
			// credential-named binding separates a live key from a content
			// hash or a trace id.
			if !credName && !hasValidator {
				return reject("value is " + shape.Detail + "; nothing binds it to a credential")
			}
		}
		if benignName && !hasValidator {
			return reject("bound to '" + bound + "', which names a build artifact rather than a credential")
		}
	}

	// --- corroboration
	if cls.IsLiteral() {
		add("in-literal", 0.04, "value is a complete "+cls.String())
	}
	if cls.IsComment() {
		add("in-comment", -0.10, "value appears in a comment")
	}
	if credName {
		add("credential-binding", 0.12, "bound to '"+bound+"'")
	}
	if benignName {
		add("artifact-binding", -0.12, "bound to '"+bound+"'")
	}
	if callee != "" && isCredentialCallee(callee) {
		add("credential-callee", 0.06, "passed to "+callee+"()")
	}
	if st.ModelReady() && ev.Surprisal > 0 {
		switch {
		case ev.Surprisal >= 5.0:
			add("file-relative-surprisal", 0.05, fmt.Sprintf("%.2f bits/char against this file's own character model", ev.Surprisal))
		case ev.Surprisal < 2.5:
			add("file-relative-surprisal", -0.08, fmt.Sprintf("only %.2f bits/char; indistinguishable from this file's ambient text", ev.Surprisal))
		}
	}
	switch exposure.Class {
	case ExposurePublic:
		add("published-by-design", -0.20, exposure.Reason)
	case ExposureIdentifier:
		add("identifier-not-credential", -0.18, exposure.Reason)
	case ExposureTest:
		add("non-production-scope", -0.10, exposure.Reason)
	}

	if v.Delta > 0.25 {
		v.Delta = 0.25
	}
	if v.Delta < -0.35 {
		v.Delta = -0.35
	}
	return v
}

// literalRunFragment reports whether a match is a proper slice of a literal
// that is one uninterrupted token run.
//
// This is the structural answer to Go's RE2 having no lookbehind. `\b` treats
// `-`, `.`, `+`, `/` and `=` as word boundaries, so a prefix-anchored rule
// matches happily in the middle of an inlined base64 blob, and a trailing `\b`
// can stop mid-run and return a truncated value. A developer who hard-codes a
// key writes the key and nothing else; when the surrounding literal is a single
// run and strictly longer, the regex found a slice of something else.
func literalRunFragment(litValue, match string) bool {
	if litValue == "" || len(litValue) <= len(match)+2 {
		return false
	}
	if !strings.Contains(litValue, match) {
		return false
	}
	for i := 0; i < len(litValue); i++ {
		if !isTokenRunChar(litValue[i]) {
			return false
		}
	}
	return true
}

// pemHeaderWithoutBody reports a PEM armour banner that carries no key.
//
// Every library that reads or writes PEM ships the banners as string constants
// — node-forge, jsrsasign and sshpk all do — and each one was reported as a
// critical private-key leak. A real key has a body: base64 between the BEGIN
// and END markers. The banner alone is a format constant.
func pemHeaderWithoutBody(litValue, value string) bool {
	if !strings.Contains(value, "-----BEGIN") {
		return false
	}
	if strings.Contains(litValue, "-----END") {
		return false
	}
	i := strings.Index(litValue, "-----")
	if i < 0 {
		return false
	}
	if j := strings.Index(litValue[i+5:], "-----"); j >= 0 {
		i += 5 + j + 5
	}
	body := 0
	for k := i; k < len(litValue); k++ {
		if isTokenRunChar(litValue[k]) {
			body++
		}
	}
	return body < 40
}

// credentialCallees are functions whose argument is a credential by contract.
var credentialCallees = []string{
	"setapikey", "setaccesstoken", "settoken", "authenticate", "authorize",
	"setcredentials", "withcredentials", "signin", "login", "createclient",
	"setauth", "setbearertoken", "setsecret", "configureauth",
}

func isCredentialCallee(callee string) bool {
	n := normalizeName(callee)
	if n == "" {
		return false
	}
	for _, c := range credentialCallees {
		if strings.HasSuffix(n, c) {
			return true
		}
	}
	return false
}

func round2(f float64) float64 {
	return float64(int64(f*100+copySign(0.5, f))) / 100
}

func copySign(mag, sign float64) float64 {
	if sign < 0 {
		return -mag
	}
	return mag
}

// NarrowToLiteral shrinks a span that encloses exactly one complete string or
// template literal down to that literal's payload. Rules that anchor on the
// key as well as the value — `apiKey\s*[:=]\s*"([^"]+)"` without a capture
// group — otherwise look like boundary-crossing matches.
func (st *Structure) NarrowToLiteral(start, end int) (int, int, bool) {
	if st == nil || len(st.spans) == 0 || end <= start {
		return 0, 0, false
	}
	s32, e32 := int32(start), int32(end)
	lo, hi := 0, len(st.spans)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if st.spans[mid].End <= s32 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	found := -1
	for i := lo; i < len(st.spans) && st.spans[i].Start < e32; i++ {
		sp := st.spans[i]
		if !sp.Kind.IsLiteral() || sp.Start < s32 || sp.End > e32 {
			continue
		}
		if found >= 0 {
			return 0, 0, false
		}
		found = i
	}
	if found < 0 {
		return 0, 0, false
	}
	sp := st.spans[found]
	// Step inside the delimiters; a template chunk closed by `${` carries a
	// two-byte terminator, which LiteralAt accounts for via its own payload
	// bounds, so a one-byte inset on each side is the safe common case.
	a, b := int(sp.Start)+1, int(sp.End)-1
	if b <= a {
		return 0, 0, false
	}
	return a, b, true
}

// skipStructural names the legacy pattern classes that are not secret-class
// detections. Links, parameters and GraphQL fragments legitimately appear in
// code and in comments, so the region test does not apply to them.
func skipStructural(name string) bool {
	switch {
	case name == "Link/URL", name == "Parameter", name == "Email",
		name == "Phone Number", name == "Firebase Url":
		return true
	case strings.HasPrefix(name, "GraphQL "), strings.HasPrefix(name, "Firebase Url"):
		return true
	}
	return false
}

// reportPublicExposure and minSeverityFloor are operator report filters, set
// once during flag parsing before any worker starts.
//
// A Stripe publishable key, a Firebase web config and a Supabase anon JWT are
// all live, high-entropy, provider-issued values that the vendor documents as
// safe to ship. Reporting them as leaked credentials is the false positive an
// operator actually loses time to, so they are classified and withheld by
// default rather than being scored down and printed anyway.
var (
	reportPublicExposure bool
	minSeverityFloor     int
)

// severityRank orders severities for --min-severity. Zero means unset.
func severityRank(s Severity) int {
	switch s {
	case SevInfo:
		return 1
	case SevLow:
		return 2
	case SevMedium:
		return 3
	case SevHigh:
		return 4
	case SevCritical:
		return 5
	}
	return 0
}

// suppressedByExposure reports whether a finding is withheld because the value
// is published by design or identifies a resource without granting access.
func suppressedByExposure(e Exposure) bool {
	if reportPublicExposure {
		return false
	}
	return e == ExposurePublic || e == ExposureIdentifier
}

// belowSeverityFloor reports whether a finding sits under --min-severity.
func belowSeverityFloor(s Severity) bool {
	return minSeverityFloor > 0 && severityRank(s) < minSeverityFloor
}

// mockModuleMarkers identify a module whose purpose is to serve fabricated HTTP
// responses. Their presence alone proves nothing — a production bundle can
// contain tree-shaken handlers next to real configuration — so the marker only
// arms the check; the literal must also sit inside a response constructor.
var mockModuleMarkers = []string{
	"msw", "setupWorker", "setupServer", "HttpResponse", "rest.get", "rest.post",
	"graphql.query", "graphql.mutation", "nock(", "miragejs", "createServer({",
	"jest.mock(", "vi.mock(", "__mocks__", "fetchMock", "axios-mock-adapter",
}

// mockResponseCallees construct the body of a fabricated response.
var mockResponseCallees = []string{
	"json", "text", "xml", "reply", "respondwith", "response", "res",
	"mockresolvedvalue", "mockreturnvalue", "mockimplementation",
}

// isMockResponseFixture reports a value that is fabricated response data.
//
// Mock handlers bind provider-shaped tokens to `access_token` and `apiKey`
// exactly as real configuration does, so nothing about the value or its binding
// separates them. What does separate them is where the value lives: inside the
// response constructor of a module built to fake HTTP.
func isMockResponseFixture(body string, st *Structure, lit *Literal) bool {
	if !inMockResponsePosition(st, lit) {
		return false
	}
	for _, m := range mockModuleMarkers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

// inMockResponsePosition reports a value sitting where fabricated response data
// lives: inside a response constructor, or inside an object the module itself
// names as a mock or a fixture.
func inMockResponsePosition(st *Structure, lit *Literal) bool {
	callee := normalizeName(st.EnclosingCalleeName(lit))
	for _, c := range mockResponseCallees {
		if callee != "" && callee == c {
			return true
		}
	}
	obj := normalizeName(st.ObjectName(lit))
	if obj == "" {
		return false
	}
	for _, p := range mockObjectPrefixes {
		if strings.HasPrefix(obj, p) {
			return true
		}
	}
	return false
}

// mockObjectPrefixes name an object whose members are fabricated by declaration.
var mockObjectPrefixes = []string{"mock", "fixture", "stub", "fake", "dummy", "sample", "seed"}
