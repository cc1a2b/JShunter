package jshunter

import (
	"encoding/base64"
	"regexp"
	"strings"
	"unicode/utf8"
)

// uriUserinfoRe matches a URI that carries a username and password.
var uriUserinfoRe = regexp.MustCompile(`://[^/\s:@]+:[^/\s:@]+@`)

// Value-shape analysis.
//
// Entropy alone cannot separate a credential from a build artifact, because a
// content hash, a UUID and an API key are all genuinely random. What separates
// them is shape: a SHA-256 is exactly sixty-four lowercase hex characters, a
// UUID carries its dashes in fixed positions, an inlined asset base64-decodes
// to a PNG header, and an i18n string decodes to a sentence. Every function
// here answers a question about the value itself, independent of any rule.

// ValueShape names what a candidate value structurally is.
type ValueShape uint8

const (
	ShapeUnknown ValueShape = iota
	ShapeHexDigest
	ShapeUUID
	ShapeEncodedAsset
	ShapeEncodedText
	ShapeNaturalLanguage
	ShapePathLike
	ShapeRepetitive
	ShapeOpaqueToken
)

// String renders a shape for evidence output.
func (s ValueShape) String() string {
	switch s {
	case ShapeHexDigest:
		return "hex-digest"
	case ShapeUUID:
		return "uuid"
	case ShapeEncodedAsset:
		return "base64-encoded-asset"
	case ShapeEncodedText:
		return "base64-encoded-text"
	case ShapeNaturalLanguage:
		return "natural-language"
	case ShapePathLike:
		return "path-like"
	case ShapeRepetitive:
		return "repetitive"
	case ShapeOpaqueToken:
		return "opaque-token"
	}
	return "unknown"
}

// Credentialish reports whether the shape is consistent with a real secret.
func (s ValueShape) Credentialish() bool {
	return s == ShapeOpaqueToken || s == ShapeUnknown
}

// ValueAnalysis is the full shape verdict for one candidate.
type ValueAnalysis struct {
	Shape       ValueShape
	Charset     string
	Detail      string
	Entropy     float64
	Normalized  float64
	MaxRun      int
	Sequential  bool
	DecodedKind string
}

// AnalyzeValue classifies a candidate secret by shape alone.
func AnalyzeValue(v string) ValueAnalysis {
	a := ValueAnalysis{
		Entropy: shannonEntropy(v),
		Charset: charsetName(v),
		MaxRun:  maxRunLength(v),
	}
	a.Normalized = normalizedEntropy(v)
	a.Sequential = hasSequentialRun(v, 6)

	switch {
	// Ordered so a hand-typed placeholder is never mistaken for a digest: an
	// all-'a' 32-character string is both valid hex and obviously not a hash.
	case a.Sequential || a.MaxRun >= 6 || repeatedUnit(v):
		a.Shape, a.Detail = ShapeRepetitive, "sequential or repeated character run"
	case looksLikeUUID(v):
		a.Shape, a.Detail = ShapeUUID, "canonical UUID layout"
	case looksLikeHexDigest(v):
		a.Shape, a.Detail = ShapeHexDigest, "exact digest length for "+digestName(len(v))
	case hasUnresolvedTemplate(v):
		a.Shape, a.Detail = ShapeRepetitive, "carries an unresolved template placeholder"
	case digestBodyLen(v) > 0:
		a.Shape, a.Detail = ShapeHexDigest, "wraps an exact-length "+digestName(digestBodyLen(v))+" digest"
	case looksPathLike(v):
		a.Shape, a.Detail = ShapePathLike, "path or URL shaped"
	case looksNaturalLanguage(v):
		a.Shape, a.Detail = ShapeNaturalLanguage, "reads as prose, not an opaque token"
	default:
		if kind, detail, ok := decodedPayloadKind(v); ok {
			a.DecodedKind = kind
			a.Detail = detail
			if kind == "text" || kind == "json" {
				a.Shape = ShapeEncodedText
			} else {
				a.Shape = ShapeEncodedAsset
			}
			break
		}
		a.Shape, a.Detail = ShapeOpaqueToken, "opaque high-variance token"
	}
	return a
}

// charsetName labels the alphabet a value is drawn from. The label is evidence
// in itself: an all-lowercase-hex value of digest length is a build artifact
// whatever its entropy says.
func charsetName(s string) string {
	if s == "" {
		return "empty"
	}
	var lower, upper, digit, hexOnly, b64url, b64std, other bool
	hexOnly = true
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			lower = true
			if c > 'f' {
				hexOnly = false
			}
		case c >= 'A' && c <= 'Z':
			upper = true
			if c > 'F' {
				hexOnly = false
			}
		case c >= '0' && c <= '9':
			digit = true
		case c == '-' || c == '_':
			b64url = true
			hexOnly = false
		case c == '+' || c == '/' || c == '=':
			b64std = true
			hexOnly = false
		default:
			other = true
			hexOnly = false
		}
	}
	switch {
	case other:
		return "mixed"
	case hexOnly && lower && !upper:
		return "hex-lower"
	case hexOnly && upper && !lower:
		return "hex-upper"
	case hexOnly:
		return "hex-mixed"
	case b64std:
		return "base64"
	case b64url:
		return "base64url"
	case lower && upper && digit:
		return "base62"
	case digit && !lower && !upper:
		return "numeric"
	}
	return "alphanumeric"
}

// normalizedEntropy is entropy relative to the maximum achievable for the
// observed alphabet, which makes short values comparable to long ones.
func normalizedEntropy(s string) float64 {
	if len(s) < 2 {
		return 0
	}
	seen := make(map[byte]struct{}, 64)
	for i := 0; i < len(s); i++ {
		seen[s[i]] = struct{}{}
	}
	if len(seen) < 2 {
		return 0
	}
	maxBits := log2i(len(seen))
	if maxBits <= 0 {
		return 0
	}
	e := shannonEntropy(s) / maxBits
	if e > 1 {
		return 1
	}
	return e
}

func log2i(n int) float64 {
	bits := 0.0
	v := float64(n)
	for v > 1 {
		v /= 2
		bits++
	}
	return bits
}

// digestLengths maps a hex length to the digest that produces it.
var digestLengths = map[int]string{
	32: "MD5", 40: "SHA-1", 56: "SHA-224", 64: "SHA-256",
	96: "SHA-384", 128: "SHA-512",
}

func digestName(n int) string {
	if s, ok := digestLengths[n]; ok {
		return s
	}
	return "a digest"
}

// looksLikeHexDigest reports an exact-length pure-hex value. Content hashes,
// ETags, git object ids, CSS-module hashes and integrity fragments all land
// here, and none of them is a credential.
func looksLikeHexDigest(s string) bool {
	if _, ok := digestLengths[len(s)]; !ok {
		return false
	}
	return isHexString(s)
}

func isHexString(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHexDigit(s[i]) {
			return false
		}
	}
	return true
}

// looksLikeUUID matches the canonical 8-4-4-4-12 layout.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !isHexDigit(c) {
			return false
		}
	}
	return true
}

// maxRunLength is the longest run of one repeated character.
func maxRunLength(s string) int {
	best, run := 0, 0
	var prev byte
	for i := 0; i < len(s); i++ {
		if i > 0 && s[i] == prev {
			run++
		} else {
			run = 1
		}
		if run > best {
			best = run
		}
		prev = s[i]
	}
	return best
}

// hasSequentialRun detects ascending or descending character runs such as
// `abcdef` or `987654`, the signature of a hand-typed placeholder.
func hasSequentialRun(s string, minRun int) bool {
	if len(s) < minRun {
		return false
	}
	up, down := 1, 1
	for i := 1; i < len(s); i++ {
		d := int(s[i]) - int(s[i-1])
		if d == 1 {
			up++
			if up >= minRun {
				return true
			}
		} else {
			up = 1
		}
		if d == -1 {
			down++
			if down >= minRun {
				return true
			}
		} else {
			down = 1
		}
	}
	return false
}

// repeatedUnit reports a value built by repeating a short unit, such as
// `abcabcabcabc` or `11112222`.
func repeatedUnit(s string) bool {
	n := len(s)
	if n < 12 {
		return false
	}
	for unit := 1; unit <= 6; unit++ {
		if n%unit != 0 {
			continue
		}
		ok := true
		for i := unit; i < n; i++ {
			if s[i] != s[i-unit] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// looksPathLike reports values that are file paths, URLs or media references.
// A URI carrying userinfo is excluded: `postgres://user:pass@host/db` is a
// credential that happens to be shaped like a URL, and rejecting it as "just a
// path" loses exactly the finding an operator most wants.
func looksPathLike(s string) bool {
	if uriUserinfoRe.MatchString(s) {
		return false
	}
	// A URL whose path carries a long opaque segment is a credential in URL
	// form — a Slack or Discord incoming webhook is exactly that, and the URL
	// is the whole secret. Only plain asset and route references qualify here.
	if hasOpaquePathSegment(s) {
		return false
	}
	if strings.Contains(s, "://") {
		return true
	}
	if strings.Count(s, "/") >= 2 {
		return true
	}
	lower := strings.ToLower(s)
	for _, ext := range []string{
		".js", ".mjs", ".cjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif",
		".svg", ".webp", ".avif", ".woff", ".woff2", ".ttf", ".otf", ".eot",
		".wasm", ".json", ".html", ".ico", ".mp4", ".webm", ".txt", ".xml",
	} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// englishStopWords is a deliberately small, high-frequency set. Its job is to
// recognise a sentence, not to translate one.
var englishStopWords = []string{
	" the ", " and ", " you ", " your ", " for ", " with ", " this ", " that ",
	" please ", " must ", " not ", " are ", " is ", " was ", " has ", " have ",
	" can ", " will ", " would ", " should ", " enter ", " invalid ", " valid ",
	" required ", " error ", " failed ", " success ", " least ", " characters ",
	" password ", " email ", " address ", " again ", " try ", " from ", " into ",
}

// looksNaturalLanguage reports prose rather than an opaque token. The i18n
// catalogue entries that dominate bundled front-end code all land here, and a
// credential essentially never does.
func looksNaturalLanguage(s string) bool {
	if len(s) < 8 {
		return false
	}
	if !utf8.ValidString(s) {
		return false
	}
	// Prose is lowercase-dominant. Requiring that keeps PEM banners, HTTP header
	// names and SCREAMING_CASE constants out of this class — they have the word
	// shape of a sentence but none of the case distribution.
	lower := 0
	for i := 0; i < len(s); i++ {
		if s[i] >= 'a' && s[i] <= 'z' {
			lower++
		}
	}
	if lower*10 < len(s)*3 {
		return false
	}

	padded := " " + strings.ToLower(s) + " "
	for _, w := range englishStopWords {
		if strings.Contains(padded, w) {
			return true
		}
	}

	spaces := strings.Count(s, " ")
	if spaces == 0 {
		return false
	}
	// Two or more space-separated words whose letters alternate like a natural
	// language rather than like a random alphabet.
	words := strings.Fields(s)
	if len(words) < 2 {
		return false
	}
	letters, vowels, transitions := 0, 0, 0
	var prevVowel, havePrev bool
	for i := 0; i < len(s); i++ {
		c := s[i] | 0x20
		if c < 'a' || c > 'z' {
			havePrev = false
			continue
		}
		letters++
		v := c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u'
		if v {
			vowels++
		}
		if havePrev && v != prevVowel {
			transitions++
		}
		prevVowel, havePrev = v, true
	}
	if letters < 8 {
		return false
	}
	vowelRatio := float64(vowels) / float64(letters)
	altRatio := float64(transitions) / float64(letters)
	// Natural language sits near 40% vowels with frequent alternation; random
	// base62 sits nearer 20% with far fewer runs broken.
	return vowelRatio >= 0.25 && vowelRatio <= 0.60 && altRatio >= 0.40
}

// assetMagic maps leading bytes of a decoded payload to the asset it is.
var assetMagic = []struct {
	prefix []byte
	name   string
}{
	{[]byte{0x89, 'P', 'N', 'G'}, "PNG image"},
	{[]byte{0xFF, 0xD8, 0xFF}, "JPEG image"},
	{[]byte("GIF8"), "GIF image"},
	{[]byte("RIFF"), "RIFF container (WebP/WAV)"},
	{[]byte("wOFF"), "WOFF font"},
	{[]byte("wOF2"), "WOFF2 font"},
	{[]byte{0x00, 0x01, 0x00, 0x00}, "TrueType font"},
	{[]byte("OTTO"), "OpenType font"},
	{[]byte{0x00, 'a', 's', 'm'}, "WebAssembly module"},
	{[]byte("%PDF"), "PDF document"},
	{[]byte("PK\x03\x04"), "ZIP archive"},
	{[]byte{0x1F, 0x8B}, "gzip stream"},
	{[]byte("ID3"), "MP3 audio"},
	{[]byte("OggS"), "Ogg container"},
	{[]byte{0x42, 0x4D}, "BMP image"},
	{[]byte{0x00, 0x00, 0x01, 0x00}, "ICO image"},
}

// decodedPayloadKind base64-decodes a candidate and classifies what came out.
// A value that decodes to a PNG header is an inlined asset; one that decodes to
// a JSON object or a readable sentence is data. Neither is a credential, and no
// amount of entropy tuning can tell them apart from the outside.
func decodedPayloadKind(v string) (kind, detail string, ok bool) {
	if len(v) < 24 || len(v)%4 == 1 {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(v)
	}
	if err != nil {
		raw, err = base64.URLEncoding.DecodeString(v)
	}
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(v)
	}
	if err != nil || len(raw) < 8 {
		return "", "", false
	}

	for _, m := range assetMagic {
		if len(raw) >= len(m.prefix) && string(raw[:len(m.prefix)]) == string(m.prefix) {
			return "asset", "decodes to a " + m.name, true
		}
	}

	if !utf8.Valid(raw) {
		return "", "", false
	}
	printable := 0
	for _, b := range raw {
		if b == '\t' || b == '\n' || b == '\r' || (b >= 0x20 && b < 0x7F) {
			printable++
		}
	}
	if printable*10 < len(raw)*9 {
		return "", "", false
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "", "", false
	}
	switch text[0] {
	case '{', '[':
		if strings.Contains(text, "\":") || strings.Contains(text, "\": ") {
			return "json", "decodes to a JSON document", true
		}
	case '<':
		return "asset", "decodes to markup", true
	}
	if looksNaturalLanguage(text) {
		return "text", "decodes to readable text", true
	}
	return "", "", false
}

// tokenRunChars is the alphabet an opaque credential is drawn from. A match
// whose neighbours inside the same literal come from this set is a slice of a
// longer run, not a delimited value.
func isTokenRunChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
		c == '+' || c == '/' || c == '=' || c == '_' || c == '-' || c == '.'
}

// FragmentVerdict describes whether a match is a slice of a longer opaque run.
type FragmentVerdict struct {
	IsFragment bool
	RunStart   int
	RunEnd     int
	LeadBytes  int
	TrailBytes int
	Detail     string
}

// DetectFragment expands the match to the maximal surrounding run of token
// characters within `limitStart:limitEnd` and reports whether the match is a
// proper slice of it.
//
// This is the structural answer to Go's RE2 having no lookbehind: `\b` treats
// `-`, `.`, `+`, `/` and `=` as boundaries, so a prefix-anchored rule such as
// AIza… happily matches in the middle of an inlined base64 blob. Expanding to
// the real run settles it without another regex.
func DetectFragment(body string, start, end, limitStart, limitEnd int) FragmentVerdict {
	if start < limitStart {
		limitStart = start
	}
	if end > limitEnd {
		limitEnd = end
	}
	rs := start
	for rs > limitStart && isTokenRunChar(body[rs-1]) {
		rs--
	}
	re := end
	for re < limitEnd && isTokenRunChar(body[re]) {
		re++
	}
	v := FragmentVerdict{
		RunStart: rs, RunEnd: re,
		LeadBytes: start - rs, TrailBytes: re - end,
	}
	if v.LeadBytes == 0 && v.TrailBytes == 0 {
		return v
	}

	// A single trailing separator is ordinary punctuation, not a longer run.
	if v.LeadBytes == 0 && v.TrailBytes <= 1 {
		return v
	}
	// Leading context that is itself a credential-naming fragment (`key=`,
	// `token_`) is a binding, not a blob, and the run test must not fire on it.
	lead := body[rs:start]
	if v.LeadBytes > 0 && !runLooksOpaque(lead) {
		if v.TrailBytes == 0 {
			return v
		}
	}

	v.IsFragment = true
	switch {
	case v.LeadBytes > 0 && v.TrailBytes > 0:
		v.Detail = "match is interior to a longer opaque run"
	case v.LeadBytes > 0:
		v.Detail = "match begins inside a longer opaque run"
	default:
		v.Detail = "match ends inside a longer opaque run"
	}
	return v
}

// runLooksOpaque reports whether a neighbouring run reads as encoded data
// rather than as an identifier a developer typed.
func runLooksOpaque(s string) bool {
	if len(s) < 3 {
		return false
	}
	var digits, upper, lower int
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'A' && c <= 'Z':
			upper++
		case c >= 'a' && c <= 'z':
			lower++
		}
	}
	classes := 0
	for _, n := range []int{digits, upper, lower} {
		if n > 0 {
			classes++
		}
	}
	return classes >= 2 || shannonEntropy(s) >= 3.0
}

// templatePlaceholders are the markers of a value assembled at runtime. A
// literal that still contains one was never a credential: the credential is
// whatever the placeholder resolves to.
var templatePlaceholders = []string{"${", "{{", "%s", "%d", "<%=", "#{"}

func hasUnresolvedTemplate(v string) bool {
	for _, m := range templatePlaceholders {
		if strings.Contains(v, m) {
			return true
		}
	}
	return false
}

// digestBodyLen reports the length of a contiguous hex run that dominates the
// value and is exactly a digest length.
//
// Build tooling wraps content hashes in short affixes — `key-<md5>`,
// `<md5>-us1`, `dapi<md5>`, `v1.<sha1>` — and those shapes collide exactly with
// several provider token formats. Finding the digest inside the affix lets the
// same rule that protects a bare hash protect the wrapped one, while a real
// provider token bound to a credential-named identifier still reports.
func digestBodyLen(v string) int {
	if len(v) < 16 {
		return 0
	}
	best, run := 0, 0
	for i := 0; i <= len(v); i++ {
		if i < len(v) && isHexDigit(v[i]) {
			run++
			continue
		}
		if run > best {
			best = run
		}
		run = 0
	}
	if _, ok := digestLengths[best]; !ok {
		return 0
	}
	// Only a short, generic affix marks a wrapped build hash. A provider that
	// prefixes its keys distinctively — `sk-or-v1-` and the like — is issuing a
	// credential that merely happens to be hex, and must still report.
	if len(v)-best > 6 {
		return 0
	}
	if best*5 < len(v)*3 {
		return 0
	}
	return best
}

// uriPassword returns the password field of a URI that carries userinfo.
func uriPassword(v string) (string, bool) {
	i := strings.Index(v, "://")
	if i < 0 {
		return "", false
	}
	rest := v[i+3:]
	at := strings.IndexByte(rest, '@')
	if at < 0 {
		return "", false
	}
	userinfo := rest[:at]
	colon := strings.IndexByte(userinfo, ':')
	if colon < 0 {
		return "", false
	}
	return userinfo[colon+1:], true
}

// uriPasswordIsPlaceholder reports a connection URI whose password field is a
// documented placeholder rather than a credential. It reuses the same corpus
// the database-URI validator already applies, so both paths agree.
func uriPasswordIsPlaceholder(v string) (string, bool) {
	pw, ok := uriPassword(v)
	if !ok || pw == "" {
		return "", false
	}
	if hasUnresolvedTemplate(pw) {
		return pw, true
	}
	low := strings.ToLower(pw)
	if _, bad := dbURIPlaceholderExact[low]; bad {
		return pw, true
	}
	for _, frag := range dbURIPlaceholderSubstr {
		if strings.Contains(low, frag) {
			return pw, true
		}
	}
	return "", false
}

// hasOpaquePathSegment reports a path segment long and varied enough to be a
// generated credential rather than a human-authored route or filename.
func hasOpaquePathSegment(s string) bool {
	for _, seg := range strings.Split(s, "/") {
		if len(seg) < 20 || strings.Contains(seg, ".") {
			continue
		}
		if charClassDiversity(seg) >= 2 && shannonEntropy(seg) >= 3.5 {
			return true
		}
	}
	return false
}
