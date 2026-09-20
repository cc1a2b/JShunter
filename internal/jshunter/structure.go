package jshunter

import (
	"bytes"
	"math"
	"strings"
)

// Structural classification of a scanned body.
//
// A regex match is only evidence once you know where it landed. The same forty
// base64 characters mean "credential" inside a string literal, "chunk hash"
// inside an identifier, and "nothing at all" when they straddle the seam
// between two adjacent tokens of a minified bundle. This file turns the token
// stream from jslex.go into an index that answers that question in O(log n),
// plus the per-literal structural context that replaces guessing from a
// fixed-width character window.

// SpanClass names the syntactic region a byte range falls in.
type SpanClass uint8

const (
	ClassCode SpanClass = iota
	ClassString
	ClassTemplate
	ClassLineComment
	ClassBlockComment
	ClassRegex
	// ClassStraddle means the range crosses a token boundary and therefore
	// cannot be a single literal value.
	ClassStraddle
)

// String renders a span class for --explain output and evidence reasons.
func (c SpanClass) String() string {
	switch c {
	case ClassString:
		return "string-literal"
	case ClassTemplate:
		return "template-literal"
	case ClassLineComment:
		return "line-comment"
	case ClassBlockComment:
		return "block-comment"
	case ClassRegex:
		return "regex-literal"
	case ClassStraddle:
		return "straddles-token-boundary"
	}
	return "code"
}

// IsLiteral reports whether the class can legitimately hold a hard-coded value.
func (c SpanClass) IsLiteral() bool { return c == ClassString || c == ClassTemplate }

// IsComment reports whether the class is a comment region.
func (c SpanClass) IsComment() bool { return c == ClassLineComment || c == ClassBlockComment }

// LiteralRole describes what a string literal is doing in the program.
type LiteralRole uint8

const (
	RoleUnknown LiteralRole = iota
	RoleAssignment
	RoleObjectValue
	RolePropertyKey
	RoleCallArg
	RoleArrayElem
	RoleReturn
	RoleImportSpec
	RoleMemberIndex
	RoleComparison
	RoleConcat
	RoleTaggedTemplate
)

// String renders a role for evidence output.
func (r LiteralRole) String() string {
	switch r {
	case RoleAssignment:
		return "assignment"
	case RoleObjectValue:
		return "object-value"
	case RolePropertyKey:
		return "property-key"
	case RoleCallArg:
		return "call-argument"
	case RoleArrayElem:
		return "array-element"
	case RoleReturn:
		return "return-value"
	case RoleImportSpec:
		return "module-specifier"
	case RoleMemberIndex:
		return "member-index"
	case RoleComparison:
		return "comparison-operand"
	case RoleConcat:
		return "concatenation-operand"
	case RoleTaggedTemplate:
		return "tagged-template"
	}
	return "unknown"
}

// Binding is true for roles where the literal is bound to a name the operator
// can read — the roles whose name carries real evidence about intent.
func (r LiteralRole) Binding() bool {
	switch r {
	case RoleAssignment, RoleObjectValue, RoleCallArg, RoleReturn, RoleImportSpec:
		return true
	}
	return false
}

type span struct {
	Start int32
	End   int32
	Kind  SpanClass
}

// Literal is one candidate-bearing string or template literal together with the
// structural context the scanner recovered for it.
type Literal struct {
	Start, End       int32
	ValStart, ValEnd int32
	Kind             SpanClass
	Role             LiteralRole
	NameStart        int32
	NameEnd          int32
	CalleeStart      int32
	CalleeEnd        int32
	// EnclosingCallee names the innermost call the literal sits inside at any
	// nesting depth, which Callee does not: a value in an object passed to
	// HttpResponse.json({...}) is a call argument two levels down.
	EnclosingCalleeStart int32
	EnclosingCalleeEnd   int32
	ArgIndex             int32
	ObjID                int32
	ObjNameStart         int32
	ObjNameEnd           int32
	Flags                uint8
}

// StructureStats records what the scan saw, for --stats and reliability gating.
type StructureStats struct {
	Bytes          int
	Tokens         int
	Strings        int
	Templates      int
	Comments       int
	Regexes        int
	Keywords       int
	Identifiers    int
	Punctuators    int
	StructuralOps  int
	Unterminated   int
	LiteralBytes   int
	IndexedLiteral int
	Truncated      bool
}

// Structure is the byte-level map of one scanned body.
type Structure struct {
	src      []byte
	spans    []span
	literals []Literal
	objKeys  [][]string
	lineAt   []int32
	model    bigramModel

	Stats StructureStats

	// Reliable gates every *rejection* the structural layer can make. When the
	// body is not confidently JavaScript the layer still contributes positive
	// evidence but never suppresses a match, so a misclassified input can cost
	// precision but never causes a missed secret.
	Reliable bool
}

// Literal-index bounds. Values shorter than the floor cannot be a credential;
// values above the ceiling are inlined assets, not secrets. Skipping both keeps
// the index proportional to the number of plausible candidates rather than to
// the number of tokens in the bundle.
const (
	literalIndexMinLen = 8
	literalIndexMaxLen = 16384
	maxIndexedSpans    = 8 << 20
)

// AnalyzeStructure lexes src once and builds the classification index.
// It is pure: no globals are touched, so callers may run it concurrently.
func AnalyzeStructure(src []byte) *Structure {
	st := &Structure{src: src}
	st.Stats.Bytes = len(src)
	if len(src) == 0 {
		return st
	}

	lx := NewLexer(src)
	st.model.init()
	st.indexLines(src)

	// Rolling window of the three most recent significant tokens. Structural
	// context is recoverable from that alone because the roles that matter are
	// all expressible as short suffixes of the token stream.
	var p1, p2 Token
	var have1, have2 bool
	// Index of the literal emitted immediately before the current token, so a
	// following ':' can retroactively re-label it as a property key.
	lastLit := -1

	for {
		t := lx.Next()
		if t.Kind == TokEOF {
			break
		}
		st.Stats.Tokens++

		switch t.Kind {
		case TokWhitespace:
			continue

		case TokLineComment, TokBlockComment, TokHashbang:
			st.Stats.Comments++
			st.addSpan(t.Start, t.End, commentClass(t.Kind))
			continue

		case TokRegex:
			st.Stats.Regexes++
			st.addSpan(t.Start, t.End, ClassRegex)
			st.model.feed(src[t.Start:t.End])

		case TokString, TokTemplate:
			cls := ClassString
			if t.Kind == TokTemplate {
				cls = ClassTemplate
				st.Stats.Templates++
			} else {
				st.Stats.Strings++
			}
			if t.Flags&tokFlagUnterminated != 0 {
				st.Stats.Unterminated++
			}
			st.addSpan(t.Start, t.End, cls)
			vlen := int(t.ValEnd - t.ValStart)
			st.Stats.LiteralBytes += vlen
			if vlen >= literalIndexMinLen && vlen <= literalIndexMaxLen {
				lastLit = len(st.literals)
				st.literals = append(st.literals, st.contextFor(t, cls, lx, p1, have1, p2, have2))
				st.Stats.IndexedLiteral++
			} else {
				lastLit = -1
				// Short literals are the file's ambient vocabulary; they belong
				// in the reference model, long blobs do not.
				st.model.feed(src[t.ValStart:t.ValEnd])
			}

		case TokIdent:
			st.Stats.Identifiers++
			st.model.feed(src[t.Start:t.End])
		case TokKeyword:
			st.Stats.Keywords++
			st.model.feed(src[t.Start:t.End])
		case TokNumber:
			st.model.feed(src[t.Start:t.End])
		case TokPunct:
			st.Stats.Punctuators++
			if t.End-t.Start == 1 && isStructuralPunct(src[t.Start]) {
				st.Stats.StructuralOps++
			}
			st.model.feed(src[t.Start:t.End])
			if t.End-t.Start == 1 && src[t.Start] == ':' {
				if lastLit >= 0 {
					st.literals[lastLit].Role = RolePropertyKey
				}
				st.recordObjectKey(lx.openObjectID(), p1, have1)
			}
		}

		if t.Kind != TokString && t.Kind != TokTemplate {
			lastLit = -1
		}
		p2, have2 = p1, have1
		p1, have1 = t, true
	}

	st.model.finish()
	st.Reliable = st.assessReliability()
	return st
}

// recordObjectKey files a property name under the object literal that declares
// it, so a later lookup can ask what an object's whole key-set looks like. A
// value's siblings are what separate a Firebase web config from a real server
// key that merely shares the property name `apiKey`.
func (st *Structure) recordObjectKey(objID int32, key Token, have bool) {
	if objID <= 0 || !have {
		return
	}
	var name string
	switch key.Kind {
	case TokIdent, TokKeyword:
		name = st.text(key)
	case TokString:
		name = st.textRange(key.ValStart, key.ValEnd)
	default:
		return
	}
	if name == "" {
		return
	}
	for int32(len(st.objKeys)) < objID {
		st.objKeys = append(st.objKeys, nil)
	}
	keys := st.objKeys[objID-1]
	if len(keys) >= 64 {
		return
	}
	st.objKeys[objID-1] = append(keys, name)
}

// SiblingKeys returns every property name declared by the object literal that
// directly encloses a literal.
func (st *Structure) SiblingKeys(lit *Literal) []string {
	if st == nil || lit == nil || lit.ObjID <= 0 || int(lit.ObjID) > len(st.objKeys) {
		return nil
	}
	return st.objKeys[lit.ObjID-1]
}

// indexLines records the offset of every line start so Position can answer in
// O(log n). The previous per-finding backward scan cost O(offset), which on a
// minified single-line bundle is the whole body — once per finding.
func (st *Structure) indexLines(src []byte) {
	st.lineAt = append(st.lineAt, 0)
	for i := 0; i < len(src); i++ {
		if src[i] == '\n' {
			st.lineAt = append(st.lineAt, int32(i+1))
		}
	}
}

// Position returns the 1-indexed line and column of a byte offset.
func (st *Structure) Position(offset int) (line, col int) {
	if st == nil || len(st.lineAt) == 0 {
		return positionAt(string(st.src), offset)
	}
	if offset < 0 {
		offset = 0
	}
	if offset > len(st.src) {
		offset = len(st.src)
	}
	o := int32(offset)
	lo, hi := 0, len(st.lineAt)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if st.lineAt[mid] <= o {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return 1, offset + 1
	}
	return lo, offset - int(st.lineAt[lo-1]) + 1
}

// SpanAt returns the recorded span covering start, if any.
func (st *Structure) SpanAt(start int) (int, int, SpanClass, bool) {
	if st == nil || len(st.spans) == 0 {
		return 0, 0, ClassCode, false
	}
	s32 := int32(start)
	lo, hi := 0, len(st.spans)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if st.spans[mid].Start <= s32 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return 0, 0, ClassCode, false
	}
	sp := st.spans[lo-1]
	if s32 >= sp.Start && s32 < sp.End {
		return int(sp.Start), int(sp.End), sp.Kind, true
	}
	return 0, 0, ClassCode, false
}

// InSourcemapComment reports whether an offset sits inside a `//# sourceMappingURL=`
// comment, which is a build artifact rather than source.
//
// The check used to slice the whole enclosing line and run a regex over it. On a
// minified bundle the line is the entire file, so the cost was quadratic in the
// number of matches. Asking the span index instead is O(log n) and exact.
func (st *Structure) InSourcemapComment(start int) bool {
	a, b, cls, ok := st.SpanAt(start)
	if !ok || cls != ClassLineComment {
		return false
	}
	if b-a > 512 {
		b = a + 512
	}
	return sourcemapMarkerRe.Match(st.src[a:b])
}

func commentClass(k TokenKind) SpanClass {
	if k == TokBlockComment {
		return ClassBlockComment
	}
	return ClassLineComment
}

func (st *Structure) addSpan(start, end int32, kind SpanClass) {
	if end <= start {
		return
	}
	if len(st.spans) >= maxIndexedSpans {
		st.Stats.Truncated = true
		return
	}
	st.spans = append(st.spans, span{Start: start, End: end, Kind: kind})
}

// contextFor recovers the structural role of a literal from the token suffix
// preceding it plus the scanner's open-group stack.
func (st *Structure) contextFor(t Token, cls SpanClass, lx *Lexer, p1 Token, have1 bool, p2 Token, have2 bool) Literal {
	lit := Literal{
		Start: t.Start, End: t.End,
		ValStart: t.ValStart, ValEnd: t.ValEnd,
		Kind: cls, Flags: t.Flags, ArgIndex: -1, ObjID: lx.openObjectID(),
	}
	lit.EnclosingCalleeStart, lit.EnclosingCalleeEnd = lx.enclosingCallee()
	lit.ObjNameStart, lit.ObjNameEnd = lx.openObjectName()
	if t.Flags&tokFlagTagged != 0 {
		lit.Role = RoleTaggedTemplate
		if have1 && p1.Kind == TokIdent {
			lit.NameStart, lit.NameEnd = p1.Start, p1.End
		}
		return lit
	}
	if !have1 {
		return lit
	}

	p1Text := st.text(p1)

	switch p1.Kind {
	case TokKeyword:
		switch p1Text {
		case "return", "throw", "case":
			lit.Role = RoleReturn
		case "import", "from":
			lit.Role = RoleImportSpec
		}
		return lit

	case TokIdent:
		// `from` is contextual, so it lexes as an identifier in most positions.
		if p1Text == "from" {
			lit.Role = RoleImportSpec
		}
		return lit

	case TokPunct:
		switch p1Text {
		case "=", "+=", "||=", "&&=", "??=":
			lit.Role = RoleAssignment
			if have2 && (p2.Kind == TokIdent || p2.Kind == TokKeyword) {
				lit.NameStart, lit.NameEnd = p2.Start, p2.End
			}
		case ":":
			lit.Role = RoleObjectValue
			if have2 && (p2.Kind == TokIdent || p2.Kind == TokKeyword) {
				lit.NameStart, lit.NameEnd = p2.Start, p2.End
			} else if have2 && p2.Kind == TokString {
				lit.NameStart, lit.NameEnd = p2.ValStart, p2.ValEnd
			}
		case "(":
			lit.Role = RoleCallArg
			lit.ArgIndex = 0
			lit.CalleeStart, lit.CalleeEnd = lx.openCallee()
			if n := st.textRange(lit.CalleeStart, lit.CalleeEnd); n == "require" || n == "import" {
				lit.Role = RoleImportSpec
			}
		case ",":
			s, e := lx.openCallee()
			if e > s {
				lit.Role = RoleCallArg
				lit.CalleeStart, lit.CalleeEnd = s, e
				lit.ArgIndex = lx.openArgIndex()
			} else if lx.openBracket() == '[' {
				lit.Role = RoleArrayElem
			}
		case "[":
			if have2 && (p2.Kind == TokIdent || p2.Kind == TokPunct && (st.text(p2) == ")" || st.text(p2) == "]")) {
				lit.Role = RoleMemberIndex
				if p2.Kind == TokIdent {
					lit.NameStart, lit.NameEnd = p2.Start, p2.End
				}
			} else {
				lit.Role = RoleArrayElem
			}
		case "===", "==", "!==", "!=":
			lit.Role = RoleComparison
			if have2 && p2.Kind == TokIdent {
				lit.NameStart, lit.NameEnd = p2.Start, p2.End
			}
		case "+":
			lit.Role = RoleConcat
		}
	}
	return lit
}

func (st *Structure) text(t Token) string {
	if t.Start < 0 || int(t.End) > len(st.src) || t.End < t.Start {
		return ""
	}
	return string(st.src[t.Start:t.End])
}

func (st *Structure) textRange(a, b int32) string {
	if a < 0 || b <= a || int(b) > len(st.src) {
		return ""
	}
	return string(st.src[a:b])
}

// assessReliability decides whether structural rejection may be trusted. The
// test is deliberately conservative: it must be satisfied that the body really
// is JavaScript-like, because the cost of a wrong "yes" is a missed secret.
func (st *Structure) assessReliability() bool {
	if st.Stats.Truncated {
		return false
	}
	if st.Stats.Strings > 0 && st.Stats.Unterminated*20 > st.Stats.Strings {
		return false
	}
	// Brackets and terminators are what a program has and a configuration file,
	// a log or a prose document does not. Requiring a real population of them is
	// a cheap, high-specificity test for "this body is JavaScript or JSON" — and
	// in both of those every hard-coded value is a string literal, which is the
	// premise structural rejection rests on. Commas are excluded deliberately:
	// prose is full of them, so counting them would admit plain text.
	if st.Stats.StructuralOps < 3 && !(st.Stats.Keywords >= 1 && st.Stats.StructuralOps >= 1) {
		return false
	}
	if looksLikeMarkup(st.src) {
		return false
	}
	return true
}

func isStructuralPunct(c byte) bool {
	switch c {
	case '{', '}', '(', ')', '[', ']', ';':
		return true
	}
	return false
}

// looksLikeMarkup detects HTML or XML bodies handed to the scanner whole. Their
// text nodes live outside any literal, so structural rejection would silently
// drop real findings.
func looksLikeMarkup(src []byte) bool {
	head := src
	if len(head) > 2048 {
		head = head[:2048]
	}
	lower := bytes.ToLower(head)
	for _, marker := range [][]byte{
		[]byte("<!doctype html"), []byte("<html"), []byte("<?xml"), []byte("<svg"),
	} {
		if bytes.Contains(lower, marker) {
			return true
		}
	}
	// A high density of closing tags in the first kilobytes is markup even when
	// no doctype survived an extraction step.
	closers := bytes.Count(lower, []byte("</"))
	return closers >= 8 && closers*120 >= len(lower)
}

// Classify reports the syntactic region covering [start, end).
func (st *Structure) Classify(start, end int) SpanClass {
	if st == nil || len(st.spans) == 0 {
		return ClassCode
	}
	if end <= start {
		end = start + 1
	}
	s32, e32 := int32(start), int32(end)

	// Rightmost span beginning at or before start.
	lo, hi := 0, len(st.spans)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if st.spans[mid].Start <= s32 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo > 0 {
		sp := st.spans[lo-1]
		if s32 >= sp.Start && s32 < sp.End {
			if e32 <= sp.End {
				return sp.Kind
			}
			return ClassStraddle
		}
	}
	// start sits in code; a match reaching into the next span crosses a boundary.
	if lo < len(st.spans) && st.spans[lo].Start < e32 {
		return ClassStraddle
	}
	return ClassCode
}

// LiteralAt returns the indexed literal wholly containing [start, end), or nil.
func (st *Structure) LiteralAt(start, end int) *Literal {
	if st == nil || len(st.literals) == 0 {
		return nil
	}
	s32, e32 := int32(start), int32(end)
	lo, hi := 0, len(st.literals)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if st.literals[mid].Start <= s32 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return nil
	}
	lit := &st.literals[lo-1]
	if s32 >= lit.ValStart && e32 <= lit.ValEnd {
		return lit
	}
	return nil
}

// BindingName returns the identifier or property key the literal is bound to.
func (st *Structure) BindingName(lit *Literal) string {
	if st == nil || lit == nil {
		return ""
	}
	return st.textRange(lit.NameStart, lit.NameEnd)
}

// CalleeName returns the callee of the call a literal is an argument to.
func (st *Structure) CalleeName(lit *Literal) string {
	if st == nil || lit == nil {
		return ""
	}
	return st.textRange(lit.CalleeStart, lit.CalleeEnd)
}

// LiteralValue returns the raw payload of an indexed literal.
func (st *Structure) LiteralValue(lit *Literal) string {
	if st == nil || lit == nil {
		return ""
	}
	return st.textRange(lit.ValStart, lit.ValEnd)
}

// Surprisal scores how unlike the rest of this file a candidate reads, in bits
// per character under the file's own character-transition model. Minified
// identifier soup and the file's ambient vocabulary score low; a value drawn
// from a generator the file never otherwise produces scores high.
func (st *Structure) Surprisal(s string) float64 {
	if st == nil {
		return 0
	}
	return st.model.surprisal(s)
}

// ModelReady reports whether the file carried enough text to make Surprisal
// meaningful.
func (st *Structure) ModelReady() bool { return st != nil && st.model.total >= 4096 }

// --- file-relative character model ---------------------------------------

const bigramAlphabet = 64

type bigramModel struct {
	counts []uint32
	rowSum []uint32
	total  uint64
	last   int
	primed bool
}

func (m *bigramModel) init() {
	m.counts = make([]uint32, bigramAlphabet*bigramAlphabet)
	m.rowSum = make([]uint32, bigramAlphabet)
	m.last = -1
}

func (m *bigramModel) feed(b []byte) {
	if m.counts == nil || m.total > 1<<22 {
		return
	}
	for _, c := range b {
		s := symIndex(c)
		if m.last >= 0 {
			m.counts[m.last*bigramAlphabet+s]++
			m.rowSum[m.last]++
			m.total++
		}
		m.last = s
	}
	// Token boundaries are not transitions.
	m.last = -1
}

func (m *bigramModel) finish() { m.primed = m.total >= 4096 }

// surprisal returns mean -log2 P(c_i | c_{i-1}) with add-one smoothing.
// Returns 0 when the model saw too little text to be worth consulting.
func (m *bigramModel) surprisal(s string) float64 {
	if !m.primed || len(s) < 2 {
		return 0
	}
	var bits float64
	var n int
	prev := symIndex(s[0])
	for i := 1; i < len(s); i++ {
		cur := symIndex(s[i])
		c := float64(m.counts[prev*bigramAlphabet+cur]) + 1
		r := float64(m.rowSum[prev]) + float64(bigramAlphabet)
		bits += -math.Log2(c / r)
		n++
		prev = cur
	}
	if n == 0 {
		return 0
	}
	return bits / float64(n)
}

// symIndex folds a byte into the 64-symbol alphabet the model is built over.
// Case is preserved because case pattern is what separates base64 from hex.
func symIndex(c byte) int {
	switch {
	case c >= 'a' && c <= 'z':
		return int(c - 'a')
	case c >= 'A' && c <= 'Z':
		return 26 + int(c-'A')
	case c >= '0' && c <= '9':
		return 52 + int(c-'0')
	}
	switch c {
	case '+', '/', '-', '_', '=', '.':
		return 62
	}
	return 63
}

// --- lexer accessors used by context recovery ----------------------------

// openCallee returns the span of the callee identifier for the innermost open
// call group, or an empty range when the innermost group is not a call.
func (l *Lexer) openCallee() (int32, int32) {
	for i := len(l.stack) - 1; i >= 0; i-- {
		if l.stack[i].open == '(' {
			return l.stack[i].calleeS, l.stack[i].calleeE
		}
		if l.stack[i].open == '[' || l.stack[i].open == '{' {
			return 0, 0
		}
	}
	return 0, 0
}

// enclosingCallee returns the callee of the nearest open call group at any
// depth, looking past intervening object and array literals.
func (l *Lexer) enclosingCallee() (int32, int32) {
	for i := len(l.stack) - 1; i >= 0; i-- {
		if l.stack[i].open == '(' && l.stack[i].calleeE > l.stack[i].calleeS {
			return l.stack[i].calleeS, l.stack[i].calleeE
		}
	}
	return 0, 0
}

// EnclosingCalleeName returns the callee of the nearest enclosing call.
func (st *Structure) EnclosingCalleeName(lit *Literal) string {
	if st == nil || lit == nil {
		return ""
	}
	return st.textRange(lit.EnclosingCalleeStart, lit.EnclosingCalleeEnd)
}

// openObjectName returns the identifier the outermost enclosing object literal
// was bound to. The outermost name is the one that describes the whole
// structure: in `const mockUsers = {acme:{token:"…"}}` the useful answer is
// mockUsers, not acme.
func (l *Lexer) openObjectName() (int32, int32) {
	for i := 0; i < len(l.stack); i++ {
		if l.stack[i].open == '{' && l.stack[i].nameE > l.stack[i].nameS {
			return l.stack[i].nameS, l.stack[i].nameE
		}
	}
	return 0, 0
}

// ObjectName returns the name of the object literal enclosing a value.
func (st *Structure) ObjectName(lit *Literal) string {
	if st == nil || lit == nil {
		return ""
	}
	return st.textRange(lit.ObjNameStart, lit.ObjNameEnd)
}

// openArgIndex returns the comma count of the innermost open group.
func (l *Lexer) openArgIndex() int32 {
	if n := len(l.stack); n > 0 {
		return l.stack[n-1].argIndex
	}
	return -1
}

// openObjectID returns the identifier of the innermost open object literal, or
// zero when the scanner is not inside one.
func (l *Lexer) openObjectID() int32 {
	for i := len(l.stack) - 1; i >= 0; i-- {
		if l.stack[i].open == '{' {
			return l.stack[i].objID
		}
	}
	return 0
}

// openBracket returns the delimiter of the innermost open group.
func (l *Lexer) openBracket() byte {
	if n := len(l.stack); n > 0 {
		return l.stack[n-1].open
	}
	return 0
}

// credentialNameTokens are the name fragments that make a binding name real
// evidence of intent. Matched against the identifier or property key a literal
// is bound to, which is a far stronger signal than the same words appearing
// anywhere inside a fixed-width character window.
var credentialNameTokens = []string{
	"secret", "token", "apikey", "api_key", "apisecret", "accesskey", "access_key",
	"privatekey", "private_key", "clientsecret", "client_secret", "password", "passwd",
	"pwd", "credential", "auth", "bearer", "signature", "signingkey", "signing_key",
	"sessionkey", "session_key", "refreshtoken", "refresh_token", "accesstoken",
	"access_token", "idtoken", "id_token", "webhooksecret", "webhook_secret",
	"encryptionkey", "encryption_key", "masterkey", "master_key", "dsn", "conn",
	"connectionstring", "connection_string", "license", "licence", "cert", "pem",
	// An incoming-webhook URL is the credential, and it is almost always bound
	// to a name ending in _URL rather than _SECRET.
	"webhook", "webhookurl", "webhook_url",
}

// benignNameTokens mark bindings whose value is a public identifier by
// construction. A forty-character random value bound to `integrity`, `hash` or
// `buildId` is a build artifact, not a credential, no matter how it scores.
var benignNameTokens = []string{
	"integrity", "sri", "hash", "checksum", "digest", "etag", "revision", "commit",
	"buildid", "build_id", "chunkid", "chunk_id", "moduleid", "module_id", "version",
	"sourcemappingurl", "contenthash", "content_hash", "fingerprint", "cachekey",
	"cache_key", "nonce", "uuid", "guid", "traceid", "trace_id", "spanid", "span_id",
	"requestid", "request_id", "correlationid", "correlation_id", "svgpath", "viewbox",
	"path", "d", "data", "base64", "icon", "image", "font", "wasm", "sprite",
	"colour", "color", "gradient", "translation", "locale", "i18n", "message",
}

// nameSignal classifies a binding name into credential evidence, benign
// evidence, or neither. Comparison is case- and separator-insensitive so
// `API_KEY`, `apiKey` and `api-key` all read the same.
func nameSignal(name string) (credential bool, benign bool) {
	if name == "" {
		return false, false
	}
	norm := normalizeName(name)
	if norm == "" {
		return false, false
	}
	for _, t := range credentialNameTokens {
		if strings.Contains(norm, strings.ReplaceAll(t, "_", "")) {
			credential = true
			break
		}
	}
	for _, t := range benignNameTokens {
		tn := strings.ReplaceAll(t, "_", "")
		if norm == tn || strings.Contains(norm, tn) && len(tn) >= 4 {
			benign = true
			break
		}
	}
	return credential, benign
}

func normalizeName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + 32)
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		}
	}
	return b.String()
}
