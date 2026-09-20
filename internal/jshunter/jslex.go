package jshunter

// ECMAScript byte-span scanner.
//
// Pattern matching alone cannot tell a credential from the middle of a minified
// identifier, a slice of an inlined base64 font, or the body of a regular
// expression. A hard-coded credential in JavaScript is structurally a string
// literal, a template literal, or a comment — never anything else. Classifying
// every byte of the response is therefore the only way to reject that noise
// without inventing yet another heuristic regex.
//
// The scanner is single-pass, allocation-light, and works on the exact bytes the
// detection rules run against, so every offset it reports stays valid for
// line/column reporting. It never panics and every branch consumes at least one
// byte, so malformed or adversarial input terminates.

// TokenKind classifies one byte span of a source file.
type TokenKind uint8

const (
	TokEOF TokenKind = iota
	TokWhitespace
	TokLineComment
	TokBlockComment
	TokHashbang
	TokString
	TokTemplate
	TokRegex
	TokNumber
	TokIdent
	TokKeyword
	TokPunct
)

// String renders a token kind for --explain output and test failures.
func (k TokenKind) String() string {
	switch k {
	case TokWhitespace:
		return "whitespace"
	case TokLineComment:
		return "line-comment"
	case TokBlockComment:
		return "block-comment"
	case TokHashbang:
		return "hashbang"
	case TokString:
		return "string"
	case TokTemplate:
		return "template"
	case TokRegex:
		return "regex"
	case TokNumber:
		return "number"
	case TokIdent:
		return "identifier"
	case TokKeyword:
		return "keyword"
	case TokPunct:
		return "punctuator"
	}
	return "eof"
}

// Token flags carried alongside a span.
const (
	tokFlagUnterminated uint8 = 1 << iota
	tokFlagHasEscape
	tokFlagTemplateHead // span opened with a backtick
	tokFlagTemplateTail // span closed with a backtick
	tokFlagTagged       // template literal preceded by a tag expression
)

// Token is one classified byte span. Start/End bound the whole token including
// delimiters; ValStart/ValEnd bound the literal payload for strings, templates
// and comments. Offsets index the original source, never a rewritten copy.
type Token struct {
	Kind     TokenKind
	Start    int32
	End      int32
	ValStart int32
	ValEnd   int32
	Quote    byte
	Flags    uint8
}

// Len is the token's width in bytes.
func (t Token) Len() int32 { return t.End - t.Start }

// group tracks one open bracket so the scanner can answer three questions a
// flat byte loop cannot: whether a `}` closes a template substitution, whether
// a `)` closes a control-flow head (which makes a following `/` a regex), and
// which call a string literal is an argument to.
type group struct {
	open      byte
	ctrl      bool
	templSub  bool
	objectLit bool
	objID     int32
	nameS     int32
	nameE     int32
	calleeS   int32
	calleeE   int32
	argIndex  int32
}

// Lexer walks a JavaScript source and emits classified spans in order.
type Lexer struct {
	src []byte
	pos int

	stack     []group
	lastClose group
	hasClose  bool

	prev      Token
	hasPrev   bool
	prevText  []byte
	prev2     Token
	hasPrev2  bool
	prev2Text []byte
	objSeq    int32

	// Set when a `}` closed a template substitution: the next token continues
	// the enclosing template literal rather than starting fresh code.
	// templResumeAt is the offset of that `}`, so the resumed chunk spans from
	// its delimiter exactly as a chunk opened by a backtick does.
	resumeTemplate bool
	templResumeAt  int
}

// NewLexer prepares a scanner over src. The slice is retained, not copied.
func NewLexer(src []byte) *Lexer {
	return &Lexer{src: src, stack: make([]group, 0, 32)}
}

// Pos reports the scanner's current byte offset.
func (l *Lexer) Pos() int { return l.pos }

// Next returns the next token. At end of input it returns a TokEOF token whose
// span is empty and positioned at the end of the source.
func (l *Lexer) Next() Token {
	if l.resumeTemplate {
		l.resumeTemplate = false
		t := l.scanTemplateChunk(l.templResumeAt, l.pos, false)
		l.remember(t)
		return t
	}
	if l.pos >= len(l.src) {
		n := int32(len(l.src))
		return Token{Kind: TokEOF, Start: n, End: n, ValStart: n, ValEnd: n}
	}

	start := l.pos
	c := l.src[start]

	switch {
	case start == 0 && c == '#' && start+1 < len(l.src) && l.src[start+1] == '!':
		return l.emitTrivia(TokHashbang, l.scanToLineEnd(start+2))

	case isJSSpace(c):
		l.pos = start + 1
		for l.pos < len(l.src) && isJSSpace(l.src[l.pos]) {
			l.pos++
		}
		return Token{Kind: TokWhitespace, Start: int32(start), End: int32(l.pos), ValStart: int32(start), ValEnd: int32(l.pos)}

	case c == '/' && start+1 < len(l.src) && l.src[start+1] == '/':
		return l.emitTrivia(TokLineComment, l.scanToLineEnd(start+2))

	case c == '/' && start+1 < len(l.src) && l.src[start+1] == '*':
		return l.emitTrivia(TokBlockComment, l.scanBlockComment(start))

	// Annex B HTML-like open comment, still legal in classic scripts and still
	// emitted by a few legacy bundlers wrapping inline script bodies.
	case c == '<' && hasPrefixAt(l.src, start, "<!--"):
		return l.emitTrivia(TokLineComment, l.scanToLineEnd(start+4))

	case c == '"' || c == '\'':
		t := l.scanString(start, c)
		l.remember(t)
		return t

	case c == '`':
		t := l.scanTemplateChunk(start, start+1, true)
		l.remember(t)
		return t

	case c == '/':
		if l.regexAllowed() {
			if t, ok := l.scanRegex(start); ok {
				l.remember(t)
				return t
			}
		}
		t := l.scanPunct(start)
		l.remember(t)
		return t

	case c >= '0' && c <= '9':
		t := l.scanNumber(start)
		l.remember(t)
		return t

	case c == '.' && start+1 < len(l.src) && l.src[start+1] >= '0' && l.src[start+1] <= '9':
		t := l.scanNumber(start)
		l.remember(t)
		return t

	case isIdentStart(c),
		// Obfuscators emit identifiers written entirely as \uXXXX escapes.
		c == '\\' && start+1 < len(l.src) && l.src[start+1] == 'u':
		t := l.scanIdent(start)
		l.remember(t)
		return t
	}

	t := l.scanPunct(start)
	l.remember(t)
	return t
}

// emitTrivia finalises a comment-like span whose end offset is already known.
func (l *Lexer) emitTrivia(kind TokenKind, end int) Token {
	start := l.pos
	l.pos = end
	inner := start
	switch kind {
	case TokLineComment:
		inner = start + 2
	case TokBlockComment:
		inner = start + 2
	case TokHashbang:
		inner = start + 2
	}
	if inner > end {
		inner = end
	}
	ve := end
	if kind == TokBlockComment && end-start >= 4 && l.src[end-1] == '/' && l.src[end-2] == '*' {
		ve = end - 2
	}
	if ve < inner {
		ve = inner
	}
	return Token{Kind: kind, Start: int32(start), End: int32(end), ValStart: int32(inner), ValEnd: int32(ve)}
}

func (l *Lexer) scanToLineEnd(from int) int {
	i := from
	for i < len(l.src) {
		c := l.src[i]
		if c == '\n' || c == '\r' {
			return i
		}
		// U+2028 LINE SEPARATOR / U+2029 PARAGRAPH SEPARATOR terminate a
		// single-line comment just like a newline.
		if c == 0xE2 && i+2 < len(l.src) && l.src[i+1] == 0x80 && (l.src[i+2] == 0xA8 || l.src[i+2] == 0xA9) {
			return i
		}
		i++
	}
	return len(l.src)
}

func (l *Lexer) scanBlockComment(start int) int {
	i := start + 2
	for i+1 < len(l.src) {
		if l.src[i] == '*' && l.src[i+1] == '/' {
			return i + 2
		}
		i++
	}
	return len(l.src)
}

// scanString consumes a quoted literal. An unterminated literal ends at the
// newline rather than swallowing the rest of the file, which keeps one broken
// quote in a minified bundle from destroying the classification of everything
// after it.
func (l *Lexer) scanString(start int, quote byte) Token {
	i := start + 1
	var flags uint8
	for i < len(l.src) {
		c := l.src[i]
		if c == '\\' {
			flags |= tokFlagHasEscape
			i += 2
			continue
		}
		if c == quote {
			l.pos = i + 1
			return Token{
				Kind: TokString, Start: int32(start), End: int32(i + 1),
				ValStart: int32(start + 1), ValEnd: int32(i), Quote: quote, Flags: flags,
			}
		}
		if c == '\n' || c == '\r' {
			break
		}
		i++
	}
	if i > len(l.src) {
		i = len(l.src)
	}
	l.pos = i
	return Token{
		Kind: TokString, Start: int32(start), End: int32(i),
		ValStart: int32(start + 1), ValEnd: int32(i), Quote: quote,
		Flags: flags | tokFlagUnterminated,
	}
}

// scanTemplateChunk consumes one run of template text. `opening` distinguishes a
// fresh backtick from the `}` that closes a substitution and resumes the same
// template. A chunk ends at the closing backtick or at `${`, whichever comes
// first; `${` pushes a substitution group so the matching `}` resumes here.
func (l *Lexer) scanTemplateChunk(start, contentStart int, opening bool) Token {
	i := contentStart
	var flags uint8
	if opening {
		flags |= tokFlagTemplateHead
		if l.hasPrev && (l.prev.Kind == TokIdent || l.prev.Kind == TokString || l.prev.Kind == TokTemplate ||
			(l.prev.Kind == TokPunct && l.prev.Len() == 1 && (l.src[l.prev.Start] == ')' || l.src[l.prev.Start] == ']'))) {
			flags |= tokFlagTagged
		}
	}
	for i < len(l.src) {
		c := l.src[i]
		if c == '\\' {
			flags |= tokFlagHasEscape
			i += 2
			continue
		}
		if c == '`' {
			l.pos = i + 1
			return Token{
				Kind: TokTemplate, Start: int32(start), End: int32(i + 1),
				ValStart: int32(contentStart), ValEnd: int32(i), Quote: '`',
				Flags: flags | tokFlagTemplateTail,
			}
		}
		if c == '$' && i+1 < len(l.src) && l.src[i+1] == '{' {
			l.push(group{open: '{', templSub: true})
			l.pos = i + 2
			return Token{
				Kind: TokTemplate, Start: int32(start), End: int32(i + 2),
				ValStart: int32(contentStart), ValEnd: int32(i), Quote: '`', Flags: flags,
			}
		}
		i++
	}
	l.pos = len(l.src)
	return Token{
		Kind: TokTemplate, Start: int32(start), End: int32(len(l.src)),
		ValStart: int32(contentStart), ValEnd: int32(len(l.src)), Quote: '`',
		Flags: flags | tokFlagUnterminated,
	}
}

// scanRegex consumes a regular-expression literal. It reports failure instead of
// guessing: a `/` with no unescaped closing `/` before the end of the line is a
// division operator, so the caller retries as a punctuator. That backtrack is
// what makes the regex-versus-division decision safe without a full parser.
func (l *Lexer) scanRegex(start int) (Token, bool) {
	i := start + 1
	inClass := false
	for i < len(l.src) {
		c := l.src[i]
		switch {
		case c == '\\':
			i += 2
			continue
		case c == '\n' || c == '\r':
			return Token{}, false
		case c == '[':
			inClass = true
		case c == ']':
			inClass = false
		case c == '/' && !inClass:
			j := i + 1
			for j < len(l.src) && isIdentPart(l.src[j]) {
				j++
			}
			l.pos = j
			return Token{
				Kind: TokRegex, Start: int32(start), End: int32(j),
				ValStart: int32(start + 1), ValEnd: int32(i),
			}, true
		}
		i++
	}
	return Token{}, false
}

func (l *Lexer) scanNumber(start int) Token {
	i := start
	if l.src[i] == '0' && i+1 < len(l.src) {
		switch l.src[i+1] {
		case 'x', 'X', 'o', 'O', 'b', 'B':
			i += 2
			for i < len(l.src) && (isHexDigit(l.src[i]) || l.src[i] == '_') {
				i++
			}
			if i < len(l.src) && l.src[i] == 'n' {
				i++
			}
			l.pos = i
			return Token{Kind: TokNumber, Start: int32(start), End: int32(i), ValStart: int32(start), ValEnd: int32(i)}
		}
	}
	for i < len(l.src) && (isDigit(l.src[i]) || l.src[i] == '_') {
		i++
	}
	if i < len(l.src) && l.src[i] == '.' {
		i++
		for i < len(l.src) && (isDigit(l.src[i]) || l.src[i] == '_') {
			i++
		}
	}
	if i < len(l.src) && (l.src[i] == 'e' || l.src[i] == 'E') {
		j := i + 1
		if j < len(l.src) && (l.src[j] == '+' || l.src[j] == '-') {
			j++
		}
		if j < len(l.src) && isDigit(l.src[j]) {
			i = j
			for i < len(l.src) && (isDigit(l.src[i]) || l.src[i] == '_') {
				i++
			}
		}
	}
	if i < len(l.src) && l.src[i] == 'n' {
		i++
	}
	if i == start {
		i++
	}
	l.pos = i
	return Token{Kind: TokNumber, Start: int32(start), End: int32(i), ValStart: int32(start), ValEnd: int32(i)}
}

func (l *Lexer) scanIdent(start int) Token {
	i := start
	if l.src[i] == '#' || l.src[i] == '\\' {
		i++
	}
	for i < len(l.src) {
		c := l.src[i]
		if isIdentPart(c) {
			i++
			continue
		}
		// \u{...} and \uXXXX escapes are legal inside identifiers.
		if c == '\\' && i+1 < len(l.src) && l.src[i+1] == 'u' {
			i += 2
			if i < len(l.src) && l.src[i] == '{' {
				for i < len(l.src) && l.src[i] != '}' {
					i++
				}
				if i < len(l.src) {
					i++
				}
			} else {
				for n := 0; n < 4 && i < len(l.src) && isHexDigit(l.src[i]); n++ {
					i++
				}
			}
			continue
		}
		break
	}
	if i == start {
		i++
	}
	l.pos = i
	kind := TokIdent
	if isJSKeyword(l.src[start:i]) {
		kind = TokKeyword
	}
	return Token{Kind: kind, Start: int32(start), End: int32(i), ValStart: int32(start), ValEnd: int32(i)}
}

// multiPuncts is ordered longest-first so the scanner takes the maximal munch.
var multiPuncts = [][]byte{
	[]byte(">>>="),
	[]byte("..."), []byte("==="), []byte("!=="), []byte("**="), []byte("<<="),
	[]byte(">>="), []byte(">>>"), []byte("&&="), []byte("||="), []byte("??="),
	[]byte("=>"), []byte("=="), []byte("!="), []byte("<="), []byte(">="),
	[]byte("&&"), []byte("||"), []byte("??"), []byte("?."), []byte("++"),
	[]byte("--"), []byte("+="), []byte("-="), []byte("*="), []byte("/="),
	[]byte("%="), []byte("&="), []byte("|="), []byte("^="), []byte("<<"),
	[]byte(">>"), []byte("**"),
}

func (l *Lexer) scanPunct(start int) Token {
	width := 1
	for _, p := range multiPuncts {
		if hasPrefixBytesAt(l.src, start, p) {
			width = len(p)
			break
		}
	}
	end := start + width
	if end > len(l.src) {
		end = len(l.src)
	}
	l.pos = end
	l.trackGroup(l.src[start], int32(start))
	return Token{Kind: TokPunct, Start: int32(start), End: int32(end), ValStart: int32(start), ValEnd: int32(end)}
}

// trackGroup maintains the bracket stack that gives `)`/`}` their meaning and
// records the callee and argument index of every open call.
func (l *Lexer) trackGroup(c byte, at int32) {
	switch c {
	case '(':
		g := group{open: '('}
		if l.hasPrev {
			switch l.prev.Kind {
			case TokKeyword:
				switch string(l.prevText) {
				case "if", "for", "while", "with", "switch", "catch":
					g.ctrl = true
				}
			case TokIdent:
				g.calleeS, g.calleeE = l.prev.Start, l.prev.End
			}
			// `import(...)` is a keyword call, so record it as a callee too or
			// dynamic imports lose their module-specifier role.
			if l.prev.Kind == TokKeyword && string(l.prevText) == "import" {
				g.calleeS, g.calleeE = l.prev.Start, l.prev.End
			}
		}
		l.push(g)
	case '[':
		l.push(group{open: '['})
	case '{':
		g := group{open: '{', objectLit: l.braceIsObjectLiteral()}
		if g.objectLit {
			l.objSeq++
			g.objID = l.objSeq
			// `const mockUsers = {…}` — the name the object literal is bound to
			// says what the whole object is for, which no individual member does.
			if l.hasPrev2 && l.prev2.Kind == TokIdent && l.hasPrev {
				switch string(l.prevText) {
				case "=", ":":
					g.nameS, g.nameE = l.prev2.Start, l.prev2.End
				}
			}
		}
		l.push(g)
	case ')', ']', '}':
		l.pop()
		if l.resumeTemplate {
			l.templResumeAt = int(at)
		}
	case ',':
		if n := len(l.stack); n > 0 {
			l.stack[n-1].argIndex++
		}
	}
}

// braceIsObjectLiteral distinguishes `{a:1}` from a statement block by looking
// at what precedes the brace. It only governs whether a following `/` is read
// as a regex, and the regex scanner backtracks on a wrong guess.
func (l *Lexer) braceIsObjectLiteral() bool {
	if !l.hasPrev {
		return false
	}
	switch l.prev.Kind {
	case TokPunct:
		switch string(l.prevText) {
		case "(", ",", "=", ":", "[", "!", "?", "=>", "&&", "||", "??", "+", "-", "*", "/":
			return true
		}
		return false
	case TokKeyword:
		switch string(l.prevText) {
		case "return", "typeof", "in", "of", "case", "yield", "await", "delete", "void", "throw":
			return true
		}
		return false
	}
	return false
}

func (l *Lexer) push(g group) {
	// Bound the stack so pathological input cannot grow it without limit.
	if len(l.stack) < 1<<16 {
		l.stack = append(l.stack, g)
	}
}

func (l *Lexer) pop() {
	n := len(l.stack)
	if n == 0 {
		l.hasClose = false
		return
	}
	l.lastClose = l.stack[n-1]
	l.hasClose = true
	l.stack = l.stack[:n-1]
	if l.lastClose.templSub {
		l.resumeTemplate = true
	}
}

// remember records the last significant token, which drives regex-versus-division
// disambiguation and structural context extraction.
func (l *Lexer) remember(t Token) {
	l.prev2, l.hasPrev2, l.prev2Text = l.prev, l.hasPrev, l.prevText
	l.prev = t
	l.hasPrev = true
	if t.Start >= 0 && int(t.End) <= len(l.src) && t.End >= t.Start {
		l.prevText = l.src[t.Start:t.End]
	} else {
		l.prevText = nil
	}
}

// regexAllowed answers whether a `/` at the current position opens a regular
// expression literal. The answer is a function of the previous significant
// token; the ambiguous `)` and `}` cases are resolved from the bracket stack.
func (l *Lexer) regexAllowed() bool {
	if !l.hasPrev {
		return true
	}
	switch l.prev.Kind {
	case TokNumber, TokString, TokRegex, TokIdent:
		return false
	case TokTemplate:
		return l.prev.Flags&tokFlagTemplateTail == 0
	case TokKeyword:
		switch string(l.prevText) {
		case "this", "super", "null", "true", "false":
			return false
		}
		return true
	case TokPunct:
		switch string(l.prevText) {
		case ")":
			return l.hasClose && l.lastClose.ctrl
		case "]":
			return false
		case "}":
			return !(l.hasClose && l.lastClose.objectLit)
		case "++", "--":
			return false
		}
		return true
	}
	return true
}

// --- byte classification -------------------------------------------------

func isJSSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '\v', '\f':
		return true
	}
	return false
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isHexDigit(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

// isIdentStart treats every byte at or above 0x80 as an identifier byte. That
// over-accepts a handful of non-identifier code points, but under-accepting
// would split a UTF-8 identifier into fragments and let a rule match across the
// seam — the exact failure mode the scanner exists to prevent.
func isIdentStart(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
		c == '_' || c == '$' || c == '#' || c >= 0x80
}

func isIdentPart(c byte) bool { return isIdentStart(c) || isDigit(c) }

func hasPrefixAt(b []byte, at int, s string) bool {
	if at+len(s) > len(b) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if b[at+i] != s[i] {
			return false
		}
	}
	return true
}

func hasPrefixBytesAt(b []byte, at int, p []byte) bool {
	if at+len(p) > len(b) {
		return false
	}
	for i := range p {
		if b[at+i] != p[i] {
			return false
		}
	}
	return true
}

var jsKeywords = map[string]struct{}{
	"await": {}, "break": {}, "case": {}, "catch": {}, "class": {}, "const": {},
	"continue": {}, "debugger": {}, "default": {}, "delete": {}, "do": {},
	"else": {}, "enum": {}, "export": {}, "extends": {}, "false": {},
	"finally": {}, "for": {}, "function": {}, "if": {}, "import": {}, "in": {},
	"instanceof": {}, "new": {}, "null": {}, "return": {}, "super": {},
	"switch": {}, "this": {}, "throw": {}, "true": {}, "try": {}, "typeof": {},
	"var": {}, "void": {}, "while": {}, "with": {}, "yield": {}, "let": {},
	"static": {}, "of": {}, "async": {}, "get": {}, "set": {},
}

func isJSKeyword(b []byte) bool {
	if len(b) < 2 || len(b) > 10 {
		return false
	}
	_, ok := jsKeywords[string(b)]
	return ok
}
