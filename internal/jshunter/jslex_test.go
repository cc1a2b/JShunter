package jshunter

import (
	"strings"
	"testing"
)

// lx_spanOf returns the first token of kind k whose text equals want, or a zero
// token when the scanner never produced it.
func lx_spanOf(t *testing.T, src string, k TokenKind, want string) (Token, bool) {
	t.Helper()
	l := NewLexer([]byte(src))
	for {
		tok := l.Next()
		if tok.Kind == TokEOF {
			return Token{}, false
		}
		if tok.Kind == k && src[tok.Start:tok.End] == want {
			return tok, true
		}
	}
}

// lx_kinds collects every non-whitespace token kind in order.
func lx_kinds(src string) []TokenKind {
	l := NewLexer([]byte(src))
	var out []TokenKind
	for {
		tok := l.Next()
		if tok.Kind == TokEOF {
			return out
		}
		if tok.Kind == TokWhitespace {
			continue
		}
		out = append(out, tok.Kind)
	}
}

// lx_classify reports the class the structure index assigns to the first
// occurrence of needle in src.
func lx_classify(t *testing.T, src, needle string) SpanClass {
	t.Helper()
	i := strings.Index(src, needle)
	if i < 0 {
		t.Fatalf("needle %q not present in source", needle)
	}
	return AnalyzeStructure([]byte(src)).Classify(i, i+len(needle))
}

func TestLex_RegexLiteralNotComment(t *testing.T) {
	// The historical stripJSComments bug: the `\/\/` inside a URL-matching
	// regex was read as a line comment and blanked the rest of the line. On a
	// single-line bundle that discarded most of the file.
	src := `var re=/^https?:\/\//i;var K="AKIA2OGYBAH6STMMNXWG";`
	if _, ok := lx_spanOf(t, src, TokRegex, `/^https?:\/\//i`); !ok {
		t.Fatalf("regex literal was not recognised")
	}
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after a regex literal classified as %v, want %v", got, ClassString)
	}
}

func TestLex_DivisionIsNotRegex(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"identifier operand", `var r=a/b;var s=c/d;`},
		{"call result operand", `var r=f(1)/g(2)/h;`},
		{"member operand", `var r=o.x/o.y/2;`},
		{"number operand", `var r=10/2/1;`},
		{"postfix increment", `var r=i++/2/j;`},
		{"array index operand", `var r=a[0]/b[1]/c;`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, k := range lx_kinds(tc.src) {
				if k == TokRegex {
					t.Fatalf("division parsed as a regex literal in %q", tc.src)
				}
			}
		})
	}
}

func TestLex_RegexAfterControlParen(t *testing.T) {
	src := `if(a)/abc/.test(b);`
	if _, ok := lx_spanOf(t, src, TokRegex, `/abc/`); !ok {
		t.Errorf("regex after a control-flow paren was not recognised")
	}
}

func TestLex_UnterminatedRegexFallsBackToDivision(t *testing.T) {
	// No closing slash before end of line, so the `/` is division. The
	// backtrack is what keeps one ambiguous slash from swallowing the file.
	src := "var a = b\nvar c = 1 / 2\nvar k = \"AKIA2OGYBAH6STMMNXWG\"\n"
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after an ambiguous slash classified as %v, want %v", got, ClassString)
	}
}

func TestLex_CommentMarkersInsideStrings(t *testing.T) {
	src := `var u="https://acme.example/a";var k="AKIA2OGYBAH6STMMNXWG";`
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after a URL string classified as %v, want %v", got, ClassString)
	}
	if got := lx_classify(t, src, "https://acme.example/a"); got != ClassString {
		t.Errorf("URL inside a string classified as %v, want %v", got, ClassString)
	}
}

func TestLex_StringQuoteInsideComment(t *testing.T) {
	src := "// it's a comment with \"quotes\"\nvar k=\"AKIA2OGYBAH6STMMNXWG\";"
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after an apostrophe-bearing comment classified as %v, want %v", got, ClassString)
	}
}

func TestLex_EscapedQuoteDoesNotEndString(t *testing.T) {
	src := `var a="he said \"hi\" and left";var k="AKIA2OGYBAH6STMMNXWG";`
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after an escaped-quote string classified as %v, want %v", got, ClassString)
	}
}

func TestLex_TemplateWithNestedSubstitution(t *testing.T) {
	src := "const u=`/api/${v}/x/${`inner${q}`}/y`;const k=\"AKIA2OGYBAH6STMMNXWG\";"
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after a nested template classified as %v, want %v", got, ClassString)
	}
	if got := lx_classify(t, src, "/api/"); got != ClassTemplate {
		t.Errorf("template text classified as %v, want %v", got, ClassTemplate)
	}
	if got := lx_classify(t, src, "q"); got == ClassTemplate {
		t.Errorf("substitution expression must lex as code, got %v", got)
	}
}

func TestLex_TemplateSubstitutionIsCode(t *testing.T) {
	src := "const s=`a${AKIA2OGYBAH6STMMNXWG}b`;"
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassCode {
		t.Errorf("identifier inside a substitution classified as %v, want %v", got, ClassCode)
	}
}

func TestLex_BlockCommentAndSourcemapMarker(t *testing.T) {
	src := "/* banner AKIA2OGYBAH6STMMNXWG */\nvar a=1;\n//# sourceMappingURL=app.js.map"
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassBlockComment {
		t.Errorf("value inside a block comment classified as %v, want %v", got, ClassBlockComment)
	}
	if got := lx_classify(t, src, "sourceMappingURL"); got != ClassLineComment {
		t.Errorf("sourcemap marker classified as %v, want %v", got, ClassLineComment)
	}
}

func TestLex_MatchStraddlingTokensIsRejected(t *testing.T) {
	// A rule matching across the seam between two adjacent literals is the
	// signature of a coincidence, never of a real value.
	src := `var a=["AKIA2OGYBAH6ST","MMNXWGxxxxxxxxxx"];`
	st := AnalyzeStructure([]byte(src))
	i := strings.Index(src, "AKIA2OGYBAH6ST")
	j := strings.Index(src, "MMNXWGxxxxxxxxxx") + len("MMNXWGxxxxxxxxxx")
	if got := st.Classify(i, j); got != ClassStraddle {
		t.Errorf("cross-token match classified as %v, want %v", got, ClassStraddle)
	}
}

func TestLex_IdentifierInterior(t *testing.T) {
	src := `var xxAKIA2OGYBAH6STMMNXWGyy=1;`
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassCode {
		t.Errorf("identifier interior classified as %v, want %v", got, ClassCode)
	}
}

func TestLex_HashbangAndModernSyntax(t *testing.T) {
	src := "#!/usr/bin/env node\nclass C{#p=1n;m(){return this?.x ?? 1_000}}\nconst k=\"AKIA2OGYBAH6STMMNXWG\";"
	if got := lx_classify(t, src, "AKIA2OGYBAH6STMMNXWG"); got != ClassString {
		t.Errorf("value after modern syntax classified as %v, want %v", got, ClassString)
	}
	if got := lx_classify(t, src, "/usr/bin/env node"); got != ClassLineComment {
		t.Errorf("hashbang classified as %v, want line-comment-like trivia", got)
	}
}

func TestLex_TerminatesOnPathologicalInput(t *testing.T) {
	cases := []string{
		"", "/", "`", "\"", "'", "/*", "${", "}", "`${`${`${",
		strings.Repeat("`${", 4096), strings.Repeat("\"\\", 4096),
		strings.Repeat("/", 4096), strings.Repeat("{", 100000),
	}
	for _, src := range cases {
		l := NewLexer([]byte(src))
		last := -1
		for n := 0; ; n++ {
			tok := l.Next()
			if tok.Kind == TokEOF {
				break
			}
			if n > len(src)*4+64 {
				t.Fatalf("scanner failed to terminate on %d-byte input", len(src))
			}
			if l.Pos() <= last {
				t.Fatalf("scanner stalled at offset %d on %d-byte input", l.Pos(), len(src))
			}
			last = l.Pos()
		}
	}
}

func TestStructure_LiteralContextRoles(t *testing.T) {
	cases := []struct {
		name     string
		src      string
		needle   string
		wantRole LiteralRole
		wantName string
	}{
		{"const assignment", `const apiKey="AKIA2OGYBAH6STMMNXWG";`, "AKIA2OGYBAH6STMMNXWG", RoleAssignment, "apiKey"},
		{"member assignment", `window.cfg.secretToken="AKIA2OGYBAH6STMMNXWG";`, "AKIA2OGYBAH6STMMNXWG", RoleAssignment, "secretToken"},
		{"object value", `var o={awsKey:"AKIA2OGYBAH6STMMNXWG"};`, "AKIA2OGYBAH6STMMNXWG", RoleObjectValue, "awsKey"},
		{"quoted object key", `var o={"aws_key":"AKIA2OGYBAH6STMMNXWG"};`, "AKIA2OGYBAH6STMMNXWG", RoleObjectValue, "aws_key"},
		{"call argument", `configure("AKIA2OGYBAH6STMMNXWG");`, "AKIA2OGYBAH6STMMNXWG", RoleCallArg, ""},
		{"module specifier", `import x from "@scope/pkg-name";`, "@scope/pkg-name", RoleImportSpec, ""},
		{"require specifier", `var x=require("@scope/pkg-name");`, "@scope/pkg-name", RoleImportSpec, ""},
		{"return value", `function f(){return "AKIA2OGYBAH6STMMNXWG"}`, "AKIA2OGYBAH6STMMNXWG", RoleReturn, ""},
		{"comparison", `if(mode==="production-mode"){}`, "production-mode", RoleComparison, "mode"},
		{"member index", `var v=obj["some_long_key"];`, "some_long_key", RoleMemberIndex, "obj"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := AnalyzeStructure([]byte(tc.src))
			i := strings.Index(tc.src, tc.needle)
			lit := st.LiteralAt(i, i+len(tc.needle))
			if lit == nil {
				t.Fatalf("no indexed literal covers %q", tc.needle)
			}
			if lit.Role != tc.wantRole {
				t.Errorf("role = %v, want %v", lit.Role, tc.wantRole)
			}
			if got := st.BindingName(lit); got != tc.wantName {
				t.Errorf("binding name = %q, want %q", got, tc.wantName)
			}
		})
	}
}

func TestStructure_PropertyKeyIsNotAValue(t *testing.T) {
	src := `var o={"AKIA2OGYBAH6STMMNXWG":1};`
	st := AnalyzeStructure([]byte(src))
	i := strings.Index(src, "AKIA2OGYBAH6STMMNXWG")
	lit := st.LiteralAt(i, i+len("AKIA2OGYBAH6STMMNXWG"))
	if lit == nil {
		t.Fatal("no indexed literal for the key")
	}
	if lit.Role != RolePropertyKey {
		t.Errorf("role = %v, want %v", lit.Role, RolePropertyKey)
	}
}

func TestStructure_CalleeAndArgIndex(t *testing.T) {
	src := `initSDK("us-east-1","AKIA2OGYBAH6STMMNXWG");`
	st := AnalyzeStructure([]byte(src))
	i := strings.Index(src, "AKIA2OGYBAH6STMMNXWG")
	lit := st.LiteralAt(i, i+len("AKIA2OGYBAH6STMMNXWG"))
	if lit == nil {
		t.Fatal("no indexed literal for the second argument")
	}
	if got := st.CalleeName(lit); got != "initSDK" {
		t.Errorf("callee = %q, want %q", got, "initSDK")
	}
	if lit.ArgIndex != 1 {
		t.Errorf("arg index = %d, want 1", lit.ArgIndex)
	}
}

func TestStructure_ReliabilityRefusesNonJavaScript(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want bool
	}{
		{"minified bundle", `(self.webpackChunk=self.webpackChunk||[]).push([[51],{7:(e,t,n)=>{n.d(t,{q:()=>i});const i={k:"v"}}}]);`, true},
		// JSON is gated deliberately: every hard-coded value in a JSON body is
		// a string literal, so structural rejection is sound there too.
		{"json document", `{"a":1,"b":true,"c":null,"d":[1,2,3],"e":{"f":"g"}}`, true},
		{"single statement", `const k="AKIA2OGYBAH6STMMNXWG";`, true},
		{"bare value", `AKIA2OGYBAH6STMMNXWG`, false},
		{"yaml", "key: value\nother: thing\n", false},
		{"html page", "<!DOCTYPE html><html><head><title>x</title></head><body><p>API_KEY=abcdefghijklmnop</p></body></html>", false},
		{"dotenv text", "API_KEY=abcdefghijklmnop\nDB_PASSWORD=hunter2hunter2\n", false},
		{"plain prose", "the quick brown fox jumps over the lazy dog and then keeps going for a while", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := AnalyzeStructure([]byte(tc.src)).Reliable; got != tc.want {
				t.Errorf("Reliable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestStructure_NameSignal(t *testing.T) {
	cases := []struct {
		name           string
		wantCredential bool
		wantBenign     bool
	}{
		{"apiKey", true, false},
		{"API_KEY", true, false},
		{"api-key", true, false},
		{"clientSecret", true, false},
		{"awsSecretAccessKey", true, false},
		{"integrity", false, true},
		{"contentHash", false, true},
		{"buildId", false, true},
		{"__webpack_require__", false, false},
		{"", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cred, benign := nameSignal(tc.name)
			if cred != tc.wantCredential || benign != tc.wantBenign {
				t.Errorf("nameSignal(%q) = (%v,%v), want (%v,%v)", tc.name, cred, benign, tc.wantCredential, tc.wantBenign)
			}
		})
	}
}
