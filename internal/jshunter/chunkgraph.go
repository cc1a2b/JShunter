package jshunter

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Bundler chunk-graph recovery.
//
// A modern application ships one entry bundle and several hundred lazily loaded
// chunks. Scanning the entry point alone sees a fraction of the code, and the
// other chunks are not linked from anywhere a crawler can reach — their URLs are
// assembled at runtime from a manifest the bundler inlines into the entry file.
// Recovering that manifest turns a single URL into the full asset list, which is
// the difference between scanning one file and scanning the application.
//
// Extraction is driven from the token stream rather than from regexes over raw
// text, so a manifest that happens to sit inside a comment or a template
// substitution is not mistaken for a live one.

// ChunkRef is one discovered chunk asset.
type ChunkRef struct {
	ID     string `json:"id,omitempty"`
	Name   string `json:"name,omitempty"`
	URL    string `json:"url,omitempty"`
	Path   string `json:"path"`
	Source string `json:"source"`
}

// RouteRef is one discovered client-side route.
type RouteRef struct {
	Path      string `json:"path"`
	Component string `json:"component,omitempty"`
	Source    string `json:"source"`
}

// ChunkGraph is everything recovered from one bundle.
type ChunkGraph struct {
	PublicPath string     `json:"public_path,omitempty"`
	Runtime    string     `json:"runtime,omitempty"`
	Chunks     []ChunkRef `json:"chunks,omitempty"`
	Routes     []RouteRef `json:"routes,omitempty"`
}

// Recovery bounds. A malformed or hostile bundle must cost bounded work and
// return whatever was recovered rather than nothing.
const (
	cgMaxChunks     = 20000
	cgMaxRoutes     = 5000
	cgCaptureTokens = 4096
	cgMaxMapEntries = 20000
)

// cgChunkExts are the asset kinds a reconstructed path must end in. Anything
// else is a coincidence, not a chunk.
var cgChunkExts = []string{".js", ".mjs", ".cjs", ".css", ".wasm"}

// ExtractChunkGraph recovers the lazy-chunk manifest and client routes from a
// bundle. baseURL may be empty, in which case paths are left relative.
//
// The function is pure: it touches no package state and may be called
// concurrently.
func ExtractChunkGraph(baseURL string, body []byte) *ChunkGraph {
	g := &ChunkGraph{}
	if len(body) == 0 {
		return g
	}
	st := AnalyzeStructure(body)

	g.PublicPath = cgPublicPath(body)
	g.Runtime = cgDetectRuntime(body)

	seenChunk := make(map[string]struct{})
	seenRoute := make(map[string]struct{})

	for _, c := range cgWebpackChunkMaps(body) {
		g.addChunk(c, seenChunk)
	}
	for _, c := range cgViteDeps(body, st) {
		g.addChunk(c, seenChunk)
	}
	for _, c := range cgDynamicImports(st) {
		g.addChunk(c, seenChunk)
	}
	for _, c := range cgManifestAssets(st) {
		g.addChunk(c, seenChunk)
	}
	for _, r := range cgRouteTables(body) {
		g.addRoute(r, seenRoute)
	}
	for _, r := range cgManifestRoutes(st) {
		g.addRoute(r, seenRoute)
	}

	g.resolve(baseURL)
	sort.Slice(g.Chunks, func(i, j int) bool {
		if g.Chunks[i].Path != g.Chunks[j].Path {
			return g.Chunks[i].Path < g.Chunks[j].Path
		}
		return g.Chunks[i].Source < g.Chunks[j].Source
	})
	sort.Slice(g.Routes, func(i, j int) bool {
		if g.Routes[i].Path != g.Routes[j].Path {
			return g.Routes[i].Path < g.Routes[j].Path
		}
		return g.Routes[i].Source < g.Routes[j].Source
	})
	return g
}

func (g *ChunkGraph) addChunk(c ChunkRef, seen map[string]struct{}) {
	if len(g.Chunks) >= cgMaxChunks || !cgValidChunkPath(c.Path) {
		return
	}
	if _, dup := seen[c.Path]; dup {
		return
	}
	seen[c.Path] = struct{}{}
	g.Chunks = append(g.Chunks, c)
}

func (g *ChunkGraph) addRoute(r RouteRef, seen map[string]struct{}) {
	if len(g.Routes) >= cgMaxRoutes || !cgValidRoutePath(r.Path) {
		return
	}
	if _, dup := seen[r.Path]; dup {
		return
	}
	seen[r.Path] = struct{}{}
	g.Routes = append(g.Routes, r)
}

// resolve turns every recovered path into an absolute URL when a base is known.
// A path that will not resolve keeps its relative form and leaves URL empty
// rather than emitting a guess.
func (g *ChunkGraph) resolve(baseURL string) {
	if baseURL == "" {
		return
	}
	base, err := url.Parse(baseURL)
	if err != nil {
		return
	}
	root := base
	if g.PublicPath != "" {
		if pp, err := url.Parse(g.PublicPath); err == nil {
			root = base.ResolveReference(pp)
		}
	}
	for i := range g.Chunks {
		ref, err := url.Parse(g.Chunks[i].Path)
		if err != nil {
			continue
		}
		g.Chunks[i].URL = root.ResolveReference(ref).String()
	}
}

func cgValidChunkPath(p string) bool {
	if p == "" || len(p) > 512 {
		return false
	}
	if strings.ContainsAny(p, " \t\n<>\"'`") || strings.Contains(p, "${") || strings.Contains(p, "undefined") {
		return false
	}
	for _, ext := range cgChunkExts {
		if strings.HasSuffix(p, ext) {
			return true
		}
	}
	return false
}

func cgValidRoutePath(p string) bool {
	if p == "" || len(p) > 256 {
		return false
	}
	if strings.ContainsAny(p, " \t\n<>\"'`;{}") || strings.Contains(p, "://") {
		return false
	}
	for _, ext := range cgChunkExts {
		if strings.HasSuffix(p, ext) {
			return false
		}
	}
	if p[0] != '/' {
		// A bare segment is a nested route only if it reads like one.
		for i := 0; i < len(p); i++ {
			c := p[i]
			if !isIdentPart(c) && c != ':' && c != '-' && c != '*' && c != '.' {
				return false
			}
		}
		return true
	}
	for i := 1; i < len(p); i++ {
		c := p[i]
		if !isIdentPart(c) && c != '/' && c != ':' && c != '-' && c != '*' && c != '.' && c != '[' && c != ']' {
			return false
		}
	}
	return true
}

// cgDetectRuntime names the bundler whose runtime is present, which tells an
// operator which manifest shapes to expect.
func cgDetectRuntime(body []byte) string {
	s := string(body)
	switch {
	case strings.Contains(s, "__BUILD_MANIFEST") || strings.Contains(s, "__NEXT_DATA__") ||
		strings.Contains(s, "webpackChunk_N_E"):
		return "next"
	case strings.Contains(s, "__vite__mapDeps") || strings.Contains(s, "__vitePreload"):
		return "vite"
	case strings.Contains(s, "turbopack") || strings.Contains(s, "__turbopack_"):
		return "turbopack"
	case strings.Contains(s, "$RefreshReg$") && strings.Contains(s, "webpackHotUpdate"):
		return "webpack5"
	case strings.Contains(s, "__webpack_require__.u") || strings.Contains(s, "webpackChunk"):
		return "webpack5"
	case strings.Contains(s, "jsonpScriptSrc") || strings.Contains(s, "webpackJsonp"):
		return "webpack4"
	case strings.Contains(s, "parcelRequire"):
		return "parcel"
	}
	return ""
}

// cgPublicPath recovers the asset root every chunk path is relative to.
func cgPublicPath(body []byte) string {
	lx := NewLexer(body)
	var prev []Token
	for {
		t := lx.Next()
		if t.Kind == TokEOF {
			return ""
		}
		if t.Kind == TokWhitespace {
			continue
		}
		if t.Kind == TokString && len(prev) >= 2 {
			eq := prev[len(prev)-1]
			name := prev[len(prev)-2]
			if eq.Kind == TokPunct && string(body[eq.Start:eq.End]) == "=" &&
				name.Kind == TokIdent && cgIsPublicPathName(string(body[name.Start:name.End])) {
				v := string(body[t.ValStart:t.ValEnd])
				if v != "" && !strings.ContainsAny(v, " \t\n<>") && !strings.Contains(v, "${") {
					return v
				}
			}
		}
		prev = append(prev, t)
		if len(prev) > 4 {
			prev = prev[1:]
		}
	}
}

func cgIsPublicPathName(n string) bool {
	return n == "p" || n == "publicPath" || n == "__webpack_public_path__" || n == "u"
}

// cgWebpackChunkMaps reconstructs chunk URLs from the runtime's own URL builder.
//
// webpack emits `r.u = e => "static/chunks/" + e + "." + {1:"a1b2",2:"c3d4"}[e] + ".js"`.
// The literal fragments give the path template and the object literals give the
// id-to-hash and id-to-name maps, so the full asset list is recoverable exactly
// rather than guessed.
func cgWebpackChunkMaps(body []byte) []ChunkRef {
	var out []ChunkRef
	for _, prop := range []string{"u", "miniCssF", "k"} {
		for _, cap := range cgCaptureAssignments(body, prop) {
			out = append(out, cgBuildChunkURLs(cap, "webpack."+prop)...)
		}
	}
	return out
}

// cgCapture is the literal and map material of one runtime assignment.
type cgCapture struct {
	literals []string
	maps     []map[string]string
}

// cgCaptureAssignments collects the right-hand side of every `<obj>.<prop>=`
// assignment, bounded so a hostile bundle cannot drive unbounded work.
func cgCaptureAssignments(body []byte, prop string) []cgCapture {
	var out []cgCapture
	lx := NewLexer(body)
	var p1, p2 Token
	var n int
	for {
		t := lx.Next()
		if t.Kind == TokEOF {
			return out
		}
		if t.Kind == TokWhitespace {
			continue
		}
		if t.Kind == TokPunct && string(body[t.Start:t.End]) == "=" &&
			p1.Kind == TokIdent && string(body[p1.ValStart:p1.ValEnd]) == prop &&
			p2.Kind == TokPunct && string(body[p2.Start:p2.End]) == "." {
			if cap, ok := cgCaptureRHS(lx, body); ok {
				out = append(out, cap)
			}
			if n++; n > 64 {
				return out
			}
		}
		p2, p1 = p1, t
	}
}

// cgCaptureRHS reads forward over one assignment's right-hand side, collecting
// its string literals in order and every object literal that maps a key to a
// string. It stops at the end of the statement or at the token budget.
func cgCaptureRHS(lx *Lexer, body []byte) (cgCapture, bool) {
	var cap cgCapture
	var stack []map[string]string
	var pendingKey string
	var prev Token

	for i := 0; i < cgCaptureTokens; i++ {
		t := lx.Next()
		if t.Kind == TokEOF {
			break
		}
		if t.Kind == TokWhitespace || t.Kind == TokLineComment || t.Kind == TokBlockComment {
			continue
		}
		if t.Kind == TokPunct {
			switch string(body[t.Start:t.End]) {
			case "{":
				stack = append(stack, make(map[string]string))
				pendingKey = ""
				prev = t
				continue
			case "}":
				if n := len(stack); n > 0 {
					if m := stack[n-1]; len(m) > 0 {
						cap.maps = append(cap.maps, m)
					}
					stack = stack[:n-1]
				}
				pendingKey = ""
				prev = t
				continue
			case ";":
				if len(stack) == 0 {
					return cap, len(cap.literals) > 0
				}
			case ":":
				if len(stack) > 0 && prev.Kind != TokEOF {
					pendingKey = cgTokenKey(body, prev)
				}
			}
			prev = t
			continue
		}
		if t.Kind == TokString || t.Kind == TokTemplate {
			v := string(body[t.ValStart:t.ValEnd])
			if n := len(stack); n > 0 && pendingKey != "" {
				if len(stack[n-1]) < cgMaxMapEntries {
					stack[n-1][pendingKey] = v
				}
				pendingKey = ""
			} else {
				cap.literals = append(cap.literals, v)
			}
		}
		prev = t
	}
	for _, m := range stack {
		if len(m) > 0 {
			cap.maps = append(cap.maps, m)
		}
	}
	return cap, len(cap.literals) > 0
}

func cgTokenKey(body []byte, t Token) string {
	switch t.Kind {
	case TokString, TokTemplate:
		return string(body[t.ValStart:t.ValEnd])
	case TokIdent, TokNumber, TokKeyword:
		return string(body[t.Start:t.End])
	}
	return ""
}

// cgBuildChunkURLs assembles the path template captured from a runtime URL
// builder. The canonical shape is prefix + id + separator + hash + extension;
// when a second map is present it names the chunk and the id-to-name map is
// applied first, exactly as the runtime does.
func cgBuildChunkURLs(cap cgCapture, source string) []ChunkRef {
	if len(cap.literals) < 2 || len(cap.maps) == 0 {
		return nil
	}
	hashes := cap.maps[len(cap.maps)-1]
	var names map[string]string
	if len(cap.maps) > 1 {
		names = cap.maps[0]
	}

	prefix := cap.literals[0]
	mid := cap.literals[1]
	suffix := ""
	if len(cap.literals) > 2 {
		suffix = cap.literals[len(cap.literals)-1]
	}

	out := make([]ChunkRef, 0, len(hashes))
	for id, hash := range hashes {
		name := id
		if names != nil {
			if n, ok := names[id]; ok && n != "" {
				name = n
			}
		}
		path := prefix + name + mid + hash + suffix
		out = append(out, ChunkRef{ID: id, Name: name, Path: path, Source: source})
	}
	// Map iteration is unordered; sort so the result is reproducible.
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// cgViteDeps recovers the dependency file table Vite inlines for its preloader.
func cgViteDeps(body []byte, st *Structure) []ChunkRef {
	if !strings.Contains(string(body), "__vite__mapDeps") && !strings.Contains(string(body), "__vitePreload") {
		return nil
	}
	var out []ChunkRef
	for i := range st.literals {
		lit := &st.literals[i]
		if lit.Role != RoleArrayElem {
			continue
		}
		p := st.LiteralValue(lit)
		if cgValidChunkPath(p) {
			out = append(out, ChunkRef{Path: p, Source: "vite.mapDeps"})
		}
	}
	return out
}

// cgDynamicImports collects every module specifier that names a chunk asset.
func cgDynamicImports(st *Structure) []ChunkRef {
	var out []ChunkRef
	for i := range st.literals {
		lit := &st.literals[i]
		if lit.Role != RoleImportSpec {
			continue
		}
		p := st.LiteralValue(lit)
		if cgValidChunkPath(p) {
			out = append(out, ChunkRef{Path: p, Source: "dynamic-import"})
		}
	}
	return out
}

// cgManifestAssets harvests chunk paths from build manifests, where each route
// maps to the array of assets it needs.
func cgManifestAssets(st *Structure) []ChunkRef {
	var out []ChunkRef
	for i := range st.literals {
		lit := &st.literals[i]
		if lit.Role != RoleArrayElem && lit.Role != RoleObjectValue {
			continue
		}
		p := st.LiteralValue(lit)
		if !cgValidChunkPath(p) {
			continue
		}
		if !strings.Contains(p, "/") {
			continue
		}
		out = append(out, ChunkRef{Path: p, Source: "build-manifest"})
	}
	return out
}

// cgManifestRoutes reads the route keys of a build manifest.
func cgManifestRoutes(st *Structure) []RouteRef {
	var out []RouteRef
	for i := range st.literals {
		lit := &st.literals[i]
		if lit.Role != RolePropertyKey {
			continue
		}
		p := st.LiteralValue(lit)
		if len(p) < 2 || p[0] != '/' || !cgValidRoutePath(p) {
			continue
		}
		out = append(out, RouteRef{Path: p, Source: "build-manifest"})
	}
	return out
}

// cgRouteSiblings are the property names that identify an object literal as a
// router entry rather than any other object with a `path` member.
var cgRouteSiblings = []string{
	"element", "component", "children", "loadchildren", "lazy", "handle",
	"errorelement", "loader", "redirectto", "canactivate", "name", "components",
}

// cgRouteTables recovers client routes from router configuration objects.
//
// It runs its own scan rather than using the shared literal index, because route
// paths are short — "/" is one byte — and the detection index deliberately skips
// values too small to be a credential. The sibling key-set is what separates
// `{path:"/users/:id",element:…}` from an i18n entry that happens to be keyed
// `path`.
func cgRouteTables(body []byte) []RouteRef {
	var out []RouteRef
	lx := NewLexer(body)
	type frame struct {
		keys   []string
		values map[string]string
	}
	var stack []frame
	var pendingKey string
	var prev Token

	for i := 0; ; i++ {
		t := lx.Next()
		if t.Kind == TokEOF || len(out) >= cgMaxRoutes {
			break
		}
		if t.Kind == TokWhitespace || t.Kind == TokLineComment || t.Kind == TokBlockComment {
			continue
		}
		if t.Kind == TokPunct {
			switch string(body[t.Start:t.End]) {
			case "{":
				if len(stack) < 256 {
					stack = append(stack, frame{values: make(map[string]string, 8)})
				}
				pendingKey = ""
			case "}":
				if n := len(stack); n > 0 {
					f := stack[n-1]
					stack = stack[:n-1]
					if p, ok := f.values["path"]; ok && cgHasRouteSibling(f.keys) && cgValidRoutePath(p) {
						out = append(out, RouteRef{
							Path:      p,
							Component: cgFrameComponent(f.values),
							Source:    "route-table",
						})
					}
				}
				pendingKey = ""
			case ":":
				if n := len(stack); n > 0 && prev.Kind != TokEOF {
					pendingKey = cgTokenKey(body, prev)
					if pendingKey != "" && len(stack[n-1].keys) < 64 {
						stack[n-1].keys = append(stack[n-1].keys, pendingKey)
					}
				}
			}
			prev = t
			continue
		}
		if (t.Kind == TokString || t.Kind == TokTemplate) && pendingKey != "" {
			if n := len(stack); n > 0 && len(stack[n-1].values) < 64 {
				stack[n-1].values[normalizeName(pendingKey)] = string(body[t.ValStart:t.ValEnd])
			}
			pendingKey = ""
		}
		prev = t
	}
	return out
}

// cgFrameComponent names the module a route entry points at, when the entry
// carries one as a plain string.
func cgFrameComponent(values map[string]string) string {
	for _, k := range []string{"component", "name", "element"} {
		if v, ok := values[k]; ok && v != "" && len(v) < 128 {
			return v
		}
	}
	return ""
}

func cgHasRouteSibling(keys []string) bool {
	for _, k := range keys {
		n := normalizeName(k)
		for _, want := range cgRouteSiblings {
			if n == want {
				return true
			}
		}
	}
	return false
}

// emitChunkGraph prints the recovered asset list and route table in a form the
// operator can pipe straight back in as the input list of a follow-up scan.
func emitChunkGraph(source string, body []byte, config *Config) {
	base := source
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = ""
	}
	g := ExtractChunkGraph(base, body)
	if len(g.Chunks) == 0 && len(g.Routes) == 0 {
		return
	}
	if !config.Quiet && g.Runtime != "" {
		fmt.Fprintf(os.Stderr, "[%sCHUNKS%s] %s: %s runtime, %d chunks, %d routes\n",
			colors["CYAN"], colors["NC"], source, g.Runtime, len(g.Chunks), len(g.Routes))
	}
	for _, c := range g.Chunks {
		target := c.URL
		if target == "" {
			target = c.Path
		}
		fmt.Printf("[CHUNK]\t%s\t%s\n", source, target)
	}
	for _, r := range g.Routes {
		fmt.Printf("[ROUTE]\t%s\t%s\n", source, r.Path)
	}
}
