package jshunter

import (
	"strings"
	"testing"
)

const cg_webpackBundle = `(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[179],{},function(n){n.O(0,[774],function(){
var r=n;r.p="/_next/static/";
r.u=function(e){return"chunks/"+({23:"about",51:"dashboard",77:"settings"}[e]||e)+"."+{23:"a1b2c3d4e5f6",51:"9f8e7d6c5b4a",77:"11aa22bb33cc"}[e]+".js"};
r.miniCssF=function(e){return"css/"+e+"."+{23:"deadbeefcafe"}[e]+".css"};
var routes=[{path:"/",element:H},{path:"/users/:id",element:U},{path:"/admin",loadChildren:function(){return import("./Admin-9f8e.js")}},{path:"settings",component:"SettingsPage"}];
var i18n={path:"Please enter a valid path",label:"Path"};
var re=/\/chunks\/([a-z]+)\.js/;
})}]);`

func cg_paths(g *ChunkGraph) []string {
	out := make([]string, 0, len(g.Chunks))
	for _, c := range g.Chunks {
		out = append(out, c.Path)
	}
	return out
}

func cg_routes(g *ChunkGraph) []string {
	out := make([]string, 0, len(g.Routes))
	for _, r := range g.Routes {
		out = append(out, r.Path)
	}
	return out
}

func cg_contains(hay []string, want string) bool {
	for _, h := range hay {
		if h == want {
			return true
		}
	}
	return false
}

func TestChunkGraph_WebpackRuntimeMap(t *testing.T) {
	g := ExtractChunkGraph("", []byte(cg_webpackBundle))

	if g.Runtime != "next" {
		t.Errorf("runtime = %q, want %q", g.Runtime, "next")
	}
	if g.PublicPath != "/_next/static/" {
		t.Errorf("public path = %q, want %q", g.PublicPath, "/_next/static/")
	}

	paths := cg_paths(g)
	for _, want := range []string{
		"chunks/about.a1b2c3d4e5f6.js",
		"chunks/dashboard.9f8e7d6c5b4a.js",
		"chunks/settings.11aa22bb33cc.js",
		"css/23.deadbeefcafe.css",
		"./Admin-9f8e.js",
	} {
		if !cg_contains(paths, want) {
			t.Errorf("chunk %q not recovered; got %v", want, paths)
		}
	}
}

func TestChunkGraph_RoutesNeedRouterSiblings(t *testing.T) {
	g := ExtractChunkGraph("", []byte(cg_webpackBundle))
	routes := cg_routes(g)

	for _, want := range []string{"/", "/users/:id", "/admin", "settings"} {
		if !cg_contains(routes, want) {
			t.Errorf("route %q not recovered; got %v", want, routes)
		}
	}
	// An i18n entry keyed `path` has no router sibling, so it is not a route.
	for _, r := range routes {
		if strings.Contains(r, " ") {
			t.Errorf("route %q contains a space; prose was mistaken for a route", r)
		}
	}
	if cg_contains(routes, "Please enter a valid path") {
		t.Error("an i18n message was reported as a route")
	}
}

func TestChunkGraph_ResolvesAgainstPublicPath(t *testing.T) {
	g := ExtractChunkGraph("https://acme.example/_next/static/chunks/main-abc.js", []byte(cg_webpackBundle))
	var got string
	for _, c := range g.Chunks {
		if c.Path == "chunks/about.a1b2c3d4e5f6.js" {
			got = c.URL
		}
	}
	want := "https://acme.example/_next/static/chunks/about.a1b2c3d4e5f6.js"
	if got != want {
		t.Errorf("resolved URL = %q, want %q", got, want)
	}
}

func TestChunkGraph_RejectsNonAssets(t *testing.T) {
	src := `var a={"x":"not-a-chunk.txt","y":"/api/users","z":"chunk-${id}.js","w":"has space.js"};
var routes=[{path:"https://evil.example/x",element:E},{path:"/ok",element:E}];`
	g := ExtractChunkGraph("", []byte(src))
	for _, c := range g.Chunks {
		if strings.Contains(c.Path, "${") || strings.Contains(c.Path, " ") ||
			strings.HasSuffix(c.Path, ".txt") {
			t.Errorf("emitted an invalid chunk path %q", c.Path)
		}
	}
	for _, r := range g.Routes {
		if strings.Contains(r.Path, "://") {
			t.Errorf("emitted an absolute URL %q as a route", r.Path)
		}
	}
	if !cg_contains(cg_routes(g), "/ok") {
		t.Errorf("valid route was dropped; got %v", cg_routes(g))
	}
}

func TestChunkGraph_DeterministicAndBounded(t *testing.T) {
	a := ExtractChunkGraph("", []byte(cg_webpackBundle))
	b := ExtractChunkGraph("", []byte(cg_webpackBundle))
	if strings.Join(cg_paths(a), "|") != strings.Join(cg_paths(b), "|") {
		t.Error("chunk order is not reproducible across runs")
	}
	if strings.Join(cg_routes(a), "|") != strings.Join(cg_routes(b), "|") {
		t.Error("route order is not reproducible across runs")
	}

	for _, src := range []string{
		"", "{", "}", "r.u=function(e){return", strings.Repeat("{", 100000),
		strings.Repeat(`r.u=function(e){return"a"+{1:"b"}[e]+".js"};`, 200),
	} {
		g := ExtractChunkGraph("", []byte(src))
		if len(g.Chunks) > cgMaxChunks || len(g.Routes) > cgMaxRoutes {
			t.Errorf("exceeded the recovery bound on a %d-byte input", len(src))
		}
	}
}

func TestChunkGraph_ViteDeps(t *testing.T) {
	src := `const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/About-BxY2.js","assets/About-CkP1.css"])))=>i.map(i=>d[i]);
__vitePreload(()=>import("./About-BxY2.js"),__vite__mapDeps([0,1]));`
	g := ExtractChunkGraph("", []byte(src))
	if g.Runtime != "vite" {
		t.Errorf("runtime = %q, want %q", g.Runtime, "vite")
	}
	paths := cg_paths(g)
	for _, want := range []string{"assets/About-BxY2.js", "assets/About-CkP1.css"} {
		if !cg_contains(paths, want) {
			t.Errorf("dep %q not recovered; got %v", want, paths)
		}
	}
}
