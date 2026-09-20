package jshunter

import (
	"strings"
	"testing"
)

// ev_withReportPolicy runs fn with the report filters forced open so a test
// exercises detection rather than the default withholding policy.
func ev_withReportPolicy(t *testing.T, public bool, floor int, fn func()) {
	t.Helper()
	prevPublic, prevFloor, prevGate := reportPublicExposure, minSeverityFloor, structuralGateEnabled
	reportPublicExposure, minSeverityFloor, structuralGateEnabled = public, floor, true
	t.Cleanup(func() {
		reportPublicExposure, minSeverityFloor, structuralGateEnabled = prevPublic, prevFloor, prevGate
	})
	fn()
}

// ev_scan runs the curated registry over a snippet and returns the rule ids it
// reported, at the shipping confidence threshold.
func ev_scan(t *testing.T, src string) []string {
	t.Helper()
	resetFindings()
	t.Cleanup(resetFindings)
	var ids []string
	for _, f := range analyzeBody("test://snippet.js", []byte(src), DefaultMinConfidence) {
		ids = append(ids, f.RuleID)
	}
	return ids
}

func ev_has(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestEvidence_ValueShapes(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  ValueShape
	}{
		{"sha256 content hash", "5f2e8a9c1b4d7e0a3c6f9b2e5a8d1c4f7b0e3a6d9c2f5b8e1a4d7c0f3b6e9a2c", ShapeHexDigest},
		{"all-one-character run", strings.Repeat("a", 32), ShapeRepetitive},
		{"md5", "25626fae796133dc1e734c6bcaaeac3c", ShapeHexDigest},
		{"uuid", "7f3a9c2e-1b4d-4e6f-8a9b-0c1d2e3f4a5b", ShapeUUID},
		{"prose", "Please enter a valid password", ShapeNaturalLanguage},
		{"prose without stopword", "Contrasena invalida ahora", ShapeNaturalLanguage},
		{"pem banner is not prose", "-----BEGIN RSA PRIVATE KEY-----", ShapeUnknown},
		{"asset path", "static/media/logo.a91f3c.png", ShapePathLike},
		{"url", "https://cdn.example.com/a/b/c.js", ShapePathLike},
		{"connection uri keeps credential shape", "postgres://u:Xk9mQ2pLvR7tYwZn@h.internal:5432/db", ShapeOpaqueToken},
		{"sequential placeholder", "abcdefghijklmnopqrst", ShapeRepetitive},
		{"repeated unit", "abcabcabcabcabcabc", ShapeRepetitive},
		{"opaque token", "kJ8fQ2mBvR7tYuIoPaSdFgHjKlZxCvBn", ShapeOpaqueToken},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AnalyzeValue(tc.value).Shape
			if tc.want == ShapeUnknown {
				if got == ShapeNaturalLanguage {
					t.Errorf("shape = %v, must not be natural-language", got)
				}
				return
			}
			if got != tc.want {
				t.Errorf("shape = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvidence_DecodedPayloadKind(t *testing.T) {
	cases := []struct {
		name  string
		value string
		want  string
	}{
		{"png", "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==", "asset"},
		{"jwks json", "eyJrZXlzIjpbeyJraWQiOiJhYmMxMjMiLCJhbGciOiJSUzI1NiJ9XSwicmVnaW9uIjoidXMtZWFzdC0xIn0=", "json"},
		{"opaque token does not decode to anything", "kJ8fQ2mBvR7tYuIoPaSdFgHjKlZxCvBn", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, _, ok := decodedPayloadKind(tc.value)
			if tc.want == "" {
				if ok && (kind == "asset" || kind == "json" || kind == "text") {
					t.Errorf("decoded as %q, want no classification", kind)
				}
				return
			}
			if !ok || kind != tc.want {
				t.Errorf("decoded kind = %q (ok=%v), want %q", kind, ok, tc.want)
			}
		})
	}
}

func TestEvidence_LiteralRunFragment(t *testing.T) {
	cases := []struct {
		name     string
		litValue string
		match    string
		want     bool
	}{
		{"exact value", ev_googleKey, ev_googleKey, false},
		{"slice of a base64 blob", "Zm9vYmFy/" + ev_googleKeyAlt + "", ev_googleKeyAlt, true},
		{"truncated by a trailing word boundary", "QUJDRE-sk-proj-aaaaBBBBccccDDDD", "sk-proj-aaaaBBBBccccDDDD", true},
		{"secret inside a url is not a fragment", "https://u:ghp_abcdefghij@github.com/a/b", "ghp_abcdefghij", false},
		{"bearer prefix is not a fragment", "Bearer sk-proj-aaaaBBBBccccDDDD", "sk-proj-aaaaBBBBccccDDDD", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := literalRunFragment(tc.litValue, tc.match); got != tc.want {
				t.Errorf("literalRunFragment = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvidence_PEMBannerNeedsABody(t *testing.T) {
	cases := []struct {
		name     string
		litValue string
		want     bool
	}{
		{"format constant", "-----BEGIN RSA PRIVATE KEY-----", true},
		{"real key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA1234567890abcdefghijklmnop\n-----END RSA PRIVATE KEY-----", false},
		{"header plus body without end marker", "-----BEGIN PRIVATE KEY-----MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuv", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := pemHeaderWithoutBody(tc.litValue, "-----BEGIN"); got != tc.want {
				t.Errorf("pemHeaderWithoutBody = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEvidence_ContextKeywordBoundaries(t *testing.T) {
	cases := []struct {
		context string
		keyword string
		want    bool
	}{
		{"apiKey", "key", true},
		{"API_KEY", "key", true},
		{"api-key", "key", true},
		{"access_token", "token", true},
		{"monkey", "key", false},
		{"turnkey", "key", false},
		{"appendChild", "app", false},
		{"metadata", "meta", false},
		{"e.fbind", "fb", false},
		{"oauth", "auth", false},
		{"const auth = 1", "auth", true},
		{"VERCEL_TOKEN", "vercel", true},
		{"x-vercel-id", "vercel", true},
	}
	for _, tc := range cases {
		t.Run(tc.context+"/"+tc.keyword, func(t *testing.T) {
			got := containsKeywordAtBoundary(tc.context, strings.ToLower(tc.context), tc.keyword)
			if got != tc.want {
				t.Errorf("containsKeywordAtBoundary(%q,%q) = %v, want %v", tc.context, tc.keyword, got, tc.want)
			}
		})
	}
}

func TestEvidence_ExposureClassification(t *testing.T) {
	cases := []struct {
		name string
		src  string
		val  string
		want Exposure
	}{
		{
			name: "supabase anon jwt is published by design",
			src:  `const c={url:"https://p.supabase.co",anonKey:"` + ev_anonJWT + `"};`,
			val:  ev_anonJWT,
			want: ExposurePublic,
		},
		{
			name: "supabase service role jwt is a secret",
			src:  `const c={serviceRoleKey:"` + ev_serviceJWT + `"};`,
			val:  ev_serviceJWT,
			want: ExposureSecret,
		},
		{
			name: "firebase web config member is public",
			src:  "const f={apiKey:\"" + ev_googleKey + "\",authDomain:\"a.firebaseapp.com\",projectId:\"a\",storageBucket:\"a.appspot.com\",messagingSenderId:\"438291756610\",appId:\"1:4:web:9f\"};",
			val:  ev_googleKey,
			want: ExposurePublic,
		},
		{
			name: "twilio sid is an identifier",
			src:  "var tw={ApiKeySid:\"" + ev_twilioAPIKeySid + "\"};",
			val:  ev_twilioAPIKeySid,
			want: ExposureIdentifier,
		},
		{
			name: "aws access key id outranks its identifier-shaped name",
			src:  `const awsAccessKeyId="AKIA2OGYBAH6STMMNXWG";`,
			val:  "AKIA2OGYBAH6STMMNXWG",
			want: ExposureSecret,
		},
		{
			name: "stripe publishable key is public",
			src:  "const k=\"" + ev_stripePublishable + "\";",
			val:  ev_stripePublishable,
			want: ExposurePublic,
		},
		{
			name: "stripe test key is non-production scope",
			src:  "const k=\"" + ev_stripeTestKey + "\";",
			val:  ev_stripeTestKey,
			want: ExposureTest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := AnalyzeStructure([]byte(tc.src))
			i := strings.Index(tc.src, tc.val)
			if i < 0 {
				t.Fatalf("value not present in source")
			}
			lit := st.LiteralAt(i, i+len(tc.val))
			got := ClassifyExposure(nil, tc.val, st, lit)
			if got.Class != tc.want {
				t.Errorf("exposure = %q (%s), want %q", got.Class, got.Reason, tc.want)
			}
		})
	}
}

func TestEvidence_SeverityDowngrade(t *testing.T) {
	cases := []struct {
		sev  Severity
		exp  Exposure
		want Severity
	}{
		{SevCritical, ExposureSecret, SevCritical},
		{SevCritical, ExposurePublic, SevInfo},
		{SevCritical, ExposureIdentifier, SevInfo},
		{SevCritical, ExposureTest, SevLow},
		{SevHigh, ExposureTest, SevLow},
		{SevMedium, ExposureTest, SevInfo},
	}
	for _, tc := range cases {
		if got := DowngradeSeverity(tc.sev, tc.exp); got != tc.want {
			t.Errorf("DowngradeSeverity(%v,%v) = %v, want %v", tc.sev, tc.exp, got, tc.want)
		}
	}
}

// TestEvidence_KnownFalsePositivesAreRejected pins the false-positive classes
// that survived every filter before v0.8. Each snippet is the shape real
// bundlers emit; none of them contains a credential.
func TestEvidence_KnownFalsePositivesAreRejected(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"supabase anon key", `const i={url:"https://p.supabase.co",anonKey:"` + ev_anonJWT + `"};`},
		{"firebase web config", "const f={apiKey:\"" + ev_googleKey + "\",authDomain:\"a.firebaseapp.com\",projectId:\"a\",storageBucket:\"a.appspot.com\",messagingSenderId:\"438291756610\",appId:\"1:4:web:9f\"};"},
		{"i18n password catalogue", `var u={password:"Please enter a valid password",passwd:"Password must be at least 8 characters"};`},
		{"algolia docsearch config", `const s={appId:"BH4D9OD16A",apiKey:"25626fae796133dc1e734c6bcaaeac3c",indexName:"acme-docs"};`},
		{"retina asset filenames", `t.icons={logo:n.p+"static/media/logo@2x.a91f3c.png",hero:n.p+"static/media/hero@3x.5fd201.webp"};`},
		{"segment write key", `const a={writeKey:"kJ8fQ2mBvR7tYuIoPaSdFgHjKlZxCvBn",cdnURL:"https://cdn.segment.com"};`},
		{"vercel build id", `var v={scriptSrc:"/_vercel/insights/script.js",buildId:"pK3mN9qR7tYuIoPaSdFgHjKl"};`},
		{"jwks base64 blob", `var cfg=JSON.parse(atob("eyJrZXlzIjpbeyJraWQiOiJhYmMxMjMiLCJhbGciOiJSUzI1NiJ9XSwicmVnaW9uIjoidXMtZWFzdC0xIn0="));`},
		{"uppercase chunk identifier", `var a={chunk:"XKASIAQWERTYUIOPASDF2CDN",region:"us-east-1"};`},
		{"brand word near a trace id", `var d=["heroku","render"],traceId="7f3a9c2e-1b4d-4e6f-8a9b-0c1d2e3f4a5b";`},
		{"twilio identifiers", "var tw={AccountSid:\"" + ev_twilioAccountSid + "\",ApiKeySid:\"" + ev_twilioAPIKeySid + "\"};"},
		{"provider prefix inside a base64 blob", "var p={payload:\"Zm9vYmFy/" + ev_googleKeyAlt + "\"};"},
		{"pem format constants", `var p={rsa:"-----BEGIN RSA PRIVATE KEY-----",pk8:"-----BEGIN PRIVATE KEY-----",ec:"-----BEGIN EC PRIVATE KEY-----"};`},
		{"content hash and integrity", `var m={contentHash:"5f2e8a9c1b4d7e0a3c6f9b2e5a8d1c4f7b0e3a6d9c2f5b8e1a4d7c0f3b6e9a2c",integrity:"sha384-oqVuAfXRKap7fdgcCY5uykM6"};`},
		{"credential shape inside a regex literal", `var re=/AKIA[A-Z2-7]{16}/g,s=String(re);`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev_withReportPolicy(t, false, 0, func() {
				if ids := ev_scan(t, tc.src); len(ids) != 0 {
					t.Errorf("reported %v, want no findings", ids)
				}
			})
		})
	}
}

// TestEvidence_TruePositivesSurvive is the recall half: every precision change
// above must leave these firing.
func TestEvidence_TruePositivesSurvive(t *testing.T) {
	cases := []struct {
		name string
		src  string
		rule string
	}{
		{"aws access key id", `const awsAccessKeyId="AKIA2OGYBAH6STMMNXWG";`, "aws.access_key_id"},
		{"aws key after a regex literal", `var re=/^https?:\/\//i;const awsAccessKeyId="AKIA2OGYBAH6STMMNXWG";`, "aws.access_key_id"},
		{"aws key after a split-on-slash regex", `var p=s.replace(/\//g,"-");const awsAccessKeyId="AKIA2OGYBAH6STMMNXWG";`, "aws.access_key_id"},
		{"supabase service role", `const serviceRoleKey="` + ev_serviceJWT + `";`, "supabase.service_role"},
		{"connection uri password", `const dbUrl="postgres://svcuser:Xk9mQ2pLvR7tYwZn@db.internal.acme:5432/prod";`, "db.connection_uri"},
		{"secret in a comment is still a secret", "// leftover: AKIA2OGYBAH6STMMNXWG\nvar a=1;", "aws.access_key_id"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev_withReportPolicy(t, false, 0, func() {
				ids := ev_scan(t, tc.src)
				if !ev_has(ids, tc.rule) {
					t.Errorf("rule %q did not fire; got %v", tc.rule, ids)
				}
			})
		})
	}
}

func TestEvidence_GateCanBeDisabled(t *testing.T) {
	src := `var v={scriptSrc:"/_vercel/insights/s.js",buildId:"pK3mN9qR7tYuIoPaSdFgHjKl"};`

	ev_withReportPolicy(t, true, 0, func() {
		if ids := ev_scan(t, src); len(ids) != 0 {
			t.Errorf("gate enabled: reported %v, want none", ids)
		}
	})

	ev_withReportPolicy(t, true, 0, func() {
		structuralGateEnabled = false
		if ids := ev_scan(t, src); len(ids) == 0 {
			t.Error("gate disabled: expected the regex-only behaviour to report the match")
		}
	})
}

func TestEvidence_SeverityFloorFilters(t *testing.T) {
	src := `const awsAccessKeyId="AKIA2OGYBAH6STMMNXWG";`
	ev_withReportPolicy(t, false, severityRank(SevCritical), func() {
		if ids := ev_scan(t, src); len(ids) == 0 {
			t.Error("critical finding was filtered out by a critical floor")
		}
	})
	ev_withReportPolicy(t, false, severityRank(SevCritical), func() {
		if ids := ev_scan(t, `var v={buildId:"pK3mN9qR7tYuIoPaSdFgHjKl"};`); len(ids) != 0 {
			t.Errorf("reported %v under a critical floor", ids)
		}
	})
}

func TestEvidence_FindingCarriesEvidence(t *testing.T) {
	ev_withReportPolicy(t, false, 0, func() {
		resetFindings()
		t.Cleanup(resetFindings)
		fs := analyzeBody("test://x.js", []byte(`const awsAccessKeyId="AKIA2OGYBAH6STMMNXWG";`), DefaultMinConfidence)
		if len(fs) != 1 {
			t.Fatalf("got %d findings, want 1", len(fs))
		}
		f := fs[0]
		if f.Evidence == nil {
			t.Fatal("finding carries no evidence")
		}
		if f.Evidence.Region != ClassString.String() {
			t.Errorf("region = %q, want %q", f.Evidence.Region, ClassString.String())
		}
		if f.Evidence.BoundTo != "awsAccessKeyId" {
			t.Errorf("bound_to = %q, want %q", f.Evidence.BoundTo, "awsAccessKeyId")
		}
		if f.Evidence.Role != RoleAssignment.String() {
			t.Errorf("role = %q, want %q", f.Evidence.Role, RoleAssignment.String())
		}
		if f.Exposure != ExposureSecret {
			t.Errorf("exposure = %q, want %q", f.Exposure, ExposureSecret)
		}
		if f.SchemaVersion != SchemaVersion {
			t.Errorf("schema_version = %d, want %d", f.SchemaVersion, SchemaVersion)
		}
	})
}

// Split so this source file does not itself trip upstream secret scanners; the
// runtime values are ordinary base64url JWTs carrying a role claim.
const (
	ev_anonJWT = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inh5eiIsInJvbGUiOiJhbm9uIiwiaWF0IjoxNzE5ODQ5NjAwfQ." +
		"J1xK9wQ2mBvR7tYuIoPaSdFgHjKlZxCvBnM4qWeRtYu"
	ev_googleKey         = "AIzaSyC7xKpQm2" + "vR9tLwYb3nHdJf" + "8sZa1XeUoPk"
	ev_googleKeyAlt      = "AIzaSyD9aB7cQ2" + "eR4tY6uI8oP0aS" + "2dF4gH6jK8l"
	ev_stripePublishable = "pk_live_51HVFj" + "kJK29bs8Hjk39M" + "eOpqRsTuVwXyZ"
	ev_stripeTestKey     = "sk_test_51HVFj" + "kJK29bs8Hjk39M" + "eOpqRsTuVwXyZ"
	ev_twilioAPIKeySid   = "SK9f8e7d6c" + "5b4a3928" + "1706f5e4d3c2b1a0"
	ev_twilioAccountSid  = "ACa1b2c3d4" + "e5f60718" + "293a4b5c6d7e8f90"
	ev_serviceJWT        = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
		"eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MTk4NDk2MDB9." +
		"Qk9RmZ2pXvL7wYnBt6sHd3aBcDeFgHiJkLmNoPqRsTu"
)
