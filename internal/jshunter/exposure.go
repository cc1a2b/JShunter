package jshunter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

// Exposure classification.
//
// The most common complaint against a secret scanner is not that it invented a
// value — it is that the value is real and publishing it was the point. A
// Stripe publishable key, a Firebase web config, a Segment write key and a
// Supabase anon JWT are all shipped to browsers deliberately. Reporting them as
// critical credentials is a false positive in every sense the operator cares
// about, and no entropy threshold will ever fix it, because the value really is
// a live random token.
//
// The fix is to read what the credential says about itself: its prefix, its
// claims, the name it is bound to, and the shape of the configuration object it
// sits in.

// Exposure states what publishing a value actually costs.
type Exposure string

const (
	// ExposureSecret is a credential that grants access and must not ship.
	ExposureSecret Exposure = "secret"
	// ExposurePublic is published to clients by design.
	ExposurePublic Exposure = "public"
	// ExposureIdentifier names a resource without granting access to it.
	ExposureIdentifier Exposure = "identifier"
	// ExposureTest is scoped to a sandbox or test environment.
	ExposureTest Exposure = "test"
)

// Actionable reports whether an exposure class warrants operator attention as a
// leaked credential.
func (e Exposure) Actionable() bool { return e == ExposureSecret }

// ExposureVerdict carries the classification and the evidence behind it.
type ExposureVerdict struct {
	Class  Exposure
	Reason string
}

// publicPrefixes are token prefixes whose issuer documents them as publishable.
var publicPrefixes = []struct {
	prefix string
	reason string
}{
	{"pk_live_", "Stripe publishable key, published to clients by design"},
	{"pk_test_", "Stripe test publishable key"},
	{"pk.", "Mapbox public access token"},
	{"sq0idp-", "Square application id, not a credential"},
	{"ca_", "Stripe Connect client id, not a credential"},
	{"phc_", "PostHog public project key, published to clients by design"},
	{"ph_", "PostHog public project key, published to clients by design"},
}

// testPrefixes mark a credential as scoped to a non-production environment.
var testPrefixes = []struct {
	prefix string
	reason string
}{
	{"sk_test_", "Stripe test-mode secret key"},
	{"rk_test_", "Stripe test-mode restricted key"},
	{"whsec_test_", "Stripe test-mode webhook secret"},
	{"access-sandbox-", "Plaid sandbox access token"},
	{"access-development-", "Plaid development access token"},
	{"sandbox-", "sandbox-scoped credential"},
	{"sq0acp-", "Square sandbox access token"},
	{"EAAAE", "Square sandbox access token"},
	{"test_", "test-environment credential"},
}

// identifierBindings name values that identify a resource without granting
// access. Reporting an account SID or an application id as a leaked credential
// is noise; the paired secret is what matters.
var identifierBindings = []string{
	"accountsid", "applicationid", "appid", "clientid", "projectid",
	"measurementid", "messagingsenderid", "senderid", "indexname", "workspaceid",
	"tenantid", "environmentid", "organizationid", "orgid", "teamid", "siteid",
	"publickey", "installationid", "deploymentid", "datasetid",
	// Twilio names every resource identifier with a `Sid` suffix; the paired
	// auth token is the credential, and the SID alone grants nothing.
	"sid",
}

// credentialOverrideWords outrank an identifier-shaped name. `awsAccessKeyId`
// ends in a word that usually marks an identifier, but the access key id is
// half of a real credential pair and must never be withheld on that basis.
var credentialOverrideWords = []string{
	"secret", "password", "passwd", "private", "credential",
	"accesskey", "signingkey", "privatekey", "sessionkey",
}

// publicBindings name values whose own identifier declares them publishable.
var publicBindings = []string{
	"anonkey", "publishablekey", "publickey", "writekey", "browserkey",
	"clientkey", "publictoken", "publicapikey", "dsn", "sentrydsn",
	"searchkey", "searchonlykey", "clientapikey", "frontendapikey",
}

// publicConfigSignatures describe client-side SDK configuration objects whose
// members are published by design. Matching on the sibling key-set is what
// separates a Firebase web config from a genuine server key that happens to
// share the property name `apiKey`.
var publicConfigSignatures = []struct {
	name    string
	keys    []string
	minHits int
	members []string
	reason  string
}{
	{
		name:    "Firebase web app config",
		keys:    []string{"apikey", "authdomain", "projectid", "storagebucket", "messagingsenderid", "appid", "databaseurl", "measurementid"},
		minHits: 3,
		members: []string{"apikey", "appid", "databaseurl", "authdomain", "storagebucket", "measurementid", "messagingsenderid", "projectid"},
		reason:  "member of a Firebase web config object, which Google documents as public",
	},
	{
		name:    "Algolia DocSearch config",
		keys:    []string{"appid", "apikey", "indexname", "searchparameters", "placeholder"},
		minHits: 3,
		members: []string{"apikey", "appid", "indexname"},
		reason:  "member of an Algolia search config object; the key is search-only",
	},
	{
		name:    "Segment or RudderStack analytics config",
		keys:    []string{"writekey", "cdnurl", "dataplaneurl", "apihost", "cdnsettings", "integrations"},
		minHits: 2,
		members: []string{"writekey"},
		reason:  "member of a browser analytics config object; write keys are client-side by design",
	},
	{
		name:    "Supabase client config",
		keys:    []string{"url", "anonkey", "supabaseurl", "supabasekey", "auth", "realtime"},
		minHits: 2,
		members: []string{"anonkey", "supabasekey"},
		reason:  "member of a Supabase browser client config",
	},
	{
		name:    "Sentry browser config",
		keys:    []string{"dsn", "tracessamplerate", "environment", "release", "integrations", "replayssessionsamplerate"},
		minHits: 2,
		members: []string{"dsn"},
		reason:  "member of a Sentry browser SDK config; the DSN is public",
	},
	{
		name:    "Typesense or Meilisearch client config",
		keys:    []string{"nodes", "apikey", "connectiontimeoutseconds", "collectionname", "queryby", "host", "searchkey", "indexuid"},
		minHits: 3,
		members: []string{"apikey", "searchkey"},
		reason:  "member of a Typesense or Meilisearch browser client config; the key is search-scoped",
	},
	{
		name:    "Browser analytics SDK config",
		keys:    []string{"apikey", "serverzone", "measurementid", "siteid", "appid", "sendpageview", "version", "defaulttracking"},
		minHits: 2,
		members: []string{"apikey"},
		reason:  "member of a browser analytics SDK config; the key is a client-side project key",
	},
	{
		name:    "Mapbox or MapLibre config",
		keys:    []string{"accesstoken", "style", "container", "center", "zoom"},
		minHits: 3,
		members: []string{"accesstoken"},
		reason:  "member of a Mapbox map initialisation object; the token is a public style token",
	},
}

// browserInitCallees are documented client-side SDK entry points. A value whose
// only use is an argument to one of them is publishable by construction.
var browserInitCallees = []string{
	"analytics.load", "rudderanalytics.load", "posthog.init", "mixpanel.init",
	"amplitude.init", "sentry.init", "initializeapp", "firebase.initializeapp",
	"docsearch", "algoliasearch", "loadstripe", "stripe", "mapboxgl",
	"intercom", "hotjar", "clarity", "gtag", "heap.load",
}

// ClassifyExposure decides what a value's disclosure actually costs, using the
// value itself plus whatever structural context the scanner recovered.
func ClassifyExposure(rule *Rule, value string, st *Structure, lit *Literal) ExposureVerdict {
	if v, ok := classifyByPrefix(value); ok {
		return v
	}
	if v, ok := classifyJWTRole(value); ok {
		return v
	}
	if st != nil && lit != nil {
		if v, ok := classifyByConfigObject(st, lit); ok {
			return v
		}
		if v, ok := classifyByBinding(st, lit); ok {
			return v
		}
		if v, ok := classifyByCallee(st, lit); ok {
			return v
		}
	}
	if rule != nil && rule.Severity == SevInfo {
		return ExposureVerdict{ExposureIdentifier, "rule classifies this value as an identifier"}
	}
	return ExposureVerdict{ExposureSecret, ""}
}

func classifyByPrefix(value string) (ExposureVerdict, bool) {
	for _, p := range publicPrefixes {
		if strings.HasPrefix(value, p.prefix) {
			return ExposureVerdict{ExposurePublic, p.reason}, true
		}
	}
	for _, p := range testPrefixes {
		if strings.HasPrefix(value, p.prefix) {
			return ExposureVerdict{ExposureTest, p.reason}, true
		}
	}
	return ExposureVerdict{}, false
}

// classifyJWTRole reads the claims a JWT carries about itself. Supabase issues
// its public anon key and its all-powerful service-role key with a byte-identical
// HS256 header, so the header can never distinguish them — the `role` claim can.
func classifyJWTRole(value string) (ExposureVerdict, bool) {
	claims, ok := decodeJWTClaims(value)
	if !ok {
		return ExposureVerdict{}, false
	}
	role, _ := claims["role"].(string)
	switch role {
	case "anon", "authenticated":
		return ExposureVerdict{ExposurePublic, "JWT role claim is '" + role + "', the publishable Supabase key"}, true
	case "service_role":
		return ExposureVerdict{ExposureSecret, "JWT role claim is 'service_role', which bypasses row-level security"}, true
	}
	if exp, ok := claims["exp"].(float64); ok && exp > 0 {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return ExposureVerdict{ExposureIdentifier, "JWT expired, no longer grants access"}, true
		}
	}
	return ExposureVerdict{}, false
}

// decodeJWTClaims returns the decoded payload of a three-segment JWT.
func decodeJWTClaims(value string) (map[string]any, bool) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.RawStdEncoding.DecodeString(parts[1])
	}
	if err != nil {
		return nil, false
	}
	var claims map[string]any
	if json.Unmarshal(payload, &claims) != nil {
		return nil, false
	}
	return claims, true
}

func classifyByConfigObject(st *Structure, lit *Literal) (ExposureVerdict, bool) {
	siblings := st.SiblingKeys(lit)
	if len(siblings) < 2 {
		return ExposureVerdict{}, false
	}
	bound := normalizeName(st.BindingName(lit))
	if bound == "" {
		return ExposureVerdict{}, false
	}
	norm := make(map[string]struct{}, len(siblings))
	for _, k := range siblings {
		if n := normalizeName(k); n != "" {
			norm[n] = struct{}{}
		}
	}
	for _, sig := range publicConfigSignatures {
		hits := 0
		for _, k := range sig.keys {
			if _, ok := norm[k]; ok {
				hits++
			}
		}
		if hits < sig.minHits {
			continue
		}
		for _, m := range sig.members {
			if bound == m {
				return ExposureVerdict{ExposurePublic, sig.reason}, true
			}
		}
	}
	return ExposureVerdict{}, false
}

func classifyByBinding(st *Structure, lit *Literal) (ExposureVerdict, bool) {
	name := normalizeName(st.BindingName(lit))
	if name == "" {
		return ExposureVerdict{}, false
	}
	for _, b := range publicBindings {
		if name == b || strings.HasSuffix(name, b) {
			return ExposureVerdict{ExposurePublic, "bound to '" + st.BindingName(lit) + "', which declares the value publishable"}, true
		}
	}
	for _, w := range credentialOverrideWords {
		if strings.Contains(name, w) {
			return ExposureVerdict{}, false
		}
	}
	for _, b := range identifierBindings {
		if name == b || strings.HasSuffix(name, b) {
			return ExposureVerdict{ExposureIdentifier, "bound to '" + st.BindingName(lit) + "', an identifier rather than a credential"}, true
		}
	}
	return ExposureVerdict{}, false
}

func classifyByCallee(st *Structure, lit *Literal) (ExposureVerdict, bool) {
	callee := strings.ToLower(st.CalleeName(lit))
	if callee == "" {
		return ExposureVerdict{}, false
	}
	for _, c := range browserInitCallees {
		short := c
		if i := strings.LastIndex(c, "."); i >= 0 {
			short = c[i+1:]
		}
		if callee == c || callee == short {
			return ExposureVerdict{ExposurePublic, "sole use is the browser SDK entry point " + st.CalleeName(lit) + "()"}, true
		}
	}
	return ExposureVerdict{}, false
}

// DowngradeSeverity maps a rule's declared severity through its exposure class.
// Severity describes what an attacker gains; a value the vendor publishes grants
// nothing, so it must not retain a critical rating just because its shape
// matched a critical rule.
func DowngradeSeverity(sev Severity, e Exposure) Severity {
	switch e {
	case ExposurePublic:
		return SevInfo
	case ExposureIdentifier:
		return SevInfo
	case ExposureTest:
		switch sev {
		case SevCritical, SevHigh:
			return SevLow
		default:
			return SevInfo
		}
	}
	return sev
}
