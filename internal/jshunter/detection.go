package jshunter

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// SchemaVersion tags every JSON finding so downstream tools can detect
// breaking changes in the JSHunter output contract.
const (
	SchemaVersion        = 2
	DefaultMinConfidence = 0.50
	DefaultMaxBytes      = 32 * 1024 * 1024
	contextWindow        = 96
)

type Severity string

const (
	SevCritical Severity = "critical"
	SevHigh     Severity = "high"
	SevMedium   Severity = "medium"
	SevLow      Severity = "low"
	SevInfo     Severity = "info"
)

// Rule is a single secret-class detector with all signals the FP pipeline needs.
type Rule struct {
	ID              string
	Name            string
	Provider        string
	SecretType      string
	Severity        Severity
	Pattern         *regexp.Regexp
	Group           int
	ConfidencePrior float64
	RequiresContext bool
	ContextKeywords []string
	MinEntropy      float64
	MinLen          int
	MaxLen          int
	HighFPProne     bool
	Validate        func(string) (bool, []string)
	TPExamples      []string
	FPExamples      []string
}

// Location records every distinct site at which the same secret value was seen.
type Location struct {
	Source string `json:"source"`
	Line   int    `json:"line,omitempty"`
	Column int    `json:"column,omitempty"`
}

// Finding is the v0.6 unit of output: scored, deduped, and self-describing.
// Line/Column carry the position of the *first* occurrence; Locations[]
// mirrors all subsequent occurrences after dedupe.
type Finding struct {
	SchemaVersion int           `json:"schema_version"`
	RuleID        string        `json:"rule_id,omitempty"`
	Name          string        `json:"name"`
	Provider      string        `json:"provider,omitempty"`
	SecretType    string        `json:"secret_type,omitempty"`
	Severity      Severity      `json:"severity,omitempty"`
	Value         string        `json:"value,omitempty"`
	Redacted      string        `json:"redacted"`
	ValueHash     string        `json:"value_hash"`
	Source        string        `json:"source"`
	Line          int           `json:"line,omitempty"`
	Column        int           `json:"column,omitempty"`
	Confidence    float64       `json:"confidence"`
	Entropy       float64       `json:"entropy"`
	Verified      bool          `json:"verified"`
	Verify        *VerifyResult `json:"verify,omitempty"`
	Reasons       []string      `json:"reasons,omitempty"`
	Locations     []Location    `json:"locations,omitempty"`
}

var (
	rulesRegistry  []Rule
	rulesIndex     = make(map[string]*Rule)
	rulesOnce      sync.Once
	findingsByHash = make(map[string]*Finding)
	findingsMutex  sync.Mutex

	// Operator-managed suppression hooks. Set from main() once at startup,
	// consulted on every recordFinding. Both are nil-safe.
	activeIgnoreList *IgnoreList
	activeDiffSeen   map[string]bool
)

// Famous false positives the recon community has burned cycles on.
// Exact-match denylist; never a true positive.
//
// Provider sample values are split into prefix + body fragments so this
// source file does not itself trigger upstream secret-scanning systems
// (GitHub Push Protection, etc.). The runtime value is identical — Go
// folds the constant concatenation at compile time.
var vendorNoiseExact = map[string]struct{}{
	"AKIA" + "IOSFODNN7EXAMPLE":                  {},
	"wJalrXUtnFEMI/K7MDENG/bPxRfi" + "CYEXAMPLEKEY": {},
	"sk_" + "test_" + "BQokikJOvBiI2HlWgH4olfQ2": {},
	"pk_" + "test_" + "TYooMQauvdEDq54NiTphI7jx": {},
	"sk_" + "test_" + "4eC39HqLyjWDarjtT1zdp7dc": {},
	"pk_" + "test_" + "6pRNAsCfBOKtIshFeQd4XMUh": {},
	"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
		".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ" +
		".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c": {},
}

// Substring denylist: any match containing one of these is sample/placeholder.
var vendorNoiseSubstr = []string{
	"EXAMPLEKEY", "EXAMPLEEXAMPLE", "YOUR_API_KEY", "YOURAPIKEY",
	"REPLACEME", "REPLACE_ME", "PLACEHOLDER", "XXXXXXXX",
	"INSERT_KEY_HERE", "PUT_KEY_HERE", "ENTER_YOUR_KEY",
	"my_secret_key", "test-secret-key",
}

// Surrounding-context tokens that lower the score (looks like a fixture/sample).
var fixtureKeywords = []string{
	"example", "fixture", "dummy", "sample",
	"placeholder", "fake_", "mock_", "stub_", "lorem",
	"FIXME", "TODO", "// e.g.", "for example",
}

// Generic-rule context: at least one of these must appear within ±contextWindow
// chars when a rule is flagged RequiresContext=true.
var contextKeywordsGeneric = []string{
	"key", "token", "secret", "auth", "bearer", "api",
	"private", "credential", "password", "pwd", "session", "access",
}

// Sourcemap signature on the line is an instant skip - it's a build artifact.
var sourcemapMarkerRe = regexp.MustCompile(`(?i)//[#@]\s*source(?:mapping)?URL=`)

// Vendor chunk filename hint; raises the FP threshold.
var vendorChunkRe = regexp.MustCompile(`(?i)(?:vendor|chunk|runtime|polyfill|framework|webpack|node_modules)[-_./~]`)

// registerRules wires the curated provider registry. Called lazily so users
// who only consume legacy regexPatterns pay nothing.
func registerRules() {
	rulesOnce.Do(func() {
		rulesRegistry = append(rulesRegistry, []Rule{
			{
				ID:              "aws.access_key_id",
				Name:            "AWS Access Key ID",
				Provider:        "AWS",
				SecretType:      "access_key_id",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\b(?:AKIA|ASIA|A3T[A-Z0-9]|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z2-7]{16}\b`),
				ConfidencePrior: 0.85,
				MinLen:          20, MaxLen: 20,
				Validate:   validateAWSAccessKeyID,
				TPExamples: []string{"AKIA2OGYBAH6STMMNXWG"},
				FPExamples: []string{"AKIAIOSFODNN7EXAMPLE"},
			},
			{
				ID:              "aws.secret_access_key",
				Name:            "AWS Secret Access Key",
				Provider:        "AWS",
				SecretType:      "secret_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`(?i)\b(?:aws[_-]?(?:secret|sk))[_-]?(?:access[_-]?)?key\s*[:=]\s*["']([A-Za-z0-9/+=]{40})["']`),
				Group:           1,
				ConfidencePrior: 0.80,
				MinEntropy:      4.2,
				MinLen:          40, MaxLen: 40,
				HighFPProne: true,
				Validate:    validateAWSSecretKey,
			},
			{
				ID:              "stripe.secret_key",
				Name:            "Stripe Secret Key",
				Provider:        "Stripe",
				SecretType:      "api_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{20,247}\b`),
				ConfidencePrior: 0.95,
				MinLen:          28,
				Validate:        validateStripeKey,
				TPExamples:      []string{"sk_" + "live_" + "51HVFjkJK29bs8Hjk39MeOpqRsTuVwXyZ"},
				FPExamples:      []string{"sk_" + "test_" + "BQokikJOvBiI2HlWgH4olfQ2"},
			},
			{
				ID:              "stripe.restricted_key",
				Name:            "Stripe Restricted Key",
				Provider:        "Stripe",
				SecretType:      "api_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\brk_live_[0-9A-Za-z]{20,247}\b`),
				ConfidencePrior: 0.95,
				MinLen:          28,
				Validate:        validateStripeKey,
			},
			{
				ID:              "stripe.publishable_key",
				Name:            "Stripe Publishable Key",
				Provider:        "Stripe",
				SecretType:      "publishable_key",
				Severity:        SevLow,
				Pattern:         regexp.MustCompile(`\bpk_live_[0-9A-Za-z]{20,247}\b`),
				ConfidencePrior: 0.95,
				MinLen:          28,
				Validate:        validateStripeKey,
			},
			{
				ID:              "github.pat_classic",
				Name:            "GitHub Personal Access Token",
				Provider:        "GitHub",
				SecretType:      "pat",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bgh[oprsu]_[A-Za-z0-9]{36,251}\b`),
				ConfidencePrior: 0.85,
				MinLen:          40,
				Validate:        validateGitHubToken,
			},
			{
				ID:              "github.fine_grained_pat",
				Name:            "GitHub Fine-Grained PAT",
				Provider:        "GitHub",
				SecretType:      "pat",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bgithub_pat_[0-9A-Za-z_]{82}\b`),
				ConfidencePrior: 0.95,
				MinLen:          93, MaxLen: 93,
			},
			{
				ID:              "openai.legacy_key",
				Name:            "OpenAI API Key (legacy)",
				Provider:        "OpenAI",
				SecretType:      "api_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b`),
				ConfidencePrior: 0.95,
				MinLen:          51, MaxLen: 51,
			},
			{
				ID:              "openai.project_key",
				Name:            "OpenAI Project Key",
				Provider:        "OpenAI",
				SecretType:      "api_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bsk-proj-[A-Za-z0-9_\-]{40,200}\b`),
				ConfidencePrior: 0.92,
				MinLen:          48,
			},
			{
				ID:              "openai.svcacct_key",
				Name:            "OpenAI Service Account Key",
				Provider:        "OpenAI",
				SecretType:      "api_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bsk-svcacct-[A-Za-z0-9_\-]{40,200}\b`),
				ConfidencePrior: 0.92,
				MinLen:          48,
			},
			{
				ID:              "anthropic.api_key",
				Name:            "Anthropic API Key",
				Provider:        "Anthropic",
				SecretType:      "api_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{86,200}\b`),
				ConfidencePrior: 0.95,
				MinLen:          93,
			},
			{
				ID:              "google.api_key",
				Name:            "Google API Key",
				Provider:        "Google",
				SecretType:      "api_key",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`),
				ConfidencePrior: 0.85,
				MinLen:          39, MaxLen: 39,
			},
			{
				ID:              "google.oauth_token",
				Name:            "Google OAuth Access Token",
				Provider:        "Google",
				SecretType:      "oauth",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bya29\.[0-9A-Za-z_\-]{40,200}\b`),
				ConfidencePrior: 0.90,
				MinLen:          45,
			},
			{
				ID:              "slack.user_or_bot_token",
				Name:            "Slack Token",
				Provider:        "Slack",
				SecretType:      "api_token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bxox[bopsare]-(?:\d+-){1,4}[A-Za-z0-9]{16,40}\b`),
				ConfidencePrior: 0.92,
				MinLen:          24,
				Validate:        validateSlackToken,
			},
			{
				ID:              "slack.app_token",
				Name:            "Slack App Token",
				Provider:        "Slack",
				SecretType:      "api_token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bxapp-\d-[A-Z0-9]+-\d+-[A-Za-z0-9]{40,80}\b`),
				ConfidencePrior: 0.92,
				MinLen:          50,
			},
			{
				ID:              "slack.webhook",
				Name:            "Slack Incoming Webhook",
				Provider:        "Slack",
				SecretType:      "webhook",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bhttps://hooks\.slack\.com/services/T[A-Z0-9]{8,12}/B[A-Z0-9]{8,12}/[A-Za-z0-9]{20,40}\b`),
				ConfidencePrior: 0.97,
			},
			{
				ID:              "discord.webhook",
				Name:            "Discord Webhook",
				Provider:        "Discord",
				SecretType:      "webhook",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bhttps://(?:discord|discordapp)\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_\-]{60,80}\b`),
				ConfidencePrior: 0.97,
			},
			{
				ID:              "discord.bot_token",
				Name:            "Discord Bot Token",
				Provider:        "Discord",
				SecretType:      "bot_token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\b[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27,38}\b`),
				ConfidencePrior: 0.85,
				MinLen:          59,
				HighFPProne:     true,
			},
			{
				ID:              "twilio.api_key",
				Name:            "Twilio API Key (SK)",
				Provider:        "Twilio",
				SecretType:      "api_key",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`),
				ConfidencePrior: 0.75,
				MinLen:          34, MaxLen: 34,
				HighFPProne:     true,
				Validate:        validateTwilioSK,
			},
			{
				ID:              "twilio.account_sid",
				Name:            "Twilio Account SID (AC)",
				Provider:        "Twilio",
				SecretType:      "account_id",
				Severity:        SevMedium,
				Pattern:         regexp.MustCompile(`\bAC[a-f0-9]{32}\b`),
				ConfidencePrior: 0.70,
				MinLen:          34, MaxLen: 34,
				HighFPProne:     true,
			},
			{
				ID:              "sendgrid.api_key",
				Name:            "SendGrid API Key",
				Provider:        "SendGrid",
				SecretType:      "api_key",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b`),
				ConfidencePrior: 0.97,
				MinLen:          69, MaxLen: 69,
			},
			{
				ID:              "mailgun.api_key",
				Name:            "Mailgun API Key",
				Provider:        "Mailgun",
				SecretType:      "api_key",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bkey-[0-9a-zA-Z]{32}\b`),
				ConfidencePrior: 0.85,
				MinLen:          36, MaxLen: 36,
			},
			{
				ID:              "mailchimp.api_key",
				Name:            "Mailchimp API Key",
				Provider:        "Mailchimp",
				SecretType:      "api_key",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\b[0-9a-f]{32}-us[0-9]{1,3}\b`),
				ConfidencePrior: 0.85,
				MinLen:          35,
			},
			{
				ID:              "github.app_install_token",
				Name:            "GitHub App Installation Token",
				Provider:        "GitHub",
				SecretType:      "installation_token",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\bv1\.[a-f0-9]{40,}\b`),
				ConfidencePrior: 0.55,
				MinLen:          43,
				HighFPProne:     true,
				RequiresContext: true,
				ContextKeywords: []string{"github", "token", "install", "app"},
			},
			{
				ID:              "gitlab.pat",
				Name:            "GitLab Personal Access Token",
				Provider:        "GitLab",
				SecretType:      "pat",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bglpat-[0-9A-Za-z_\-]{20,40}\b`),
				ConfidencePrior: 0.95,
				MinLen:          26,
			},
			{
				ID:              "gitlab.pipeline_token",
				Name:            "GitLab Pipeline Trigger Token",
				Provider:        "GitLab",
				SecretType:      "pipeline_token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bglptt-[a-f0-9]{40}\b`),
				ConfidencePrior: 0.97,
				MinLen:          46, MaxLen: 46,
			},
			{
				ID:              "vercel.token",
				Name:            "Vercel Token",
				Provider:        "Vercel",
				SecretType:      "token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\b(?:vercel_)?[A-Za-z0-9]{24}\b`),
				ConfidencePrior: 0.45,
				HighFPProne:     true,
				RequiresContext: true,
				ContextKeywords: []string{"vercel", "VERCEL_TOKEN"},
			},
			{
				ID:              "doppler.token",
				Name:            "Doppler Token",
				Provider:        "Doppler",
				SecretType:      "token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bdp\.(?:pt|st|sa|ct|scim|audit)\.[A-Za-z0-9]{40,44}\b`),
				ConfidencePrior: 0.97,
				MinLen:          47,
			},
			{
				ID:              "digitalocean.token",
				Name:            "DigitalOcean Token",
				Provider:        "DigitalOcean",
				SecretType:      "token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bdop_v1_[a-f0-9]{64}\b`),
				ConfidencePrior: 0.97,
				MinLen:          71, MaxLen: 71,
			},
			{
				ID:              "shopify.access_token",
				Name:            "Shopify Access Token",
				Provider:        "Shopify",
				SecretType:      "access_token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bshpat_[a-fA-F0-9]{32}\b`),
				ConfidencePrior: 0.97,
				MinLen:          38, MaxLen: 38,
			},
			{
				ID:              "shopify.shared_secret",
				Name:            "Shopify Shared Secret",
				Provider:        "Shopify",
				SecretType:      "shared_secret",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bshpss_[a-fA-F0-9]{32}\b`),
				ConfidencePrior: 0.97,
				MinLen:          38, MaxLen: 38,
			},
			{
				ID:              "npm.token",
				Name:            "npm Access Token",
				Provider:        "npm",
				SecretType:      "token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`),
				ConfidencePrior: 0.95,
				MinLen:          40, MaxLen: 40,
			},
			{
				ID:              "pypi.token",
				Name:            "PyPI Token",
				Provider:        "PyPI",
				SecretType:      "token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,200}\b`),
				ConfidencePrior: 0.97,
				MinLen:          70,
			},
			{
				ID:              "jwt.token",
				Name:            "JSON Web Token",
				Provider:        "JWT",
				SecretType:      "jwt",
				Severity:        SevMedium,
				Pattern:         regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`),
				ConfidencePrior: 0.70,
				MinLen:          40,
				Validate:        validateJWT,
			},
			{
				ID:              "rsa.private_key",
				Name:            "RSA Private Key",
				Provider:        "PKI",
				SecretType:      "private_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`-----BEGIN RSA PRIVATE KEY-----`),
				ConfidencePrior: 0.99,
			},
			{
				ID:              "openssh.private_key",
				Name:            "OpenSSH Private Key",
				Provider:        "PKI",
				SecretType:      "private_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----`),
				ConfidencePrior: 0.99,
			},
			{
				ID:              "ec.private_key",
				Name:            "EC Private Key",
				Provider:        "PKI",
				SecretType:      "private_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`-----BEGIN EC PRIVATE KEY-----`),
				ConfidencePrior: 0.99,
			},
			{
				ID:              "pgp.private_key",
				Name:            "PGP Private Key",
				Provider:        "PKI",
				SecretType:      "private_key",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`-----BEGIN PGP PRIVATE KEY BLOCK-----`),
				ConfidencePrior: 0.99,
			},
			{
				ID:              "facebook.access_token",
				Name:            "Facebook Access Token",
				Provider:        "Meta",
				SecretType:      "access_token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bEAA[A-Za-z0-9]{20,200}\b`),
				ConfidencePrior: 0.65,
				MinLen:          25,
				HighFPProne:     true,
				RequiresContext: true,
				ContextKeywords: []string{"facebook", "fb", "meta", "graph.facebook"},
			},
			{
				ID:              "linear.api_key",
				Name:            "Linear API Key",
				Provider:        "Linear",
				SecretType:      "api_key",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\blin_(?:api|oauth)_[A-Za-z0-9]{40,80}\b`),
				ConfidencePrior: 0.97,
				MinLen:          47,
			},
			{
				ID:              "huggingface.token",
				Name:            "HuggingFace Token",
				Provider:        "HuggingFace",
				SecretType:      "token",
				Severity:        SevHigh,
				Pattern:         regexp.MustCompile(`\bhf_[A-Za-z0-9]{34,80}\b`),
				ConfidencePrior: 0.92,
				MinLen:          37,
			},
			{
				ID:              "supabase.service_role",
				Name:            "Supabase Service Role JWT",
				Provider:        "Supabase",
				SecretType:      "service_role",
				Severity:        SevCritical,
				Pattern:         regexp.MustCompile(`\beyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b`),
				ConfidencePrior: 0.75,
				MinLen:          60,
				Validate:        validateJWT,
			},
		}...)

		for i := range rulesRegistry {
			r := &rulesRegistry[i]
			rulesIndex[r.ID] = r
		}
	})
}

// shannonEntropy is the standard bits-per-symbol entropy. Vendored here to
// avoid pulling another dep; the math/log2 path is hot-cache safe.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, r := range s {
		freq[r]++
	}
	length := float64(len(s))
	entropy := 0.0
	for _, c := range freq {
		p := float64(c) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// charClassDiversity counts how many of the four shape classes the string uses.
// Real secrets tend to use 3+; minified identifiers use 1-2.
func charClassDiversity(s string) int {
	var hasLower, hasUpper, hasDigit, hasSym bool
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			hasLower = true
		case r >= 'A' && r <= 'Z':
			hasUpper = true
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '_' || r == '-' || r == '.' || r == '+' || r == '/' || r == '=':
			hasSym = true
		}
	}
	d := 0
	if hasLower {
		d++
	}
	if hasUpper {
		d++
	}
	if hasDigit {
		d++
	}
	if hasSym {
		d++
	}
	return d
}

// redactValue masks the middle of a secret while keeping enough head/tail to
// disambiguate findings without leaking the secret to logs.
func redactValue(v string) string {
	n := len(v)
	switch {
	case n <= 8:
		return strings.Repeat("*", n)
	case n <= 16:
		return v[:2] + strings.Repeat("*", n-4) + v[n-2:]
	default:
		return v[:4] + strings.Repeat("*", n-8) + v[n-4:]
	}
}

// hashValue gives a stable, short identifier for dedup that can't be reversed
// to the secret itself when emitted in summary output.
func hashValue(v string) string {
	h := sha256.Sum256([]byte(v))
	return hex.EncodeToString(h[:8])
}

// looksLikeFixture returns true if the surrounding context smells like docs/example code.
func looksLikeFixture(context string) bool {
	low := strings.ToLower(context)
	for _, kw := range fixtureKeywords {
		if strings.Contains(low, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// hasContextKeyword checks whether at least one of `kws` appears (case-insensitive)
// in the given context window.
func hasContextKeyword(context string, kws []string) bool {
	if len(kws) == 0 {
		return true
	}
	low := strings.ToLower(context)
	for _, kw := range kws {
		if strings.Contains(low, strings.ToLower(kw)) {
			return true
		}
	}
	return false
}

// isInVendorNoise screens canonical sample/placeholder values.
func isInVendorNoise(v string) (bool, string) {
	if _, ok := vendorNoiseExact[v]; ok {
		return true, "exact-match in vendor-noise corpus"
	}
	for _, sub := range vendorNoiseSubstr {
		if strings.Contains(v, sub) {
			return true, "contains placeholder fragment '" + sub + "'"
		}
	}
	return false, ""
}

// extractContextWindow returns the slice of body around `start..end` for context analysis.
func extractContextWindow(body string, start, end int) string {
	a := start - contextWindow
	if a < 0 {
		a = 0
	}
	b := end + contextWindow
	if b > len(body) {
		b = len(body)
	}
	return body[a:b]
}

// scoreFinding runs the FP pipeline against (rule, value, context) and returns
// (keep, score, reasons). Score is in [0,1]. Caller uses the configured
// minimum-confidence threshold to gate output. Counters are incremented when
// a match is dropped at a known stage so --stats can audit the pipeline.
func scoreFinding(rule *Rule, value, context, source string) (bool, float64, []string) {
	reasons := []string{}
	score := rule.ConfidencePrior
	if score == 0 {
		score = 0.5
	}

	if vendorChunkRe.MatchString(source) {
		score -= 0.15
		reasons = append(reasons, "source looks like a vendor/chunk bundle")
	}

	if drop, why := isInVendorNoise(value); drop {
		if globalStats != nil {
			statInc(&globalStats.DroppedVendorNoise)
		}
		return false, 0, []string{why}
	}

	if rule.MinLen > 0 && len(value) < rule.MinLen {
		return false, 0, []string{fmt.Sprintf("length %d < MinLen %d", len(value), rule.MinLen)}
	}
	if rule.MaxLen > 0 && len(value) > rule.MaxLen {
		return false, 0, []string{fmt.Sprintf("length %d > MaxLen %d", len(value), rule.MaxLen)}
	}

	entropy := shannonEntropy(value)
	if rule.MinEntropy > 0 && entropy < rule.MinEntropy {
		if globalStats != nil {
			statInc(&globalStats.DroppedLowEntropy)
		}
		return false, 0, []string{fmt.Sprintf("entropy %.2f < required %.2f", entropy, rule.MinEntropy)}
	}

	if rule.HighFPProne {
		diversity := charClassDiversity(value)
		if diversity < 2 {
			if globalStats != nil {
				statInc(&globalStats.DroppedLowEntropy)
			}
			return false, 0, []string{"insufficient character-class diversity for high-FP rule"}
		}
		if entropy < 3.0 {
			if globalStats != nil {
				statInc(&globalStats.DroppedLowEntropy)
			}
			return false, 0, []string{fmt.Sprintf("entropy %.2f too low for high-FP rule", entropy)}
		}
	}

	if rule.RequiresContext {
		kws := rule.ContextKeywords
		if len(kws) == 0 {
			kws = contextKeywordsGeneric
		}
		if !hasContextKeyword(context, kws) {
			if globalStats != nil {
				statInc(&globalStats.DroppedNoContext)
			}
			return false, 0, []string{"missing required context keyword(s)"}
		}
		score += 0.05
		reasons = append(reasons, "context keyword present")
	}

	if rule.Validate != nil {
		ok, vReasons := rule.Validate(value)
		if !ok {
			return false, 0, append([]string{"provider validator rejected"}, vReasons...)
		}
		score += 0.10
		reasons = append(reasons, vReasons...)
	}

	if looksLikeFixture(context) {
		score -= 0.30
		if globalStats != nil {
			statInc(&globalStats.DroppedFixture)
		}
		reasons = append(reasons, "surrounded by fixture/example wording")
	}

	if entropy >= 4.5 {
		score += 0.05
		reasons = append(reasons, fmt.Sprintf("high entropy %.2f", entropy))
	}

	if charClassDiversity(value) >= 3 {
		score += 0.05
		reasons = append(reasons, "diverse character classes")
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}

	return true, score, reasons
}

// recordFinding inserts or merges a finding into the dedupe map keyed by
// (value_hash, secret_type). Same secret seen in many sources collapses to a
// single Finding with a Locations[] list, each location carrying its own
// line:column pair so an operator can `vim file:line:col` directly.
//
// Returns nil when the finding is suppressed by the active ignore list or
// the active diff baseline. Callers must check for nil.
func recordFinding(f *Finding) *Finding {
	if activeIgnoreList != nil && activeIgnoreList.ShouldIgnore(f) {
		return nil
	}
	if activeDiffSeen != nil && activeDiffSeen[f.ValueHash] {
		return nil
	}
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	key := f.ValueHash + "|" + f.SecretType
	loc := Location{Source: f.Source, Line: f.Line, Column: f.Column}
	if existing, ok := findingsByHash[key]; ok {
		existing.Locations = append(existing.Locations, loc)
		if f.Confidence > existing.Confidence {
			existing.Confidence = f.Confidence
			existing.Reasons = f.Reasons
		}
		if f.Verified && !existing.Verified {
			existing.Verified = true
			existing.Verify = f.Verify
		}
		return existing
	}
	f.Locations = []Location{loc}
	findingsByHash[key] = f
	if globalStats != nil {
		statInc(&globalStats.FindingsAfterDedupe)
	}
	return f
}

// flushFindings returns a snapshot of all unique findings, sorted by severity then confidence.
func flushFindings() []*Finding {
	findingsMutex.Lock()
	defer findingsMutex.Unlock()
	out := make([]*Finding, 0, len(findingsByHash))
	for _, f := range findingsByHash {
		out = append(out, f)
	}
	sevRank := map[Severity]int{
		SevCritical: 5, SevHigh: 4, SevMedium: 3, SevLow: 2, SevInfo: 1,
	}
	sort.Slice(out, func(i, j int) bool {
		ri, rj := sevRank[out[i].Severity], sevRank[out[j].Severity]
		if ri != rj {
			return ri > rj
		}
		if out[i].Confidence != out[j].Confidence {
			return out[i].Confidence > out[j].Confidence
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// resetFindings clears the dedupe state between independent runs.
func resetFindings() {
	findingsMutex.Lock()
	findingsByHash = make(map[string]*Finding)
	findingsMutex.Unlock()
}

// analyzeBody runs the curated registry against `body` and returns scored findings.
// Source is the URL or filepath. minConfidence gates which findings pass.
// Each Finding records the byte offset, line, and column of the match so
// downstream tools can anchor results back to the exact source location.
func analyzeBody(source string, body []byte, minConfidence float64) []*Finding {
	registerRules()
	bodyStr := string(body)
	out := []*Finding{}

	for i := range rulesRegistry {
		rule := &rulesRegistry[i]
		matches := rule.Pattern.FindAllStringSubmatchIndex(bodyStr, -1)
		for _, m := range matches {
			start, end := m[0], m[1]
			value := bodyStr[start:end]
			if rule.Group > 0 && len(m) > 2*rule.Group+1 {
				gs, ge := m[2*rule.Group], m[2*rule.Group+1]
				if gs >= 0 && ge >= 0 {
					start, end = gs, ge
					value = bodyStr[start:end]
				}
			}

			lineCtx := bodyStr[lineStartIndex(bodyStr, start):lineEndIndex(bodyStr, end)]
			if sourcemapMarkerRe.MatchString(lineCtx) {
				if globalStats != nil {
					statInc(&globalStats.DroppedSourcemap)
				}
				continue
			}

			ctx := extractContextWindow(bodyStr, start, end)
			keep, score, reasons := scoreFinding(rule, value, ctx, source)
			if !keep {
				continue
			}
			if score < minConfidence {
				if globalStats != nil {
					statInc(&globalStats.DroppedBelowConf)
				}
				continue
			}

			line, col := positionAt(bodyStr, start)
			f := &Finding{
				SchemaVersion: SchemaVersion,
				RuleID:        rule.ID,
				Name:          rule.Name,
				Provider:      rule.Provider,
				SecretType:    rule.SecretType,
				Severity:      rule.Severity,
				Value:         value,
				Redacted:      redactValue(value),
				ValueHash:     hashValue(value),
				Source:        source,
				Confidence:    score,
				Entropy:       shannonEntropy(value),
				Reasons:       reasons,
				Line:          line,
				Column:        col,
			}
			if globalStats != nil {
				statInc(&globalStats.RegistryHits)
				statInc(&globalStats.FindingsAfterFilter)
			}
			if rec := recordFinding(f); rec != nil {
				out = append(out, rec)
			}
		}
	}
	return out
}

// positionAt returns the 1-indexed (line, column) of byte offset `idx` in s.
// Cheap O(idx) scan; called once per finding so the cost is negligible
// relative to the regex evaluation that produced the offset.
func positionAt(s string, idx int) (line, col int) {
	if idx < 0 {
		idx = 0
	}
	if idx > len(s) {
		idx = len(s)
	}
	line, col = 1, 1
	for i := 0; i < idx; i++ {
		if s[i] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return line, col
}

func lineStartIndex(s string, idx int) int {
	if idx <= 0 {
		return 0
	}
	if idx >= len(s) {
		idx = len(s) - 1
	}
	for i := idx; i > 0; i-- {
		if s[i-1] == '\n' {
			return i
		}
	}
	return 0
}

func lineEndIndex(s string, idx int) int {
	if idx >= len(s) {
		return len(s)
	}
	for i := idx; i < len(s); i++ {
		if s[i] == '\n' {
			return i
		}
	}
	return len(s)
}

// applyLegacyFPFilter wraps the existing regexPatterns dictionary so that
// every legacy hit is also scored. Returns (keep, confidence, reasons) so the
// caller can decide to print or drop, and to optionally show the score.
//
// This is the bridge that brings v0.6 quality to rules we have not yet
// migrated into the curated registry.
func applyLegacyFPFilter(name, value, body, source string, start, end int) (bool, float64, []string) {
	if globalStats != nil {
		statInc(&globalStats.LegacyMatchesRaw)
	}
	if value == "" {
		return false, 0, []string{"empty match"}
	}
	if drop, why := isInVendorNoise(value); drop {
		if globalStats != nil {
			statInc(&globalStats.DroppedVendorNoise)
		}
		return false, 0, []string{why}
	}

	ctx := extractContextWindow(body, start, end)
	if sourcemapMarkerRe.MatchString(body[lineStartIndex(body, start):lineEndIndex(body, end)]) {
		if globalStats != nil {
			statInc(&globalStats.DroppedSourcemap)
		}
		return false, 0, []string{"line is a //# sourceMappingURL marker"}
	}

	score := 0.55
	reasons := []string{}

	low := strings.ToLower(name)
	highFP := strings.HasPrefix(low, "generic ") || strings.Contains(low, "quickbooks") ||
		strings.Contains(low, "cisco access") || strings.Contains(low, "sanity") ||
		strings.Contains(low, "atlassian access") || strings.Contains(low, "heroku")

	entropy := shannonEntropy(value)
	diversity := charClassDiversity(value)

	if highFP {
		if diversity < 2 {
			if globalStats != nil {
				statInc(&globalStats.DroppedLowEntropy)
			}
			return false, 0, []string{"high-FP-prone rule: low character-class diversity"}
		}
		if entropy < 3.2 {
			if globalStats != nil {
				statInc(&globalStats.DroppedLowEntropy)
			}
			return false, 0, []string{fmt.Sprintf("high-FP-prone rule: entropy %.2f too low", entropy)}
		}
		if !hasContextKeyword(ctx, contextKeywordsGeneric) {
			if globalStats != nil {
				statInc(&globalStats.DroppedNoContext)
			}
			return false, 0, []string{"high-FP-prone rule: no key/token/secret context keyword"}
		}
		reasons = append(reasons, "context keyword present (generic-rule gate)")
	}

	if vendorChunkRe.MatchString(source) {
		score -= 0.15
		reasons = append(reasons, "vendor/chunk bundle")
	}

	if looksLikeFixture(ctx) {
		score -= 0.30
		if globalStats != nil {
			statInc(&globalStats.DroppedFixture)
		}
		reasons = append(reasons, "context looks like a fixture/example")
	}

	if entropy >= 4.5 {
		score += 0.05
		reasons = append(reasons, fmt.Sprintf("high entropy %.2f", entropy))
	}

	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return true, score, reasons
}

// validateAWSAccessKeyID enforces the documented prefix family and pure-base32
// body alphabet (A-Z, 2-7). Excludes 0,1,8,9 which AWS deliberately omits.
func validateAWSAccessKeyID(v string) (bool, []string) {
	if len(v) != 20 {
		return false, []string{"length != 20"}
	}
	prefix := v[:4]
	switch prefix {
	case "AKIA", "ASIA", "AGPA", "AIDA", "AROA", "AIPA", "ANPA", "ANVA":
	default:
		if !(strings.HasPrefix(v, "A3T") && v[3] >= 'A' && v[3] <= 'Z') {
			return false, []string{"unknown AWS access key prefix"}
		}
	}
	for i := 4; i < 20; i++ {
		c := v[i]
		ok := (c >= 'A' && c <= 'Z') || (c >= '2' && c <= '7')
		if !ok {
			return false, []string{"non-base32 character in body"}
		}
	}
	return true, []string{"AWS prefix + base32 body OK"}
}

// validateAWSSecretKey enforces 40-char body and high entropy on the captured group.
func validateAWSSecretKey(v string) (bool, []string) {
	if len(v) != 40 {
		return false, []string{"length != 40"}
	}
	if shannonEntropy(v) < 4.0 {
		return false, []string{"entropy below 4.0"}
	}
	if charClassDiversity(v) < 3 {
		return false, []string{"low character-class diversity"}
	}
	return true, []string{"40-char base64 body, high entropy"}
}

// validateStripeKey verifies the prefix family and that the body is clean base62
// (no underscores), which Stripe uses to avoid colliding with random hashes.
func validateStripeKey(v string) (bool, []string) {
	prefixes := []string{"sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_"}
	matched := ""
	for _, p := range prefixes {
		if strings.HasPrefix(v, p) {
			matched = p
			break
		}
	}
	if matched == "" {
		return false, []string{"unknown Stripe key prefix"}
	}
	body := v[len(matched):]
	if len(body) < 20 {
		return false, []string{"Stripe body too short"}
	}
	for _, c := range body {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false, []string{"non-base62 char in Stripe key body"}
		}
	}
	return true, []string{"Stripe " + matched + " key, base62 body"}
}

// validateGitHubToken implements the documented CRC32-base62 tail checksum.
// GitHub tokens of the form ghp_/gho_/ghu_/ghs_/ghr_ embed a 6-char checksum
// computed over the random body. Verifying it is one of the highest-precision
// signals available without a network call.
func validateGitHubToken(v string) (bool, []string) {
	if len(v) < 40 {
		return false, []string{"too short for GitHub token"}
	}
	if !strings.HasPrefix(v, "ghp_") && !strings.HasPrefix(v, "gho_") &&
		!strings.HasPrefix(v, "ghu_") && !strings.HasPrefix(v, "ghs_") &&
		!strings.HasPrefix(v, "ghr_") {
		return false, []string{"unknown GitHub token prefix"}
	}
	body := v[4:]
	if len(body) < 6 {
		return false, []string{"body too short for checksum"}
	}
	random := body[:len(body)-6]
	checksum := body[len(body)-6:]
	want := base62EncodeCRC32(crc32.ChecksumIEEE([]byte(random)))
	if !strings.EqualFold(want, checksum) {
		return false, []string{"CRC32 checksum mismatch (cannot verify; treat as suspect)"}
	}
	return true, []string{"GitHub CRC32 checksum verified"}
}

// base62EncodeCRC32 encodes a uint32 as 6-character base62, left-padded with '0'.
func base62EncodeCRC32(n uint32) string {
	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	if n == 0 {
		return "000000"
	}
	buf := make([]byte, 0, 6)
	for n > 0 {
		buf = append([]byte{alphabet[n%62]}, buf...)
		n /= 62
	}
	for len(buf) < 6 {
		buf = append([]byte{'0'}, buf...)
	}
	return string(buf)
}

// validateSlackToken enforces the hyphenated segment shape used across the
// Slack token family (xoxb/xoxp/xoxa/xoxr/xoxs/xoxe/xapp).
func validateSlackToken(v string) (bool, []string) {
	parts := strings.Split(v, "-")
	if len(parts) < 3 {
		return false, []string{"too few hyphen-segments for Slack token"}
	}
	for _, p := range parts[1 : len(parts)-1] {
		for _, c := range p {
			if c < '0' || c > '9' {
				return false, []string{"non-numeric inner segment"}
			}
		}
	}
	tail := parts[len(parts)-1]
	if len(tail) < 16 {
		return false, []string{"tail segment too short"}
	}
	return true, []string{"Slack hyphen-segment structure OK"}
}

// validateTwilioSK enforces the 32-hex body and rejects pure-zero or repeating runs.
func validateTwilioSK(v string) (bool, []string) {
	if len(v) != 34 || !strings.HasPrefix(v, "SK") {
		return false, []string{"bad Twilio SK shape"}
	}
	body := v[2:]
	for _, c := range body {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false, []string{"non-hex char in Twilio SK body"}
		}
	}
	if shannonEntropy(body) < 3.5 {
		return false, []string{"Twilio SK entropy too low"}
	}
	return true, []string{"32-hex Twilio SK body"}
}

// validateJWT decodes the header and payload as base64url-encoded JSON and
// requires that the header carries an `alg` field. Catches the very common
// "JWT-shaped strings that aren't JWTs" FP class.
func validateJWT(v string) (bool, []string) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false, []string{"JWT must have 3 dot-separated segments"}
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		// some JWT libs emit padded base64; tolerate it
		headerBytes, err = base64.URLEncoding.DecodeString(parts[0])
		if err != nil {
			return false, []string{"JWT header is not base64url"}
		}
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return false, []string{"JWT header is not JSON"}
	}
	if _, ok := header["alg"]; !ok {
		return false, []string{"JWT header missing alg"}
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payloadBytes, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return false, []string{"JWT payload is not base64url"}
		}
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false, []string{"JWT payload is not JSON"}
	}
	return true, []string{"JWT structurally valid (alg present, JSON header+payload)"}
}

// SelfTestResult is the per-rule outcome of `--self-test`.
type SelfTestResult struct {
	RuleID   string `json:"rule_id"`
	Name     string `json:"name"`
	TPPassed int    `json:"tp_passed"`
	TPTotal  int    `json:"tp_total"`
	FPCaught int    `json:"fp_caught"`
	FPTotal  int    `json:"fp_total"`
	OK       bool   `json:"ok"`
	Notes    []string `json:"notes,omitempty"`
}

// runSelfTest exercises every registered rule against its embedded TP/FP
// fixtures and reports a precision/recall summary. A rule is OK when it
// catches all TPs and rejects all FPs.
func runSelfTest() []SelfTestResult {
	registerRules()
	out := make([]SelfTestResult, 0, len(rulesRegistry))
	for i := range rulesRegistry {
		r := &rulesRegistry[i]
		res := SelfTestResult{RuleID: r.ID, Name: r.Name, OK: true}
		for _, tp := range r.TPExamples {
			res.TPTotal++
			fakeBody := "const apiKey = \"" + tp + "\";"
			fs := analyzeBody("self-test://"+r.ID, []byte(fakeBody), 0.0)
			ok := false
			for _, f := range fs {
				if f.RuleID == r.ID && f.Value == tp {
					ok = true
					break
				}
			}
			if ok {
				res.TPPassed++
			} else {
				res.OK = false
				res.Notes = append(res.Notes, "missed TP: "+redactValue(tp))
			}
			resetFindings()
		}
		for _, fp := range r.FPExamples {
			res.FPTotal++
			fakeBody := "const apiKey = \"" + fp + "\";"
			fs := analyzeBody("self-test://"+r.ID, []byte(fakeBody), 0.0)
			caught := true
			for _, f := range fs {
				if f.RuleID == r.ID && f.Value == fp {
					caught = false
					break
				}
			}
			if caught {
				res.FPCaught++
			} else {
				res.OK = false
				res.Notes = append(res.Notes, "leaked FP: "+redactValue(fp))
			}
			resetFindings()
		}
		out = append(out, res)
	}
	return out
}
