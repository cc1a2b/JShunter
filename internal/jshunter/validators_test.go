package jshunter

// validators_test.go exercises every provider validator (the 7 original ones in
// detection.go and the 14 in validators_ext.go) plus the shared helpers. Each
// case asserts a genuine-format value passes and several near-misses fail at a
// real gate (wrong length/charset/prefix, low entropy, broken structure,
// placeholder). Every token-shaped literal is assembled from fragments joined
// with Go string concatenation so no contiguous secret appears in this source
// (the runtime value is identical). All non-Test identifiers are prefixed vt_.

import (
	"encoding/base64"
	"hash/crc32"
	"strings"
	"testing"
)

// vt_case is one validator input with the expected accept/reject decision.
type vt_case struct {
	name string
	in   string
	want bool
}

// vt_run drives a validator against a slice of cases.
func vt_run(t *testing.T, name string, fn func(string) (bool, []string), cases []vt_case) {
	t.Helper()
	for _, c := range cases {
		ok, reasons := fn(c.in)
		if ok != c.want {
			t.Errorf("%s(%q) = %v (reasons=%v), want %v", name, redactValue(c.in), ok, reasons, c.want)
		}
	}
}

// vt_githubToken builds a GitHub token whose 6-char CRC32-base62 checksum tail
// is genuinely valid for its random body, so validateGitHubToken accepts it.
func vt_githubToken(prefix, random string) string {
	sum := base62EncodeCRC32(crc32.ChecksumIEEE([]byte(random)))
	return prefix + random + sum
}

func TestValidator_AWSAccessKeyID(t *testing.T) {
	vt_run(t, "validateAWSAccessKeyID", validateAWSAccessKeyID, []vt_case{
		{"valid AKIA", "AKIA" + "2OGYBAH6STMMNXWG", true},
		{"valid ASIA", "ASIA" + "2OGYBAH6STMMNXWG", true},
		{"valid A3T family", "A3TX" + "OGYBAH6STMMNXWG2", true},
		{"unknown prefix", "ZZZZ" + "2OGYBAH6STMMNXWG", false},
		{"non-base32 body (0,1,8,9)", "AKIA" + "0189BAH6STMMNXWG", false},
		{"too short", "AKIA" + "2OGYBAH6", false},
		{"too long", "AKIA" + "2OGYBAH6STMMNXWG2222", false},
	})
}

func TestValidator_AWSSecretKey(t *testing.T) {
	vt_run(t, "validateAWSSecretKey", validateAWSSecretKey, []vt_case{
		{"valid high-entropy 40", "wJ4a" + "lrXUtnFE9Mz2K7bPx" + "Rf1CY3gH5tQ8uVwErTy", true},
		{"low entropy repeated", strings.Repeat("a", 40), false},
		{"wrong length 39", "wJalrXUtnFEMIK7MDENGbPxRfiCY3gH5tQ8uVwE", false},
		{"low diversity all lower", strings.Repeat("abcd", 10), false},
	})
}

func TestValidator_StripeKey(t *testing.T) {
	vt_run(t, "validateStripeKey", validateStripeKey, []vt_case{
		{"valid sk_live", "sk_" + "live_" + "51H8xExampLe00abcDEF00Demo", true},
		{"valid pk_test", "pk_" + "test_" + "TYooMQauvdEDq54NiTphI7jx", true},
		{"unknown prefix", "zz_" + "live_" + "51H8xExampLe00abcDEF00Demo", false},
		{"non-base62 body", "sk_" + "live_" + "51H8x_Examp+Le00abcDEF00Demo", false},
		{"body too short", "sk_" + "live_" + "short", false},
	})
}

func TestValidator_GitHubToken(t *testing.T) {
	valid := vt_githubToken("ghp_", "0123456789abcdefghijklmnopqrstuvwxyz")
	// Same body, deliberately corrupted checksum tail.
	bad := valid[:len(valid)-6] + "000000"
	vt_run(t, "validateGitHubToken", validateGitHubToken, []vt_case{
		{"valid checksum", valid, true},
		{"bad checksum", bad, false},
		{"unknown prefix", "ghz_" + strings.Repeat("a", 36), false},
		{"too short", "ghp_" + "abcdef", false},
	})
}

func TestValidator_SlackToken(t *testing.T) {
	vt_run(t, "validateSlackToken", validateSlackToken, []vt_case{
		{"valid xoxb", "xoxb" + "-123456789-987654321-" + "aBcDeFgHiJkLmNoPqRsT", true},
		{"non-numeric inner", "xoxb" + "-12x456789-987654321-" + "aBcDeFgHiJkLmNoPqRsT", false},
		{"tail too short", "xoxb" + "-123456789-987654321-" + "aBcDeF", false},
		{"too few segments", "xoxb" + "-onlyone", false},
	})
}

func TestValidator_TwilioSK(t *testing.T) {
	vt_run(t, "validateTwilioSK", validateTwilioSK, []vt_case{
		{"valid SK 32-hex", "SK" + "0a1b2c3d4e5f60718293a4b5c6d7e8f9", true},
		{"non-hex body", "SK" + "zzzz2c3d4e5f60718293a4b5c6d7e8f9", false},
		{"wrong prefix", "AC" + "0a1b2c3d4e5f60718293a4b5c6d7e8f9", false},
		{"low entropy", "SK" + strings.Repeat("a", 32), false},
	})
}

func TestValidator_JWT(t *testing.T) {
	enc := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	validJWT := enc(`{"alg":"HS256","typ":"JWT"}`) + "." + enc(`{"sub":"1234","name":"x"}`) + "." + "sigblob123"
	noAlg := enc(`{"typ":"JWT"}`) + "." + enc(`{"sub":"1"}`) + "." + "sig"
	badPayload := enc(`{"alg":"HS256"}`) + "." + "@@@notbase64@@@" + "." + "sig"
	vt_run(t, "validateJWT", validateJWT, []vt_case{
		{"valid JWT", validJWT, true},
		{"missing alg", noAlg, false},
		{"payload not base64", badPayload, false},
		{"not three segments", enc(`{"alg":"HS256"}`) + "." + enc(`{"sub":"1"}`), false},
	})
}

func TestValidator_AzureStorageKey(t *testing.T) {
	raw := make([]byte, 64)
	for i := range raw {
		raw[i] = byte((i*7 + 11) % 251)
	}
	body := base64.StdEncoding.EncodeToString(raw) // 88 chars, ends ==
	valid := "AccountKey=" + body
	vt_run(t, "validateAzureStorageKey", validateAzureStorageKey, []vt_case{
		{"valid 64-byte key", valid, true},
		{"missing prefix", body, false},
		{"body not 88", "AccountKey=" + body[:80], false},
		{"decodes to wrong length", "AccountKey=" + base64.StdEncoding.EncodeToString(make([]byte, 48)) + strings.Repeat("A", 24), false},
	})
}

func TestValidator_AzureADClientSecret(t *testing.T) {
	vt_run(t, "validateAzureADClientSecret", validateAzureADClientSecret, []vt_case{
		{"valid Q~ shape", "6vF8" + "Q~ASAez41kgnO1GMN9e6Lao0KDJmO1xcYV2W", true},
		{"no Q~ marker", "6vF8" + "XXASAez41kgnO1GMN9e6Lao0KDJmO1xcYV2W", false},
		{"digit not before Q~", "6vFa" + "Q~ASAez41kgnO1GMN9e6Lao0KDJmO1xcYV2W", false},
		{"too short", "6vF8" + "Q~ASA", false},
	})
}

func TestValidator_TerraformToken(t *testing.T) {
	tail := "nGyKuoQZzirDplk9yVXw_YoCONm5k45UJFHiyq-IjVkwSmZENoCxvz1hq54kw1eN"
	vt_run(t, "validateTerraformToken", validateTerraformToken, []vt_case{
		{"valid", "n8U9O6iS8LrwRZ" + ".atlasv1." + tail, true},
		{"wrong infix", "n8U9O6iS8LrwRZ" + ".atlasv2." + tail, false},
		{"first segment not 14", "short" + ".atlasv1." + tail, false},
		{"tail too short", "n8U9O6iS8LrwRZ" + ".atlasv1." + "tooShort", false},
	})
}

func TestValidator_MixedClassToken(t *testing.T) {
	vt_run(t, "validateMixedClassToken", validateMixedClassToken, []vt_case{
		{"diverse high entropy", "i3E5" + "oiiyHMRUEE7YvcwpQ9zK", true},
		{"kebab low diversity", "primary" + "-button-large-modifier", false},
		{"all lowercase", strings.Repeat("abcdef", 4), false},
	})
}

func TestValidator_StripeWebhookSecret(t *testing.T) {
	vt_run(t, "validateStripeWebhookSecret", validateStripeWebhookSecret, []vt_case{
		{"valid whsec_", "whsec_" + "4Qk9RmZ2pXvL7wYnBt6sHd3JgFa8eCu5Tb1oPq", true},
		{"missing prefix", "4Qk9RmZ2pXvL7wYnBt6sHd3JgFa8eCu5Tb1oPq", false},
		{"body too short", "whsec_" + "shortbody", false},
		{"low entropy", "whsec_" + strings.Repeat("a", 40), false},
	})
}

func TestValidator_SquareToken(t *testing.T) {
	vt_run(t, "validateSquareToken", validateSquareToken, []vt_case{
		{"valid access token", "sq0atp-" + "7Kd9Rm2QpXvL4wZnYt6BsA", true},
		{"valid oauth secret", "sq0csp-" + "9Xk2Rm7QpVL4wZnYt6BsAdF3gHj5sCe0uTb1oPqNrMz", true},
		{"wrong body length", "sq0atp-" + "7Kd9Rm2Qp", false},
		{"unknown prefix", "sq0zzz-" + "7Kd9Rm2QpXvL4wZnYt6BsA", false},
		{"low entropy", "sq0atp-" + strings.Repeat("a", 22), false},
	})
}

func TestValidator_BraintreeAccessToken(t *testing.T) {
	vt_run(t, "validateBraintreeAccessToken", validateBraintreeAccessToken, []vt_case{
		{"valid production", "access_token" + "$production$" + "s8f3k2j9d0alq7wp" + "$" + "3f8a9c2e1b7d4a6f5e0c9b8a7d6e5f4c", true},
		{"invalid env", "access_token" + "$development$" + "s8f3k2j9d0alq7wp" + "$" + "3f8a9c2e1b7d4a6f5e0c9b8a7d6e5f4c", false},
		{"merchant not 16", "access_token" + "$production$" + "short" + "$" + "3f8a9c2e1b7d4a6f5e0c9b8a7d6e5f4c", false},
		{"token not 32 hex", "access_token" + "$production$" + "s8f3k2j9d0alq7wp" + "$" + "nothex", false},
	})
}

func TestValidator_PlaidToken(t *testing.T) {
	vt_run(t, "validatePlaidToken", validatePlaidToken, []vt_case{
		{"valid non-zero uuid", "access-production-" + "3a7f2b1c-9d4e-4c8a-b6f5-1e2d3c4b5a69", true},
		{"all-zero uuid placeholder", "access-sandbox-" + "00000000-0000-0000-0000-000000000000", false},
	})
}

func TestValidator_TelegramBotToken(t *testing.T) {
	vt_run(t, "validateTelegramBotToken", validateTelegramBotToken, []vt_case{
		{"valid", "817293043" + ":" + "AA" + "F8kQ2vN7pR3wZ1xY6bH0mJ4cL9dT5sG2e", true},
		{"secret not AA", "817293043" + ":" + "BB" + "F8kQ2vN7pR3wZ1xY6bH0mJ4cL9dT5sG2e", false},
		{"id not digits", "81x293043" + ":" + "AA" + "F8kQ2vN7pR3wZ1xY6bH0mJ4cL9dT5sG2e", false},
		{"low entropy secret", "817293043" + ":" + "AA" + strings.Repeat("A", 33), false},
		{"no colon", "817293043" + "AA" + "F8kQ2vN7pR3wZ1xY6bH0mJ4cL9dT5sG2e", false},
	})
}

func TestValidator_IntercomToken(t *testing.T) {
	good := base64.StdEncoding.EncodeToString([]byte("tok:" + "0abc12de3f:9f8e7d6c5b4a"))
	bad := base64.StdEncoding.EncodeToString([]byte("notok:" + "0abc12de3f"))
	vt_run(t, "validateIntercomToken", validateIntercomToken, []vt_case{
		{"decodes to tok:", good, true},
		{"decodes to non-tok", bad, false},
		{"not base64", "@@@not base64@@@", false},
	})
}

func TestValidator_SentryOrgToken(t *testing.T) {
	payload := base64.StdEncoding.EncodeToString([]byte(`{"iat":1,"url":"https://sentry.io","org":"acme"}`))
	noURL := base64.StdEncoding.EncodeToString([]byte(`{"iat":1,"org":"acme"}`))
	vt_run(t, "validateSentryOrgToken", validateSentryOrgToken, []vt_case{
		{"valid with url claim", "sntrys_" + payload + "_" + "secretpart", true},
		{"payload missing url", "sntrys_" + noURL + "_" + "secretpart", false},
		{"missing prefix", payload + "_" + "secretpart", false},
		{"no separator", "sntrys_" + payload, false},
	})
}

func TestValidator_AirtablePAT(t *testing.T) {
	hex64 := "212d1066396ea0ad7196551fe0fb882415a26e814db1d941ebc26b8664fcd857"
	vt_run(t, "validateAirtablePAT", validateAirtablePAT, []vt_case{
		{"valid", "pat" + "y2Urs66mdmQzMj" + "." + hex64, true},
		{"left not pat+14", "pat" + "short" + "." + hex64, false},
		{"right not 64 hex", "pat" + "y2Urs66mdmQzMj" + "." + "deadbeef", false},
		{"no dot", "pat" + "y2Urs66mdmQzMj" + hex64, false},
	})
}

func TestValidator_PostmanKey(t *testing.T) {
	vt_run(t, "validatePostmanKey", validatePostmanKey, []vt_case{
		{"valid", "PMAK-" + "565771eec9a0db3520965632" + "-" + "5c71d7daef62224b8c00713c8940d9fb1a", true},
		{"first seg not 24 hex", "PMAK-" + "deadbeef" + "-" + "5c71d7daef62224b8c00713c8940d9fb1a", false},
		{"second seg not 34 hex", "PMAK-" + "565771eec9a0db3520965632" + "-" + "short", false},
		{"missing prefix", "565771eec9a0db3520965632" + "-" + "5c71d7daef62224b8c00713c8940d9fb1a", false},
	})
}

func TestValidator_DBConnURIPassword(t *testing.T) {
	vt_run(t, "validateDBConnURIPassword", validateDBConnURIPassword, []vt_case{
		{"real password", "Xy7Qw" + "2Zp9Kd", true},
		{"real mixed w/ symbol", "Str0ng" + "-P@ssw0rd", true},
		{"empty", "", false},
		{"template ${}", "${DB_PASSWORD}", false},
		{"template {{}}", "{{POSTGRES_PWD}}", false},
		{"percent-wrapped", "%MYSQL_PWD%", false},
		{"leading dollar", "$SECRET", false},
		{"all same char", "******", false},
		{"all digits", "12345678", false},
		{"too short", "aB1", false},
		{"default cred password", "password", false},
		{"default cred changeme", "changeme", false},
		{"contains placeholder fragment", "myYOUR_PASSWORDx", false},
		{"low diversity", "abcdefgh", false},
	})
}

func TestValidator_Helpers(t *testing.T) {
	if !allSameChar("aaaa") || allSameChar("aaab") || !allSameChar("") {
		t.Errorf("allSameChar wrong")
	}
	if !allDigits("12345") || allDigits("12a45") || allDigits("") {
		t.Errorf("allDigits wrong")
	}
	if !isHexLower("0a1b2c") || isHexLower("0A1B") || isHexLower("xyz") || isHexLower("") {
		t.Errorf("isHexLower wrong")
	}
	if !isBase62("aZ09") || isBase62("aZ0_9") || isBase62("a-b") || isBase62("") {
		t.Errorf("isBase62 wrong")
	}
}
