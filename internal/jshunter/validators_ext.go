package jshunter

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// This file holds the provider validators for the extended rule set added in
// rules_ext.go. Each returns (ok, reasons). A false result drops the finding in
// scoreFinding; a true result adds the +0.10 validator boost. All validators are
// pure/offline and stdlib-only.

// allSameChar reports whether s is a run of a single repeated byte ("******", "aaaa").
func allSameChar(s string) bool {
	if len(s) == 0 {
		return true
	}
	for i := 1; i < len(s); i++ {
		if s[i] != s[0] {
			return false
		}
	}
	return true
}

// allDigits reports whether s is non-empty and every byte is an ASCII digit.
func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHexLower(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return len(s) > 0
}

func isBase62(s string) bool {
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return len(s) > 0
}

// validateAzureStorageKey confirms the trailing 88-char base64 body of an
// `AccountKey=...` match decodes to exactly 64 bytes (a 512-bit storage key).
func validateAzureStorageKey(v string) (bool, []string) {
	const prefix = "AccountKey="
	if !strings.HasPrefix(v, prefix) {
		return false, []string{"missing AccountKey= prefix"}
	}
	body := v[len(prefix):]
	if len(body) != 88 {
		return false, []string{"body not 88 base64 chars"}
	}
	dec, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return false, []string{"body is not valid base64"}
	}
	if len(dec) != 64 {
		return false, []string{"decoded key is not 64 bytes"}
	}
	return true, []string{"Azure storage key decodes to 64 bytes"}
}

// validateAzureADClientSecret confirms the documented "<3><digit>Q~<tail>" shape
// and a minimum entropy on the captured secret.
func validateAzureADClientSecret(v string) (bool, []string) {
	if len(v) < 37 || len(v) > 40 {
		return false, []string{"length outside 37-40"}
	}
	idx := strings.Index(v, "Q~")
	if idx < 4 {
		return false, []string{"missing Q~ marker at offset >= 4"}
	}
	prev := v[idx-1]
	if prev < '0' || prev > '9' {
		return false, []string{"byte before Q~ is not a digit"}
	}
	if shannonEntropy(v) < 3.0 {
		return false, []string{"entropy below 3.0"}
	}
	return true, []string{"Azure AD client secret shape + entropy OK"}
}

// validateTerraformToken confirms the "<14 alnum>.atlasv1.<60-70 base64url>" shape.
func validateTerraformToken(v string) (bool, []string) {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return false, []string{"not 3 dot-separated parts"}
	}
	if len(parts[0]) != 14 || !isBase62(parts[0]) {
		return false, []string{"first segment is not 14 alnum"}
	}
	if parts[1] != "atlasv1" {
		return false, []string{"infix is not atlasv1"}
	}
	if len(parts[2]) < 60 || len(parts[2]) > 70 {
		return false, []string{"tail length outside 60-70"}
	}
	return true, []string{"Terraform Cloud token structure OK"}
}

// validateMixedClassToken rejects low-diversity / kebab-case identifiers that share
// a provider prefix. Shared by the GitLab prefix rules and Docker Hub.
func validateMixedClassToken(v string) (bool, []string) {
	if charClassDiversity(v) < 3 {
		return false, []string{"fewer than 3 character classes (looks like an identifier)"}
	}
	if shannonEntropy(v) < 3.5 {
		return false, []string{"entropy below 3.5"}
	}
	return true, []string{"mixed character classes + high entropy"}
}

// validateStripeWebhookSecret validates the whsec_ signing secret body.
func validateStripeWebhookSecret(v string) (bool, []string) {
	const prefix = "whsec_"
	if !strings.HasPrefix(v, prefix) {
		return false, []string{"missing whsec_ prefix"}
	}
	body := v[len(prefix):]
	if len(body) < 32 || len(body) > 64 {
		return false, []string{"body length outside 32-64"}
	}
	if !isBase62(body) {
		return false, []string{"non-base62 char in body"}
	}
	if shannonEntropy(body) < 4.0 {
		return false, []string{"entropy below 4.0"}
	}
	return true, []string{"Stripe webhook secret base62 body, high entropy"}
}

// validateSquareToken validates the sq0atp-/sq0csp-/sq0idp- token families.
func validateSquareToken(v string) (bool, []string) {
	var wantBody int
	switch {
	case strings.HasPrefix(v, "sq0atp-"), strings.HasPrefix(v, "sq0idp-"):
		wantBody = 22
	case strings.HasPrefix(v, "sq0csp-"):
		wantBody = 43
	default:
		return false, []string{"unknown Square token prefix"}
	}
	body := v[7:]
	if len(body) != wantBody {
		return false, []string{"unexpected Square body length"}
	}
	for _, c := range body {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false, []string{"invalid char in Square body"}
		}
	}
	if shannonEntropy(body) < 3.3 {
		return false, []string{"Square token entropy too low"}
	}
	return true, []string{"Square token prefix + body OK"}
}

// validateBraintreeAccessToken validates access_token$ENV$MERCHANT$TOKEN.
func validateBraintreeAccessToken(v string) (bool, []string) {
	parts := strings.Split(v, "$")
	if len(parts) != 4 {
		return false, []string{"not 4 $-separated parts"}
	}
	if parts[0] != "access_token" {
		return false, []string{"first segment is not access_token"}
	}
	if parts[1] != "production" && parts[1] != "sandbox" {
		return false, []string{"environment is not production/sandbox"}
	}
	if len(parts[2]) != 16 {
		return false, []string{"merchant id is not 16 chars"}
	}
	for _, c := range parts[2] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')) {
			return false, []string{"merchant id not base36"}
		}
	}
	if len(parts[3]) != 32 || !isHexLower(parts[3]) {
		return false, []string{"token segment is not 32 hex"}
	}
	if allSameChar(parts[3]) {
		return false, []string{"token segment is a repeated char"}
	}
	return true, []string{"Braintree access token structure OK"}
}

// validatePlaidToken rejects an all-zero UUID in access-<env>-<uuid>. The
// access-<env>- prefix and 8-4-4-4-12 hex shape are already enforced by the
// pattern, so the validator only has to reject the degenerate zero placeholder.
func validatePlaidToken(v string) (bool, []string) {
	compact := strings.ReplaceAll(v, "-", "")
	if strings.HasSuffix(compact, "00000000000000000000000000000000") {
		return false, []string{"all-zero UUID placeholder"}
	}
	return true, []string{"Plaid token structure OK"}
}

// validateTelegramBotToken validates <botid>:AA<35 base64url>.
func validateTelegramBotToken(v string) (bool, []string) {
	parts := strings.Split(v, ":")
	if len(parts) != 2 {
		return false, []string{"not a <id>:<secret> pair"}
	}
	if !allDigits(parts[0]) || len(parts[0]) < 8 || len(parts[0]) > 10 {
		return false, []string{"bot id is not 8-10 digits"}
	}
	sec := parts[1]
	if len(sec) != 35 || !strings.HasPrefix(sec, "AA") {
		return false, []string{"secret is not AA + 33 chars"}
	}
	for _, c := range sec {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false, []string{"non-base64url char in secret"}
		}
	}
	if shannonEntropy(sec) < 3.5 {
		return false, []string{"secret entropy too low"}
	}
	return true, []string{"Telegram bot token structure OK"}
}

// validateIntercomToken confirms the base64 decodes to a 'tok:'-prefixed blob.
func validateIntercomToken(v string) (bool, []string) {
	dec, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(v)
		if err != nil {
			return false, []string{"not valid base64"}
		}
	}
	if !strings.HasPrefix(string(dec), "tok:") {
		return false, []string{"decoded value is not tok:-prefixed"}
	}
	return true, []string{"Intercom token decodes to tok: payload"}
}

// validateSentryOrgToken decodes the sntrys_ payload and requires a JSON 'url' claim.
func validateSentryOrgToken(v string) (bool, []string) {
	const prefix = "sntrys_"
	if !strings.HasPrefix(v, prefix) {
		return false, []string{"missing sntrys_ prefix"}
	}
	rest := v[len(prefix):]
	last := strings.LastIndex(rest, "_")
	if last <= 0 {
		return false, []string{"missing payload/secret separator"}
	}
	payload := rest[:last]
	dec, err := base64.StdEncoding.DecodeString(payload)
	if err != nil {
		dec, err = base64.RawStdEncoding.DecodeString(payload)
		if err != nil {
			return false, []string{"payload is not base64"}
		}
	}
	var m map[string]any
	if err := json.Unmarshal(dec, &m); err != nil {
		return false, []string{"payload is not JSON"}
	}
	if _, ok := m["url"]; !ok {
		return false, []string{"payload missing url claim"}
	}
	return true, []string{"Sentry org token payload carries url claim"}
}

// validateAirtablePAT validates pat<14 alnum>.<64 hex>.
func validateAirtablePAT(v string) (bool, []string) {
	parts := strings.Split(v, ".")
	if len(parts) != 2 {
		return false, []string{"not 2 dot-separated parts"}
	}
	if len(parts[0]) != 17 || !strings.HasPrefix(parts[0], "pat") || !isBase62(parts[0][3:]) {
		return false, []string{"left segment is not pat+14 alnum"}
	}
	if len(parts[1]) != 64 || !isHexLower(parts[1]) {
		return false, []string{"right segment is not 64 hex"}
	}
	if shannonEntropy(parts[1]) < 2.5 {
		return false, []string{"secret entropy too low"}
	}
	return true, []string{"Airtable PAT structure OK"}
}

// validatePostmanKey validates PMAK-<24 hex>-<34 hex>.
func validatePostmanKey(v string) (bool, []string) {
	const prefix = "PMAK-"
	if !strings.HasPrefix(v, prefix) {
		return false, []string{"missing PMAK- prefix"}
	}
	segs := strings.Split(v[len(prefix):], "-")
	if len(segs) != 2 {
		return false, []string{"not 2 hyphen-separated segments"}
	}
	if len(segs[0]) != 24 || !isHexLower(segs[0]) {
		return false, []string{"first segment is not 24 hex"}
	}
	if len(segs[1]) != 34 || !isHexLower(segs[1]) {
		return false, []string{"second segment is not 34 hex"}
	}
	if shannonEntropy(segs[0]) < 2.5 || shannonEntropy(segs[1]) < 2.5 {
		return false, []string{"segment entropy too low"}
	}
	return true, []string{"Postman API key structure OK"}
}

// dbURIPlaceholderExact is the default-credential / placeholder set the DB
// connection-URI validator rejects outright (case-insensitive exact match).
var dbURIPlaceholderExact = map[string]struct{}{
	"password": {}, "passwd": {}, "pwd": {}, "pass": {}, "pass123": {},
	"changeme": {}, "change_me": {}, "change-me": {}, "changethis": {},
	"secret": {}, "secrets": {}, "supersecret": {}, "topsecret": {},
	"admin": {}, "administrator": {}, "root": {}, "toor": {}, "sa": {}, "guest": {},
	"user": {}, "username": {}, "default": {}, "example": {},
	"test": {}, "testing": {}, "testpass": {}, "test123": {}, "demo": {},
	"postgres": {}, "postgresql": {}, "mysql": {}, "mariadb": {}, "mongo": {},
	"mongodb": {}, "redis": {}, "rabbitmq": {}, "amqp": {},
	"letmein": {}, "qwerty": {}, "welcome": {}, "hunter2": {}, "abc123": {},
	"redacted": {}, "none": {}, "null": {}, "nil": {}, "todo": {}, "fixme": {},
	"yourpassword": {}, "your_password": {}, "your-password": {}, "mypassword": {},
	"dbpassword": {}, "db_password": {},
}

// dbURIPlaceholderSubstr flags interpolation / placeholder passwords by substring.
var dbURIPlaceholderSubstr = []string{
	"password", "passwd", "secret", "changeme", "change_me", "change-me",
	"placeholder", "example", "redacted", "your_password", "yourpassword",
	"your-password", "dummy", "sample", "replaceme", "replace_me", "xxxx",
	"notset", "not_set", "enter_your", "insert_", "put_your",
}

// validateDBConnURIPassword rejects placeholder/templated/default credentials
// captured from a database connection URI. v is the captured password (group 1).
func validateDBConnURIPassword(v string) (bool, []string) {
	if v == "" {
		return false, []string{"empty password"}
	}
	if strings.Contains(v, "${") || strings.Contains(v, "{{") || strings.Contains(v, "}}") ||
		strings.ContainsAny(v, "<>") || strings.HasPrefix(v, "$") ||
		(strings.HasPrefix(v, "%") && strings.HasSuffix(v, "%")) {
		return false, []string{"password is a template/interpolation placeholder"}
	}
	if allSameChar(v) {
		return false, []string{"password is a repeated character"}
	}
	if allDigits(v) {
		return false, []string{"password is all digits (port/PIN-like)"}
	}
	if len(v) < 6 {
		return false, []string{"password shorter than 6 chars"}
	}
	low := strings.ToLower(v)
	if _, ok := dbURIPlaceholderExact[low]; ok {
		return false, []string{"password is a known default/placeholder"}
	}
	for _, sub := range dbURIPlaceholderSubstr {
		if strings.Contains(low, sub) {
			return false, []string{"password contains placeholder fragment '" + sub + "'"}
		}
	}
	if shannonEntropy(v) < 2.5 {
		return false, []string{"password entropy too low"}
	}
	if charClassDiversity(v) < 2 {
		return false, []string{"password lacks character-class diversity"}
	}
	return true, []string{"database URI password looks real"}
}
