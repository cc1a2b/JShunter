package jshunter

// Regression test for the CSP keyword filter: standalone keywords ('self',
// 'none', 'strict-dynamic', 'report-sample') must be matched as exact tokens,
// never as prefixes, so real origins that merely begin with those letters are
// preserved. Identifiers are prefixed cr_.

import "testing"

func cr_contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func TestCSP_KeywordsMatchedExactlyNotAsPrefix(t *testing.T) {
	policy := "default-src 'self' 'none' 'strict-dynamic'; " +
		"script-src https://selfhosted.example.com https://noneofyour.example.net " +
		"https://strict-dynamic-cdn.example.org https://report-sample.example.io"

	got := ParseCSPOrigins(policy)

	// Hosts that merely start with a keyword must survive.
	for _, want := range []string{
		"https://selfhosted.example.com",
		"https://noneofyour.example.net",
		"https://strict-dynamic-cdn.example.org",
		"https://report-sample.example.io",
	} {
		if !cr_contains(got, want) {
			t.Errorf("ParseCSPOrigins dropped legitimate host %q (keyword prefix over-match); got %v", want, got)
		}
	}

	// The actual keywords must still be filtered out.
	for _, bad := range []string{"self", "none", "strict-dynamic", "report-sample"} {
		if cr_contains(got, bad) {
			t.Errorf("ParseCSPOrigins leaked CSP keyword %q as an origin", bad)
		}
	}
}
