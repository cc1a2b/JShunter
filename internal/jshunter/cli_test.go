package jshunter

// cli_test.go exercises the CLI-facing pure/isolable helpers:
//
//   - globMatch          (ignore.go)      — filepath.Match wrapper with a `*` fast-path
//   - applyRuleSelection (rules_cli.go)   — --only-rules / --disable-rule glob filtering
//   - LoadIgnoreFile / ShouldIgnore (ignore.go) — .jshunterignore suppression list
//
// applyRuleSelection MUTATES the package-global rulesRegistry/rulesIndex. Every
// subtest that calls it first invokes ct_snapshotRules(t), which captures the
// current registry/index and registers a t.Cleanup that restores them verbatim
// when the subtest ends. Because applyRuleSelection reassigns those globals to
// freshly allocated containers (it never mutates the original backing array or
// map in place), saving the slice header and map reference and reinstating them
// is a complete rollback — the full package test run stays green regardless of
// subtest order. These tests never call t.Parallel(): they share global state
// on purpose and must run sequentially.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ct_snapshotRules guarantees a fully populated registry and rolls back any
// mutation performed by the calling (sub)test.
func ct_snapshotRules(t *testing.T) {
	t.Helper()
	registerRules() // idempotent via sync.Once; ensures a complete baseline
	savedRegistry := rulesRegistry
	savedIndex := rulesIndex
	t.Cleanup(func() {
		rulesRegistry = savedRegistry
		rulesIndex = savedIndex
	})
}

// ct_currentRuleIDs returns the IDs currently present in rulesRegistry, in order.
func ct_currentRuleIDs() []string {
	ids := make([]string, len(rulesRegistry))
	for i := range rulesRegistry {
		ids[i] = rulesRegistry[i].ID
	}
	return ids
}

// ct_countRuleIDsMatching counts registry IDs matching pattern per globMatch.
func ct_countRuleIDsMatching(pattern string) int {
	n := 0
	for i := range rulesRegistry {
		if globMatch(pattern, rulesRegistry[i].ID) {
			n++
		}
	}
	return n
}

// ct_assertIndexConsistent verifies rulesIndex mirrors rulesRegistry exactly:
// identical cardinality and every ID mapped to its own registry element pointer.
func ct_assertIndexConsistent(t *testing.T) {
	t.Helper()
	if len(rulesIndex) != len(rulesRegistry) {
		t.Fatalf("rulesIndex len %d != rulesRegistry len %d", len(rulesIndex), len(rulesRegistry))
	}
	for i := range rulesRegistry {
		id := rulesRegistry[i].ID
		p, ok := rulesIndex[id]
		if !ok {
			t.Fatalf("rulesIndex missing id %q present in registry", id)
		}
		if p != &rulesRegistry[i] {
			t.Fatalf("rulesIndex[%q] does not point at its registry element", id)
		}
	}
}

func TestCLI_GlobMatch(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		input   string
		want    bool
	}{
		{"exact match", "aws.access_key_id", "aws.access_key_id", true},
		{"exact mismatch", "aws.access_key_id", "aws.secret_access_key", false},
		{"exact rejects prefix-only input", "aws.access_key_id", "aws", false},
		{"family star matches member", "aws.*", "aws.access_key_id", true},
		{"family star matches sibling", "aws.*", "aws.secret_access_key", true},
		{"family star rejects other provider", "aws.*", "stripe.secret_key", false},
		{"suffix star matches api_key", "*.api_key", "google.api_key", true},
		{"suffix star matches another api_key", "*.api_key", "anthropic.api_key", true},
		{"suffix star rejects non-api_key id", "*.api_key", "stripe.secret_key", false},
		{"suffix star rejects secret_access_key", "*.api_key", "aws.secret_access_key", false},
		{"double star matches token suffix", "*token*", "slack.user_or_bot_token", true},
		{"double star matches token id", "*token*", "vault.token", true},
		{"double star rejects tokenless id", "*token*", "aws.access_key_id", false},
		{"universal star matches arbitrary", "*", "literally.anything-123", true},
		{"universal star matches empty string", "*", "", true},
		{"empty pattern matches empty string", "", "", true},
		{"empty pattern rejects non-empty string", "", "anything", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := globMatch(tc.pattern, tc.input); got != tc.want {
				t.Fatalf("globMatch(%q, %q) = %v, want %v", tc.pattern, tc.input, got, tc.want)
			}
		})
	}
}

func TestCLI_ApplyRuleSelection(t *testing.T) {
	t.Run("only keeps just the selected family", func(t *testing.T) {
		ct_snapshotRules(t)
		wantAWS := ct_countRuleIDsMatching("aws.*")
		if wantAWS == 0 {
			t.Fatal("precondition failed: expected at least one aws.* rule in the registry")
		}

		n := applyRuleSelection("aws.*", "")
		if n != wantAWS {
			t.Fatalf("applyRuleSelection(only=aws.*) kept %d, want %d", n, wantAWS)
		}
		if n != len(rulesRegistry) {
			t.Fatalf("returned count %d != len(rulesRegistry) %d", n, len(rulesRegistry))
		}
		for _, id := range ct_currentRuleIDs() {
			if !strings.HasPrefix(id, "aws.") {
				t.Fatalf("rule %q survived only=aws.* but is not in the aws family", id)
			}
		}
		if _, ok := rulesIndex["aws.access_key_id"]; !ok {
			t.Fatal("aws.access_key_id should have been retained")
		}
		if _, ok := rulesIndex["stripe.secret_key"]; ok {
			t.Fatal("stripe.secret_key should have been filtered out by only=aws.*")
		}
		ct_assertIndexConsistent(t)
	})

	t.Run("disable drops every matching rule", func(t *testing.T) {
		ct_snapshotRules(t)
		baseline := len(rulesRegistry)
		drop := ct_countRuleIDsMatching("*.api_key")
		if drop == 0 {
			t.Fatal("precondition failed: expected at least one *.api_key rule in the registry")
		}

		n := applyRuleSelection("", "*.api_key")
		if n != baseline-drop {
			t.Fatalf("applyRuleSelection(disable=*.api_key) kept %d, want %d", n, baseline-drop)
		}
		for _, id := range ct_currentRuleIDs() {
			if globMatch("*.api_key", id) {
				t.Fatalf("rule %q matches the disabled glob *.api_key yet survived", id)
			}
		}
		if _, ok := rulesIndex["google.api_key"]; ok {
			t.Fatal("google.api_key should have been disabled")
		}
		if _, ok := rulesIndex["aws.access_key_id"]; !ok {
			t.Fatal("aws.access_key_id must be unaffected by disable=*.api_key")
		}
		ct_assertIndexConsistent(t)
	})

	t.Run("only and disable compose (disable applied after only)", func(t *testing.T) {
		ct_snapshotRules(t)
		awsCount := ct_countRuleIDsMatching("aws.*")
		if awsCount < 2 {
			t.Fatalf("precondition failed: expected >=2 aws.* rules, got %d", awsCount)
		}

		n := applyRuleSelection("aws.*", "aws.secret_access_key")
		if n != awsCount-1 {
			t.Fatalf("only=aws.* + disable=aws.secret_access_key kept %d, want %d", n, awsCount-1)
		}
		if _, ok := rulesIndex["aws.access_key_id"]; !ok {
			t.Fatal("aws.access_key_id should survive the combined selection")
		}
		if _, ok := rulesIndex["aws.secret_access_key"]; ok {
			t.Fatal("aws.secret_access_key must be dropped even though only=aws.* selected it")
		}
		for _, id := range ct_currentRuleIDs() {
			if !strings.HasPrefix(id, "aws.") {
				t.Fatalf("non-aws rule %q survived only=aws.*", id)
			}
			if id == "aws.secret_access_key" {
				t.Fatalf("disabled rule %q is still present", id)
			}
		}
		ct_assertIndexConsistent(t)
	})

	t.Run("empty only and empty disable is a no-op", func(t *testing.T) {
		ct_snapshotRules(t)
		before := ct_currentRuleIDs()

		n := applyRuleSelection("", "")
		if n != len(before) {
			t.Fatalf("no-op selection returned %d, want %d", n, len(before))
		}
		after := ct_currentRuleIDs()
		if len(after) != len(before) {
			t.Fatalf("registry length changed on no-op: before %d, after %d", len(before), len(after))
		}
		for i := range before {
			if before[i] != after[i] {
				t.Fatalf("registry content changed at index %d on no-op: %q -> %q", i, before[i], after[i])
			}
		}
		ct_assertIndexConsistent(t)
	})
}

func TestCLI_IgnoreList(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".jshunterignore")
	content := strings.Join([]string{
		"# suppression fixture",
		"",
		"   # indented comment is still a comment",
		"hash:deadbeefcafe1234",
		"rule:aws.*",
		"source:*.min.js",
		"rule_value:stripe.secret_key:sk_live_*",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write ignore fixture: %v", err)
	}

	il, err := LoadIgnoreFile(path)
	if err != nil {
		t.Fatalf("LoadIgnoreFile(%q): %v", path, err)
	}
	if il == nil {
		t.Fatal("LoadIgnoreFile returned a nil list for a valid file")
	}
	if len(il.Entries) != 4 {
		t.Fatalf("parsed %d entries, want 4 (comments/blank lines skipped): %+v", len(il.Entries), il.Entries)
	}

	cases := []struct {
		name    string
		finding Finding
		want    bool
	}{
		{
			name:    "hash exact match suppresses",
			finding: Finding{ValueHash: "deadbeefcafe1234", RuleID: "irrelevant", Source: "app.js"},
			want:    true,
		},
		{
			name:    "unrelated finding is not suppressed",
			finding: Finding{ValueHash: "0011223344556677", RuleID: "github.pat_classic", Source: "main.js", Value: "ghp_placeholder"},
			want:    false,
		},
		{
			name:    "rule glob suppresses whole family",
			finding: Finding{RuleID: "aws.access_key_id"},
			want:    true,
		},
		{
			name:    "rule glob leaves other providers alone",
			finding: Finding{RuleID: "stripe.publishable_key", Source: "bundle.js"},
			want:    false,
		},
		{
			name:    "source glob matches a *.min.js segment",
			finding: Finding{Source: "vendor.min.js"},
			want:    true,
		},
		{
			name:    "source glob rejects a plain .js segment",
			finding: Finding{Source: "vendor.js"},
			want:    false,
		},
		{
			name:    "rule_value suppresses when rule and value both match",
			finding: Finding{RuleID: "stripe.secret_key", Value: "sk_live_51HABCdefGHIjklMNOpqr"},
			want:    true,
		},
		{
			name:    "rule_value keeps finding when value glob fails",
			finding: Finding{RuleID: "stripe.secret_key", Value: "sk_test_51HABCdefGHIjklMNOpqr"},
			want:    false,
		},
		{
			name:    "rule_value keeps finding when rule differs",
			finding: Finding{RuleID: "square.access_token", Value: "sk_live_51HABCdefGHIjklMNOpqr"},
			want:    false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := tc.finding
			if got := il.ShouldIgnore(&f); got != tc.want {
				t.Fatalf("ShouldIgnore(%+v) = %v, want %v", f, got, tc.want)
			}
		})
	}
}

func TestCLI_LoadIgnoreFile(t *testing.T) {
	t.Run("empty path yields nil list, no error", func(t *testing.T) {
		il, err := LoadIgnoreFile("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if il != nil {
			t.Fatalf("expected nil list for empty path, got %+v", il)
		}
	})

	t.Run("missing file is not an error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "does-not-exist.ignore")
		il, err := LoadIgnoreFile(path)
		if err != nil {
			t.Fatalf("missing file should not error: %v", err)
		}
		if il != nil {
			t.Fatalf("missing file should yield a nil list, got %+v", il)
		}
	})

	t.Run("nil IgnoreList never suppresses", func(t *testing.T) {
		var il *IgnoreList
		if il.ShouldIgnore(&Finding{ValueHash: "x", RuleID: "aws.access_key_id"}) {
			t.Fatal("nil IgnoreList must return false from ShouldIgnore")
		}
	})

	errCases := []struct {
		name    string
		content string
		wantErr string
	}{
		{"missing separator", "hashdeadbeef\n", "missing ':' separator"},
		{"empty value", "hash:\n", "empty value"},
		{"unknown kind", "nope:whatever\n", "unknown kind"},
		{"rule_value without value glob", "rule_value:stripe.secret_key\n", "rule_value needs"},
	}
	for _, tc := range errCases {
		t.Run("rejects "+tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "bad.ignore")
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatalf("write fixture: %v", err)
			}
			_, err := LoadIgnoreFile(path)
			if err == nil {
				t.Fatalf("expected an error for %q, got nil", tc.content)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
