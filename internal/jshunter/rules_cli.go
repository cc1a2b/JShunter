package jshunter

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// runListRules prints every registered rule as a single-line entry. Sorted
// by rule_id so output is grep-friendly. ctx-required and validator
// annotations help operators understand which rules are high-precision.
func runListRules() {
	registerRules()
	registerVerifiers()
	rules := make([]Rule, len(rulesRegistry))
	copy(rules, rulesRegistry)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })

	fmt.Printf("%-32s %-9s %-20s %s\n", "RULE_ID", "SEVERITY", "PROVIDER", "NAME")
	for _, r := range rules {
		flags := []string{}
		if r.RequiresContext {
			flags = append(flags, "ctx")
		}
		if r.Validate != nil {
			flags = append(flags, "validate")
		}
		if r.HighFPProne {
			flags = append(flags, "high-fp")
		}
		if _, ok := verifierRegistry[r.ID]; ok {
			flags = append(flags, "verify")
		}
		flagStr := ""
		if len(flags) > 0 {
			flagStr = " [" + strings.Join(flags, ",") + "]"
		}
		fmt.Printf("%-32s %-9s %-20s %s%s\n", r.ID, r.Severity, r.Provider, r.Name, flagStr)
	}
}

// runExplainRule prints a JSON dump of a single rule, including its TP/FP
// fixtures so operators can see what the rule was designed to catch.
func runExplainRule(id string) {
	registerRules()
	registerVerifiers()
	r, ok := rulesIndex[id]
	if !ok {
		fmt.Fprintf(os.Stderr, "rule %q not found; try --list-rules\n", id)
		os.Exit(2)
	}
	type explain struct {
		ID              string   `json:"id"`
		Name            string   `json:"name"`
		Provider        string   `json:"provider,omitempty"`
		SecretType      string   `json:"secret_type,omitempty"`
		Severity        Severity `json:"severity"`
		Pattern         string   `json:"pattern"`
		ConfidencePrior float64  `json:"confidence_prior"`
		RequiresContext bool     `json:"requires_context"`
		ContextKeywords []string `json:"context_keywords,omitempty"`
		MinEntropy      float64  `json:"min_entropy,omitempty"`
		MinLen          int      `json:"min_len,omitempty"`
		MaxLen          int      `json:"max_len,omitempty"`
		HighFPProne     bool     `json:"high_fp_prone"`
		HasValidator    bool     `json:"has_validator"`
		HasVerifier     bool     `json:"has_verifier"`
		TPExamples      []string `json:"tp_examples,omitempty"`
		FPExamples      []string `json:"fp_examples,omitempty"`
	}
	_, hasV := verifierRegistry[id]
	out := explain{
		ID:              r.ID,
		Name:            r.Name,
		Provider:        r.Provider,
		SecretType:      r.SecretType,
		Severity:        r.Severity,
		Pattern:         r.Pattern.String(),
		ConfidencePrior: r.ConfidencePrior,
		RequiresContext: r.RequiresContext,
		ContextKeywords: r.ContextKeywords,
		MinEntropy:      r.MinEntropy,
		MinLen:          r.MinLen,
		MaxLen:          r.MaxLen,
		HighFPProne:     r.HighFPProne,
		HasValidator:    r.Validate != nil,
		HasVerifier:     hasV,
		TPExamples:      r.TPExamples,
		FPExamples:      r.FPExamples,
	}
	b, _ := json.MarshalIndent(out, "", "  ")
	fmt.Println(string(b))
}

// applyRuleSelection mutates rulesRegistry to honor --only-rules and
// --disable-rule, both comma-separated lists with glob support
// (`aws.*`, `*.api_key`).
//
//	only:    if non-empty, ONLY rules matching at least one pattern are kept
//	disable: rules matching any pattern are dropped (applied after `only`)
//
// Mutating the registry rather than gating at match time keeps the regex
// loop tight on big bundles.
func applyRuleSelection(only, disable string) int {
	registerRules()
	if only == "" && disable == "" {
		return len(rulesRegistry)
	}
	keep := func(id string) bool {
		if only != "" {
			matched := false
			for _, p := range strings.Split(only, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if id == p || globMatch(p, id) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
		if disable != "" {
			for _, p := range strings.Split(disable, ",") {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				if id == p || globMatch(p, id) {
					return false
				}
			}
		}
		return true
	}

	out := make([]Rule, 0, len(rulesRegistry))
	for i := range rulesRegistry {
		if keep(rulesRegistry[i].ID) {
			out = append(out, rulesRegistry[i])
		}
	}
	rulesRegistry = out
	rulesIndex = map[string]*Rule{}
	for i := range rulesRegistry {
		rulesIndex[rulesRegistry[i].ID] = &rulesRegistry[i]
	}
	return len(rulesRegistry)
}
