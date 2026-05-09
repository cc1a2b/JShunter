package jshunter

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// ExternalRule is the JSON-friendly serialization of a Rule. Validators are
// not serializable (they are Go funcs) — external rules get scoring only,
// no provider validator. That is the right trade: contributors can ship
// detectors quickly, but provider-specific liveness checks stay first-party
// to avoid pasting attack code into a YAML loader.
type ExternalRule struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Provider        string   `json:"provider"`
	SecretType      string   `json:"secret_type"`
	Severity        string   `json:"severity"`
	Pattern         string   `json:"pattern"`
	Group           int      `json:"group,omitempty"`
	ConfidencePrior float64  `json:"confidence_prior,omitempty"`
	RequiresContext bool     `json:"requires_context,omitempty"`
	ContextKeywords []string `json:"context_keywords,omitempty"`
	MinEntropy      float64  `json:"min_entropy,omitempty"`
	MinLen          int      `json:"min_len,omitempty"`
	MaxLen          int      `json:"max_len,omitempty"`
	HighFPProne     bool     `json:"high_fp_prone,omitempty"`
	TPExamples      []string `json:"tp_examples,omitempty"`
	FPExamples      []string `json:"fp_examples,omitempty"`
}

// LoadRulesFile reads, validates, compiles, and registers an external rule
// pack. Pack format: a top-level JSON array of ExternalRule objects.
//
// On any validation failure for a single rule, the loader rejects the WHOLE
// file — partial loads invite "why didn't my rule fire?" support questions.
// Returns the count of rules successfully appended.
func LoadRulesFile(path string) (int, error) {
	registerRules() // ensure built-in registry is materialized first

	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read rules file: %w", err)
	}

	var ext []ExternalRule
	if err := json.Unmarshal(raw, &ext); err != nil {
		return 0, fmt.Errorf("parse rules file: %w", err)
	}

	compiled, err := validateAndCompileExternalRules(ext)
	if err != nil {
		return 0, err
	}

	for _, r := range compiled {
		rulesRegistry = append(rulesRegistry, r)
		idx := len(rulesRegistry) - 1
		rulesIndex[r.ID] = &rulesRegistry[idx]
	}
	return len(compiled), nil
}

// validateAndCompileExternalRules enforces contract (id present, regex
// compiles, severity is one of the documented values, no field clashes with
// built-in registry) and returns the resulting Rule slice ready to register.
func validateAndCompileExternalRules(ext []ExternalRule) ([]Rule, error) {
	out := make([]Rule, 0, len(ext))
	seenIDs := map[string]struct{}{}
	for i, e := range ext {
		if strings.TrimSpace(e.ID) == "" {
			return nil, fmt.Errorf("rule[%d]: id is required", i)
		}
		if _, dup := seenIDs[e.ID]; dup {
			return nil, fmt.Errorf("rule[%d]: duplicate id %q within file", i, e.ID)
		}
		seenIDs[e.ID] = struct{}{}
		if _, dup := rulesIndex[e.ID]; dup {
			return nil, fmt.Errorf("rule[%d]: id %q clashes with built-in rule", i, e.ID)
		}
		if strings.TrimSpace(e.Name) == "" {
			return nil, fmt.Errorf("rule %q: name is required", e.ID)
		}
		if strings.TrimSpace(e.Pattern) == "" {
			return nil, fmt.Errorf("rule %q: pattern is required", e.ID)
		}

		// Length sanity: refuse a pattern over 4 KiB. v0.6 uses Go's RE2
		// engine which is ReDoS-safe by construction, but a 100 KiB regex
		// is still a memory hazard at compile time.
		if len(e.Pattern) > 4096 {
			return nil, fmt.Errorf("rule %q: pattern exceeds 4096 bytes", e.ID)
		}

		re, err := regexp.Compile(e.Pattern)
		if err != nil {
			return nil, fmt.Errorf("rule %q: pattern does not compile: %w", e.ID, err)
		}

		sev := normalizeSeverity(e.Severity)
		if sev == "" {
			return nil, fmt.Errorf("rule %q: severity must be one of critical|high|medium|low|info", e.ID)
		}

		prior := e.ConfidencePrior
		if prior == 0 {
			prior = 0.55
		}
		if prior < 0 || prior > 1 {
			return nil, fmt.Errorf("rule %q: confidence_prior must be in [0,1]", e.ID)
		}

		out = append(out, Rule{
			ID:              e.ID,
			Name:            e.Name,
			Provider:        e.Provider,
			SecretType:      e.SecretType,
			Severity:        sev,
			Pattern:         re,
			Group:           e.Group,
			ConfidencePrior: prior,
			RequiresContext: e.RequiresContext,
			ContextKeywords: e.ContextKeywords,
			MinEntropy:      e.MinEntropy,
			MinLen:          e.MinLen,
			MaxLen:          e.MaxLen,
			HighFPProne:     e.HighFPProne,
			TPExamples:      e.TPExamples,
			FPExamples:      e.FPExamples,
		})
	}
	return out, nil
}

// normalizeSeverity accepts the documented spellings and lowercases for the
// Severity enum used everywhere else.
func normalizeSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical", "crit":
		return SevCritical
	case "high":
		return SevHigh
	case "medium", "med":
		return SevMedium
	case "low":
		return SevLow
	case "info", "informational":
		return SevInfo
	}
	return ""
}
