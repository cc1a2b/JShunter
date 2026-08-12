// Package jshunter implements JSHunter's secret-detection engine: the rule
// registry, the false-positive (FP) scoring pipeline, the provider validators,
// and the built-in self-test that guards all three against regression.
//
// # Rule registry
//
// A Rule is a single secret-class detector. It pairs a compiled regular
// expression (with an optional capture Group) with the metadata the scoring
// pipeline needs: a ConfidencePrior, length bounds (MinLen/MaxLen), an entropy
// floor (MinEntropy), an optional required-context gate (RequiresContext plus
// ContextKeywords), a HighFPProne flag, an optional provider Validate function,
// and embedded TPExamples/FPExamples fixtures.
//
// Rules are wired lazily by registerRules, guarded by a sync.Once so callers
// that only consume the legacy regex patterns pay nothing. The registry is
// assembled from three sources: the curated first-party rules in detection.go,
// the second-wave provider detectors returned by extendedRules (rules_ext.go),
// and any operator-supplied detectors loaded from JSON (rules_loader.go).
// External rules are scoring-only: a Go validator func cannot be serialized, so
// provider-specific structural checks stay first-party.
//
// # Detection flow
//
// analyzeBody drives detection. For each rule it evaluates the pattern against
// the body, resolves the capture group into the candidate value, skips any
// match sitting on a sourcemap-marker line (a build artifact), extracts a
// context window of roughly plus-or-minus 96 characters around the match, and
// hands the candidate to the scoring pipeline. Survivors at or above the
// caller's minimum confidence become Findings that carry the byte offset, line,
// and column of the match.
//
// # FP scoring pipeline
//
// scoreFinding turns a raw regex hit into a confidence in [0,1], accumulating
// signed adjustments and short-circuiting on any disqualifying gate. The stages,
// in order:
//
//  1. Seed the score from the rule's ConfidencePrior (default 0.5).
//  2. Penalize matches whose source path looks like a vendor/chunk bundle.
//  3. Hard-drop values on the exact vendor-noise denylist (known sample keys).
//  4. Hard-drop values outside the rule's MinLen/MaxLen window.
//  5. Hard-drop values below the rule's Shannon-entropy floor (MinEntropy).
//  6. For HighFPProne rules, additionally require character-class diversity and
//     a minimum entropy, dropping low-diversity or low-entropy values.
//  7. For RequiresContext rules, require a nearby context keyword; drop when it
//     is absent, otherwise add a small bonus.
//  8. Run the provider Validate function: a reject is a hard drop, a pass adds a
//     validator bonus plus its structured reasons.
//  9. Penalize values wrapped in fixture/sample/placeholder wording.
//  10. Reward high entropy and diverse character classes.
//  11. Clamp the result into [0,1].
//
// Past scoring, analyzeBody enforces the caller's minimum-confidence threshold,
// then recordFinding deduplicates by (value hash, secret type): repeat sightings
// of the same secret collapse into one Finding whose Locations slice accumulates
// every source, line, and column. The active ignore list and diff baseline can
// suppress a finding at this point. Every drop increments a counter in the run
// statistics, so the filtering funnel stays auditable.
//
// # Validators
//
// A validator is a pure, offline, standard-library-only func(string) (bool,
// []string). It confirms that a candidate is structurally a real credential
// rather than a look-alike: AWS access-key checksums, Stripe/GitHub/Slack CRC
// suffixes, JWT header and payload decoding, Azure base64 key lengths,
// database-URI password capture, and similar checks. Returning false removes the
// finding outright; returning true contributes the validator bonus and its
// reasons to the score. Validators never touch the network, which keeps
// detection deterministic and safe to run anywhere. Optional, opt-in liveness
// probes (the --verify flag) are a separate concern handled by the verifier
// registry, not by validators.
//
// # Self-test
//
// runSelfTest, exposed as the --self-test CLI flag, exercises the whole engine
// against the fixtures embedded in each rule. Every TPExample must be caught and
// every FPExample must be rejected; each fixture is wrapped in a representative
// assignment and pushed through the same analyzeBody path used in production.
// The command reports per-rule true-positive and false-positive tallies and
// fails on any miss or leak, making rule drift and pipeline regressions visible
// in CI without any external corpus or network access.
package jshunter
