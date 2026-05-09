# Rule schema

JSHunter v0.6 ships with two rule sources: the **built-in registry** (Go code
in `detection.go`) and **external rule packs** loaded at runtime via
`--rules-file` (JSON). This doc covers both, plus the contract every new rule
must meet to ship.

## Mental model
 
```
fetch  →  parse  →  rule match  →  scoreFinding  →  recordFinding  →  output
                                       │
                       (vendor-noise gate, entropy gate, context gate,
                        provider validator, fixture-context penalty,
                        sourcemap-line skip, vendor-chunk penalty)
```

Every rule is just a regex paired with a per-rule **confidence prior** and
a set of **gates** that adjust or reject the score. The gates are the same
for built-in and external rules; the only thing external rules can't do is
register a Go-coded `Validate` function (we don't run user-supplied code).

## Rule fields

| Field              | Type        | Required | Notes                                                     |
|--------------------|-------------|----------|-----------------------------------------------------------|
| `id`               | string      | yes      | Stable, namespaced (`provider.subtype`). Used for dedupe. |
| `name`             | string      | yes      | Human label shown in output.                              |
| `provider`         | string      | no       | Vendor name (`AWS`, `Stripe`, …).                         |
| `secret_type`      | string      | no       | `api_key`, `pat`, `webhook`, `private_key`, …             |
| `severity`         | enum        | yes      | `critical|high|medium|low|info`.                          |
| `pattern`          | regex       | yes      | RE2 syntax. ≤ 4096 bytes.                                 |
| `group`            | int         | no       | Capture-group index (default 0 = full match).             |
| `confidence_prior` | float [0,1] | no       | Default 0.55.                                             |
| `requires_context` | bool        | no       | If true, drops match when no context keyword in ±96 chars.|
| `context_keywords` | []string    | no       | Keywords required if `requires_context: true`.            |
| `min_entropy`      | float       | no       | Drop match when Shannon entropy < this.                   |
| `min_len`          | int         | no       | Drop match shorter than this.                             |
| `max_len`          | int         | no       | Drop match longer than this.                              |
| `high_fp_prone`    | bool        | no       | Apply stricter entropy + char-class gates.                |
| `tp_examples`      | []string    | yes¹     | Example values the rule MUST match.                       |
| `fp_examples`      | []string    | yes¹     | Example values the rule MUST NOT match.                   |

¹ Required *contractually* (R6). `--self-test` walks every rule's TP and FP
fixtures; CI gates merges on `--self-test` exit code.

## Confidence model

Score starts at `confidence_prior`, then is adjusted:

| Adjustment                                     | Delta  |
|------------------------------------------------|--------|
| Source path matches `vendor/chunk/runtime/…`   | −0.15  |
| Provider validator passed                      | +0.10  |
| Context keyword present (`requires_context`)   | +0.05  |
| Surrounding text contains fixture keywords     | −0.30  |
| Shannon entropy ≥ 4.5                          | +0.05  |
| Character-class diversity ≥ 3                  | +0.05  |

Hard rejects (no score, drop the match):

- Match in `vendorNoiseExact` or contains a `vendorNoiseSubstr` fragment.
- Length below `min_len` or above `max_len`.
- Entropy below `min_entropy`.
- `high_fp_prone` rule with character-class diversity < 2 or entropy < 3.0.
- `requires_context` rule with no keyword hit.
- `Validate` function returns false (built-in rules only).
- Line is a `//# sourceMappingURL=` marker.

`--min-confidence` (default 0.50) gates the final score.

## External rule pack format

A pack is a JSON file containing an array of rule objects:

```json
[
  {
    "id": "acme.api_key",
    "name": "Acme API Key",
    "provider": "Acme",
    "secret_type": "api_key",
    "severity": "high",
    "pattern": "\\bacme_[A-Za-z0-9]{32}\\b",
    "confidence_prior": 0.85,
    "min_len": 37,
    "max_len": 37,
    "tp_examples": ["acme_aBcDeFgHiJkLmNoPqRsTuVwXyZ012345"],
    "fp_examples": ["acme_placeholder_____xxxxxxxxxxxxxx"]
  }
]
```

Load with:

```bash
jshunter --rules-file /path/to/rules.json -u https://target.com/app.js
```

Validation is strict: any rule that fails to compile or misses a required
field rejects the whole pack. That keeps "why didn't my rule fire?" out of
the support queue.

## Adding a built-in rule

1. Add a `Rule{}` literal to `registerRules()` in `detection.go`.
2. If the provider has a stable read-only liveness endpoint, register a
   verifier in `registerVerifiers()` in `verify.go` keyed by the rule ID.
3. Add `TPExamples` and `FPExamples` lists. **No rule ships without an FP
   fixture**; one of the most common failure modes is shipping a rule that
   flags a famous open-source bundle.
4. If your rule is `high_fp_prone` (matches a generic shape like 32-hex),
   either set `requires_context: true` with provider-specific
   `context_keywords`, or set `min_entropy` ≥ 3.5 and `max_len` to the
   actual provider format. **Both are usually correct.**
5. Run `go test ./...` and `./jshunter --self-test`. CI must be green.

## Provider validator contract

Validators are pure Go functions of signature
`func(value string) (ok bool, reasons []string)`. They MUST be deterministic
and offline; never call the network from a validator (use the verifier in
`verify.go` for that). They MAY be slow per call (e.g., CRC32) — they run on
matched candidates only, not every byte of the body.

Examples:

- `validateAWSAccessKeyID` — prefix family + base32 alphabet check.
- `validateGitHubToken` — CRC32 base62 trailing checksum verification.
- `validateJWT` — base64url-decode header, parse JSON, require `alg` field.
- `validateStripeKey` — prefix family + clean base62 body (no `_`).

## Anti-patterns

- ❌ A rule whose pattern is `(?i).*key.*=.*[A-Za-z0-9]{8,}.*`. This will
  flood the operator. Be specific. Use the provider's documented prefix.
- ❌ A rule with no FP fixture. You have a regex that flagged a vendor
  bundle once; that's the FP fixture. Add it.
- ❌ Calling `regexp.MustCompile` inside a hot loop. Compile once at
  registration time.
- ❌ A rule whose `severity` is `critical` for a publishable key. Public
  keys aren't credentials; they're configuration. `low` or `info` is right.
