# Changelog

All notable changes to JSHunter are tracked here. Dates are ISO-8601.

## [v0.6 — page-aware crawling, sourcemaps, cache, concurrent verify] — 2026-05-08

The "JS-aware crawler, not just a JS-file scanner" iteration.

### HTML page-awareness (`--inline-html`)

`golang.org/x/net/html` tokenizer walks the response, extracts:

- Every inline `<script>` body (scanned under `URL#inline[N]` source label)
- Every external `<script src=…>` reference plus its `integrity=` SRI hash
- Every `<meta http-equiv="Content-Security-Policy" content=…>` directive
- `<link rel="preload|modulepreload|prefetch" as="script">` referenced JS

Homepage HTML is the most common place JS-only crawlers miss secrets —
the `window.__INITIAL_STATE__ = {…}` blob, dev-only `<script type="module">`
init code, etc. Now first-class.

### Source map real parsing (`--sourcemap`)

`//# sourceMappingURL=` markers now drive a real fetch+parse pipeline:

- HTTP(S) maps fetched through the same hardened client (host limiter,
  max-bytes, SSRF guard).
- `data:application/json;base64,...` inline maps decoded.
- `data:application/json,...` percent-encoded maps unescaped.
- Each entry in `sourcesContent[]` is scanned as its own source under
  `<URL>.map#<original-path>`.

Modern bundlers (Vite, esbuild, webpack 5, Turbopack, Rspack) routinely
ship pre-minification sources verbatim — comments, dev-only code paths,
original variable names. This is the highest-leverage signal for secret
recon on a production site.

### CSP origin extraction (`--csp-origins`)

`Content-Security-Policy` response headers and `<meta http-equiv>` tags
are parsed; the host origins (excluding `'self'`, `'unsafe-*'`, `nonce-*`,
hash sources, `data:`, `blob:`, `ws:`, …) are emitted as
`[CSP] <source>\t<origin>` lines suitable for piping back into the URL
queue of a follow-up scan.

### robots.txt ingest (`--robots`)

Fetches `/robots.txt` for every unique host in the input and prints
`Disallow`, `Allow`, and `Sitemap` lines. Pure recon helper — JSHunter
does NOT respect robots.txt for its own crawling. Operators wanting
compliance pipe these paths back as the input list.

### Disk cache (`--cache-dir`)

Per-URL SHA-256 keyed on-disk cache. Two files per URL:

- `<hash>.body` — the response body
- `<hash>.meta` — JSON: status, content-type, ETag, Last-Modified, fetched_at

Re-runs attach `If-None-Match` / `If-Modified-Since`; 304 responses serve
from disk. Set-Cookie / Authorization-bearing responses are skipped
(security hazard). Mode 0600 on disk because cached bodies may carry
secrets.

### Concurrent verifier worker pool (`--verify-workers`)

`VerifyAllConcurrent` replaces the serial loop in `emitFinalOutput`. With
50 findings × 10 s timeout, serial = 8+ minutes; pooled (default 8) =
~1 min worst case. Per-host limiter still applies inside the workers, so
no provider gets slammed.

### SARIF partialFingerprints

Each SARIF result now carries `partialFingerprints`:

```json
"partialFingerprints": {
  "jshunter/valueHash": "<sha256/16>",
  "jshunter/ruleSecretType": "<rule_id>:<secret_type>"
}
```

GitHub Code Scanning uses these to persist dismissed/suppressed decisions
across runs even when the finding moves source/line.

### Go 1.24 modernization

- `ioutil.ReadAll` → `io.ReadAll` everywhere.
- `ioutil.ReadFile/WriteFile` → `os.ReadFile/WriteFile`.
- `rand.Seed(time.Now().UnixNano())` removed (Go 1.20+ auto-seeds the
  global source).

### Files added

- `html_extract.go` — `golang.org/x/net/html` tokenizer-based extractor.
- `csp.go` — Content-Security-Policy origin parser.
- `sourcemap.go` — sourceMappingURL fetch + JSON parse + sourcesContent walk.
- `cache.go` — `DiskCache` with ETag/Last-Modified revalidation.
- `robots.go` — RFC 9309 subset parser.
- `concurrent_verify.go` — bounded worker pool for liveness probes.

## [v0.6 — outputs, suppressions, AWS pair, registry CLI] — 2026-05-08

The "make it ship-ready" iteration. Output formats for CI, persistent
suppressions, registry introspection, alternative inputs, and the AWS pair
verifier that closes the verification gap left in the previous slice.

### AWS pair verifier (SigV4)

When the registry detects an Access Key ID and a Secret Access Key in the
**same source**, JSHunter pairs them and runs `sts:GetCallerIdentity` via
SigV4 — pure-stdlib HMAC-SHA256 signing, no aws-sdk dependency. A live
response sets `verified=true` on **both** findings and surfaces the IAM
ARN as `verify.account`. Strict pairing: same-source-only with single
AKID + single secret per source — multi-of-either is left to manual
triage to avoid mis-attribution.

### Output formats

| Flag       | Format                                              | Use case                          |
|------------|-----------------------------------------------------|-----------------------------------|
| `--sarif`  | SARIF 2.1.0 envelope                                | GitHub code-scanning upload       |
| `--ndjson` | One Finding per line, `json.Encoder` (no HTML escape) | jq, mlr, SIEM streaming         |

When either is set, per-source console output is suppressed so the
structured stream stays parseable.

### Suppressions

`--ignore-file PATH` — `.jshunterignore` syntax:

```
hash:<value_hash_hex>           # single finding by hash
rule:<rule_id_or_glob>          # entire rule or family
source:<glob>                   # all findings from matching source
rule_value:<rule>:<value-glob>  # rule + value-glob combo
```

Globs use `filepath.Match`. Applied at `recordFinding` so suppressions
work across both registry and legacy paths.

`--diff PREVIOUS.json` — reads a previous schema-v2 envelope, computes
the set of `value_hash` values already reported, and reports only
findings NOT in that set. Schema-version mismatch is a hard error.

### Registry introspection / selection

| Flag                  | Effect                                                 |
|-----------------------|--------------------------------------------------------|
| `--list-rules`        | Tabular dump of `rule_id severity provider name [flags]` |
| `--explain RULE_ID`   | Full rule JSON (incl. TP/FP fixtures)                  |
| `--only-rules a,b,*c` | Run only matching rules (glob suffix supported)        |
| `--disable-rule x,y`  | Drop matching rules from the registry                  |

Selection is applied **before** `--list-rules` / `--explain` /
`--self-test`, so an operator can scope CI gates to specific rule families.

### Alternative inputs

`--har FILE` — ingest a Chrome DevTools HAR archive directly, skipping
the fetcher. Only entries with JS-typed Content-Type (or `.js` URL
suffix) and 2xx/3xx status are scanned. base64-encoded response bodies
are decoded automatically (std/URL/raw variants tolerated).

### Quality of life

`--no-color` disables ANSI color; if stdout is not a TTY,
`disableColors()` runs automatically so piping to a file produces clean
text.

### Files added

- `aws_pair.go` — SigV4 + pair verifier.
- `sarif.go` — SARIF 2.1.0 envelope builder.
- `ndjson.go` — streaming output.
- `har.go` — HAR ingestion.
- `ignore.go` — `.jshunterignore` loader and matcher.
- `diff.go` — previous-envelope baseline.
- `rules_cli.go` — `--list-rules`, `--explain`, registry selection.
- `.jshunterignore.example` — operator template.

## [v0.6 — verifier + observability + crawler hardening] — 2026-05-08

The "trust the output" iteration on top of the v0.6 FP pipeline.

### Live verification (`--verify`)

Off-by-default, opt-in liveness probes against documented read-only
endpoints. A verified secret carries `verified=true` and confidence is
elevated to `1.0`. Per-host limiter + bounded timeout per probe; secrets
are never leaked into transport-error strings (sanitized).

| Provider     | Endpoint                                      | Auth                          |
|--------------|-----------------------------------------------|-------------------------------|
| Stripe       | `GET /v1/balance`                             | `Authorization: Bearer …`     |
| GitHub       | `GET /user`                                   | `Authorization: token …`      |
| OpenAI       | `GET /v1/models`                              | `Authorization: Bearer …`     |
| Anthropic    | `GET /v1/models`                              | `x-api-key` + `anthropic-version` |
| Slack        | `GET /api/auth.test`                          | `Authorization: Bearer …`     |
| SendGrid     | `GET /v3/scopes`                              | `Authorization: Bearer …`     |
| Mailgun      | `GET /v3/domains`                             | HTTP Basic `api:<key>`        |
| HuggingFace  | `GET /api/whoami-v2`                          | `Authorization: Bearer …`     |

Citations live next to each verifier in `verify.go`.

### Operator observability (`--stats`)

Per-stage atomic counters with a fresh run-id per process:

- `URLsFetched`, `URLsBlocked`, `BytesParsed`, `BytesTruncated`
- `RegistryHits`, `LegacyMatchesRaw`
- `DroppedVendorNoise`, `DroppedFixture`, `DroppedSourcemap`
- `DroppedLowEntropy`, `DroppedNoContext`, `DroppedBelowConf`, `DroppedRegistryDup`
- `FindingsAfterFilter`, `FindingsAfterDedupe`
- `VerifyAttempts`, `VerifyAlive`, `VerifyDead`, `VerifyError`

Printed to stderr at end of run when `--stats` is set, so stdout pipelines
stay clean.

### Crawler hardening

- Per-host outbound concurrency cap (default 4, configurable via `--per-host`).
- Exponential backoff with ±25% jitter between retries.
- `Retry-After` header (seconds and HTTP-date forms) is honored.
- 429/5xx circuit breaker: after 5 consecutive bad responses on a host, all
  requests to that host are dropped for 30 s (or the longest `Retry-After`
  observed, whichever is greater).

### Output schema

- `Finding` now carries `line`, `column`, and `verify{alive,status,account,note}`.
- `Location[]` carries `line` and `column` per occurrence — operators can
  paste the JSON straight into `vim file:line:col`.

### Console redaction (`--show-secrets`)

By default the console prints redacted values (`AKIA****GHIJ`); the full
value is written to the `-o` output file because that's what the operator
explicitly asked for. `--show-secrets` reverts to v0.6.0 behavior.

### Extensibility (`--rules-file`)

Operators ship custom rules at runtime via JSON pack. Format documented in
`RULES.md`. External rules participate in `--self-test` automatically.
Loader rejects the whole pack on any validation failure (no partial loads).

### Tests

`detection_test.go` ships with:
- Property tests for `shannonEntropy` (bounds, monotonicity).
- Length and middle-mask tests for `redactValue`.
- Round-trip CRC32 base62 test for `validateGitHubToken`.
- Structural tests for `validateJWT`, `validateAWSAccessKeyID`,
  `validateStripeKey`.
- Vendor-noise denylist coverage (canonical AWS docs example).
- Schema-version assertion test (golden-file in spirit).
- Loader contract tests (missing/duplicate id, bad regex, oversized regex).
- Backoff-bounds and `parseRetryAfter` smoke tests.
- `runSelfTest` is invoked by `TestRegistry_AllRules_FixturesPass` so any
  rule whose TP fixture stops matching, or whose FP fixture starts being
  reported, fails CI.

### Documentation

- New `RULES.md` covering the full schema, confidence model, and rule
  authoring contract.
- New `CREDITS.md` honestly naming TruffleHog, Gitleaks, detect-secrets,
  Nosey Parker, secretlint, Semgrep secrets pack as inspirations.

## [v0.6 — initial false-positive surgery] — 2026-05-08

The "kill the false positives" release. Every secret-class match now flows
through a confidence-scoring pipeline before it is reported, the highest-volume
providers get format-and-checksum validators, and the JSON output is
schema-versioned so downstream tools can detect breaking changes.

### Detector additions

- New curated rule registry (`detection.go`) for highest-precision providers:
  AWS access keys (prefix family + 16-char base32 body), AWS secret keys,
  Stripe (`sk/rk/pk_(live|test)_` + clean base62), GitHub PATs (CRC32 base62
  checksum verified), GitHub fine-grained PATs, OpenAI legacy/project/svcacct,
  Anthropic, Google API + ya29 OAuth, Slack token family + app + webhook,
  Discord webhook + bot token, Twilio SK + AC, SendGrid, Mailgun, Mailchimp,
  GitHub App installation tokens, GitLab PAT + pipeline trigger, Vercel,
  Doppler, DigitalOcean, Shopify (access + shared secret), npm, PyPI, JWT
  (with structural decode), private keys (RSA/OpenSSH/EC/PGP), Facebook
  access token, Linear, HuggingFace, Supabase service-role JWT.

### False-positive fixes

- Vendor-noise denylist: canonical AWS docs example
  (`AKIAIOSFODNN7EXAMPLE`), `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
  Stripe public test fixtures, the canonical 3-part `eyJ...` example JWT.
- Substring denylist for placeholder fragments (`YOUR_API_KEY`,
  `REPLACE_ME`, `PLACEHOLDER`, `XXXXXXXX`, etc.).
- Sourcemap-line skip: any match on a `//# sourceMappingURL=` line is
  dropped — that line is a build artifact, not a secret.
- Vendor/chunk filename gate: matches in `vendor*.js`, `chunk-*.js`,
  `runtime-*.js`, `polyfill*.js`, `framework*.js`, `node_modules/*` paths
  start with a confidence penalty.
- Fixture-context penalty: surrounding text containing `example`,
  `dummy`, `sample`, `placeholder`, `mock_`, `stub_`, `fake_`, `lorem`,
  `FIXME` lowers the score by 0.30.
- Generic-rule context gate: `Generic Api Key`, `Generic Secret`,
  `Quickbooks Api Key`, `Cisco Access Token`, `Sanity Token`,
  `Atlassian Access Token`, `Heroku Api Key 2/3` now require a
  `key|token|secret|auth|bearer|api|password|...` keyword within ±96
  chars and entropy ≥ 3.2 with character-class diversity ≥ 2.
- Provider validators: AWS access key (prefix + base32 body), Stripe
  (prefix family + clean base62), GitHub (CRC32 base62 checksum), Slack
  (hyphen-segment shape), JWT (header decodes to JSON with `alg`),
  Twilio (32-hex body + entropy gate).

### Broken patterns repaired

The following v0.5 patterns could **never match** in a body because they
were anchored with `^...$` (which only match a complete one-line input)
or had escape errors. v0.6 corrects them:

- `Dropbox Access Token` — was `^sl\.…$`, now `\bsl\.…\b`.
- `Twitter Bearer Token` — was `^AAAA…$`, now bounded `\bAAAA…\b`.
- `Username Password Combo` — was `^[a-z]+://…@`, now scoped to body matches.
- `Crowdstrike Api Key` — was `^…$`, now requires a `crowdstrike/cs` keyword.
- `Azure Storage Account Key` — was `^…={0,43}$`, now anchored to
  `AccountKey=`/`azure_storage_key` context.
- `Phone Number` — was `^\+\d{9,14}$`, now matches inside text bodies.
- `Ali Cloud Access Key` / `Tencent Cloud Access Key` — anchors removed.
- `Json Web Token` — was `ey…\.…\.…$` (trailing-only), now `\beyJ…\.eyJ…\.…\b`.
- `Github Access Token` — `com*` typo (matched `co`, `com`, `comm…`)
  replaced with proper `\.com\b`.
- `Password in Url` — broken `\\s` / `\\\\` escapes replaced with valid
  regex character classes.
- `Amazon Mws Auth Token` — `\\.` escape errors replaced with `\.`.
- `Heroku Api Key 3` — unbounded `.*` (ReDoS hazard) replaced with
  bounded `[^\n]{0,80}`.

### High-FP rules tightened

- `Quickbooks Api Key` (`A[0-9a-f]{32}` matched any commit hash starting
  with A) — now requires `quickbooks|qbo|intuit` context keyword.
- `Cisco Api Key` (`cisco[A-Za-z0-9]{30}`) — now requires
  `cisco_api_key=` style assignment.
- `Cisco Access Token` (`access_token=\w+`) — now requires `cisco_`
  keyword to avoid generic OAuth flows.
- `Sanity Token` (`sk[a-zA-Z0-9]{32,}`) — now requires `sanity_token=`
  context.
- `Atlassian Access Token` (`{20,}\.{6,}\.{25,}`) — replaced with the
  documented Atlassian `ATATT3…` token shape, gated by context keyword.
- `Heroku Api Key 2` (`heroku[A-Za-z0-9]{32}`) — replaced with the
  proper `heroku_api_key=UUID` shape.

### CLI additions

- `--min-confidence FLOAT` / `-mc` (default `0.50`) — gate on per-finding
  confidence.
- `--show-confidence` / `-sc` — print `[conf=X.XX]` next to each finding.
- `--no-fp-filter` — disable the FP filter (debug; v0.5-compatible output).
- `--self-test` — run the rule registry against its built-in TP/FP
  fixtures and exit non-zero on regression. Suitable for CI.
- `--max-bytes N` (default 32 MiB) — cap response body reads to defend
  against gzip bombs and pathological streaming.
- `--allow-internal` — permit `localhost`, `127.0.0.0/8`, RFC1918, and
  link-local targets. **Off by default** to prevent SSRF when piping
  untrusted URL lists.

### Output schema

- Top-level `schema_version: 2` field added to all `--json` output.
- New `findings[]` array carries: `rule_id`, `name`, `provider`,
  `secret_type`, `severity`, `value`, `redacted`, `value_hash`,
  `source`, `confidence`, `entropy`, `verified`, `reasons[]`,
  `locations[]`. Same secret seen in N sources collapses to one
  Finding with `locations[]` listing all N.
- The legacy `matches{name: [value, …]}` map is retained for backward
  compatibility within schema v2.

### Operational hardening

- Target URL validation refuses non-HTTP(S) schemes (no `file://`),
  loopback, RFC1918, and link-local hosts unless `--allow-internal` is
  passed. The intent is making JSHunter safe to run against
  user-supplied URL lists.
- Response body reads are now bounded by `--max-bytes` via
  `io.LimitReader`.

## [v0.5] — 2026-01-22

Pre-release baseline. Single-file `jshunter.go`, ~190 regex patterns,
basic match/no-match output, no confidence scoring.
