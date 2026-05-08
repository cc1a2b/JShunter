# Credits

JSHunter is a competitive recon tool. Pretending it sprang from nowhere would
be dishonest — the secret-detection space has years of public work that
inspired both the rule shapes and the false-positive techniques baked into
v0.6. This file names them.

## Prior art that shaped the v0.6 detection layer

- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)** — the
  reference for "regex match, then live-verify against the provider." The
  per-provider verifier endpoints (Stripe `/v1/balance`, GitHub `/user`,
  Slack `auth.test`, SendGrid `/v3/scopes`, Mailgun `/v3/domains`) used in
  JSHunter's `--verify` flow are the same lightweight, read-only endpoints
  TruffleHog adopted; we cite them in `verify.go` so a reviewer can audit.
- **[Gitleaks](https://github.com/gitleaks/gitleaks)** — TOML rule pack
  shape, the idea of explicit per-rule TP/FP fixtures, and many of the
  long-tail provider regexes JSHunter inherited. Gitleaks's "rules.toml"
  was the model for JSHunter's external `--rules-file` JSON loader.
- **[Yelp/detect-secrets](https://github.com/Yelp/detect-secrets)** — entropy
  thresholds and the "high-entropy-string" plugin family. The Shannon-entropy
  + character-class-diversity gate in `detection.go::scoreFinding` is in the
  spirit of detect-secrets's filters.
- **[praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker)** —
  performance reference for high-volume scanning; the multi-pattern ideas
  that will land in v0.7 trace back here.
- **[secretlint](https://github.com/secretlint/secretlint)** — provider
  rotation tracking; their issue tracker is the canonical place to learn
  when a provider has changed token format.
- **[Semgrep secrets pack](https://semgrep.dev/p/secrets)** — context-aware
  rule construction, especially the "shape + context window" pattern that
  JSHunter's `RequiresContext` + `ContextKeywords` per-rule fields encode.
- **GitHub Engineering blog: "Behind GitHub's new authentication token formats"**
  ([link](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/))
  — source for the CRC32 base62 checksum used in
  `detection.go::validateGitHubToken`.
- **AWS access key bitwise analysis (WithSecure Labs)**
  ([link](https://labs.withsecure.com/publications/a-bitwise-analysis-of-aws-access-key-identifiers))
  — base32 alphabet (A–Z, 2–7) + prefix family encoded in
  `validateAWSAccessKeyID`.

## Vendor & provider documentation cited inline

Every validator in `verify.go` carries a vendor docs link as a comment.
When a provider rotates token format or moves an endpoint, those comments
are the single source of truth for what to update.

## License

JSHunter is MIT-licensed. The works above retain their respective licenses;
JSHunter does not vendor source from any of them. Where a regex is similar
to a Gitleaks or detect-secrets pattern, that is convergent design on
provider-published shapes, not a direct copy.

— Hussain Alsharman, JSHunter author
