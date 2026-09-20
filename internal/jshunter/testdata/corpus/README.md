# Labelled false-positive corpus

Thirty small JavaScript files that pin JSHunter's precision claim in place, plus
`labels.json`, which says what the scanner is expected to report for each one.
The corpus is data only: no Go code lives here, and the harness that reads it
lives with the other tests in `internal/jshunter`.

## The two halves

**`fp_*.js` — the negative half (20 files).** Realistic bundler output that
contains no credential at all but is dense with the shapes that fool secret
scanners: content hashes and build ids, SRI `sha384-` values, trace and debug
UUIDs, i18n catalogues keyed on `password` / `apiKey` / `auth.token`, configs
that vendors document as public (Firebase web config, Algolia search key,
Segment write key, Sentry DSN, Mapbox `pk.`, Stripe `pk_live_`, Supabase anon
JWT), base64 that decodes to a PNG or a JWKS or an English sentence, provider
prefixes buried inside longer base64 runs, regex literals full of
credential-shaped text, SVG path data, Twilio SIDs, and placeholder values.
Every one of these is labelled `"expect": "none"`: at the default confidence
threshold the scanner must report zero findings.

**`tp_*.js` — the positive half (10 files).** Realistic code in which a value
that really would be a credential is bound to a credential-named identifier and
shipped to the browser. Each is labelled `"expect": "some"` with the rule ids
that must fire and a minimum finding count. These exist so that tightening the
false-positive pipeline cannot quietly turn into "report nothing".

The negative half is the important half. A change that makes an `fp_` file fire
is a regression even if every `tp_` file still passes.

## Labels

`labels.json` has one entry per `.js` file:

```json
"fp_webpack_runtime_hashes.js": { "expect": "none" },
"tp_aws_access_key.js": {
  "expect": "some",
  "rule_ids": ["aws.access_key_id"],
  "min_findings": 1
}
```

Fields:

- `expect` — `"none"` or `"some"`.
- `rule_ids` — for `"some"`, the curated-registry rule ids that must appear in
  the `findings[]` array of the JSON output.
- `min_findings` — for `"some"`, the minimum number of `findings[]` entries.
- `match_names_any` — optional. At least one of these keys must be present in
  the `matches[]` map, for cases the legacy regex map covers but the curated
  registry deliberately does not. Only `tp_generic_api_key.js` uses this, and it
  lists two names because two legacy patterns match the same span and the one
  that survives is chosen by Go map iteration order over `regexPatterns` — so
  the same input yields `Generic Api Key` on one run and `Authorization Api` on
  the next. Any assertion on a single legacy key name is flaky.
- `note` — plain-English description of what the file pins. Not machine-read.

`expect: "none"` is about `findings[]`, the curated registry output. The legacy
`matches[]` map is far noisier — it carries `Email`, `Link/URL` and several
brand-word regexes — so a harness that asserts on `matches[]` for the negative
half will fail for reasons that have nothing to do with secret detection.

## Running it by hand

```
go build -o /tmp/jsh ./cmd/jshunter
/tmp/jsh -f internal/jshunter/testdata/corpus/fp_webpack_runtime_hashes.js -j -q
```

`-j` emits the v2 envelope; `findings[]` is the registry output with `rule_id`,
`confidence`, `severity` and (when the structural gate ran) `evidence`. Note
that the tool prints nothing at all when a file yields neither findings nor
legacy matches, so an empty stdout means "clean", not "crashed".

Three flags change what the negative half looks like and must stay off when
measuring against these labels: `--include-public` un-suppresses values
classified as published-by-design or as non-granting identifiers,
`--no-structural` turns the structural gate off entirely (v0.7 regex-only
behaviour), and `--no-fp-filter` keeps every raw match. Confidence is measured
at the default `--min-confidence 0.50`.

## Adding a case

1. Write the file as output a real bundler would produce — webpack 5, Vite or
   Rollup, esbuild, a Next.js app-router chunk, an Angular or Vue chunk, a
   sourcemap-recovered source, or an inline `<script>` body. Keep it between 40
   and 200 lines and let the surrounding code be ordinary: the shapes under test
   should be embedded in believable code, not listed in a bare table.
2. Name it `fp_<what-it-pins>.js` or `tp_<provider-or-class>.js`.
3. Add a `labels.json` entry with a `note` saying what it pins.
4. Run the scanner over it and check the result matches the label. For a `tp_`
   file, read the rule in `detection.go` or `rules_ext.go` first: the pattern,
   `MinLen`/`MaxLen`, `MinEntropy` and the validator all have to be satisfied,
   and several validators check a checksum or a decode.

Two properties of the current pipeline are easy to trip over when writing a
`tp_` file. A value that is URL-shaped, digest-shaped or UUID-shaped is rejected
unless the identifier it is bound to names a credential, so bind it to something
like `apiKey`, `accessToken`, `webhookSecret` or `AWS_ACCESS_KEY_ID`. And the
words `example`, `sample`, `dummy`, `fixture`, `placeholder`, `mock_`, `stub_`,
`lorem`, `TODO` and `FIXME` anywhere within roughly 96 characters of the value
cost it 0.30 confidence, which is enough to push a mid-prior rule under the
threshold. Keep them out of `tp_` files unless the point of the case is that
they suppress the finding.

## No live credentials, ever

Nothing in this directory may be a working credential, and nothing may be a
plausible-looking contiguous provider secret either — GitHub push protection and
upstream secret scanners block those on push, and a corpus that cannot be pushed
is worthless.

Every value here is structurally valid but provably dead, built one of these
ways:

- A documented public value: a Stripe publishable key, a Firebase web config
  key, a Supabase anon JWT, a Mapbox `pk.` token. These are public by design.
- A dictionary-derived body over the rule's charset, so the value reads as
  synthetic on sight: an `AKIA` prefix over `ACMECORP…`, or
  `access_token$production$acmemerchant0001$…`.
- A body that decodes to readable English. The Azure account key in
  `tp_azure_storage_key.js` is 88 base64 characters that decode to exactly 64
  ASCII bytes saying so, which satisfies the validator's length and decode test
  while being obviously not a key. The PEM body in `tp_private_key_pem.js` is
  base64 of a repeated sentence, not DER.
- A deliberately broken checksum. The `ghp_`-shaped value in
  `fp_identifier_soup_prefixes.js` has a CRC32 tail that does not verify, which
  is exactly why it belongs in the negative half.
- A deterministic hex or base62 filler with no relationship to any issuer.

When you add a case, keep to those five. Do not paste a value you found in a
real bundle, a paste site, or an incident report, even a revoked one.

## Placeholders

Sample values are not stored verbatim. Every token-shaped value is written as a
`%%JSHTnnn%%` placeholder and reassembled at run time from the fragment table in
`../../corpus_tokens_test.go`, which splits each value the same way the
vendor-noise corpus in `detection.go` does.

The reason is mechanical: a corpus of realistic provider tokens trips upstream
secret scanning on every push. The materialised bytes are identical to what a
scan sees in the field, so the gate measures the real thing; only the on-disk
representation differs. `cp_materialise` fails the test on any placeholder it
cannot resolve, so a fixture can never quietly scan as its own placeholder text.

When adding a fixture, write the value as a placeholder and add the fragments to
`cp_tokens`. Never commit a live credential here.
