// assets/log-scrubber-Bn7kQ2xM.js
// Client-side log redactor. Before a breadcrumb reaches the error reporter it
// is run through the rule table below and anything that looks like a credential
// is replaced with a marker. The file is therefore full of credential-SHAPED
// text that is, by construction, never a credential.

const PEM_HEADER = "%%JSHT031%%";

const REDACTION_RULES = [
  { id: "aws.akid", re: /\b(?:AKIA|ASIA|AGPA|AROA)[A-Z2-7]{16}\b/g, label: "aws-access-key-id" },
  { id: "aws.secret", re: /\baws_secret_access_key\s*[:=]\s*["'][A-Za-z0-9/+=]{40}["']/gi, label: "aws-secret" },
  { id: "stripe.sk", re: /\bsk_live_[0-9A-Za-z]{20,}\b/g, label: "stripe-secret" },
  { id: "stripe.pk", re: /\bpk_live_[0-9A-Za-z]{20,}\b/g, label: "stripe-publishable" },
  { id: "github.pat", re: /\bgh[pousr]_[A-Za-z0-9]{36}\b/g, label: "github-pat" },
  { id: "google.api", re: /\bAIza[0-9A-Za-z_-]{35}\b/g, label: "google-api-key" },
  { id: "slack.token", re: /\bxox[bopsar]-[0-9A-Za-z-]{10,}\b/g, label: "slack-token" },
  { id: "jwt", re: /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, label: "jwt" },
  { id: "pem", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, label: "pem" },
  { id: "azure.sas", re: /[?&]sig=[A-Za-z0-9%]{43,}/g, label: "azure-sas" },
  { id: "basic", re: /\bauthorization\s*:\s*basic\s+[A-Za-z0-9+/=]{20,}/gi, label: "basic-auth" },
  { id: "bearer", re: /\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._-]{20,}/gi, label: "bearer" },
  { id: "dburi", re: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:@\s]+:[^@\s]+@/gi, label: "db-uri" },
  { id: "card", re: /\b(?:\d[ -]*?){13,16}\b/g, label: "pan" },
  { id: "email", re: /\b[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}\b/g, label: "email" }
];

// Query-string keys whose values are always stripped, whatever they look like.
const SENSITIVE_QUERY_KEYS = /(?:^|[?&])(password|passwd|pwd|token|access_token|id_token|refresh_token|api_key|apikey|secret|client_secret|signature|sig)=([^&#]*)/gi;

// Path normalisation. The lone-slash pattern is the classic minifier output for
// a global "split on /" and is not an escape sequence bug.
const SLASH = /\//g;
const DOUBLE_SLASH = /\/\//g;
const TRAILING_SLASH = /\/+$/;
const LEADING_SLASH = /^\/+/;
const UUID_IN_PATH = /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/gi;
const HEX_IN_PATH = /\b[0-9a-f]{16,64}\b/g;

const PASSWORD_POLICY_RE = {
  length: /^.{12,128}$/,
  upper: /[A-Z]/,
  lower: /[a-z]/,
  digit: /\d/,
  symbol: /[^\w\s]/,
  repeated: /(.)\1{3,}/,
  sequential: /(?:0123|1234|2345|3456|abcd|bcde|qwer|asdf)/i,
  commonWords: /\b(?:password|passwd|pwd|letmein|welcome|admin|qwerty)\b/i
};

const MARKER = "[redacted]";

function scrub(line) {
  if (typeof line !== "string" || line.length === 0) return line;
  let out = line;
  out = out.replace(SENSITIVE_QUERY_KEYS, (m, key) => m.slice(0, m.indexOf(key) + key.length + 1) + MARKER);
  for (const rule of REDACTION_RULES) {
    rule.re.lastIndex = 0;
    out = out.replace(rule.re, `${MARKER}:${rule.label}`);
  }
  if (out.includes(PEM_HEADER)) {
    const start = out.indexOf(PEM_HEADER);
    const end = out.indexOf(PEM_FOOTER);
    out = out.slice(0, start) + `${MARKER}:pem` + (end > -1 ? out.slice(end + PEM_FOOTER.length) : "");
  }
  return out;
}

function normalisePath(p) {
  return p
    .replace(DOUBLE_SLASH, "/")
    .replace(UUID_IN_PATH, ":id")
    .replace(HEX_IN_PATH, ":hash")
    .replace(TRAILING_SLASH, "")
    .split(SLASH)
    .filter(Boolean)
    .join("/");
}

function passwordIssues(candidate) {
  const issues = [];
  if (!PASSWORD_POLICY_RE.length.test(candidate)) issues.push("length");
  if (!PASSWORD_POLICY_RE.upper.test(candidate)) issues.push("upper");
  if (!PASSWORD_POLICY_RE.digit.test(candidate)) issues.push("digit");
  if (PASSWORD_POLICY_RE.repeated.test(candidate)) issues.push("repeated");
  if (PASSWORD_POLICY_RE.sequential.test(candidate)) issues.push("sequential");
  if (PASSWORD_POLICY_RE.commonWords.test(candidate)) issues.push("common");
  return issues;
}

export { scrub, normalisePath, passwordIssues, REDACTION_RULES, SENSITIVE_QUERY_KEYS, PASSWORD_POLICY_RE };
