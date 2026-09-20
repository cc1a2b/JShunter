// assets/setup-wizard-Bk9pR4tM.js
// Self-hosted admin console. The wizard renders a form pre-filled with the
// default configuration template; every credential slot below is unset until
// the operator saves real values into the server-side secret store.
const DEFAULT_CONFIG = {
  integrations: {
    analytics: { enabled: false, apiKey: "YOUR_API_KEY", projectId: "" },
    crm: { enabled: false, apiKey: "REPLACE_ME", region: "eu" },
    search: { enabled: false, apiKey: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", index: "" },
    mailer: { enabled: false, apiKey: "%%JSHT014%%", domain: "" },
    mailerAlt: { enabled: false, apiKey: "%%JSHT015%%", domain: "" },
    objectStore: {
      enabled: false,
      accessKeyId: "%%JSHT016%%",
      secretAccessKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      bucket: "",
      endpoint: "https://s3.eu-west-1.amazonaws.com"
    },
    telephony: {
      enabled: false,
      accountSid: "%%JSHT038%%",
      apiKeySid: "%%JSHT039%%",
      authToken: "00000000000000000000000000000000"
    }
  },
  database: {
    url: "%%JSHT027%%",
    templatedUrl: "%%JSHT028%%",
    readReplicaUrl: "%%JSHT029%%",
    pool: { min: 2, max: 20, idleTimeoutMillis: 30000 }
  },
  cache: {
    url: "%%JSHT030%%",
    ttlSeconds: 900
  },
  security: {
    signingSecret: "0123456789abcdef0123456789abcdef",
    previousSigningSecret: "deadbeefdeadbeefdeadbeefdeadbeef",
    sessionCookieName: "acme.sid",
    sameSite: "lax",
    secureCookies: true
  },
  smtp: {
    host: "",
    port: 587,
    username: "",
    password: "changeme",
    fromAddress: "no-reply@acme-corp.dev"
  }
};

const UNSET_MARKERS = [
  "YOUR_API_KEY",
  "REPLACE_ME",
  "CHANGE_ME",
  "changeme",
  "notset",
  "",
  "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "00000000000000000000000000000000",
  "0123456789abcdef0123456789abcdef"
];

function isUnset(value) {
  if (value == null) return true;
  const v = String(value).trim();
  if (v.length === 0) return true;
  if (UNSET_MARKERS.includes(v)) return true;
  if (/^(.)\1+$/.test(v)) return true;
  if (/\$\{[A-Z0-9_]+\}/.test(v)) return true;
  return false;
}

function pendingIntegrations(config = DEFAULT_CONFIG) {
  return Object.entries(config.integrations)
    .filter(([, cfg]) => !cfg.enabled || Object.values(cfg).some(isUnset))
    .map(([name]) => name);
}

function validationMessages(config = DEFAULT_CONFIG) {
  const out = [];
  if (isUnset(config.database.url.split(":")[2])) out.push("Set a database password before continuing.");
  if (isUnset(config.security.signingSecret)) out.push("Generate a signing secret.");
  if (isUnset(config.smtp.host)) out.push("Add an SMTP host so the console can send mail.");
  for (const name of pendingIntegrations(config)) {
    out.push(`The ${name} integration is not configured yet.`);
  }
  return out;
}

export { DEFAULT_CONFIG, UNSET_MARKERS, isUnset, pendingIntegrations, validationMessages };
