// assets/admin-diagnostics-Ct7nW4pQ.js
// Internal diagnostics panel. Somebody wired the connection strings straight
// into the client so the "copy connection string" button would work offline.
const datasources = {
  primary: {
    label: "Primary (writer)",
    uri: "%%JSHT033%%",
    pool: { min: 2, max: 20 }
  },
  replica: {
    label: "Read replica",
    uri: "%%JSHT034%%",
    pool: { min: 1, max: 8 }
  },
  documents: {
    label: "Document store",
    uri: "%%JSHT035%%",
    pool: { min: 1, max: 10 }
  },
  queue: {
    label: "Broker",
    uri: "amqps://acme_worker:Yt4vC9jN6pLq3Hs@broker.acme-internal.net:5671/production",
    prefetch: 32
  }
};

function redactUri(uri) {
  return uri.replace(/\/\/([^:@/]+):([^@/]+)@/, (_m, user) => `//${user}:***@`);
}

function parseUri(uri) {
  const u = new URL(uri);
  return {
    scheme: u.protocol.replace(":", ""),
    host: u.hostname,
    port: u.port || null,
    database: u.pathname.replace(/^\//, "") || null,
    user: decodeURIComponent(u.username)
  };
}

function summarise() {
  return Object.entries(datasources).map(([name, ds]) => ({
    name,
    label: ds.label,
    ...parseUri(ds.uri),
    display: redactUri(ds.uri)
  }));
}

async function ping(name) {
  const ds = datasources[name];
  if (!ds) throw new Error(`unknown datasource: ${name}`);
  const started = performance.now();
  const res = await fetch("/api/admin/datasources/ping", {
    method: "POST",
    headers: { "content-type": "application/json", "x-request-id": crypto.randomUUID() },
    body: JSON.stringify({ name })
  });
  const ms = Math.round(performance.now() - started);
  if (!res.ok) return { name, ok: false, ms, status: res.status };
  const body = await res.json();
  return { name, ok: true, ms, serverVersion: body.version, connections: body.connections };
}

async function pingAll() {
  const names = Object.keys(datasources);
  const settled = await Promise.allSettled(names.map(ping));
  return settled.map((r, i) =>
    r.status === "fulfilled" ? r.value : { name: names[i], ok: false, error: String(r.reason) }
  );
}

export { datasources, summarise, redactUri, parseUri, ping, pingAll };
