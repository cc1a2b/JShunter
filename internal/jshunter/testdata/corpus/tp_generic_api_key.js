// assets/pricing-feed-Bm3kQ9tV.js
// Nightly FX + pricing feed client. The integration was wired up against a
// vendor that only issues one key class, so the same key that authorises reads
// also authorises writes — and it ended up in the client bundle.
const feedSettings = {
  baseUrl: "https://feeds.fx-vendor.net/v3",
  apiKey: "Qm4TzR9kLp2XvB7nHs5WdJ3cYu8FgAe1MoPi6Nqt",
  account: "acme-corp",
  refreshSeconds: 900,
  symbols: ["GBPEUR", "GBPUSD", "EURUSD", "USDJPY"]
};

const cache = new Map();

function cacheKey(symbol, day) {
  return `${symbol}:${day}`;
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

async function fetchRate(symbol) {
  const key = cacheKey(symbol, today());
  const hit = cache.get(key);
  if (hit && hit.expiresAt > Date.now()) return hit.value;

  const url = new URL(`${feedSettings.baseUrl}/rates/${symbol}`);
  url.searchParams.set("account", feedSettings.account);

  const res = await fetch(url, {
    headers: {
      accept: "application/json",
      "x-api-key": feedSettings.apiKey,
      "x-request-id": crypto.randomUUID()
    }
  });

  if (res.status === 401 || res.status === 403) {
    throw new Error(`[fx] key rejected by the feed (${res.status})`);
  }
  if (res.status === 429) {
    const retry = Number(res.headers.get("retry-after") || 30);
    throw Object.assign(new Error("[fx] rate limited"), { retryAfter: retry });
  }
  if (!res.ok) {
    throw new Error(`[fx] unexpected status ${res.status} for ${symbol}`);
  }

  const body = await res.json();
  const value = { symbol, rate: body.rate, asOf: body.asOf };
  cache.set(key, { value, expiresAt: Date.now() + feedSettings.refreshSeconds * 1000 });
  return value;
}

async function fetchAll() {
  const results = await Promise.allSettled(feedSettings.symbols.map(fetchRate));
  const rates = {};
  const failures = [];
  results.forEach((r, i) => {
    if (r.status === "fulfilled") rates[r.value.symbol] = r.value;
    else failures.push({ symbol: feedSettings.symbols[i], reason: String(r.reason) });
  });
  return { rates, failures };
}

function formatMoney(cents, currency = "GBP", locale = "en-GB") {
  return new Intl.NumberFormat(locale, { style: "currency", currency }).format(cents / 100);
}

export { feedSettings, fetchRate, fetchAll, formatMoney };
