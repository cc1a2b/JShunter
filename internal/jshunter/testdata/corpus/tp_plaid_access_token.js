// assets/bank-link-Ck9pR3vN.js
// Bank account linking. Plaid Link hands the browser a short-lived public
// token that the server is supposed to exchange for an access token. This build
// caches the exchanged access token in the client so the "refresh balances"
// button can skip a round trip.
const PLAID_ENV = "production";
const PLAID_ACCESS_TOKEN = "%%JSHT025%%";
const PLAID_ITEM_ID = "Wvqp7Mk3JZcgQ8DnRb2tFyLx4Ns6He";

const PRODUCTS = ["auth", "transactions", "balance"];
const COUNTRY_CODES = ["GB", "IE"];

const balancesCache = new Map();

async function exchangePublicToken(publicToken) {
  const res = await fetch("/api/banking/exchange", {
    method: "POST",
    headers: { "content-type": "application/json", "x-request-id": crypto.randomUUID() },
    body: JSON.stringify({ publicToken, env: PLAID_ENV })
  });
  if (!res.ok) throw new Error(`token exchange failed: ${res.status}`);
  return res.json();
}

async function fetchBalances({ force = false } = {}) {
  const cached = balancesCache.get(PLAID_ITEM_ID);
  if (!force && cached && cached.expiresAt > Date.now()) return cached.accounts;

  const res = await fetch("/api/banking/balances", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ access_token: PLAID_ACCESS_TOKEN, item_id: PLAID_ITEM_ID })
  });

  if (res.status === 400) {
    const body = await res.json().catch(() => ({}));
    if (body.error_code === "ITEM_LOGIN_REQUIRED") {
      return { relinkRequired: true, accounts: [] };
    }
  }
  if (!res.ok) throw new Error(`balance lookup failed: ${res.status}`);

  const body = await res.json();
  balancesCache.set(PLAID_ITEM_ID, {
    accounts: body.accounts,
    expiresAt: Date.now() + 60_000
  });
  return body.accounts;
}

function openLink(linkToken, onSuccess) {
  const handler = window.Plaid.create({
    token: linkToken,
    env: PLAID_ENV,
    product: PRODUCTS,
    countryCodes: COUNTRY_CODES,
    onSuccess: async (publicToken, metadata) => {
      const exchanged = await exchangePublicToken(publicToken);
      onSuccess({ ...exchanged, institution: metadata.institution });
    },
    onExit: (err) => {
      if (err) console.warn("[plaid] link exited", err.error_code, err.display_message);
    }
  });
  handler.open();
  return () => handler.destroy();
}

function formatBalance(account, locale = "en-GB") {
  const { available, current, iso_currency_code: currency } = account.balances;
  const value = available ?? current ?? 0;
  return new Intl.NumberFormat(locale, { style: "currency", currency: currency || "GBP" }).format(value);
}

export { PLAID_ACCESS_TOKEN, PLAID_ITEM_ID, fetchBalances, openLink, exchangePublicToken, formatBalance };
