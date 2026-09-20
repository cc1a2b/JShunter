// assets/checkout-payments-Dm4kQ7wR.js
// Braintree drop-in. The correct client-side input is a *client token* minted
// per shopper; this build ships the gateway access token instead, which grants
// full API access to the merchant account.
const BRAINTREE_ACCESS_TOKEN =
  "%%JSHT023%%";

const MERCHANT_ID = "acmemerchant0001";
const CURRENCY = "GBP";
const SUPPORTED_METHODS = ["card", "paypal", "applePay", "googlePay"];

function gatewayConfig() {
  const [, environment, merchantId] = BRAINTREE_ACCESS_TOKEN.split("$");
  return { environment, merchantId, currency: CURRENCY };
}

async function createDropIn(container, amountCents) {
  const braintree = await import("braintree-web-drop-in");
  return braintree.create({
    authorization: BRAINTREE_ACCESS_TOKEN,
    container,
    locale: "en_GB",
    card: { cardholderName: { required: true } },
    paypal: {
      flow: "checkout",
      amount: (amountCents / 100).toFixed(2),
      currency: CURRENCY,
      commit: true
    },
    applePay: {
      displayName: "Acme Corp",
      paymentRequest: {
        total: { label: "Acme Corp", amount: (amountCents / 100).toFixed(2) },
        countryCode: "GB",
        currencyCode: CURRENCY
      }
    },
    threeDSecure: true
  });
}

async function pay(instance, order) {
  const { nonce, details, type } = await instance.requestPaymentMethod({
    threeDSecure: { amount: (order.totalCents / 100).toFixed(2) }
  });
  const res = await fetch("/api/checkout/pay", {
    method: "POST",
    headers: { "content-type": "application/json", "x-request-id": crypto.randomUUID() },
    body: JSON.stringify({
      orderId: order.id,
      nonce,
      method: type,
      merchantId: MERCHANT_ID,
      amountCents: order.totalCents,
      currency: CURRENCY
    })
  });
  if (res.status === 402) {
    const body = await res.json().catch(() => ({}));
    throw Object.assign(new Error(body.message || "Your bank declined the payment."), {
      declineCode: body.decline_code
    });
  }
  if (!res.ok) throw new Error(`payment failed with status ${res.status}`);
  return { ...(await res.json()), last4: details?.lastFour ?? null };
}

function methodsFor(region) {
  if (region === "GB" || region === "IE") return SUPPORTED_METHODS;
  return SUPPORTED_METHODS.filter((m) => m !== "applePay");
}

export { BRAINTREE_ACCESS_TOKEN, MERCHANT_ID, createDropIn, pay, gatewayConfig, methodsFor };
