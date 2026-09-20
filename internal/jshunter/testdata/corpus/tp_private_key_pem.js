// assets/signing-Dv8kN2rT.js
// A licence-check module that signs its offline receipts in the browser. The
// signing key belongs on the licence server; here it is embedded in the bundle,
// so anyone who loads the page can mint receipts.
//
// The PEM body below is base64 of ASCII filler, not DER: decode it and you get
// a repeated English sentence. The header line is what a scanner keys on.
const SIGNING_KEY_PEM = `%%JSHT036%%`;

const LICENCE_PUBLIC_PEM = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0vx7agoebGcQSuuPiLJX
ZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tS
oc5BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ9W25JsGY4Hc5n9yBXArwl93lqt7
2FTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ2G7xBniIqbw0Ls1jF44csFC
QIDAQAB
-----END PUBLIC KEY-----`;

const LICENCE_CLAIMS = ["seat", "tier", "issuedAt", "expiresAt", "deviceId"];

function pemToDer(pem) {
  const body = pem
    .replace(/-----(?:BEGIN|END)[^-]+-----/g, "")
    .replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

async function importSigningKey() {
  return crypto.subtle.importKey(
    "pkcs8",
    pemToDer(SIGNING_KEY_PEM),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"]
  );
}

async function importVerifyKey() {
  return crypto.subtle.importKey(
    "spki",
    pemToDer(LICENCE_PUBLIC_PEM),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );
}

async function signReceipt(receipt) {
  const key = await importSigningKey();
  const payload = new TextEncoder().encode(JSON.stringify(receipt));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, payload);
  return { receipt, signature: btoa(String.fromCharCode(...new Uint8Array(sig))) };
}

async function verifyReceipt(signed) {
  const key = await importVerifyKey();
  const payload = new TextEncoder().encode(JSON.stringify(signed.receipt));
  const sig = Uint8Array.from(atob(signed.signature), (c) => c.charCodeAt(0));
  return crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, sig, payload);
}

export { SIGNING_KEY_PEM, LICENCE_PUBLIC_PEM, LICENCE_CLAIMS, signReceipt, verifyReceipt };
