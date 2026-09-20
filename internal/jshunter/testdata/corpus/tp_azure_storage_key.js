// assets/asset-sync-Bq6nT2wK.js
// Editorial asset sync. It talks to Blob Storage with a full account
// connection string instead of a scoped SAS URL, so the shared key that grants
// read/write/delete on the whole account ships to the browser.
//
// The key below is 88 base64 characters that decode to 64 bytes of ASCII, which
// is what makes it structurally valid without being usable anywhere.
const AZURE_STORAGE_CONNECTION_STRING =
  "DefaultEndpointsProtocol=https;AccountName=acmeeditorial;%%JSHT022%%;EndpointSuffix=core.windows.net";

const CONTAINER = "editorial-media";
const MAX_BLOCK_BYTES = 4 * 1024 * 1024;

function parseConnectionString(cs) {
  return Object.fromEntries(
    cs
      .split(";")
      .filter(Boolean)
      .map((pair) => {
        const idx = pair.indexOf("=");
        return [pair.slice(0, idx), pair.slice(idx + 1)];
      })
  );
}

const parsed = parseConnectionString(AZURE_STORAGE_CONNECTION_STRING);
const accountName = parsed.AccountName;
const accountKey = parsed.AccountKey;
const blobEndpoint = `https://${accountName}.blob.${parsed.EndpointSuffix}`;

async function signingKey() {
  const raw = Uint8Array.from(atob(accountKey), (c) => c.charCodeAt(0));
  return crypto.subtle.importKey("raw", raw, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
}

async function sharedKeyAuth(method, path, headers) {
  const canonical = [
    method.toUpperCase(),
    headers["content-encoding"] ?? "",
    headers["content-language"] ?? "",
    headers["content-length"] ?? "",
    "",
    headers["content-type"] ?? "",
    "",
    "",
    "",
    "",
    "",
    "",
    `x-ms-date:${headers["x-ms-date"]}`,
    `x-ms-version:${headers["x-ms-version"]}`,
    `/${accountName}${path}`
  ].join("\n");
  const key = await signingKey();
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(canonical));
  return `SharedKey ${accountName}:${btoa(String.fromCharCode(...new Uint8Array(sig)))}`;
}

async function putBlob(name, blob) {
  const path = `/${CONTAINER}/${encodeURIComponent(name)}`;
  const headers = {
    "x-ms-date": new Date().toUTCString(),
    "x-ms-version": "2025-11-05",
    "x-ms-blob-type": "BlockBlob",
    "content-type": blob.type || "application/octet-stream",
    "content-length": String(blob.size)
  };
  headers.authorization = await sharedKeyAuth("PUT", path, headers);
  const res = await fetch(blobEndpoint + path, { method: "PUT", headers, body: blob });
  if (!res.ok) throw new Error(`blob upload failed: ${res.status}`);
  return blobEndpoint + path;
}

async function listBlobs(prefix = "") {
  const path = `/${CONTAINER}?restype=container&comp=list&prefix=${encodeURIComponent(prefix)}`;
  const headers = { "x-ms-date": new Date().toUTCString(), "x-ms-version": "2025-11-05" };
  headers.authorization = await sharedKeyAuth("GET", `/${CONTAINER}`, headers);
  const res = await fetch(blobEndpoint + path, { headers });
  if (!res.ok) throw new Error(`list failed: ${res.status}`);
  const xml = new DOMParser().parseFromString(await res.text(), "application/xml");
  return [...xml.querySelectorAll("Blob > Name")].map((n) => n.textContent);
}

export { AZURE_STORAGE_CONNECTION_STRING, blobEndpoint, putBlob, listBlobs, MAX_BLOCK_BYTES };
