// assets/inline-assets-Ck2pV9wN.js
// Rollup url/asset plugin inlined every asset under the 8 KB threshold as a
// data: URI. Nothing here is a credential — each blob decodes to an image, a
// font subset, a JSON config, a JWKS document, or a run of silence.

const ICON_TRANSPARENT_PX =
  "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

const ICON_CART =
  "data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTcgMThhMiAyIDAgMTAwIDQgMiAyIDAgMDAwLTR6Ii8+PC9zdmc+";

// Inter subset, 4 glyph ranges, emitted by subfont. Trimmed for the bundle.
const FONT_INTER_SUBSET =
  "data:font/woff2;base64,d09GMgABAAAAAAoAAAoAAAAB4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGhYbjCocgQgGYACDagsyAAE2AiQDgWQEIAWDLAeBXhu9CDLDcNzGuhMEQpSKEtmbEZH5Uu7/7tzbLhLU1bQY1XSNo0Vd8yhJlDRR0mTT9v//n3PffZvbzvPMhNNpJp3O0+k0nU7T6TSdTtPpNJ1O0+k0nU7T6TSdTtPpNJ1O0+k0nU4";

// The runtime config the server renders into the page; base64 only so that a
// literal '<' in a feature-flag name cannot break out of the script tag.
const RUNTIME_CONFIG_B64 =
  "eyJsb2NhbGUiOiJlbi1HQiIsImN1cnJlbmN5IjoiR0JQIiwiZmxhZ3MiOnsibmV3Q2hlY2tvdXQiOnRydWUsImJldGFTZWFyY2giOmZhbHNlfSwiY2RuIjoiaHR0cHM6Ly9jZG4uYWNtZS1zdGF0aWMubmV0In0=";

// The identity provider's public JWKS, baked in so the first token check does
// not have to wait on a network round-trip. Public keys only.
const JWKS_B64 =
  "eyJrZXlzIjpbeyJrdHkiOiJSU0EiLCJ1c2UiOiJzaWciLCJraWQiOiIyMDI2LTA0LXJvdGF0ZS1hIiwiYWxnIjoiUlMyNTYiLCJuIjoiMHZ4N2Fnb2ViR2NRU3V1UGlMSlhacHROOW5uZHJRbWJYRXBzMmFpQUZiV2hNNzhMaFd4NGNiYmZBQXRWVDg2end1MVJLN2FQRkZ4dWhEUjFMNnRTb2NfQkpFQ1BlYldLUlhqQlpDaUZWNG4zb2tuamhNc3RuNjR0Wl8yVy01SnNHWTRIYzVuOXlCWEFyd2w5M2xxdDdfUk41dzZDZjBoNFF5UTV2LTY1WUdqUVIwX0ZEVzJRdnpxWTM2OFFRTWljQXRhU3F6czhLSlpnblliOWM3ZDB6Z2RBWkh6dTZxTVF2Ukw1aGFqcm4xbjkxQ2JPcGJJU0QwOHFOTHlyZGt0LWJGVFdoQUk0dk1RRmg2V2VadTBmTTRsRmQyTmNSd3IzWFBrc0lOSGFRLUdfeEJuaUlxYncwTHMxakY0NC1jc0ZDdXIta0VnVThhd2FwSnpLbnFES2d3IiwiZSI6IkFRQUIifV19";

// Short marketing string, base64 so the copy team can ship it without a deploy.
const STRAPLINE_B64 =
  "VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZyB3aGlsZSB0aGUgYnVpbGQgY2FjaGUgd2FybXMgdXAu";

// 1024 zeroed PCM samples, used to prime the audio worklet before the first
// real buffer arrives. All-zero input base64-encodes to a run of 'A'.
const SILENT_PCM_B64 =
  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

function decodeJSON(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return JSON.parse(new TextDecoder().decode(bytes));
}

function decodeText(b64) {
  return new TextDecoder().decode(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
}

const runtimeConfig = decodeJSON(RUNTIME_CONFIG_B64);
const jwks = decodeJSON(JWKS_B64);
const strapline = decodeText(STRAPLINE_B64);

function preloadInlineAssets() {
  [ICON_TRANSPARENT_PX, ICON_CART, FONT_INTER_SUBSET].forEach((href) => {
    const link = document.createElement("link");
    link.rel = "preload";
    link.as = href.startsWith("data:font") ? "font" : "image";
    link.href = href;
    if (link.as === "font") link.crossOrigin = "anonymous";
    document.head.appendChild(link);
  });
}

export {
  ICON_TRANSPARENT_PX,
  ICON_CART,
  FONT_INTER_SUBSET,
  RUNTIME_CONFIG_B64,
  JWKS_B64,
  STRAPLINE_B64,
  SILENT_PCM_B64,
  runtimeConfig,
  jwks,
  strapline,
  preloadInlineAssets
};
