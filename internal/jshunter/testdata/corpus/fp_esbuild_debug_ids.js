// out/bundle.js — esbuild 0.27.x, format=esm, sourcemap=external
// Sentry bundler plugin injects the debug-id shim below at the top of every chunk.
(function () {
  try {
    var g = typeof window !== "undefined" ? window : typeof global !== "undefined" ? global : {};
    g._sentryDebugIds = g._sentryDebugIds || {};
    var e = new g.Error().stack;
    if (e) {
      g._sentryDebugIds[e] = "79a8b4a0-19ba-4a43-a68d-84544cb86bf0";
      g._sentryDebugIdIdentifier = "sentry-dbid-79a8b4a0-19ba-4a43-a68d-84544cb86bf0";
    }
  } catch (t) {}
})();

var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all) __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if ((from && typeof from === "object") || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, {
          get: () => from[key],
          enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable
        });
  }
  return to;
};

// src/telemetry/ids.ts
var ids_exports = {};
__export(ids_exports, {
  BUILD: () => BUILD,
  DEBUG_IDS: () => DEBUG_IDS,
  newTrace: () => newTrace
});

var BUILD = {
  debugId: "71deb677-b125-4163-aad9-612c6522409a",
  releaseId: "acme-web@2026.9.3+8f0ebcd0",
  bundleHash: "78ba480f4722ece43133b7485d2418279cc1321fac34f9700fa040248774299b",
  esbuildVersion: "0.27.4"
};

var DEBUG_IDS = {
  "out/bundle.js": "79a8b4a0-19ba-4a43-a68d-84544cb86bf0",
  "out/checkout.js": "71deb677-b125-4163-aad9-612c6522409a",
  "out/profile.js": "36ac9b72-a056-4941-aa30-24488bcd80ea"
};

var hex = "0123456789abcdef";
function rand(n) {
  var out = "";
  var buf = new Uint8Array(n);
  (globalThis.crypto || {}).getRandomValues?.(buf);
  for (var i = 0; i < n; i++) out += hex[buf[i] >> 4] + hex[buf[i] & 15];
  return out;
}

function newTrace() {
  return {
    traceId: rand(16),
    spanId: rand(8),
    parentSpanId: null,
    sampled: Math.random() < 0.05,
    debugId: BUILD.debugId
  };
}

function traceparent(ctx) {
  return "00-" + ctx.traceId + "-" + ctx.spanId + "-" + (ctx.sampled ? "01" : "00");
}

export { BUILD, DEBUG_IDS, newTrace, traceparent };
//# debugId=79a8b4a0-19ba-4a43-a68d-84544cb86bf0
//# sourceMappingURL=bundle.js.map
