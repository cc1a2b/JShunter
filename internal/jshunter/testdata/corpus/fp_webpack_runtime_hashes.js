/*! acme-storefront runtime chunk - webpack 5.98.0 - production */
(self.webpackChunk_N_E = self.webpackChunk_N_E || []).push([
  [4821],
  {
    18344: function (e, t, n) {
      "use strict";
      n.d(t, { Z: () => u, chunkManifest: () => c, assetIntegrity: () => d });

      // __webpack_require__.u — maps a chunk id to its content-hashed filename.
      var r = {
        4821: "899d829b5b25317fad5bdf7ea7f0588d",
        5177: "2517af99998eb39718e6a38be8b38989",
        6390: "5e507da6073ea793c370d26f9edf96ad",
        7024: "1f0291e7ade15d0b4f1e8620b344a31b",
        8812: "14429362ee39aa8b68ffd60d427fe8bf",
        9903: "c00d65ee7d11b28648ccb3c97a41c5b6"
      };
      n.u = function (e) {
        return "static/chunks/" + e + "." + r[e] + ".js";
      };
      n.miniCssF = function (e) {
        return "static/css/" + e + "." + r[e].slice(0, 16) + ".css";
      };

      // Module-id -> short module hash, emitted by the deterministic ids plugin.
      var o = { 123: "26148512", 456: "b82d0dee", 789: "17b97d44", 1011: "f23c50be" };

      var c = {
        buildId: "8f0ebcd03824029dc8f19ac0ee67d5dbcea67604",
        contentHash: "78ba480f4722ece43133b7485d2418279cc1321fac34f9700fa040248774299b",
        runtimeHash: "3ef0a9e796e291e76e5fa53f24a3e297101ec107",
        revision: "d37fc76ca361f5ffe8f3f94623d326563efd69e9",
        etag: 'W/"6b535fcd83f5c1f0341151c92a9c074cddd217c1930fd7f2c02c380078c5afea"',
        moduleIds: o,
        chunkIds: Object.keys(r).map(Number)
      };

      // Emitted by subresource-integrity-webpack-plugin.
      var d = {
        "static/chunks/4821.js": "sha384-uIKNCLjLEeFjE/Kr7gbjFeuG2UGOH+IxcZ8I9amMmdT1O2T5XcFlXQn73+7pvPre",
        "static/chunks/5177.js": "sha384-LN1RP03SCXoPwWrOTYbxnnCIEFlmeilN30tjSLhU+rwpkWK/CaDuRuuCXGhrhR2H",
        "static/css/6390.css": "sha384-tVWMuRkNJdpf5NzdN2MxtXzCnDH2X+6AiHA+f9tyLbZVlXHSdIdBJk8X6BOxzElW"
      };

      // Regional asset manifest: <asset digest>-<edge pop>.
      var f = {
        "%%JSHT017%%": "/static/edge/us1/storefront.js",
        "%%JSHT018%%": "/static/edge/us2/storefront.js",
        "5e507da6073ea793c370d26f9edf96ad-eu1": "/static/edge/eu1/storefront.js"
      };

      // IndexedDB cache index. Keys are "key-" + the 32-char asset digest.
      var p = {
        "%%JSHT019%%": { size: 148213, gz: 41022 },
        "%%JSHT007%%": { size: 92004, gz: 28711 },
        "%%JSHT020%%": { size: 310448, gz: 88190 }
      };

      // Service-worker precache manifest written by workbox-webpack-plugin.
      var h = [
        { url: "/static/chunks/4821.js", revision: "899d829b5b25317fad5bdf7ea7f0588d" },
        { url: "/static/chunks/5177.js", revision: "2517af99998eb39718e6a38be8b38989" },
        { url: "/static/media/logo.svg", revision: null }
      ];

      // App-shell version marker written by the release pipeline. The "v1."
      // prefix is the shell schema version, the tail is the git commit sha.
      var m = {
        appVersion: "%%JSHT008%%",
        appChannel: "stable",
        installedAt: 1767225600000
      };

      function u(e) {
        var t = document.createElement("script");
        t.src = n.p + n.u(e);
        t.crossOrigin = "anonymous";
        if (d["static/chunks/" + e + ".js"]) {
          t.integrity = d["static/chunks/" + e + ".js"];
        }
        document.head.appendChild(t);
        return new Promise(function (r, o) {
          t.onload = function () {
            r({ chunk: e, hash: c.contentHash, app: m.appVersion });
          };
          t.onerror = function () {
            o(new Error("chunk load failed: " + e));
          };
        });
      }

      n.p = "https://cdn.acme-static.net/_next/";
      t.regionalAssets = f;
      t.precache = h;
      t.cacheIndex = p;
    }
  }
]);
