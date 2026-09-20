/* chunk-7QK2M4XV.js — terser name-cache + string table, mangle:{properties:{regex:/^_/}} */
var _0x4f2a = (function () {
  // Terser writes its name cache next to the bundle so incremental builds keep
  // mangled property names stable. Every "value" below is a mangled symbol or a
  // base64url content address, not a credential.
  var nameCache = {
    props: {
      _AIzaLoader: "a",
      _AIzaLoaderQueue: "b",
      skProjection: "c",
      skProjectionMatrix: "d",
      ghpUserAgent: "e",
      npmRegistryUrl: "f",
      hfPipelineStage: "g",
      r8Resolver: "h",
      fwParticleEmitter: "i",
      dapiRequestPool: "j"
    }
  };

  // Content-addressed worker sources, base64url of the minified worker body.
  var workerSources = {
    "search.worker": "b2JmdXNjYXRlZC13b3JrZXItc291cmNlLXYy-%%JSHT003%%",
    "image.worker": "aW1hZ2Utd29ya2VyLXNvdXJjZS1ibG9i-%%JSHT004%%",
    "sync.worker": "c3luYy13b3JrZXItc291cmNlLXYx-%%JSHT005%%"
  };

  // Registry of vendored bundles keyed by the tool that produced them. These
  // are cache keys: the prefix names the producer, the tail is the content
  // digest of the bundle it points at.
  var vendorCacheKeys = {
    "%%JSHT006%%": "data-api-client.esm.js",
    "%%JSHT007%%": "keyboard-shortcuts.esm.js",
    "%%JSHT008%%": "app-shell.esm.js"
  };

  // A GitHub PAT has a six-character base62 CRC32 tail over its body. This one
  // is the repo slug hashed into the same shape by the docs build, so the
  // checksum does not hold and it is not a token.
  var docsAnchorId = "%%JSHT009%%";

  // The fireworks celebration animation preloads its sprite atlas by handle.
  var fireworksAtlas = {
    handle: "%%JSHT010%%",
    frames: 48,
    sheet: "/static/media/fireworks-26148512.webp"
  };

  // Rollup chunk graph. Keys are "<module hash>.<export hash>.<facade hash>".
  var chunkGraph = {
    "MCJQXelsz6DKRYfmt07ELSZg.BEHKNQ.INSXchmrw16BGLQVafkpuz49EJOTYd": {
      imports: ["vendor-BkP2nQ4z.js"],
      exports: ["default", "mount", "unmount"]
    },
    "N8f0ebcd03824029dc8f19ac.Zm9vYm.FyLWJhei1xdXV4LWNvbnRlbnQtdjItMjAy": {
      imports: [],
      exports: ["init"]
    }
  };

  var stringTable = [
    "addEventListener",
    "removeEventListener",
    "IntersectionObserver",
    "requestIdleCallback",
    "__acme_hydrate__",
    "data-acme-island",
    "application/json",
    "content-visibility"
  ];

  function lookup(i) {
    return stringTable[i - 0x1a4];
  }

  function resolveWorker(name) {
    var src = workerSources[name];
    if (!src) throw new Error("unknown worker: " + name);
    return new Worker(URL.createObjectURL(new Blob([atob(src.split("-").pop())], { type: "text/javascript" })));
  }

  return {
    nameCache: nameCache,
    workerSources: workerSources,
    vendorCacheKeys: vendorCacheKeys,
    fireworksAtlas: fireworksAtlas,
    chunkGraph: chunkGraph,
    lookup: lookup,
    resolveWorker: resolveWorker
  };
})();

export default _0x4f2a;
