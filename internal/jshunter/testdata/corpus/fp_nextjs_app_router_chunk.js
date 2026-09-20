(self.__next_f = self.__next_f || []).push([0]);
(self.__next_f = self.__next_f || []).push([
  2,
  '3:I[41923,["8812","static/chunks/8812-14429362ee39aa8b.js","9903","static/chunks/app/(shop)/layout-c00d65ee7d11b286.js"],"Providers"]\n'
]);
(self.__next_f = self.__next_f || []).push([
  2,
  '4:I[63690,["7024","static/chunks/7024-1f0291e7ade15d0b.js"],"ClientPageRoot"]\n'
]);

// Injected by next/dist/build/webpack/plugins/define-env-plugin.
self.__VERCEL_RUNTIME = {
  target: "vercel",
  region: "iad1",
  deploymentId: "HUhu7KXkxANan0DQdq3GTgt6",
  skewProtection: true,
  projectName: "acme-storefront"
};

self.__NEXT_DATA__ = {
  props: { pageProps: {} },
  page: "/[locale]/checkout",
  query: { locale: "en-GB" },
  buildId: "8f0ebcd03824029dc8f19ac0ee67d5dbcea67604",
  assetPrefix: "https://cdn.acme-static.net",
  runtimeConfig: {},
  nextExport: false,
  autoExport: false,
  isFallback: false,
  scriptLoader: []
};

self.__BUILD_MANIFEST = {
  polyfillFiles: ["static/chunks/polyfills-c67a75d1b6f99dc8.js"],
  devFiles: [],
  ampDevFiles: [],
  lowPriorityFiles: [
    "static/8f0ebcd03824029dc8f19ac0ee67d5dbcea67604/_buildManifest.js",
    "static/8f0ebcd03824029dc8f19ac0ee67d5dbcea67604/_ssgManifest.js"
  ],
  rootMainFiles: [
    "static/chunks/webpack-899d829b5b25317f.js",
    "static/chunks/main-app-2517af99998eb397.js"
  ],
  pages: {
    "/_app": ["static/chunks/pages/_app-5e507da6073ea793.js"],
    "/checkout": ["static/chunks/pages/checkout-1f0291e7ade15d0b.js"]
  }
};

self.__SSG_MANIFEST = new Set(["/", "/catalog", "/catalog/[slug]"]);
self.__SSG_MANIFEST_CB && self.__SSG_MANIFEST_CB();

// next/script + next/font preload descriptors.
const fontPreload = [
  {
    href: "/_next/static/media/inter-latin-400-normal-26148512.woff2",
    as: "font",
    type: "font/woff2",
    crossOrigin: "anonymous",
    integrity: "sha384-uIKNCLjLEeFjE/Kr7gbjFeuG2UGOH+IxcZ8I9amMmdT1O2T5XcFlXQn73+7pvPre"
  },
  {
    href: "/_next/static/media/inter-latin-600-normal-b82d0dee.woff2",
    as: "font",
    type: "font/woff2",
    crossOrigin: "anonymous",
    integrity: "sha384-LN1RP03SCXoPwWrOTYbxnnCIEFlmeilN30tjSLhU+rwpkWK/CaDuRuuCXGhrhR2H"
  }
];

// Server-action ids are HMAC digests of the module path + export name.
const serverActions = {
  "7f9c1a": "899d829b5b25317fad5bdf7ea7f0588d",
  "2b4e88": "2517af99998eb39718e6a38be8b38989",
  "c0119d": "5e507da6073ea793c370d26f9edf96ad"
};

// Request-scoped correlation headers forwarded to the RSC fetch layer.
function rscHeaders(ctx) {
  return {
    "x-request-id": ctx.requestId,
    "x-correlation-id": ctx.correlationId,
    "x-deployment-id": self.__VERCEL_RUNTIME.deploymentId,
    "next-router-state-tree": ctx.tree,
    RSC: "1"
  };
}

const defaultCtx = {
  requestId: "cb1e5a2a-4c0a-4248-a408-87ad427dd7ea",
  correlationId: "de62f7b7-8224-442c-ad0d-cf0d6d1f38b4",
  traceId: "bfc5b495-0a26-474d-af99-fbaf056ef8e0",
  spanId: "fea95d86-6d5f-4777-ad18-eebd524286fa",
  tree: ["", { children: ["(shop)", { children: ["checkout", {}] }] }]
};

export { rscHeaders, defaultCtx, fontPreload, serverActions };
