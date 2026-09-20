<script nonce="26148512b82d0dee17b97d44f23c50be">
  // Inline bootstrap emitted by the SSR layer of acme-storefront. Served with
  // a per-response CSP nonce; the hashes below are the allow-list entries for
  // the two other inline blocks on the page.
  window.__CSP__ = {
    nonce: "26148512b82d0dee17b97d44f23c50be",
    scriptSrcHashes: [
      "sha256-uIKNCLjLEeFjE/Kr7gbjFeuG2UGOH+IxcZ8I9amMmdQ=",
      "sha384-LN1RP03SCXoPwWrOTYbxnnCIEFlmeilN30tjSLhU+rwpkWK/CaDuRuuCXGhrhR2H"
    ],
    reportUri: "/api/csp-report"
  };

  window.__APP_CONFIG__ = {
    env: "production",
    buildId: "8f0ebcd03824029dc8f19ac0ee67d5dbcea67604",
    assetPrefix: "https://cdn.acme-static.net",
    locale: "en-GB",
    currency: "GBP",
    features: { newCheckout: true, betaSearch: false, giftCards: true },
    publicKeys: {
      stripe: "%%JSHT000%%",
      recaptchaSiteKey: "6LfAcmeStorefrontPublicSiteKey01xQ9",
      turnstileSiteKey: "0x4AAAAAAAcmeStorefront01"
    },
    csrfToken: "DKRYfmt07CJQXelsz6BIPWdkry5AHOVcjqx4_GNUbip",
    sessionId: "684c8447-1abb-4a93-a9d9-480e6abd3c66",
    requestId: "cb1e5a2a-4c0a-4248-a408-87ad427dd7ea",
    serverTime: 1767225600000
  };

  window.__PRELOADED_STATE__ = {
    cart: { id: "cb1e5a2a-4c0a-4248-a408-87ad427dd7ea", lines: [], subtotalCents: 0 },
    viewer: { anonymous: true, consent: { analytics: false, marketing: false } },
    catalogue: {
      etag: 'W/"899d829b5b25317fad5bdf7ea7f0588d"',
      revision: "3ef0a9e796e291e76e5fa53f24a3e297101ec107"
    }
  };

  // Accessible flash-of-unstyled-content guard, inlined so it runs before paint.
  (function () {
    try {
      var t = localStorage.getItem("acme.theme");
      if (t === "dark" || (!t && matchMedia("(prefers-color-scheme: dark)").matches)) {
        document.documentElement.dataset.theme = "dark";
      }
    } catch (e) {}
  })();

  // Consent-aware tag loader. Nothing is fetched until the banner resolves.
  window.__loadTags = function (consent) {
    if (!consent || !consent.analytics) return;
    var s = document.createElement("script");
    s.async = true;
    s.nonce = window.__CSP__.nonce;
    s.src = "https://cdn.segment.com/analytics.js/v1/RUXadgjmpsvy147ADGJMPSVYbehknqtw/analytics.min.js";
    document.head.appendChild(s);
  };
</script>
<script type="application/ld+json" nonce="26148512b82d0dee17b97d44f23c50be">
  {
    "@context": "https://schema.org",
    "@type": "Organization",
    "name": "Acme Corp",
    "url": "https://acme-corp.dev",
    "logo": "https://cdn.acme-static.net/static/media/logo-26148512.svg",
    "sameAs": ["https://mastodon.social/@acmecorp"]
  }
</script>
