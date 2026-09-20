// assets/telemetry-Bx8kM4pL.js
// Every identifier in this module is a *publishable* key: the vendors below
// document these values as safe to ship in client bundles. Rotating them is a
// deploy, not an incident.
const analyticsConfig = {
  segment: {
    writeKey: "RUXadgjmpsvy147ADGJMPSVYbehknqtw",
    cdn: "https://cdn.segment.com/analytics.js/v1",
    integrations: { "Segment.io": true, Amplitude: true, Intercom: false }
  },
  sentry: {
    dsn: "https://5e507da6073ea793c370d26f9edf96ad@o4507221.ingest.de.sentry.io/4507221000000001",
    release: "acme-web@2026.9.3+8f0ebcd0",
    environment: "production",
    tracesSampleRate: 0.05,
    replaysSessionSampleRate: 0.01
  },
  stripe: {
    publishableKey: "%%JSHT000%%",
    apiVersion: "2026-06-30.basil",
    locale: "en-GB"
  },
  mapbox: {
    accessToken:
      "pk.BIPWdkry5CJQXelsz6DKRYfmt07ELSZgnu18FMTahov29GNUbipw3AHOVcjq.JOTYdinsx27CHMRWbglqv0",
    style: "mapbox://styles/acme/clx7q2n4k00p901qz8b2d3e4f",
    center: [-0.1276, 51.5072]
  },
  ga4: { measurementId: "G-7QK2M4XVD1", sendPageView: false },
  amplitude: { apiKey: "899d829b5b25317fad5bdf7ea7f0588d", serverZone: "EU" },
  hotjar: { siteId: 3918274, version: 6 },
  intercom: { appId: "q7x2md9p" }
};

// Meta Pixel. `fbq` is loaded from connect.facebook.net; the consent payload
// below is the base64 blob the tag manager hands to the pixel on page load.
const metaPixel = {
  pixelId: "918273645012",
  consentPayload: "%%JSHT001%%",
  autoConfig: true,
  dataProcessingOptions: ["LDU"]
};

function loadSegment() {
  const s = document.createElement("script");
  s.async = true;
  s.src = `${analyticsConfig.segment.cdn}/${analyticsConfig.segment.writeKey}/analytics.min.js`;
  s.crossOrigin = "anonymous";
  document.head.appendChild(s);
}

function loadStripe() {
  return import("https://js.stripe.com/v3/").then(() =>
    window.Stripe(analyticsConfig.stripe.publishableKey, {
      apiVersion: analyticsConfig.stripe.apiVersion,
      locale: analyticsConfig.stripe.locale
    })
  );
}

function loadMapbox(container) {
  return import("mapbox-gl").then(({ default: mapboxgl }) => {
    mapboxgl.accessToken = analyticsConfig.mapbox.accessToken;
    return new mapboxgl.Map({
      container,
      style: analyticsConfig.mapbox.style,
      center: analyticsConfig.mapbox.center,
      zoom: 11
    });
  });
}

function initMetaPixel() {
  if (typeof window.fbq !== "function") return;
  window.fbq("init", metaPixel.pixelId, {}, { agent: "acme-web" });
  window.fbq("dataProcessingOptions", metaPixel.dataProcessingOptions);
  window.fbq("track", "PageView");
}

export { analyticsConfig, metaPixel, loadSegment, loadStripe, loadMapbox, initMetaPixel };
