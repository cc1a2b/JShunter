// assets/observability-Cf6mX3qP.js
// Browser telemetry wiring: OpenTelemetry web SDK, Datadog RUM and a feature
// flag client. RUM client tokens and client-side flag ids are public: the
// vendors scope them to ingest-only and expect them in the page.
import { WebTracerProvider } from "@opentelemetry/sdk-trace-web";
import { ZoneContextManager } from "@opentelemetry/context-zone";
import { W3CTraceContextPropagator } from "@opentelemetry/core";

const datadogRum = {
  applicationId: "36ac9b72-a056-4941-aa30-24488bcd80ea",
  clientToken: "pub899d829b5b25317fad5bdf7ea7f0588d",
  site: "datadoghq.eu",
  service: "acme-storefront",
  env: "production",
  version: "2026.9.3",
  sessionSampleRate: 20,
  sessionReplaySampleRate: 2,
  trackResources: true,
  allowedTracingUrls: ["https://api.acme-corp.dev"]
};

const launchDarkly = {
  clientSideId: "26148512b82d0dee17b97d44",
  bootstrap: "localStorage",
  streaming: true
};

const otel = {
  serviceName: "acme-storefront-web",
  collector: "https://otlp.acme-corp.dev/v1/traces",
  propagators: ["tracecontext", "baggage"],
  resourceAttributes: {
    "service.name": "acme-storefront-web",
    "service.version": "2026.9.3",
    "deployment.environment": "production",
    "telemetry.sdk.language": "webjs"
  }
};

// A request in flight carries the ids below; they are correlation handles with
// no authority attached to them.
const activeContext = {
  traceId: "bfc5b495-0a26-474d-af99-fbaf056ef8e0",
  spanId: "fea95d86-6d5f-4777-ad18-eebd524286fa",
  parentSpanId: "71deb677-b125-4163-aad9-612c6522409a",
  requestId: "cb1e5a2a-4c0a-4248-a408-87ad427dd7ea",
  correlationId: "de62f7b7-8224-442c-ad0d-cf0d6d1f38b4",
  sessionId: "684c8447-1abb-4a93-a9d9-480e6abd3c66"
};

const traceparent = "00-bfc5b4950a26474daf99fbaf056ef8e0-fea95d866d5f4777-01";
const tracestate = "acme=t61rcWkgMzE,dd=s:1;p:fea95d866d5f4777";
const baggage = "acme.tier=free,acme.surface=storefront,acme.build=8f0ebcd0";

function makeProvider() {
  const provider = new WebTracerProvider({ resource: otel.resourceAttributes });
  provider.register({
    contextManager: new ZoneContextManager(),
    propagator: new W3CTraceContextPropagator()
  });
  return provider;
}

function instrumentFetch(provider) {
  const original = window.fetch.bind(window);
  window.fetch = async function (input, init = {}) {
    const headers = new Headers(init.headers || {});
    headers.set("traceparent", traceparent);
    headers.set("tracestate", tracestate);
    headers.set("baggage", baggage);
    headers.set("x-request-id", activeContext.requestId);
    headers.set("x-correlation-id", activeContext.correlationId);
    const started = performance.now();
    try {
      const res = await original(input, { ...init, headers });
      report({ url: String(input), status: res.status, ms: performance.now() - started });
      return res;
    } catch (err) {
      report({ url: String(input), status: 0, ms: performance.now() - started, error: String(err) });
      throw err;
    }
  };
}

function report(event) {
  if (!navigator.sendBeacon) return;
  const body = JSON.stringify({
    ...event,
    ...activeContext,
    service: datadogRum.service,
    version: datadogRum.version
  });
  navigator.sendBeacon(otel.collector, new Blob([body], { type: "application/json" }));
}

export { datadogRum, launchDarkly, otel, activeContext, traceparent, tracestate, baggage, makeProvider, instrumentFetch };
