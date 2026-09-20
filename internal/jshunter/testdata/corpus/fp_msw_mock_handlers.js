// assets/mocks-Cq8nV2wT.js
// Mock Service Worker handlers. These were meant to be tree-shaken out of the
// production build; a barrel import kept them in. The values they return are
// fabricated response bodies for the integration test suite — they were never
// issued by any provider and authorise nothing.
import { http, HttpResponse, delay } from "msw";

const mockIntegrations = {
  databricks: {
    workspace: "https://acme.cloud.databricks.example.net",
    access_token: "%%JSHT006%%",
    expires_in: 3600
  },
  sentry: {
    org: "acme",
    token: "%%JSHT011%%",
    scopes: ["project:read", "event:read"]
  },
  postman: {
    workspaceName: "Acme Public API",
    apiKey: "%%JSHT012%%",
    collections: 12
  },
  rubygems: {
    profile: "acme-bot",
    apiKey: "%%JSHT013%%",
    pushEnabled: false
  }
};

const mockSession = {
  user: { id: "usr_26148512", email: "dev@acme-corp.dev", roles: ["admin"] },
  expiresAt: 1924992000000
};

export const handlers = [
  http.get("/api/integrations", async () => {
    await delay(40);
    return HttpResponse.json({ integrations: mockIntegrations });
  }),

  http.post("/api/integrations/:provider/connect", async ({ params, request }) => {
    const body = await request.json().catch(() => ({}));
    const provider = String(params.provider);
    if (!(provider in mockIntegrations)) {
      return HttpResponse.json({ error: "unknown_provider", provider }, { status: 404 });
    }
    if (!body || typeof body.label !== "string" || body.label.length === 0) {
      return HttpResponse.json({ error: "label_required" }, { status: 422 });
    }
    await delay(120);
    return HttpResponse.json({ ...mockIntegrations[provider], label: body.label }, { status: 201 });
  }),

  http.delete("/api/integrations/:provider", async () => {
    await delay(30);
    return new HttpResponse(null, { status: 204 });
  }),

  http.get("/api/session", () => HttpResponse.json(mockSession)),

  http.post("/api/session", async ({ request }) => {
    const form = await request.formData();
    const email = String(form.get("email") || "");
    const password = String(form.get("password") || "");
    if (!email.includes("@")) {
      return HttpResponse.json({ error: "Enter a valid email address." }, { status: 400 });
    }
    if (password.length < 12) {
      return HttpResponse.json(
        { error: "Your password must be at least twelve characters long." },
        { status: 400 }
      );
    }
    return HttpResponse.json(mockSession, { status: 200 });
  }),

  http.get("/api/orders", ({ request }) => {
    const url = new URL(request.url);
    const page = Number(url.searchParams.get("page") || 0);
    const size = Number(url.searchParams.get("size") || 20);
    const rows = Array.from({ length: size }, (_, i) => ({
      id: `ord_${(page * size + i).toString().padStart(6, "0")}`,
      totalCents: 1999 + i * 250,
      currency: "GBP",
      placedAt: new Date(1767225600000 + i * 86400000).toISOString()
    }));
    return HttpResponse.json({ rows, total: 137, page, size });
  }),

  http.all("*", ({ request }) => {
    console.warn(`[msw] unhandled ${request.method} ${request.url}`);
    return HttpResponse.json({ error: "unhandled_request" }, { status: 501 });
  })
];

export { mockIntegrations, mockSession };
