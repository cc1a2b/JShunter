// assets/support-widget-Cm4qT8zR.js
// Twilio resource SIDs are opaque *identifiers*, not credentials: they appear
// in dashboard URLs, webhook payloads and client SDK config. The auth token and
// the API key secret live on the server and never reach this bundle.
const twilioConfig = {
  accountSid: "%%JSHT040%%",
  apiKeySid: "%%JSHT041%%",
  messagingServiceSid: "%%JSHT042%%",
  conversationsServiceSid: "%%JSHT043%%",
  verifyServiceSid: "VA14429362ee39aa8b68ffd60d427fe8bf",
  taskRouterWorkspaceSid: "WSc00d65ee7d11b28648ccb3c97a41c5b6",
  flexFlowSid: "FO899d829b5b25317fad5bdf7ea7f0588d",
  region: "ie1",
  edge: "dublin"
};

// The browser never holds a long-lived credential: it asks our backend for a
// short-lived grant, which the backend mints with the API key *secret*.
const tokenEndpoint = "/api/support/voice-grant";

async function mintVoiceGrant(identity) {
  const res = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/json", "x-request-id": crypto.randomUUID() },
    body: JSON.stringify({
      identity,
      accountSid: twilioConfig.accountSid,
      apiKeySid: twilioConfig.apiKeySid,
      ttlSeconds: 600
    })
  });
  if (!res.ok) throw new Error(`[voice] grant request failed with ${res.status}`);
  const { grant, expiresAt } = await res.json();
  return { grant, expiresAt };
}

async function startCall(identity, to) {
  const { Device } = await import("@twilio/voice-sdk");
  const { grant } = await mintVoiceGrant(identity);
  const device = new Device(grant, {
    edge: twilioConfig.edge,
    codecPreferences: ["opus", "pcmu"],
    logLevel: "warn"
  });
  device.on("error", (e) => console.warn("[voice] device error", e.code, e.message));
  await device.register();
  return device.connect({ params: { To: to, ServiceSid: twilioConfig.messagingServiceSid } });
}

// Conversations (chat) widget config. Same story: SIDs only.
const chatConfig = {
  serviceSid: twilioConfig.conversationsServiceSid,
  conversationSid: "CH899d829b5b25317fad5bdf7ea7f0588d",
  participantSid: "MB2517af99998eb39718e6a38be8b38989",
  channelSid: "CH5e507da6073ea793c370d26f9edf96ad",
  attributes: { locale: "en-GB", surface: "storefront", tier: "free" }
};

// Verify (SMS OTP) widget config.
const verifyConfig = {
  serviceSid: twilioConfig.verifyServiceSid,
  channels: ["sms", "call", "whatsapp"],
  codeLength: 6,
  rateLimitKey: "phone-per-hour",
  copy: {
    prompt: "We sent a six-digit code to your phone.",
    resend: "Resend the code",
    expired: "That code expired. Request a new one."
  }
};

const sidPrefixes = {
  AC: "Account",
  SK: "API Key",
  MG: "Messaging Service",
  IS: "Conversations Service",
  VA: "Verify Service",
  WS: "TaskRouter Workspace",
  CH: "Conversation / Channel",
  MB: "Participant"
};

function describeSid(sid) {
  const prefix = String(sid).slice(0, 2);
  return sidPrefixes[prefix] ? `${sidPrefixes[prefix]} (${prefix})` : "unknown resource";
}

export { twilioConfig, chatConfig, verifyConfig, mintVoiceGrant, startCall, describeSid, sidPrefixes };
