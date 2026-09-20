// assets/assistant-Bn8kR4vQ.js
// In-app assistant. It calls the model gateway straight from the browser, so
// the gateway key is in the bundle and every visitor can spend the account's
// credit with it.
const OPENROUTER_API_KEY =
  "%%JSHT024%%";

const GATEWAY = "https://openrouter.ai/api/v1/chat/completions";
const MODEL = "anthropic/claude-sonnet-4.5";
const MAX_TOKENS = 1024;

const SYSTEM_PROMPT = [
  "You are the Acme Corp storefront assistant.",
  "Answer questions about orders, delivery and returns.",
  "If you do not know, say so and offer to open a support ticket."
].join(" ");

function buildMessages(history, question) {
  return [
    { role: "system", content: SYSTEM_PROMPT },
    ...history.slice(-8).map((m) => ({ role: m.role, content: m.content })),
    { role: "user", content: question }
  ];
}

async function ask(history, question, { signal } = {}) {
  const res = await fetch(GATEWAY, {
    method: "POST",
    signal,
    headers: {
      "content-type": "application/json",
      authorization: `Bearer ${OPENROUTER_API_KEY}`,
      "http-referer": "https://acme-corp.dev",
      "x-title": "Acme Storefront Assistant"
    },
    body: JSON.stringify({
      model: MODEL,
      max_tokens: MAX_TOKENS,
      temperature: 0.2,
      stream: true,
      messages: buildMessages(history, question)
    })
  });

  if (res.status === 401) throw new Error("The assistant key was rejected.");
  if (res.status === 429) throw new Error("The assistant is busy. Try again shortly.");
  if (!res.ok || !res.body) throw new Error(`assistant request failed: ${res.status}`);
  return res.body;
}

async function* streamText(body) {
  const reader = body.pipeThrough(new TextDecoderStream()).getReader();
  let buffer = "";
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += value;
    let idx;
    while ((idx = buffer.indexOf("\n\n")) !== -1) {
      const frame = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 2);
      if (!frame.startsWith("data:")) continue;
      const payload = frame.slice(5).trim();
      if (payload === "[DONE]") return;
      try {
        const delta = JSON.parse(payload).choices?.[0]?.delta?.content;
        if (delta) yield delta;
      } catch {
        // partial frame; wait for the next chunk
      }
    }
  }
}

export { ask, streamText, buildMessages, MODEL, OPENROUTER_API_KEY };
