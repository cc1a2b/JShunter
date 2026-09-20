// assets/feedback-widget-Cp5nQ8vT.js
// The in-app feedback widget posts straight to Slack from the browser so that
// the team gets messages without a backend hop. The incoming-webhook URL is the
// credential: anyone who reads this bundle can post into the channel.
const SLACK_WEBHOOK_URL = "%%JSHT026%%";

const CHANNEL_HINT = "#product-feedback";
const MAX_MESSAGE_CHARS = 2000;

const SENTIMENTS = [
  { id: "love", emoji: ":heart:", label: "Loving it" },
  { id: "meh", emoji: ":neutral_face:", label: "It is fine" },
  { id: "bug", emoji: ":beetle:", label: "Something is broken" },
  { id: "idea", emoji: ":bulb:", label: "I have an idea" }
];

function buildBlocks({ sentiment, message, page, viewer }) {
  const s = SENTIMENTS.find((x) => x.id === sentiment) || SENTIMENTS[1];
  return [
    {
      type: "header",
      text: { type: "plain_text", text: `${s.label} — ${page}`, emoji: true }
    },
    {
      type: "section",
      text: { type: "mrkdwn", text: `${s.emoji} ${message.slice(0, MAX_MESSAGE_CHARS)}` }
    },
    {
      type: "context",
      elements: [
        { type: "mrkdwn", text: `*viewer:* ${viewer.anonymous ? "anonymous" : viewer.id}` },
        { type: "mrkdwn", text: `*build:* 2026.9.3` },
        { type: "mrkdwn", text: `*ua:* ${navigator.userAgent.slice(0, 80)}` }
      ]
    }
  ];
}

async function sendFeedback(input) {
  if (!input || !input.message || input.message.trim().length < 3) {
    throw new Error("Write a little more before sending.");
  }
  const body = JSON.stringify({
    channel: CHANNEL_HINT,
    username: "acme-storefront",
    icon_emoji: ":shopping_trolley:",
    text: `${input.sentiment}: ${input.message.slice(0, 140)}`,
    blocks: buildBlocks(input)
  });

  const res = await fetch(SLACK_WEBHOOK_URL, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body
  });

  if (res.status === 429) {
    const retry = Number(res.headers.get("retry-after") || 30);
    throw Object.assign(new Error("Slack is rate limiting us."), { retryAfter: retry });
  }
  if (!res.ok) {
    throw new Error(`Slack rejected the message (${res.status}).`);
  }
  return { ok: true };
}

function mount(root) {
  root.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const form = new FormData(ev.target);
    const status = root.querySelector("[data-status]");
    try {
      await sendFeedback({
        sentiment: String(form.get("sentiment") || "meh"),
        message: String(form.get("message") || ""),
        page: location.pathname,
        viewer: window.__APP_CONFIG__?.viewer ?? { anonymous: true }
      });
      status.textContent = "Thanks — the team has it.";
    } catch (err) {
      status.textContent = err.message;
      status.dataset.state = "error";
    }
  });
}

export { sendFeedback, buildBlocks, mount, SENTIMENTS, SLACK_WEBHOOK_URL };
