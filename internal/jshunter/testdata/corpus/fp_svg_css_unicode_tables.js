// assets/icons-Dt3nV7wQ.js — sprite sheet, emotion style registry, unicode tables
const ICON_PATHS = {
  cart: "M7 18c-1.1 0-1.99.9-1.99 2S5.9 22 7 22s2-.9 2-2-.9-2-2-2zM1 2v2h2l3.6 7.59-1.35 2.45c-.16.28-.25.61-.25.96 0 1.1.9 2 2 2h12v-2H7.42c-.14 0-.25-.11-.25-.25l.03-.12L8.1 13h7.45c.75 0 1.41-.41 1.75-1.03l3.58-6.49A1 1 0 0 0 20 4H5.21l-.94-2H1z",
  user: "M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z",
  search: "M15.5 14h-.79l-.28-.27a6.5 6.5 0 1 0-.7.7l.27.28v.79l5 4.99L20.49 19l-4.99-5zm-6 0C7.01 14 5 11.99 5 9.5S7.01 5 9.5 5 14 7.01 14 9.5 11.99 14 9.5 14z",
  spinner: "M12 2a10 10 0 1 0 10 10h-3a7 7 0 1 1-7-7V2z",
  chevron: "M8.59 16.59 13.17 12 8.59 7.41 10 6l6 6-6 6-1.41-1.41z",
  lock: "M18 8h-1V6c0-2.76-2.24-5-5-5S7 3.24 7 6v2H6c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V10c0-1.1-.9-2-2-2zM9 6c0-1.66 1.34-3 3-3s3 1.34 3 3v2H9V6zm3 12c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"
};

// @emotion/serialize output. The class suffix is a murmur hash of the rules.
const STYLE_REGISTRY = {
  "css-1a2b3c4": "display:flex;align-items:center;gap:8px;padding:12px 16px;border-radius:10px;",
  "css-9f8e7d6": "position:absolute;inset:0;background:linear-gradient(180deg,#0b1020 0%,#131a33 100%);",
  "css-26148512": "font-variation-settings:'wght' 620;letter-spacing:-0.01em;line-height:1.25;",
  "css-b82d0dee": "grid-template-columns:repeat(auto-fill,minmax(232px,1fr));grid-gap:20px;",
  "css-17b97d44": "clip-path:polygon(0 0,100% 0,100% calc(100% - 18px),0 100%);will-change:transform;"
};

const KEYFRAMES = {
  "animation-f23c50be":
    "@keyframes animation-f23c50be{0%{transform:translate3d(0,8px,0);opacity:0}60%{opacity:1}100%{transform:none}}",
  "animation-899d829b":
    "@keyframes animation-899d829b{from{stroke-dashoffset:188.5}to{stroke-dashoffset:0}}"
};

// Unicode ranges shipped with each font subset (css @font-face unicode-range).
const UNICODE_RANGES = {
  latin: "U+0000-00FF,U+0131,U+0152-0153,U+02BB-02BC,U+2000-206F,U+2074,U+20AC,U+FEFF,U+FFFD",
  latinExt: "U+0100-024F,U+0259,U+1E00-1EFF,U+2020,U+20A0-20AB,U+2C60-2C7F,U+A720-A7FF",
  greek: "U+0370-03FF",
  cyrillic: "U+0400-045F,U+0490-0491,U+04B0-04B1,U+2116",
  arabic: "U+0600-06FF,U+0750-077F,U+08A0-08FF,U+FB50-FDFF,U+FE70-FEFF"
};

// Emoji shortcode table used by the comment composer.
const EMOJI = {
  ":tada:": { char: "🎉", cp: "1F389", group: "activities" },
  ":rocket:": { char: "🚀", cp: "1F680", group: "travel" },
  ":fire:": { char: "🔥", cp: "1F525", group: "nature" },
  ":heart:": { char: "❤️", cp: "2764-FE0F", group: "symbols" },
  ":+1:": { char: "👍", cp: "1F44D", group: "people" },
  ":lock:": { char: "🔒", cp: "1F512", group: "objects" },
  ":key:": { char: "🔑", cp: "1F511", group: "objects" }
};

const SKIN_TONE_MODIFIERS = ["1F3FB", "1F3FC", "1F3FD", "1F3FE", "1F3FF"];

const ZWJ_SEQUENCES = [
  "1F468-200D-1F4BB",
  "1F469-200D-1F4BB",
  "1F3F3-FE0F-200D-1F308",
  "1F469-200D-1F467-200D-1F466"
];

function sprite(name, size = 24) {
  const d = ICON_PATHS[name];
  if (!d) return "";
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" aria-hidden="true"><path d="${d}"/></svg>`;
}

function injectStyles(target = document.head) {
  const style = document.createElement("style");
  style.setAttribute("data-emotion", "css");
  style.textContent =
    Object.entries(STYLE_REGISTRY)
      .map(([cls, rules]) => `.${cls}{${rules}}`)
      .join("") + Object.values(KEYFRAMES).join("");
  target.appendChild(style);
  return style;
}

function shortcodeToChar(text) {
  return text.replace(/:[a-z0-9_+-]+:/g, (m) => (EMOJI[m] ? EMOJI[m].char : m));
}

export { ICON_PATHS, STYLE_REGISTRY, KEYFRAMES, UNICODE_RANGES, EMOJI, SKIN_TONE_MODIFIERS, ZWJ_SEQUENCES, sprite, injectStyles, shortcodeToChar };
