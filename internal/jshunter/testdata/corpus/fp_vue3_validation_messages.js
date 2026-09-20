/* acme-account-ui — Vue 3.6 + vee-validate 4, built with Vite (rollup) */
import { defineComponent as e, ref as r, computed as c, openBlock as o, createElementBlock as b } from "./vendor-BkP2nQ4z.js";

const rules = {
  required: (v) => (!!v && String(v).trim().length > 0) || "This field is required.",
  email: (v) => /^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(v) || "Enter a valid email address.",
  minLength: (n) => (v) => (v || "").length >= n || `Use at least ${n} characters.`,
  maxLength: (n) => (v) => (v || "").length <= n || `Use no more than ${n} characters.`
};

const fieldMessages = {
  password: "Choose a password you do not use anywhere else.",
  passwd: "Password",
  pwd: "Password",
  confirmPassword: "Re-enter the password to confirm it.",
  "errors.password": "That password is not strong enough yet.",
  "errors.password.length": "Passwords need at least twelve characters.",
  "errors.password.upper": "Add at least one capital letter.",
  "errors.password.digit": "Add at least one number.",
  "errors.confirmPassword": "The confirmation does not match the password you chose.",
  "errors.currentPassword": "That is not your current password.",
  "auth.token": "Your sign-in link has already been used. Request a new one.",
  "auth.token.expired": "This link expired after fifteen minutes. Request a new one.",
  apiKey: "Personal access keys let scripts act on your behalf.",
  "apiKey.name": "Give the key a name you will recognise later.",
  "apiKey.scopes": "Grant only the scopes the integration actually needs.",
  secret: "Keep this value out of client-side code and version control.",
  token: "Tokens inherit the permissions of the account that created them."
};

const strengthLabels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

function scorePassword(value) {
  if (!value) return 0;
  let score = 0;
  if (value.length >= 12) score++;
  if (value.length >= 16) score++;
  if (/[A-Z]/.test(value) && /[a-z]/.test(value)) score++;
  if (/\d/.test(value)) score++;
  if (/[^\w\s]/.test(value)) score++;
  return Math.min(score, 4);
}

const ChangePasswordForm = e({
  name: "ChangePasswordForm",
  props: { locale: { type: String, default: "en-GB" } },
  setup(props) {
    const currentPassword = r("");
    const password = r("");
    const confirmPassword = r("");
    const submitted = r(false);

    const errors = c(() => {
      const out = {};
      if (submitted.value) {
        if (!currentPassword.value) out.currentPassword = fieldMessages["errors.currentPassword"];
        if (scorePassword(password.value) < 3) out.password = fieldMessages["errors.password"];
        if (password.value.length < 12) out.password = fieldMessages["errors.password.length"];
        if (confirmPassword.value !== password.value)
          out.confirmPassword = fieldMessages["errors.confirmPassword"];
      }
      return out;
    });

    const strength = c(() => strengthLabels[scorePassword(password.value)]);

    async function submit() {
      submitted.value = true;
      if (Object.keys(errors.value).length) return { ok: false, errors: errors.value };
      const res = await fetch("/api/account/password", {
        method: "POST",
        headers: { "content-type": "application/json", "x-request-id": crypto.randomUUID() },
        body: JSON.stringify({
          currentPassword: currentPassword.value,
          password: password.value
        })
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        return { ok: false, errors: { password: body.message || fieldMessages["errors.password"] } };
      }
      return { ok: true };
    }

    return { currentPassword, password, confirmPassword, errors, strength, submit, rules };
  }
});

export { ChangePasswordForm, fieldMessages, rules, scorePassword, strengthLabels };
