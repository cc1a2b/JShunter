/**
 * main-DK4pQ7vL.js — Angular 20 application bundle (esbuild, optimization on)
 * Locale bundle merged in by @angular/localize/tools at build time.
 */
import { ɵɵdefineInjectable as t, Injectable as n } from "./chunk-PN2WQZ7A.js";

const MESSAGES_EN_GB = {
  "auth.signIn.title": "Sign in to your account",
  "auth.signIn.submit": "Continue",
  "auth.token": "Your session token has expired. Sign in again to continue.",
  "auth.token.refreshFailed": "We could not refresh your session. Please sign in again.",
  "auth.mfa.prompt": "Enter the six-digit code from your authenticator app.",

  password: "Password",
  passwd: "Password (legacy label, retained for the v2 sign-in form)",
  pwd: "Password",
  confirmPassword: "Confirm password",
  currentPassword: "Current password",
  newPassword: "New password",

  "errors.password.required": "Enter a password to continue.",
  "errors.password.tooShort": "Your password must be at least twelve characters long.",
  "errors.password.tooCommon": "That password appears in a list of commonly used passwords.",
  "errors.password.mismatch": "The two passwords you entered do not match.",
  "errors.password.reuse": "You cannot reuse one of your last five passwords.",
  "errors.passwd.legacy": "This account still uses the old password format. Reset it to continue.",
  "errors.pwd.expired": "Your password expired on {expiresOn}. Choose a new one.",

  apiKey: "API key",
  "apiKey.hint": "Keys are shown once when created and cannot be recovered afterwards.",
  "apiKey.revoke": "Revoke this key",
  "apiKey.revoked": "That key was revoked and can no longer be used.",
  "apiKey.copy": "Copy key to clipboard",
  "secret.rotate": "Rotate signing secret",
  "secret.rotated": "The signing secret was rotated. Update your integrations.",

  "billing.card.expired": "The card ending {last4} expired. Add a new payment method.",
  "billing.invoice.paid": "Invoice {number} was paid on {paidOn}.",
  "cart.empty": "Your basket is empty.",
  "cart.itemCount": "{count, plural, =0 {No items} one {1 item} other {# items}}"
};

const TRANSLATIONS_ID_MAP = {
  "8f0ebcd03824029d": "auth.signIn.title",
  "c8f19ac0ee67d5db": "auth.token",
  "cea6760489d829b5": "errors.password.tooShort",
  "b25317fad5bdf7ea": "apiKey.hint"
};

class I18nService {
  constructor() {
    this.locale = "en-GB";
    this.messages = MESSAGES_EN_GB;
    this.ids = TRANSLATIONS_ID_MAP;
  }
  get(key, params) {
    const raw = this.messages[key];
    if (raw === undefined) {
      if (typeof ngDevMode !== "undefined" && ngDevMode) {
        console.warn(`[i18n] missing message for key "${key}" in ${this.locale}`);
      }
      return key;
    }
    if (!params) return raw;
    return raw.replace(/\{(\w+)\}/g, (m, p) => (p in params ? String(params[p]) : m));
  }
  has(key) {
    return Object.prototype.hasOwnProperty.call(this.messages, key);
  }
}
I18nService.ɵprov = t({ token: I18nService, factory: () => new I18nService(), providedIn: "root" });

const PASSWORD_POLICY = {
  minLength: 12,
  requireUpper: true,
  requireDigit: true,
  requireSymbol: false,
  messageKeys: ["errors.password.tooShort", "errors.password.tooCommon", "errors.password.reuse"]
};

export { I18nService, MESSAGES_EN_GB, PASSWORD_POLICY, TRANSLATIONS_ID_MAP };
