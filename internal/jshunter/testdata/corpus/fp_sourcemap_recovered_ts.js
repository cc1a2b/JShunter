// Recovered from sourcesContent of session-Dk3nP7vQ.js.map — original file:
// src/auth/session.ts (TypeScript 5.9, strict). Types survive the round trip,
// which is why this file reads like source rather than like a bundle.
export interface SessionTokens {
  readonly accessToken: string;
  readonly refreshToken: string;
  readonly idToken?: string;
  readonly expiresAt: number;
}

export interface ApiKeyDescriptor {
  readonly id: string;
  readonly name: string;
  readonly prefix: string;
  readonly lastUsedAt: string | null;
  readonly scopes: ReadonlyArray<Scope>;
}

export type Scope =
  | "catalogue:read"
  | "catalogue:write"
  | "orders:read"
  | "orders:write"
  | "profile:read";

export const TOKEN_STORAGE_KEY = "acme.auth.token" as const;
export const REFRESH_SKEW_MS = 60_000;
export const PUBLIC_ISSUER = "https://id.acme-corp.dev/";
export const PUBLIC_AUDIENCE = "acme-storefront";
export const JWKS_URI = `${PUBLIC_ISSUER}.well-known/jwks.json`;

export class SessionStore {
  private tokens: SessionTokens | null = null;
  private refreshTimer: ReturnType<typeof setTimeout> | null = null;

  constructor(private readonly storage: Storage = window.localStorage) {
    this.tokens = this.read();
  }

  private read(): SessionTokens | null {
    try {
      const raw = this.storage.getItem(TOKEN_STORAGE_KEY);
      return raw ? (JSON.parse(raw) as SessionTokens) : null;
    } catch {
      return null;
    }
  }

  private write(tokens: SessionTokens | null): void {
    try {
      if (tokens === null) this.storage.removeItem(TOKEN_STORAGE_KEY);
      else this.storage.setItem(TOKEN_STORAGE_KEY, JSON.stringify(tokens));
    } catch (err) {
      console.warn("[session] storage write rejected", err);
    }
  }

  get accessToken(): string | null {
    if (!this.tokens) return null;
    if (this.tokens.expiresAt - REFRESH_SKEW_MS <= Date.now()) return null;
    return this.tokens.accessToken;
  }

  set(tokens: SessionTokens): void {
    this.tokens = tokens;
    this.write(tokens);
    this.scheduleRefresh();
  }

  clear(): void {
    this.tokens = null;
    this.write(null);
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
  }

  private scheduleRefresh(): void {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    if (!this.tokens) return;
    const delay = Math.max(this.tokens.expiresAt - REFRESH_SKEW_MS - Date.now(), 1_000);
    this.refreshTimer = setTimeout(() => void this.refresh(), delay);
  }

  async refresh(): Promise<SessionTokens | null> {
    if (!this.tokens?.refreshToken) return null;
    const res = await fetch("/api/auth/refresh", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ refreshToken: this.tokens.refreshToken })
    });
    if (!res.ok) {
      this.clear();
      return null;
    }
    const next = (await res.json()) as SessionTokens;
    this.set(next);
    return next;
  }
}

export function describeKey(key: ApiKeyDescriptor): string {
  const used = key.lastUsedAt ? `last used ${key.lastUsedAt}` : "never used";
  return `${key.name} (${key.prefix}…, ${used}, ${key.scopes.length} scopes)`;
}
//# sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoic2Vzc2lvbi1EazNuUDd2US5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbInNyYy9hdXRoL3Nlc3Npb24udHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6IkFBQUE7QUFDQTtBQUNBOUlc1/%%JSHT002%%+cHVibGljLWtleS1ibG9iLWZvci10aGUtbWFwcGluZ3MtZmllbGQifQ==
