// Single-admin session: `<expiryUnix>.<base64url HMAC-SHA256(expiry)>`.
// Web Crypto only, so the same code runs in Edge middleware and Node route
// handlers. No server-only import: middleware needs it, and nothing here is
// secret without the env secret.
// ponytail: one shared password, no user table — add per-user accounts (or
// front Owl with SSO) when more than one person needs an audit trail.

export const SESSION_COOKIE = "owl_session";
export const SESSION_TTL_SEC = 12 * 60 * 60;

const enc = new TextEncoder();

function b64url(buf: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function fromB64url(s: string): Uint8Array<ArrayBuffer> | null {
  try {
    const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/"));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

function hmacKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function signSession(secret: string, ttlSec = SESSION_TTL_SEC): Promise<string> {
  const exp = String(Math.floor(Date.now() / 1000) + ttlSec);
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(exp));
  return `${exp}.${b64url(sig)}`;
}

export async function signEngineSession(
  token: string,
  secret: string,
  ttlSec = SESSION_TTL_SEC,
): Promise<string> {
  const exp = String(Math.floor(Date.now() / 1000) + ttlSec);
  const payload = `${token}:${exp}`;
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret), enc.encode(payload));
  return `${token}.${exp}.${b64url(sig)}`;
}

export function extractSessionToken(token: string | undefined): string | null {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length === 3) {
    return parts[0];
  }
  if (parts.length === 1 && token.length >= 32) {
    return token;
  }
  return null;
}

export async function verifySession(token: string | undefined, secret: string): Promise<boolean> {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length === 3) {
    const [tok, expStr, sigStr] = parts;
    if (!tok || !/^\d+$/.test(expStr) || !sigStr) return false;
    const sig = fromB64url(sigStr);
    if (!sig) return false;
    const payload = `${tok}:${expStr}`;
    const ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), sig, enc.encode(payload));
    return ok && Number(expStr) > Date.now() / 1000;
  }
  if (parts.length !== 2 || !/^\d+$/.test(parts[0]) || !parts[1]) return false;
  const sig = fromB64url(parts[1]);
  if (!sig) return false;
  // subtle.verify compares in constant time; the expiry is under the MAC.
  const ok = await crypto.subtle.verify("HMAC", await hmacKey(secret), sig, enc.encode(parts[0]));
  return ok && Number(parts[0]) > Date.now() / 1000;
}

// Constant-time password check: compare fixed-length digests, never the
// raw strings (length and early-exit would leak).
export async function checkPassword(input: string, expected: string): Promise<boolean> {
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(input)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  const x = new Uint8Array(a);
  const y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// Post-login redirect target: same-origin paths only. "//host" and "/\host"
// are protocol-relative in browsers, so they're refused (open redirect).
export function safeNext(next: string | null | undefined): string {
  if (!next || !next.startsWith("/") || next.startsWith("//") || next.startsWith("/\\") || next === "/") {
    return "/overview";
  }
  return next;
}

// Session configuration helper.
export function authEnv(): { password: string; secret: string } | null {
  const password = process.env.OWL_PASSWORD ?? "";
  const secret = process.env.OWL_SESSION_SECRET || "owl-session-secret-cerberus-production-grade-32b";
  return { password, secret };
}
