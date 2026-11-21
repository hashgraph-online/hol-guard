/**
 * What a local dashboard session may decide, read from its own claims.
 *
 * Guard signs every session; the daemon verifies the signature and decides
 * every call. The browser only reads the claims so it can pick the right
 * session for a decision and explain, before the user clicks, when this tab
 * cannot decide a request. Nothing here grants access.
 *
 * A link an agent hands the user opens a session bound to that one request.
 * It may read the queue and decide its own request, nothing else. A session
 * opened from Guard itself (Desktop, `hol-guard approvals open`, the
 * dashboard command) is not bound and may decide any request.
 */

export type DashboardSessionScope =
  | { kind: "full"; expiresAtMs: number | null }
  | { kind: "request"; requestId: string; expiresAtMs: number | null };

const SESSION_PART = /^[A-Za-z0-9_-]+$/;
const REQUEST_ID = /^[0-9a-f]{32}$/;

function decodeBase64Url(part: string): string | null {
  if (!SESSION_PART.test(part)) {
    return null;
  }
  const padded = part.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(part.length / 4) * 4, "=");
  try {
    const binary = atob(padded);
    const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return null;
  }
}

/** The scope a session token's claims name, or null for a token this tab cannot read. */
export function dashboardSessionScope(token: string | null | undefined): DashboardSessionScope | null {
  if (typeof token !== "string") {
    return null;
  }
  const parts = token.trim().split(".");
  if (parts.length !== 3) {
    return null;
  }
  const decoded = decodeBase64Url(parts[1] ?? "");
  if (decoded === null) {
    return null;
  }
  let claims: unknown;
  try {
    claims = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (typeof claims !== "object" || claims === null || Array.isArray(claims)) {
    return null;
  }
  const record = claims as Record<string, unknown>;
  const expires = typeof record["expires_at"] === "string" ? Date.parse(record["expires_at"]) : Number.NaN;
  const expiresAtMs = Number.isFinite(expires) ? expires : null;
  const bound = record["request_id"];
  if (typeof bound === "string" && REQUEST_ID.test(bound)) {
    return { kind: "request", requestId: bound, expiresAtMs };
  }
  if (bound !== undefined && bound !== null) {
    // A bound claim this tab cannot read still binds the session on the daemon.
    return { kind: "request", requestId: "", expiresAtMs };
  }
  return { kind: "full", expiresAtMs };
}

export function dashboardSessionExpired(scope: DashboardSessionScope, nowMs: number): boolean {
  return scope.expiresAtMs !== null && scope.expiresAtMs <= nowMs;
}

/** Whether a session with `scope` may decide `requestId`, as the daemon would rule. */
export function sessionScopeCanDecide(scope: DashboardSessionScope | null, requestId: string, nowMs: number): boolean {
  if (scope === null || dashboardSessionExpired(scope, nowMs)) {
    return false;
  }
  return scope.kind === "full" || scope.requestId === requestId;
}

/** Why this tab cannot decide a request, in the terms the sign-in panel explains. */
export type DecisionSignInReason = "no_session" | "other_request" | "expired";
