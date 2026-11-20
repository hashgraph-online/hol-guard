/**
 * Which saved dashboard session this tab decides a request with.
 *
 * A link an agent relays opens a session bound to one request. Saving it
 * over the dashboard's own session used to leave every later tab able to
 * read the queue but unable to decide anything else, so the bound session is
 * kept under its own per-request key and a live full session stays in place.
 *
 * Nothing here grants access. The daemon checks every call; this module only
 * orders the sessions the browser already holds, skips ones the daemon has
 * refused, and says why none can decide when that is the case.
 */

import {
  dashboardSessionExpired,
  dashboardSessionScope,
  type DashboardSessionScope,
  type DecisionSignInReason,
} from "./dashboard-session-scope";

const SESSION_KEY = "guard-token";

type StorageGetter = () => Storage;
const tabStorage: StorageGetter = () => window.sessionStorage;
const browserStorage: StorageGetter = () => window.localStorage;

function readFrom(getStorage: StorageGetter, key: string): string | null {
  try {
    return getStorage().getItem(key);
  } catch {
    return null;
  }
}

function writeTo(getStorage: StorageGetter, key: string, value: string): void {
  try {
    if (getStorage().getItem(key) !== value) {
      getStorage().setItem(key, value);
    }
  } catch {
    // Storage the browser refuses is left as it is.
  }
}

function writeBoth(key: string, value: string): void {
  writeTo(tabStorage, key, value);
  writeTo(browserStorage, key, value);
}

export function requestSessionStorageKey(requestId: string): string {
  return `${SESSION_KEY}:request:${requestId}`;
}

// Sessions the daemon refused in this page. Their claims can still look
// current (Guard restarted, or the session was revoked), so they are skipped
// until the page reloads.
const refusedSessions = new Set<string>();

export function markSessionRefused(token: string): void {
  refusedSessions.add(token);
}

export function sessionRefused(token: string): boolean {
  return refusedSessions.has(token);
}

// Set once the daemon refuses a decision sent with no session, so a recheck
// keeps asking for sign-in until some session appears.
let anonymousDecisionRefused = false;

export function markAnonymousDecisionRefused(): void {
  anonymousDecisionRefused = true;
}

export function forgetRefusedSessionsForTests(): void {
  refusedSessions.clear();
  anonymousDecisionRefused = false;
  lastLinkedSession = null;
}

function liveFullSession(token: string | null, nowMs: number): token is string {
  const scope = dashboardSessionScope(token);
  return token !== null && scope?.kind === "full" && !dashboardSessionExpired(scope, nowMs) && !sessionRefused(token);
}

let lastLinkedSession: string | null = null;

/**
 * The session the tab should use after opening a link that carries
 * `guardToken`. A bound session is saved for its own request; a live full
 * session in either store stays the tab's session. Storage is written only
 * the first time a link is seen, so tabs holding different links never
 * rewrite each other's storage on every storage event.
 */
export function rememberLinkedGuardSession(guardToken: string): string {
  const now = Date.now();
  const scope = dashboardSessionScope(guardToken);
  // An ended bound link is never saved: it would replace a live session
  // another link left for the same request.
  const ended = scope?.kind === "request" && dashboardSessionExpired(scope, now);
  const firstSeen = lastLinkedSession !== guardToken && !ended;
  lastLinkedSession = guardToken;
  if (scope?.kind === "request" && scope.requestId) {
    if (firstSeen) {
      forgetExpiredRequestSessions(now);
      writeBoth(requestSessionStorageKey(scope.requestId), guardToken);
    }
    // The browser-wide session is the newest one any tab saved. A tab's own
    // copy may predate a Guard restart, so it is never copied back over it.
    for (const stored of [readFrom(browserStorage, SESSION_KEY), readFrom(tabStorage, SESSION_KEY)]) {
      if (stored !== guardToken && liveFullSession(stored, now)) {
        if (firstSeen) writeTo(tabStorage, SESSION_KEY, stored);
        return stored;
      }
    }
  }
  if (ended) return readFrom(tabStorage, SESSION_KEY) ?? readFrom(browserStorage, SESSION_KEY) ?? guardToken;
  if (firstSeen) writeBoth(SESSION_KEY, guardToken);
  return guardToken;
}

function forgetExpiredRequestSessions(nowMs: number): void {
  const prefix = requestSessionStorageKey("");
  for (const getStorage of [tabStorage, browserStorage]) {
    try {
      const storage = getStorage();
      const expired: string[] = [];
      for (let index = 0; index < storage.length; index += 1) {
        const key = storage.key(index);
        if (key === null || !key.startsWith(prefix)) continue;
        const scope = dashboardSessionScope(storage.getItem(key));
        if (scope === null || dashboardSessionExpired(scope, nowMs)) expired.push(key);
      }
      for (const key of expired) storage.removeItem(key);
    } catch {
      // Storage the browser refuses is left as it is.
    }
  }
}

/** Raised instead of a decision no session in this tab can make. */
export class GuardDecisionSignInRequiredError extends Error {
  readonly requestId: string;
  readonly reason: DecisionSignInReason;

  constructor(requestId: string, reason: DecisionSignInReason) {
    super("Sign in to decide this request.");
    this.name = "GuardDecisionSignInRequiredError";
    this.requestId = requestId;
    this.reason = reason;
  }
}

export type GuardDecisionSessionVerdict =
  | { kind: "ready"; token: string | null }
  | { kind: "sign_in"; reason: DecisionSignInReason };

type Candidate = { token: string; scope: DashboardSessionScope | null };

/**
 * Sessions that may decide `requestId`, best first: the tab's own, the one
 * saved for the whole browser, then the one a link left for this request.
 * A session the tab cannot read is left for the daemon to judge. A full
 * session whose claims have lapsed is still tried last, because the daemon
 * renews one within its grace window; a lapsed bound session is not, since
 * the daemon never renews those.
 */
export function decisionSessionCandidates(requestId: string, current: string | null): string[] {
  const now = Date.now();
  const seen = new Set<string>();
  const live: Candidate[] = [];
  const lapsed: Candidate[] = [];
  const tokens = [
    current,
    readFrom(browserStorage, SESSION_KEY),
    readFrom(tabStorage, requestSessionStorageKey(requestId)),
    readFrom(browserStorage, requestSessionStorageKey(requestId)),
  ];
  for (const token of tokens) {
    if (token === null || token === "" || seen.has(token) || sessionRefused(token)) continue;
    seen.add(token);
    const scope = dashboardSessionScope(token);
    if (scope === null) {
      live.push({ token, scope });
      continue;
    }
    if (scope.kind === "request" && scope.requestId !== requestId) continue;
    if (!dashboardSessionExpired(scope, now)) {
      live.push({ token, scope });
    } else if (scope.kind === "full") {
      lapsed.push({ token, scope });
    }
  }
  return [...live, ...lapsed].map((candidate) => candidate.token);
}

/**
 * Whether this tab can try to decide `requestId`, and with which session
 * first. With no session at all the call is left to the daemon, which
 * answers in the shell's own sign-in screen.
 */
export function decisionSessionVerdict(requestId: string, current: string | null): GuardDecisionSessionVerdict {
  const candidates = decisionSessionCandidates(requestId, current);
  if (candidates.length > 0) {
    return { kind: "ready", token: candidates[0] ?? null };
  }
  if (current === null) {
    return anonymousDecisionRefused ? { kind: "sign_in", reason: "no_session" } : { kind: "ready", token: null };
  }
  const scope = dashboardSessionScope(current);
  if (sessionRefused(current) || scope === null || dashboardSessionExpired(scope, Date.now())) {
    return { kind: "sign_in", reason: "expired" };
  }
  return { kind: "sign_in", reason: "other_request" };
}

/** Whether a decision's 401 is the daemon refusing the session, not a gate code. */
export async function decisionRefusedSession(response: Response): Promise<boolean> {
  if (response.status !== 401) return false;
  try {
    const payload: unknown = await response.clone().json();
    if (typeof payload !== "object" || payload === null) return true;
    const error = (payload as Record<string, unknown>)["error"];
    return error === undefined || error === "unauthorized";
  } catch {
    return true;
  }
}
