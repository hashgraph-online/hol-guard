import { forgetRefusedSessionsForTests } from "./dashboard-decision-session";
import {
  GuardDecisionSignInRequiredError,
  guardDecisionSession,
  readGuardToken,
  resolveRequestWithQueueResult,
} from "./guard-api";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

type Recorded = { url: string; session: string | null };

class MapStorage {
  writes = 0;
  constructor(readonly map: Map<string, string>) {}
  get length(): number {
    return this.map.size;
  }
  key(index: number): string | null {
    return [...this.map.keys()][index] ?? null;
  }
  getItem(key: string): string | null {
    return this.map.get(key) ?? null;
  }
  setItem(key: string, value: string): void {
    this.writes += 1;
    this.map.set(key, value);
  }
  removeItem(key: string): void {
    this.map.delete(key);
  }
}

let installs = 0;
function installWindow(
  token: string | null,
  stores: { tab?: Map<string, string>; browser?: Map<string, string> } = {},
): { tab: MapStorage; browser: MapStorage } {
  forgetRefusedSessionsForTests();
  installs += 1;
  const tab = new MapStorage(stores.tab ?? new Map());
  const browser = new MapStorage(stores.browser ?? new Map());
  // A distinct path per install keeps the token cache from carrying over.
  const pathname = `/requests/t${installs}`;
  const search = token === null ? "" : `?guard-token=${encodeURIComponent(token)}`;
  Object.defineProperty(globalThis, "window", {
    configurable: true,
    value: {
      location: { origin: "http://127.0.0.1:4174", pathname, search, hash: "" },
      sessionStorage: tab,
      localStorage: browser,
    },
  });
  return { tab, browser };
}

function stubFetch(answer: (session: string | null) => Response): Recorded[] {
  const calls: Recorded[] = [];
  globalThis.fetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const session = new Headers(init?.headers).get("X-Guard-Dashboard-Session");
    calls.push({ url: input instanceof Request ? input.url : String(input), session });
    return answer(session);
  };
  return calls;
}

const ok = () =>
  new Response(JSON.stringify({ resolved: true, remaining_pending_count: 0 }), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
const refused = () => new Response(JSON.stringify({ error: "unauthorized" }), { status: 401 });

function sessionToken(claims: Record<string, unknown>, label: string): string {
  return `gld1.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.${label}`;
}

async function decide(requestId: string): Promise<unknown> {
  try {
    await resolveRequestWithQueueResult({ requestId, action: "allow", scope: "artifact", reason: "reviewed" });
    return null;
  } catch (error) {
    return error;
  }
}

const requestA = "a".repeat(32);
const requestB = "b".repeat(32);
const later = new Date(Date.now() + 60 * 60 * 1000).toISOString();
const earlier = new Date(Date.now() - 1000).toISOString();
const full = sessionToken({ surface: "approval-center", expires_at: later }, "full");
const otherFull = sessionToken({ surface: "approval-center", expires_at: later }, "full-2");
const lapsedFull = sessionToken({ surface: "approval-center", expires_at: earlier }, "lapsed-full");
const boundA = sessionToken({ surface: "approval-center", request_id: requestA, expires_at: later }, "a");
const boundB = sessionToken({ surface: "approval-center", request_id: requestB, expires_at: later }, "b");
const lapsedA = sessionToken({ surface: "approval-center", request_id: requestA, expires_at: earlier }, "lapsed-a");

{
  const { browser } = installWindow(boundA, { browser: new Map([["guard-token", full]]) });
  assert(readGuardToken() === full, "a request link keeps the full session as the tab's session");
  assert(browser.map.get("guard-token") === full, "a request link never overwrites the full session");
  assert(browser.map.get(`guard-token:request:${requestA}`) === boundA, "the link's session is kept for its request");
  const verdict = guardDecisionSession(requestB);
  assert(verdict.kind === "ready" && verdict.token === full, "the full session decides other requests");
}

{
  // This tab holds an older request's session; another tab saved a full one.
  const { browser } = installWindow(boundB, {
    tab: new Map([["guard-token", boundA]]),
    browser: new Map([["guard-token", full]]),
  });
  assert(readGuardToken() === full, "a full session in the browser store is found behind the tab's narrower one");
  assert(browser.map.get("guard-token") === full, "opening a link never erases a full session in the browser store");
}

{
  // A reloaded tab still holds an older full session; another tab saved a newer one.
  const { tab, browser } = installWindow(boundA, {
    tab: new Map([["guard-token", otherFull]]),
    browser: new Map([["guard-token", full]]),
  });
  assert(readGuardToken() === full, "a request link prefers the browser-wide full session");
  assert(browser.map.get("guard-token") === full, "a tab's own copy never overwrites the browser-wide session");
  assert(tab.map.get("guard-token") === full, "the tab picks up the browser-wide session");
}

{
  const shared = new Map<string, string>();
  installWindow(boundA, { browser: shared });
  assert(readGuardToken() === boundA, "with no full session the link's session is the tab's session");
  installWindow(null, { browser: shared });
  const other = guardDecisionSession(requestB);
  assert(other.kind === "sign_in" && other.reason === "other_request", "a session bound elsewhere asks for sign-in");
  const own = guardDecisionSession(requestA);
  assert(own.kind === "ready" && own.token === boundA, "the bound session decides its own request");

  installWindow(boundB, { browser: shared });
  assert(readGuardToken() === boundB, "a second link opens its own request");
  installWindow(null, { browser: shared });
  const first = guardDecisionSession(requestA);
  assert(first.kind === "ready" && first.token === boundA, "the first request keeps its own bound session");

  const calls = stubFetch(ok);
  assert((await decide(requestA)) === null, "a decision with the bound session succeeds");
  assert(calls.length === 1 && calls[0]?.session === boundA, "the decision is sent once with the request's session");

  const unsent = stubFetch(ok);
  const error = await decide("c".repeat(32));
  assert(
    error instanceof GuardDecisionSignInRequiredError && error.reason === "other_request",
    "a request no session can decide asks for sign-in",
  );
  assert(unsent.length === 0, "a decision no session can make is never sent");
}

{
  const { tab, browser } = installWindow(boundA);
  readGuardToken();
  const writes = tab.writes + browser.writes;
  for (let index = 0; index < 5; index += 1) {
    readGuardToken();
    guardDecisionSession(requestA);
  }
  assert(tab.writes + browser.writes === writes, "reading a linked session again never rewrites storage");
}

{
  installWindow(null, { browser: new Map([["guard-token", lapsedA]]) });
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "sign_in" && verdict.reason === "expired", "an ended bound session asks to sign in again");
}

{
  const shared = new Map([
    ["guard-token", full],
    [`guard-token:request:${requestB}`, lapsedA],
  ]);
  installWindow(boundA, { browser: shared });
  readGuardToken();
  assert(!shared.has(`guard-token:request:${requestB}`), "ended request sessions are forgotten");
}

{
  // A lapsed full session is still tried: the daemon renews one in its grace window.
  installWindow(null, { browser: new Map([["guard-token", lapsedFull]]) });
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "ready" && verdict.token === lapsedFull, "a lapsed full session is left for the daemon to renew");
}

{
  installWindow(null, { browser: new Map([["guard-token", full]]) });
  const calls = stubFetch(refused);
  const error = await decide(requestA);
  assert(
    error instanceof GuardDecisionSignInRequiredError && error.reason === "expired",
    "a session the daemon refuses asks to sign in again",
  );
  const before = calls.length;
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "sign_in" && verdict.reason === "expired", "a refused session stays refused on recheck");
  const again = await decide(requestA);
  assert(again instanceof GuardDecisionSignInRequiredError, "a refused session is not sent again");
  assert(calls.length === before, "no decision is sent with a refused session");
}

{
  // Guard restarted: the stored full session is dead, the link's own session is not.
  installWindow(boundA, { browser: new Map([["guard-token", full]]) });
  readGuardToken();
  const calls = stubFetch((session) => (session === boundA ? ok() : refused()));
  assert((await decide(requestA)) === null, "a refused full session falls back to the link's own session");
  assert(calls.at(-1)?.session === boundA, "the fallback decision is sent with the link's session");
}

{
  // A second full session saved by another tab replaces a refused one.
  const shared = new Map([["guard-token", full]]);
  installWindow(null, { browser: shared });
  stubFetch(refused);
  await decide(requestA);
  shared.set("guard-token", otherFull);
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "ready" && verdict.token === otherFull, "a new session from another tab is picked up");
}

{
  installWindow(null, { browser: new Map([["guard-token", full]]) });
  stubFetch(
    () => new Response(JSON.stringify({ error: "approval_password_invalid", message: "Wrong password." }), { status: 401 }),
  );
  const error = await decide(requestA);
  assert(
    error instanceof Error && !(error instanceof GuardDecisionSignInRequiredError),
    "a wrong approval password stays a gate error, not a sign-in prompt",
  );
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "ready" && verdict.token === full, "a gate refusal does not mark the session refused");
}

{
  installWindow(null);
  const calls = stubFetch(ok);
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "ready" && verdict.token === null, "with no session at all the daemon decides");
  assert((await decide(requestA)) === null && calls.length === 1, "a tab with no session still sends the decision");
}

{
  // An ended link for a request never replaces a live session saved for it.
  const shared = new Map([[`guard-token:request:${requestA}`, boundA]]);
  installWindow(lapsedA, { browser: shared });
  readGuardToken();
  assert(shared.get(`guard-token:request:${requestA}`) === boundA, "an ended link keeps the live request session");
  assert(!shared.has("guard-token"), "an ended link is never saved as the tab's session");
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "ready" && verdict.token === boundA, "the live request session still decides");
}

{
  // A decision the daemon refused with no session keeps asking for sign-in.
  const shared = new Map<string, string>();
  installWindow(null, { browser: shared });
  stubFetch(refused);
  const error = await decide(requestA);
  assert(error instanceof GuardDecisionSignInRequiredError && error.reason === "no_session", "no session asks to sign in");
  const verdict = guardDecisionSession(requestA);
  assert(verdict.kind === "sign_in" && verdict.reason === "no_session", "a recheck with still no session keeps the panel");
  shared.set("guard-token", full);
  const signedIn = guardDecisionSession(requestA);
  assert(signedIn.kind === "ready" && signedIn.token === full, "a session from another tab clears the panel");
}

{
  // Renewal saves a new tab session; a Pulse continuation sends it, not the old one.
  const renewed = sessionToken({ surface: "approval-center", expires_at: later }, "renewed");
  installWindow(null, { browser: new Map([["guard-token", full]]) });
  const calls = stubFetch((session) => {
    const last = calls.at(-1);
    if (last?.url.endsWith("/v1/initialize")) {
      return new Response(JSON.stringify({ dashboard_session_token: renewed }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    }
    if (session !== renewed) return refused();
    const continued = calls.filter((call) => call.session === renewed).length > 1;
    return continued
      ? ok()
      : new Response(JSON.stringify({ error: "approval_gate_pulse_required" }), { status: 403 });
  });
  assert((await decide(requestA)) === null, "a renewed session carries the decision through Pulse");
  assert(calls.at(-1)?.session === renewed, "the Pulse continuation is sent with the renewed session");
  assert(!calls.slice(2).some((call) => call.session === full), "the replaced session is not sent again");
}

console.log("dashboard-decision-session.test.ts: all tests passed");
