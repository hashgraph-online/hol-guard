import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  dashboardSessionExpired,
  dashboardSessionScope,
  sessionScopeCanDecide,
  type DecisionSignInReason,
} from "./dashboard-session-scope";
import { ReviewDecisionSignIn, decisionSignInCopy } from "./review-decision-sign-in";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function token(claims: unknown): string {
  return `gld1.${Buffer.from(JSON.stringify(claims)).toString("base64url")}.signature`;
}

const requestId = "0123456789abcdef0123456789abcdef";
const otherId = "fedcba9876543210fedcba9876543210";
const now = Date.parse("2026-11-20T12:00:00Z");
const later = "2026-11-20T13:00:00Z";

const full = dashboardSessionScope(token({ expires_at: later }));
assert(full?.kind === "full" && full.expiresAtMs === Date.parse(later), "a session without a request is full");
assert(sessionScopeCanDecide(full, requestId, now), "a full session decides any request");

const bound = dashboardSessionScope(token({ request_id: requestId, expires_at: later }));
assert(bound?.kind === "request" && bound.requestId === requestId, "a session naming a request is bound to it");
assert(sessionScopeCanDecide(bound, requestId, now), "a bound session decides its own request");
assert(!sessionScopeCanDecide(bound, otherId, now), "a bound session cannot decide another request");

const unreadableBinding = dashboardSessionScope(token({ request_id: 7 }));
assert(
  unreadableBinding?.kind === "request" && !sessionScopeCanDecide(unreadableBinding, requestId, now),
  "a binding this tab cannot read still binds",
);

const ended = dashboardSessionScope(token({ expires_at: "2026-11-20T11:59:59Z" }));
assert(ended !== null && dashboardSessionExpired(ended, now), "a past expiry has ended");
assert(!sessionScopeCanDecide(ended, requestId, now), "an ended session decides nothing");

for (const opaque of [null, "", "token-queue", "a.b", "a.!!.c", `a.${Buffer.from("[1]").toString("base64url")}.c`]) {
  assert(dashboardSessionScope(opaque) === null, `an unreadable session has no scope: ${String(opaque)}`);
}

const reasons: DecisionSignInReason[] = ["no_session", "other_request", "expired"];
const headlines = new Set<string>();
for (const reason of reasons) {
  const copy = decisionSignInCopy(reason);
  headlines.add(copy.headline);
  const markup = renderToStaticMarkup(
    createElement(ReviewDecisionSignIn, { requestId, reason, onRecheck: () => {} }),
  );
  assert(markup.includes(copy.headline), `${reason}: the panel names the problem`);
  assert(markup.includes(`hol-guard-desktop://requests/${requestId}`), `${reason}: the panel opens the request in Desktop`);
  assert(markup.includes(`hol-guard approvals open ${requestId}`), `${reason}: the panel shows the terminal command`);
  assert(markup.includes("Check again"), `${reason}: the panel can pick up a new session`);
  assert(!/password|token/i.test(markup), `${reason}: the panel never asks for a secret`);
}
assert(headlines.size === reasons.length, "each reason explains itself");

const malformed = renderToStaticMarkup(
  createElement(ReviewDecisionSignIn, { requestId: "not-a-request", reason: "no_session", onRecheck: () => {} }),
);
assert(
  !malformed.includes("hol-guard-desktop://") && !malformed.includes("approvals open"),
  "a malformed request id gets no link or command",
);

console.log("review-decision-sign-in.test.ts: all tests passed");
