import assert from "node:assert/strict";
import { GUARD_AUTH_REQUIRED, guardSessionRecoveryCommand, isGuardAuthenticationError } from "./guard-auth-error";

assert.equal(isGuardAuthenticationError(GUARD_AUTH_REQUIRED), true);
assert.equal(isGuardAuthenticationError("unauthorized (401)"), true);
assert.equal(isGuardAuthenticationError("Request failed with 401"), true);
assert.equal(isGuardAuthenticationError("Failed to fetch"), false);
assert.equal(isGuardAuthenticationError("Request failed with 403"), false);
const requestId = "request-123";
assert.equal(guardSessionRecoveryCommand(`/requests/${requestId}`), `hol-guard approvals open ${requestId}`);
assert.equal(guardSessionRecoveryCommand(`/requests/${requestId}/`), `hol-guard approvals open ${requestId}`);
assert.equal(guardSessionRecoveryCommand(`/approvals/${requestId}`), `hol-guard approvals open ${requestId}`);
assert.equal(guardSessionRecoveryCommand(`/approvals/${requestId}/`), `hol-guard approvals open ${requestId}`);
const maximumRequestId = `r${"a".repeat(255)}`;
assert.equal(
  guardSessionRecoveryCommand(`/requests/${maximumRequestId}`),
  `hol-guard approvals open ${maximumRequestId}`,
);
for (const unsafePath of [
  "/requests/$(malicious)",
  "/requests/../settings",
  "/approvals/../../settings",
  "/requests/request-123/extra",
  "/requests/request-123;touch",
  "/requests/request-123 && touch injected-sentinel",
  "/requests/request-123`whoami`",
  `/requests/${"r".repeat(257)}`,
]) {
  assert.equal(guardSessionRecoveryCommand(unsafePath), "hol-guard dashboard", `rejects unsafe path ${unsafePath}`);
}
