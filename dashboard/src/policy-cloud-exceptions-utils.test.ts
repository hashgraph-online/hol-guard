import {
  groupCloudExceptions,
  isCloudExceptionActive,
  isCloudExceptionAckFailure,
  isCloudExceptionExpiringSoon,
  resolveCloudExceptionExpiryTimestamp,
  resolveCloudExceptionHeadline,
  resolvePersonInitials,
  summarizeCloudExceptions,
} from "./policy-cloud-exceptions-utils";
import type { GuardCloudException } from "./guard-types";
import type { GuardCloudExceptionRequestItem } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const activeException: GuardCloudException = {
  id: "artifact:codex:project:demo",
  effect: "allow",
  scope: "artifact",
  harness: "codex",
  owner: "owner@example.com",
  approver: "approver@example.com",
  expiry: "2099-01-01T00:00:00+00:00",
  artifact_id: "codex:project:demo",
  source_receipt_id: "receipt-1",
  bundle_hash: "sha256:demo",
  ack_status: "synced",
  last_used_at: null,
  rejection_reason: null,
};

const expiringSoonException: GuardCloudException = {
  ...activeException,
  id: "artifact:codex:project:soon",
  artifact_id: "codex:project:soon",
  expiry: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString(),
};

const ackFailureException: GuardCloudException = {
  ...activeException,
  id: "artifact:codex:project:failed",
  artifact_id: "codex:project:failed",
  ack_status: "failed",
  rejection_reason: "Bundle signature mismatch",
};

const pendingRequest: GuardCloudExceptionRequestItem = {
  requestId: "req-1",
  scope: "artifact",
  status: "pending",
  reason: "Temporary allow",
  owner: "owner@example.com",
  requestedAt: "2026-06-13T00:00:00+00:00",
  requestedExpiresAt: "2099-01-01T00:00:00+00:00",
};

assert(isCloudExceptionActive(activeException), "active exception should be active");
assert(!isCloudExceptionActive({ ...activeException, expiry: "2020-01-01T00:00:00+00:00" }), "expired exception inactive");
assert(isCloudExceptionExpiringSoon(expiringSoonException), "expiring soon exception detected");
assert(isCloudExceptionAckFailure(ackFailureException), "ack failure detected");
assert(resolveCloudExceptionHeadline(activeException) === "codex:project:demo", "artifact headline resolved");
assert(resolvePersonInitials("owner@example.com") === "OW", "email initials resolved");

const summary = summarizeCloudExceptions(
  [activeException, expiringSoonException, ackFailureException],
  [pendingRequest],
);
assert(summary.activeCount === 3, "summary active count");
assert(summary.pendingCount === 1, "summary pending count");
assert(summary.expiringSoonCount === 1, "summary expiring soon count");
assert(summary.ackFailureCount === 1, "summary ack failure count");

const groups = groupCloudExceptions(
  [activeException, expiringSoonException, ackFailureException],
  [pendingRequest],
);
assert(groups.active.length === 3, "group active count");
assert(groups.pending.length === 1, "group pending count");
assert(groups.expiringSoon.length === 1, "group expiring soon count");

const legacyExpiryException: GuardCloudException = {
  ...activeException,
  id: "artifact:codex:project:legacy",
  artifact_id: "codex:project:legacy",
  expiry: "",
  expires_at: "2099-06-01T00:00:00+00:00",
};
assert(isCloudExceptionActive(legacyExpiryException), "legacy expires_at keeps exception active");
assert(
  resolveCloudExceptionExpiryTimestamp(legacyExpiryException)?.getTime() ===
    new Date("2099-06-01T00:00:00+00:00").getTime(),
  "legacy expires_at resolves for sorting",
);

console.log("policy-cloud-exceptions-utils.test.ts: all assertions passed");
