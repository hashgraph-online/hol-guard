import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  groupCloudExceptions,
  isCloudExceptionActive,
  resolvePersonDisplayLabel,
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

const here = dirname(fileURLToPath(import.meta.url));

const now = new Date("2026-06-13T12:00:00+00:00");

const activeException: GuardCloudException = {
  id: "artifact:codex:project:live",
  effect: "allow",
  scope: "artifact",
  harness: "codex",
  owner: "owner@example.com",
  approver: "approver@example.com",
  expiry: "2099-01-01T00:00:00+00:00",
  artifact_id: "codex:project:live",
  source_receipt_id: "receipt-live",
  bundle_hash: "sha256:live-bundle",
  ack_status: "synced",
  last_used_at: null,
  rejection_reason: null,
};

const expiredException: GuardCloudException = {
  ...activeException,
  id: "artifact:codex:project:expired",
  artifact_id: "codex:project:expired",
  expiry: "2020-01-01T00:00:00+00:00",
};

const pendingRequest: GuardCloudExceptionRequestItem = {
  requestId: "req-pending",
  scope: "artifact",
  status: "pending",
  reason: "Temporary allow for rollout",
  owner: "owner@example.com",
  requestedAt: "2026-06-13T00:00:00+00:00",
  requestedExpiresAt: "2099-01-01T00:00:00+00:00",
};

assert(
  groupCloudExceptions([], []).active.length === 0 && groupCloudExceptions([], []).pending.length === 0,
  "empty API payloads produce empty active and pending groups",
);

const pendingGroups = groupCloudExceptions([], [pendingRequest], now);
assert(pendingGroups.pending.length === 1, "pending request renders from API response");
assert(pendingGroups.active.length === 0, "pending-only response keeps active group empty");

const activeGroups = groupCloudExceptions([activeException, expiredException], [], now);
assert(activeGroups.active.length === 1, "only non-expired synced exceptions stay active");
assert(activeGroups.active[0]?.id === activeException.id, "active exception id preserved from DTO");
assert(!isCloudExceptionActive(expiredException, now), "expired exception is not active");

const summary = summarizeCloudExceptions([activeException, expiredException], [pendingRequest], now);
assert(summary.activeCount === 1, "summary counts only active synced exceptions");
assert(summary.pendingCount === 1, "summary counts pending requests");

assert(resolvePersonDisplayLabel(null) === "Unknown", "missing owner falls back safely");
assert(resolvePersonInitials(undefined) === "UN", "missing approver initials fall back safely");

const viewsSource = readFileSync(join(here, "policy-workspace-views.tsx"), "utf8");
assert(viewsSource.includes("!cloudManaged"), "local remove action gated to non-cloud rules");
assert(viewsSource.includes("canClear = onClear !== undefined && !cloudManaged"), "cloud exceptions cannot be removed locally");

console.log("policy-data-truth.test.ts: all assertions passed");
