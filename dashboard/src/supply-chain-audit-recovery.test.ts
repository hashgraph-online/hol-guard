import {
  createSupplyChainSyncApprovalGate,
  isStandaloneSyncRecoveryGate,
  resolveSupplyChainAuditRecoveryGate,
} from "./supply-chain-audit-recovery";
import { resolveBusyHint } from "./supply-chain-audit-recovery-modal";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const syncRequiredPayload = {
  audit_status: "incomplete",
  audit_outcome: "sync_required",
  message: "Sync Guard supply-chain intel on this device before auditing workspace packages.",
  supply_chain: { status: "sync_required" },
};

const syncGate = resolveSupplyChainAuditRecoveryGate(syncRequiredPayload);
assert(syncGate !== null, "sync_required resolves recovery gate");
assert(syncGate!.primaryAction === "sync", "sync_required offers sync action");
assert(syncGate!.autoRetryAuditAfterPrimary === true, "sync_required auto-retries audit");
assert(syncGate!.steps.length === 2, "sync_required shows two-step flow");

const standaloneSyncGate = createSupplyChainSyncApprovalGate();
assert(isStandaloneSyncRecoveryGate(standaloneSyncGate), "plain sync approval is a standalone sync");
assert(
  standaloneSyncGate.headline === "Approve supply-chain intel sync",
  "standalone sync approval does not mention auditing",
);
assert(
  standaloneSyncGate.steps.length === 1 && standaloneSyncGate.steps[0].title === "Sync intel",
  "standalone sync approval does not promise an audit step",
);

const chainedSyncGate = createSupplyChainSyncApprovalGate({ autoRetryAuditAfterPrimary: true });
assert(!isStandaloneSyncRecoveryGate(chainedSyncGate), "sync approval before an audit is not standalone");
assert(
  chainedSyncGate.headline === "Sync supply-chain intel before auditing",
  "sync approval before an audit keeps the audit framing",
);
assert(chainedSyncGate.steps.length === 2, "sync approval before an audit shows both steps");
assert(!isStandaloneSyncRecoveryGate(syncGate!), "sync_required recovery chains into the audit");

const inventoryEmptyGate = resolveSupplyChainAuditRecoveryGate({
  audit_status: "incomplete",
  audit_outcome: "inventory_empty",
});
assert(inventoryEmptyGate?.primaryAction === "sync", "inventory_empty offers sync recovery");

const noProjectGate = resolveSupplyChainAuditRecoveryGate({
  audit_status: "incomplete",
  audit_outcome: "no_project_files",
});
assert(noProjectGate?.primaryAction === "retry_audit", "no_project_files offers retry only");
assert(
  noProjectGate?.autoRetryAuditAfterPrimary === false,
  "no_project_files does not auto-chain sync",
);

assert(
  resolveSupplyChainAuditRecoveryGate({
    exit_code: 2,
    evaluation: { decision: "block" },
  }) === null,
  "completed blocked audits do not open recovery",
);

console.log("supply-chain-audit-recovery.test.ts: all assertions passed");

assert(resolveBusyHint("syncing", 2) === null, "a quick sync shows no waiting hint");
const syncHint = resolveBusyHint("syncing", 12) ?? "";
assert(syncHint.includes("12s"), "a slow sync shows how long Guard has waited");
assert(syncHint.includes("45s"), "a slow sync says when Guard stops waiting");
assert(resolveBusyHint("approval", 30) === null, "the approval step has no busy hint");
assert((resolveBusyHint("auditing", 7) ?? "").includes("7s"), "a slow audit shows elapsed time");
