import { resolveSupplyChainAuditRecoveryGate } from "./supply-chain-audit-recovery";

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
