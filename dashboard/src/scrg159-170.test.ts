import { resolveHomeProtectionStatus, resolveLastBlockedInstall, resolveIntelStaleness } from "./home-protection-module";
import { buildSupplyChainStats } from "./supply-chain-workspace";
import { deriveFrontendAuditResults } from "./audit-workspace";
import { groupPoliciesByHarness, resolveSecurityModeCopy } from "./policy-workspace";
import { resolveFeedSourceMode, resolveFeedStaleness } from "./feed-health-workspace";
import type { GuardRuntimeSnapshot, GuardManagedInstall, GuardReceipt, GuardPolicyDecision, PackageManagerProtection } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const makeProtection = (
  protected_managers: string[],
  unprotected_managers: string[],
): PackageManagerProtection => ({
  protected_managers,
  unprotected_managers,
  path_status: "in_path",
  path_contains_shim_dir: true,
  restart_shell_required: false,
  shell_profile_configured: true,
  shell_profile_path: "/mock-home/.zshrc",
  shim_dir: "/usr/local/hol-guard/shims",
  supported_managers: [...protected_managers, ...unprotected_managers],
  installed_managers: protected_managers,
  active_managers: protected_managers,
  missing_shims: [],
});

const baseSnapshot: GuardRuntimeSnapshot = {
  generated_at: new Date().toISOString(),
  approval_center_url: null,
  runtime_state: null,
  device: {
    installation_id: "test-install-id",
    device_label: "Test Machine",
    local_registered: false,
  },
  latest_connect_state: null,
  proof_status: {
    state: "not_connected",
    label: "Not connected",
    detail: "",
    request_id: null,
    pairing_completed_at: null,
    first_synced_at: null,
    receipts_stored: 0,
    inventory_items: 0,
    runtime_session_id: null,
    runtime_session_synced_at: null,
  },
  pending_count: 0,
  receipt_count: 0,
  headline_state: "local_only",
  headline_label: "Local only",
  headline_detail: "",
  sync_configured: false,
  cloud_state: "local_only",
  cloud_state_label: "Offline, free",
  cloud_state_detail: "Running locally",
  cloud_pairing_state: {
    state: "local_only",
    label: "Not connected",
    detail: "",
    sync_configured: false,
    dashboard_url: "",
    inbox_url: "",
    fleet_url: "",
    connect_url: "",
  },
  cloud_sync_health: {
    state: "disabled",
    label: "Sync disabled",
    detail: "Cloud sync is turned off.",
    pending_events: 0,
    last_synced_at: null,
    next_retry_after: null,
  },
  dashboard_url: "",
  inbox_url: "",
  fleet_url: "",
  connect_url: "",
  items: [],
  latest_receipts: [],
  managed_installs: [],
  supply_chain: undefined,
};

const makeInstall = (active: boolean, updatedAt: string): GuardManagedInstall => ({
  harness: "claude",
  active,
  workspace: null,
  manifest: {},
  updated_at: updatedAt,
});

const makeReceipt = (decision: "allow" | "block", timestamp: string): GuardReceipt => ({
  receipt_id: `receipt-${Math.random()}`,
  harness: "claude",
  artifact_id: "test-artifact",
  artifact_name: "test-pkg",
  artifact_hash: "abc123",
  source_scope: null,
  policy_decision: decision,
  timestamp,
  capabilities_summary: "",
  changed_capabilities: [],
  provenance_summary: "",
  user_override: null,
});

const makePolicy = (harness: string): GuardPolicyDecision => ({
  harness,
  scope: "global",
  artifact_id: "test-artifact",
  workspace: null,
  publisher: null,
  action: "allow",
  reason: null,
  source: "user",
  updated_at: new Date().toISOString(),
});

assert(
  resolveHomeProtectionStatus({ ...baseSnapshot, supply_chain: undefined }) === "unknown",
  "SCRG159-A: no supply_chain should return unknown",
);

const protectedSnapshot = {
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection(["npm", "pip"], []),
  },
};
assert(
  resolveHomeProtectionStatus(protectedSnapshot) === "protected",
  "SCRG159-B: all protected should return protected",
);

const partialSnapshot = {
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection(["npm"], ["pip"]),
  },
};
assert(
  resolveHomeProtectionStatus(partialSnapshot) === "partial",
  "SCRG159-C: partial protection should return partial",
);

const stagedSnapshot = {
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: {
      ...makeProtection([], ["pnpm"]),
      installed_managers: ["pnpm"],
      path_status: "restart_required" as const,
      restart_shell_required: true,
    },
  },
};
assert(
  resolveHomeProtectionStatus(stagedSnapshot) === "staged",
  "SCRG159-C2: restart-required protection should return staged",
);

assert(
  resolveLastBlockedInstall([]) === null,
  "SCRG159-D: no installs should return null",
);

const recentDate = new Date(Date.now() - 1000).toISOString();
const olderDate = new Date(Date.now() - 10000).toISOString();
const lastBlocked = resolveLastBlockedInstall([
  makeInstall(false, olderDate),
  makeInstall(false, recentDate),
  makeInstall(true, recentDate),
]);
assert(lastBlocked !== null, "SCRG159-E: should find a blocked install");
assert(lastBlocked!.updated_at === recentDate, "SCRG159-F: should return the most recent blocked install");

const intelResult = resolveIntelStaleness(baseSnapshot);
assert(!intelResult.stale, "SCRG159-G: no receipts should not be stale");

const stats = buildSupplyChainStats(baseSnapshot);
assert(stats.totalApps === 0, "SCRG160-A: empty snapshot has 0 apps");
assert(stats.preventedInstalls === 0, "SCRG160-B: empty snapshot has 0 prevented");

const snapshotWithInstalls = {
  ...baseSnapshot,
  managed_installs: [
    makeInstall(true, new Date().toISOString()),
    makeInstall(false, new Date().toISOString()),
  ],
  supply_chain: {
    package_manager_protection: makeProtection(["npm"], ["pip"]),
  },
};
const statsWithInstalls = buildSupplyChainStats(snapshotWithInstalls);
assert(statsWithInstalls.totalApps === 2, "SCRG160-C: 2 managed installs");
assert(statsWithInstalls.activeApps === 1, "SCRG160-D: 1 active app");
assert(statsWithInstalls.preventedInstalls === 1, "SCRG160-E: 1 prevented install");
assert(statsWithInstalls.protectedManagers === 1, "SCRG160-F: 1 protected manager");
assert(statsWithInstalls.unprotectedManagers === 1, "SCRG160-G: 1 unprotected manager");

const restartRequiredStats = buildSupplyChainStats({
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: {
      ...makeProtection([], ["npm", "pip"]),
      path_status: "restart_required",
      restart_shell_required: true,
      installed_managers: ["pnpm"],
      active_managers: [],
      protected_managers: [],
      supported_managers: ["pnpm", "npm", "pip"],
      unprotected_managers: ["npm", "pip"],
      missing_shims: [],
    },
  },
});
assert(restartRequiredStats.stagedManagers === 1, "SCRG160-H: staged manager count tracks restart-required installs");
assert(restartRequiredStats.unprotectedManagers === 2, "SCRG160-I: restart-required manager should not count as unprotected");

const auditEmpty = deriveFrontendAuditResults([], baseSnapshot);
assert(Array.isArray(auditEmpty), "SCRG162-A: audit should return array");

const auditWithOfflineDaemon = deriveFrontendAuditResults([], baseSnapshot);
const daemonIssue = auditWithOfflineDaemon.find((r) => r.id === "daemon-offline");
assert(daemonIssue !== undefined, "SCRG162-B: should flag offline daemon as critical");
assert(daemonIssue!.severity === "critical", "SCRG162-C: daemon-offline should be critical");

const auditWithUnprotected = deriveFrontendAuditResults(
  [],
  {
    ...baseSnapshot,
    supply_chain: {
      package_manager_protection: makeProtection(["npm"], ["pip"]),
    },
  },
);
const pipIssue = auditWithUnprotected.find((r) => r.id === "unprotected-pip");
assert(pipIssue !== undefined, "SCRG162-D: unprotected pip should be flagged");
assert(pipIssue!.severity === "high", "SCRG162-E: unprotected manager should be high severity");
assert(pipIssue!.remediation.includes("Guard"), "SCRG162-F: remediation should point back to Guard action");

const auditWithInstalledUnprotected = deriveFrontendAuditResults(
  [],
  {
    ...baseSnapshot,
    supply_chain: {
      package_manager_protection: {
        ...makeProtection([], ["npm", "pnpm"]),
        installed_managers: ["npm", "pnpm"],
        active_managers: [],
        path_status: "missing_from_path",
        path_contains_shim_dir: false,
      },
    },
  },
);
const installedNpmIssue = auditWithInstalledUnprotected.find((r) => r.id === "unprotected-npm");
assert(installedNpmIssue !== undefined, "SCRG162-F2: installed npm should still appear in audit");
assert(
  installedNpmIssue!.title.includes("PATH still needs repair"),
  "SCRG162-F3: installed manager should not claim shim is missing",
);
assert(
  installedNpmIssue!.remediationAction?.label === "Repair PATH",
  "SCRG162-F4: installed manager remediation should repair PATH instead of install",
);

const auditWithRestartInstalled = deriveFrontendAuditResults(
  [],
  {
    ...baseSnapshot,
    supply_chain: {
      package_manager_protection: {
        ...makeProtection([], ["pnpm"]),
        installed_managers: ["pnpm"],
        path_status: "restart_required",
        restart_shell_required: true,
      },
    },
  },
);
const restartPnpmIssue = auditWithRestartInstalled.find((r) => r.id === "unprotected-pnpm");
assert(restartPnpmIssue !== undefined, "SCRG162-F6: restart-required installed manager should appear");
assert(
  restartPnpmIssue!.title.includes("waiting for restart"),
  "SCRG162-F7: restart-required manager should prompt for restart",
);
assert(
  restartPnpmIssue!.remediationAction === null,
  "SCRG162-F8: restart-required manager should not expose install remediation",
);

const receiptNow = new Date().toISOString();
const blockedReceipt = makeReceipt("block", receiptNow);
const auditWithBlocked = deriveFrontendAuditResults([blockedReceipt], baseSnapshot);
const blockedItem = auditWithBlocked.find((r) => r.id === `blocked-${blockedReceipt.receipt_id}`);
assert(blockedItem !== undefined, "SCRG162-G: blocked receipt should appear in audit");
assert(blockedItem!.severity === "medium", "SCRG162-H: blocked receipt should be medium");

const workspaceAuditReceipt = {
  ...makeReceipt("block", receiptNow),
  harness: "package-firewall",
  artifact_name: "Workspace supply-chain audit",
  capabilities_summary: "Workspace audit completed with block decision across 3 packages.",
  scanner_evidence: [
    {
      operation: "audit",
      audit_decision: "block",
      blocked_package_count: 1,
      manifest_paths: ["package.json"],
      lockfile_paths: ["package-lock.json"],
      total_packages: 3,
    },
  ],
};
const auditWithWorkspaceScan = deriveFrontendAuditResults([workspaceAuditReceipt], baseSnapshot);
const workspaceAuditItem = auditWithWorkspaceScan.find(
  (result) => result.id === `workspace-audit-${workspaceAuditReceipt.receipt_id}`,
);
assert(workspaceAuditItem !== undefined, "SCRG162-I: workspace audit receipt should render in audit tab");
assert(workspaceAuditItem!.severity === "high", "SCRG162-J: blocked workspace audit should be high severity");
assert(
  workspaceAuditItem!.detail.includes("Workspace audit completed"),
  "SCRG162-K: workspace audit detail should summarize the receipt",
);

const policies = [makePolicy("claude"), makePolicy("claude"), makePolicy("cursor")];
const grouped = groupPoliciesByHarness(policies);
assert(grouped.get("claude")?.length === 2, "SCRG164-A: 2 claude policies");
assert(grouped.get("cursor")?.length === 1, "SCRG164-B: 1 cursor policy");

const strictCopy = resolveSecurityModeCopy("strict");
assert(strictCopy.tone === "attention", "SCRG164-C: strict mode is attention tone");
assert(strictCopy.label.toLowerCase().includes("protect"), "SCRG164-D: strict mode shows Protect label");

const balancedCopy = resolveSecurityModeCopy("balanced");
assert(balancedCopy.tone === "green", "SCRG164-E: balanced is green tone");

const unknownCopy = resolveSecurityModeCopy(undefined);
assert(typeof unknownCopy.label === "string", "SCRG164-F: undefined level returns a string label");

assert(resolveFeedSourceMode("local_only") === "sample", "SCRG165-A: local_only = sample mode");
assert(resolveFeedSourceMode("paired_waiting") === "full", "SCRG165-B: paired_waiting = full mode");
assert(resolveFeedSourceMode("paired_active") === "live", "SCRG165-C: paired_active = live mode");

const stalenessNoActivity = resolveFeedStaleness(baseSnapshot);
assert(!stalenessNoActivity.stale, "SCRG165-D: no receipts is not stale");
assert(stalenessNoActivity.lastActivity === null, "SCRG165-E: no receipts has null lastActivity");

const freshReceipt = makeReceipt("allow", new Date().toISOString());
const freshSnapshot = { ...baseSnapshot, latest_receipts: [freshReceipt] };
const staleness = resolveFeedStaleness(freshSnapshot);
assert(!staleness.stale, "SCRG165-F: recent receipt is not stale");

const oldDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
const oldReceipt = makeReceipt("allow", oldDate);
const oldSnapshot = { ...baseSnapshot, latest_receipts: [oldReceipt] };
const oldStaleness = resolveFeedStaleness(oldSnapshot);
assert(oldStaleness.stale, "SCRG165-G: 8-day-old receipt is stale");
assert(oldStaleness.ageLabel.includes("stale"), "SCRG165-H: stale label mentions stale");
