import { resolveView, viewTitle } from "./app";
import { hubTitleForTab } from "./supply-chain-hub-workspace";
import {
  buildDemoRuntimeSnapshot,
  loadStatusPage,
  loadSupplyChainPage,
  loadAuditPage,
  loadEvidencePage,
  loadPolicyPage,
  loadFeedPage,
  type StatusPageData,
  type SupplyChainPageData,
  type AuditPageData,
  type EvidencePageData,
  type PolicyPageData,
  type FeedPageData,
} from "./guard-api";
import { buildSupplyChainStats } from "./supply-chain-workspace";
import { deriveFrontendAuditResults } from "./audit-workspace";
import { groupPoliciesByHarness, resolveCloudPolicyBundleCopy, resolveSecurityModeCopy } from "./policy-workspace";
import { resolveFeedSourceMode, resolveFeedStaleness } from "./feed-health-workspace";
import type {
  GuardRuntimeSnapshot,
  GuardManagedInstall,
  GuardReceipt,
  GuardPolicyDecision,
  PackageManagerProtection,
} from "./guard-types";

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

const freeSnapshot: GuardRuntimeSnapshot = {
  generated_at: new Date().toISOString(),
  approval_center_url: null,
  runtime_state: null,
  device: { installation_id: "free-device", device_label: "Free Machine", local_registered: false },
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
  cloud_state_detail: "Running locally without cloud sync.",
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
    label: "Cloud sync disabled",
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

const paidSnapshot: GuardRuntimeSnapshot = {
  ...freeSnapshot,
  sync_configured: true,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  cloud_state_detail: "Cloud sync is active and healthy.",
  cloud_pairing_state: {
    state: "paired_active",
    label: "Connected",
    detail: "Cloud sync is active.",
    sync_configured: true,
    dashboard_url: "https://hol.org/guard",
    inbox_url: "https://hol.org/guard/inbox",
    fleet_url: "https://hol.org/guard/protect",
    connect_url: "https://hol.org/guard/connect",
  },
  cloud_sync_health: {
    state: "healthy",
    label: "Cloud sync healthy",
    detail: "All events synced.",
    pending_events: 0,
    last_synced_at: new Date().toISOString(),
    next_retry_after: null,
  },
};

const degradedSnapshot: GuardRuntimeSnapshot = {
  ...freeSnapshot,
  sync_configured: true,
  cloud_state: "paired_waiting",
  cloud_state_label: "Degraded",
  cloud_state_detail: "Cloud sync is degraded.",
  cloud_pairing_state: {
    state: "paired_waiting",
    label: "Degraded",
    detail: "Cloud sync is degraded.",
    sync_configured: true,
    dashboard_url: "https://hol.org/guard",
    inbox_url: "https://hol.org/guard/inbox",
    fleet_url: "https://hol.org/guard/protect",
    connect_url: "https://hol.org/guard/connect",
  },
  cloud_sync_health: {
    state: "degraded",
    label: "Cloud sync degraded",
    detail: "Sync is experiencing issues.",
    pending_events: 5,
    last_synced_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
    next_retry_after: new Date(Date.now() + 5 * 60 * 1000).toISOString(),
  },
};

const pairedPolicySnapshot: GuardRuntimeSnapshot = {
  ...paidSnapshot,
  cloud_policy_bundle_version: "policy-2026-06-05.1",
  cloud_policy_rollout_state: "enforcing",
};

const makeInstall = (active: boolean): GuardManagedInstall => ({
  harness: "claude",
  active,
  workspace: null,
  manifest: {},
  updated_at: new Date().toISOString(),
});

const makeReceipt = (decision: "allow" | "block"): GuardReceipt => ({
  receipt_id: `receipt-${Math.random()}`,
  harness: "claude",
  artifact_id: "test-artifact",
  artifact_name: "test-pkg",
  artifact_hash: "abc123",
  source_scope: null,
  policy_decision: decision,
  timestamp: new Date().toISOString(),
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
  resolveView("/supply-chain") === "supply-chain",
  "SCRG171-A: /supply-chain resolves to supply-chain view",
);

assert(
  resolveView("/audit") === "audit",
  "SCRG171-B: /audit resolves to audit view",
);

assert(
  resolveView("/policy") === "policy",
  "SCRG171-C: /policy resolves to policy view",
);

assert(
  resolveView("/feed-health") === "feed-health",
  "SCRG171-D: /feed-health resolves to feed-health view",
);

assert(
  resolveView("/supply-chain/extra") !== "supply-chain",
  "SCRG171-E: /supply-chain sub-paths do not match supply-chain view",
);

assert(
  resolveView("/audit-log") !== "audit",
  "SCRG171-F: /audit-log does not match audit view",
);

assert(
  resolveView("/policies") !== "policy",
  "SCRG171-G: /policies does not match policy view",
);

assert(
  resolveView("/feed") !== "feed-health",
  "SCRG171-H: /feed does not match feed-health view",
);

assert(
  viewTitle("supply-chain") === "Supply Chain" &&
    viewTitle("audit") === "Audit" &&
    viewTitle("policy") === "Policy" &&
    viewTitle("feed-health") === "Feed Health",
  "SCRG171-H2: route titles stay specific inside Trust Center views",
);

assert(
  hubTitleForTab("supply-chain") === "Supply Chain" &&
    hubTitleForTab("audit") === "Audit" &&
    hubTitleForTab("policy") === "Policy" &&
    hubTitleForTab("feed-health") === "Feed Health",
  "SCRG171-H3: hub header mirrors active Trust Center tab",
);

assert(
  typeof loadStatusPage === "function",
  "SCRG171-I: loadStatusPage is exported as a function",
);

assert(
  typeof loadSupplyChainPage === "function",
  "SCRG171-J: loadSupplyChainPage is exported as a function",
);

const cloudBundleCopy = resolveCloudPolicyBundleCopy(pairedPolicySnapshot);
assert(cloudBundleCopy !== null, "SCRG171-K: paired cloud bundle should expose policy workspace copy");
assert(cloudBundleCopy!.label.includes("policy-2026-06-05.1"), "SCRG171-L: cloud bundle label includes version");
assert(cloudBundleCopy!.detail.includes("Guard Cloud Controls"), "SCRG171-M: cloud bundle detail preserves cloud ownership");

assert(
  typeof loadAuditPage === "function",
  "SCRG171-K: loadAuditPage is exported as a function",
);

assert(
  typeof loadEvidencePage === "function",
  "SCRG171-L: loadEvidencePage is exported as a function",
);

assert(
  typeof loadPolicyPage === "function",
  "SCRG171-M: loadPolicyPage is exported as a function",
);

assert(
  typeof loadFeedPage === "function",
  "SCRG171-N: loadFeedPage is exported as a function",
);

const demoSnapshot = buildDemoRuntimeSnapshot();

assert(
  typeof demoSnapshot.cloud_state === "string",
  "SCRG171-O: demo snapshot exposes cloud_state for loader wiring",
);

assert(
  Array.isArray(demoSnapshot.items),
  "SCRG171-P: demo snapshot provides items array for inbox loader",
);

assert(
  Array.isArray(demoSnapshot.latest_receipts),
  "SCRG171-Q: demo snapshot provides latest_receipts for evidence loader",
);

const supplyChainStats = buildSupplyChainStats({
  ...freeSnapshot,
  managed_installs: [makeInstall(true), makeInstall(false)],
  supply_chain: { package_manager_protection: makeProtection(["npm"], ["pip"]) },
});
assert(
  supplyChainStats.totalApps === 2,
  "SCRG171-R: supply-chain loader data: totalApps reflects managed installs",
);
assert(
  supplyChainStats.activeApps === 1,
  "SCRG171-S: supply-chain loader data: activeApps reflects active installs",
);
assert(
  supplyChainStats.preventedInstalls === 1,
  "SCRG171-T: supply-chain loader data: preventedInstalls reflects blocked installs",
);

const auditResults = deriveFrontendAuditResults(
  [makeReceipt("block")],
  {
    ...freeSnapshot,
    supply_chain: { package_manager_protection: makeProtection([], ["pip"]) },
  },
);
assert(
  auditResults.length >= 2,
  "SCRG171-U: audit loader data: results include both blocked receipts and unprotected managers",
);
assert(
  auditResults.some((r) => r.severity === "high"),
  "SCRG171-V: audit loader data: unprotected manager appears as high severity",
);
const unprotectedManagerAudit = auditResults.find((r) => r.id === "unprotected-pip");
assert(
  unprotectedManagerAudit?.remediationAction?.action === "package_shim_path",
  "SCRG171-V2: unprotected manager audit issue exposes a daemon remediation action",
);
assert(
  unprotectedManagerAudit?.remediationAction?.manager === "pip",
  "SCRG171-V3: unprotected manager remediation action targets the affected manager",
);
assert(
  auditResults.some((r) => r.severity === "medium"),
  "SCRG171-W: audit loader data: blocked receipt appears as medium severity",
);

const policies = [makePolicy("claude"), makePolicy("claude"), makePolicy("cursor")];
const grouped = groupPoliciesByHarness(policies);
assert(
  grouped.get("claude")?.length === 2,
  "SCRG171-X: policy loader data: claude policies grouped correctly",
);
assert(
  grouped.get("cursor")?.length === 1,
  "SCRG171-Y: policy loader data: cursor policies grouped correctly",
);

assert(
  resolveFeedSourceMode(freeSnapshot.cloud_state) === "sample",
  "SCRG171-Z: feed loader data: free state maps to sample feed mode",
);
assert(
  resolveFeedSourceMode(paidSnapshot.cloud_state) === "live",
  "SCRG171-AA: feed loader data: paid state maps to live feed mode",
);
assert(
  resolveFeedSourceMode(degradedSnapshot.cloud_state) === "full",
  "SCRG171-AB: feed loader data: degraded state maps to full feed mode",
);

const freeFeedness = resolveFeedStaleness(freeSnapshot);
assert(
  !freeFeedness.stale,
  "SCRG171-AC: feed loader data: free snapshot with no receipts is not stale",
);

const strictMode = resolveSecurityModeCopy("strict");
assert(
  strictMode.tone === "attention",
  "SCRG171-AD: policy loader data: strict security mode has attention tone",
);

const balancedMode = resolveSecurityModeCopy("balanced");
assert(
  balancedMode.tone === "green",
  "SCRG171-AE: policy loader data: balanced security mode has green tone",
);

const paidSyncMode = resolveFeedSourceMode(paidSnapshot.cloud_state);
assert(
  paidSyncMode === "live",
  "SCRG171-AF: paid snapshot cloud state drives live feed mode in FeedHealthWorkspace",
);

const degradedSyncMode = resolveFeedSourceMode(degradedSnapshot.cloud_state);
assert(
  degradedSyncMode === "full",
  "SCRG171-AG: degraded snapshot cloud state drives full feed mode in FeedHealthWorkspace",
);

function verifyLoaderTypeShape<T extends object>(
  loaderFn: (...args: never[]) => Promise<T>,
  fnName: string,
): void {
  assert(typeof loaderFn === "function", `${fnName} must be a function`);
  assert(
    loaderFn.constructor.name === "AsyncFunction" || loaderFn.toString().includes("async"),
    `${fnName} must be an async function`,
  );
}

verifyLoaderTypeShape(loadStatusPage as () => Promise<StatusPageData>, "loadStatusPage");
verifyLoaderTypeShape(
  loadSupplyChainPage as () => Promise<SupplyChainPageData>,
  "loadSupplyChainPage",
);
verifyLoaderTypeShape(loadAuditPage as () => Promise<AuditPageData>, "loadAuditPage");
verifyLoaderTypeShape(loadEvidencePage as () => Promise<EvidencePageData>, "loadEvidencePage");
verifyLoaderTypeShape(loadPolicyPage as () => Promise<PolicyPageData>, "loadPolicyPage");
verifyLoaderTypeShape(loadFeedPage as () => Promise<FeedPageData>, "loadFeedPage");
