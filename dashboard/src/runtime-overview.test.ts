import { resolveCloudIntelCopy, resolveCloudSyncHealthCopy, resolveProtectionLevelCopy, resolveApprovalCenterHealth, resolveProofStatusCopy, resolvePackageManagerProtectionCopy } from "./runtime-overview";
import type { GuardCloudSyncHealth, GuardProofStatus, GuardRuntimeSnapshot, PackageManagerProtection } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const healthDisabled: GuardCloudSyncHealth = {
  state: "disabled",
  label: "Sync disabled",
  detail: "Cloud sync is turned off on this machine.",
  pending_events: 0,
  last_synced_at: null,
  next_retry_after: null
};

const healthHealthy: GuardCloudSyncHealth = {
  state: "healthy",
  label: "Sync healthy",
  detail: "Cloud sync is running normally.",
  pending_events: 0,
  last_synced_at: new Date().toISOString(),
  next_retry_after: null
};

const localOnlyCopy = resolveCloudIntelCopy("local_only");
assert(localOnlyCopy.label === "Offline, free", "T507: local_only label should be 'Offline, free'");
assert(localOnlyCopy.detail.length > 0, "T507: local_only detail should not be empty");
assert(localOnlyCopy.detail.includes("locally"), "T507: local_only detail should mention 'locally'");

const localOnlySyncCopy = resolveCloudSyncHealthCopy(healthDisabled);
assert(localOnlySyncCopy.label === healthDisabled.label, "T507: cloud sync health label should match");
assert(localOnlySyncCopy.detail === healthDisabled.detail, "T507: cloud sync health detail should match");

const protectionBalanced = resolveProtectionLevelCopy("balanced");
assert(protectionBalanced.includes("secrets"), "T507: balanced description should mention secrets");

const pairedActiveCopy = resolveCloudIntelCopy("paired_active");
assert(pairedActiveCopy.label === "Synced, pro", "T508: paired_active label should be 'Synced, pro'");
assert(pairedActiveCopy.detail.length > 0, "T508: paired_active detail should not be empty");
assert(pairedActiveCopy.detail.includes("Guard Cloud"), "T508: paired_active detail should mention Guard Cloud");

const pairedWaitingCopy = resolveCloudIntelCopy("paired_waiting");
assert(pairedWaitingCopy.label === "First sync in progress", "T508: paired_waiting label should describe automatic first sync");
assert(pairedWaitingCopy.detail.includes("first shared proof"), "T508: paired_waiting detail should mention the first shared proof");

const pairedActiveSyncCopy = resolveCloudSyncHealthCopy(healthHealthy);
assert(pairedActiveSyncCopy.label === healthHealthy.label, "T508: healthy sync label should match");

const protectionStrict = resolveProtectionLevelCopy("strict");
assert(protectionStrict.includes("network"), "T508: strict description should mention network");

const protectionCustom = resolveProtectionLevelCopy("custom");
assert(protectionCustom.includes("Custom"), "T508: custom description should mention Custom");

const baseSnapshot: GuardRuntimeSnapshot = {
  generated_at: new Date().toISOString(),
  approval_center_url: "http://localhost:7392/approval",
  runtime_state: {
    session_id: "sess-1",
    daemon_host: "localhost",
    daemon_port: 7391,
    started_at: new Date().toISOString(),
    last_heartbeat_at: new Date().toISOString(),
    approval_center_url: "http://localhost:7392/approval",
  },
  device: {
    installation_id: "install-abc123def456",
    device_label: "My MacBook Pro",
    local_registered: true,
  },
  latest_connect_state: null,
  proof_status: {
    state: "not_connected",
    label: "Not connected",
    detail: "No cloud proof yet.",
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
  headline_state: "protected",
  headline_label: "Protected",
  headline_detail: "Guard is active.",
  sync_configured: false,
  cloud_state: "local_only",
  cloud_state_label: "Offline",
  cloud_state_detail: "Running locally.",
  cloud_pairing_state: {
    state: "local_only",
    label: "Offline",
    detail: "No cloud.",
    sync_configured: false,
    dashboard_url: "http://localhost:7392",
    inbox_url: "http://localhost:7392/inbox",
    fleet_url: "http://localhost:7392/fleet",
    connect_url: "http://localhost:7392/connect",
  },
  cloud_sync_health: healthDisabled,
  dashboard_url: "http://localhost:7392",
  inbox_url: "http://localhost:7392/inbox",
  fleet_url: "http://localhost:7392/fleet",
  connect_url: "http://localhost:7392/connect",
  items: [],
  latest_receipts: [],
};

const healthyApproval = resolveApprovalCenterHealth(baseSnapshot);
assert(healthyApproval.state === "ready", "T738: protected snapshot with URL should be ready");
assert(healthyApproval.label.toLowerCase().includes("ready"), "T738: ready label should say ready");
assert(healthyApproval.detail.includes("http://localhost:7392/approval"), "T738: ready detail should include the URL");

const nullRuntimeSnapshot: GuardRuntimeSnapshot = { ...baseSnapshot, runtime_state: null };
const offlineApproval = resolveApprovalCenterHealth(nullRuntimeSnapshot);
assert(offlineApproval.state === "stale", "T738: null runtime_state (non-setup) should be stale");
assert(offlineApproval.label.toLowerCase().includes("offline"), "T738: stale label should mention offline");

const setupSnapshot: GuardRuntimeSnapshot = { ...baseSnapshot, runtime_state: null, headline_state: "setup" };
const startingApproval = resolveApprovalCenterHealth(setupSnapshot);
assert(startingApproval.state === "starting", "T738: null runtime_state + setup headline should be starting");
assert(startingApproval.label.toLowerCase().includes("starting"), "T738: starting label should say starting");

const noUrlSnapshot: GuardRuntimeSnapshot = { ...baseSnapshot, approval_center_url: null };
const repairApproval = resolveApprovalCenterHealth(noUrlSnapshot);
assert(repairApproval.state === "repair_needed", "T738: null approval_center_url should need repair");
assert(repairApproval.label.toLowerCase().includes("unreachable"), "T738: repair label should mention unreachable");
assert(repairApproval.detail.toLowerCase().includes("repair"), "T738: repair detail should suggest repair action");

const baseProof: GuardProofStatus = {
  state: "not_connected",
  label: "Not connected",
  detail: "No proof yet.",
  request_id: null,
  pairing_completed_at: null,
  first_synced_at: null,
  receipts_stored: 0,
  inventory_items: 0,
  runtime_session_id: null,
  runtime_session_synced_at: null,
};

const notConnectedCopy = resolveProofStatusCopy(baseProof);
assert(notConnectedCopy.tone === "slate", "P1: not_connected tone should be slate");
assert(notConnectedCopy.label === "Local only", "P1: not_connected label should be 'Local only'");
assert(notConnectedCopy.detail.toLowerCase().includes("local"), "P1: not_connected detail should mention local protection");

const syncedCopy = resolveProofStatusCopy({ ...baseProof, state: "synced", label: "Synced", detail: "All good." });
assert(syncedCopy.tone === "green", "P2: synced tone should be green");
assert(syncedCopy.label === "Synced", "P2: synced label should match proof label");
assert(syncedCopy.detail === "All good.", "P2: synced detail should pass through from proof");

const pendingCopy = resolveProofStatusCopy({ ...baseProof, state: "pending", label: "Pending", detail: "Connecting..." });
assert(pendingCopy.tone === "blue", "P3: pending tone should be blue");
assert(pendingCopy.label === "Pending", "P3: pending label should match proof label");

const waitingCopy = resolveProofStatusCopy({ ...baseProof, state: "waiting", label: "Waiting", detail: "Hold on." });
assert(waitingCopy.tone === "blue", "P4: waiting tone should be blue");
assert(waitingCopy.label === "Waiting", "P4: waiting label should match proof label");

const failedCopy = resolveProofStatusCopy({ ...baseProof, state: "failed", label: "Failed", detail: "Connection error." });
assert(failedCopy.tone === "attention", "P5: failed tone should be attention");
assert(failedCopy.label === "Failed", "P5: failed label should match proof label");

const expiredCopy = resolveProofStatusCopy({ ...baseProof, state: "expired", label: "Expired", detail: "Timed out." });
assert(expiredCopy.tone === "attention", "P6: expired tone should be attention");
assert(expiredCopy.label === "Expired", "P6: expired label should match proof label");

const unavailableCopy = resolveProofStatusCopy({ ...baseProof, state: "sync_unavailable", label: "Unavailable", detail: "No plan." });
assert(unavailableCopy.tone === "slate", "P7: sync_unavailable tone should be slate");
assert(unavailableCopy.label === "Cloud proof not available", "P7: sync_unavailable label should indicate unavailability");
assert(
  unavailableCopy.detail.toLowerCase().includes("cloud") || unavailableCopy.detail.toLowerCase().includes("connect"),
  `P7: sync_unavailable detail should mention cloud or connect (upgrade path) — got: "${unavailableCopy.detail}"`
);

const baseProtection: PackageManagerProtection = {
  path_status: "in_path",
  path_contains_shim_dir: true,
  restart_shell_required: false,
  shell_profile_configured: true,
  shell_profile_path: "/mock-home/.zshrc",
  shim_dir: "/mock-home/.hol/shims",
  supported_managers: ["npm", "pip", "cargo"],
  installed_managers: ["npm", "pip"],
  active_managers: ["npm", "pip"],
  missing_shims: [],
  protected_managers: ["npm", "pip"],
  unprotected_managers: [],
};

const inPathCopy = resolvePackageManagerProtectionCopy(baseProtection);
assert(inPathCopy.pathTone === "green", "SC1: in_path tone should be green");
assert(inPathCopy.pathLabel.toLowerCase().includes("in path") || inPathCopy.pathLabel.toLowerCase().includes("in path"), "SC1: in_path label should indicate shim is in PATH");
assert(inPathCopy.pathDetail.includes(baseProtection.shim_dir), "SC1: in_path detail should include the shim directory");
assert(inPathCopy.protectedList.length === 2, "SC1: protected list should reflect protected_managers");
assert(inPathCopy.protectedList.includes("npm"), "SC1: npm should appear in protected list");
assert(inPathCopy.protectedList.includes("pip"), "SC1: pip should appear in protected list");
assert(inPathCopy.unprotectedList.length === 0, "SC1: unprotected list should be empty when all managers are protected");

const missingFromPathProtection: PackageManagerProtection = {
  ...baseProtection,
  path_status: "missing_from_path",
  path_contains_shim_dir: false,
  restart_shell_required: false,
  protected_managers: ["npm"],
  unprotected_managers: ["pip", "cargo"],
};

const missingFromPathCopy = resolvePackageManagerProtectionCopy(missingFromPathProtection);
assert(missingFromPathCopy.pathTone === "attention", "SC2: missing_from_path tone should be attention");
assert(
  missingFromPathCopy.pathLabel.toLowerCase().includes("missing") || missingFromPathCopy.pathLabel.toLowerCase().includes("not"),
  `SC2: missing_from_path label should signal a warning — got: "${missingFromPathCopy.pathLabel}"`
);
assert(
  missingFromPathCopy.pathDetail.toLowerCase().includes("bypass") || missingFromPathCopy.pathDetail.toLowerCase().includes("not on path") || missingFromPathCopy.pathDetail.toLowerCase().includes("missing"),
  `SC2: missing_from_path detail should describe the bypass risk — got: "${missingFromPathCopy.pathDetail}"`
);
assert(missingFromPathCopy.unprotectedList.includes("pip"), "SC2: pip should appear in unprotected list");
assert(missingFromPathCopy.unprotectedList.includes("cargo"), "SC2: cargo should appear in unprotected list");
assert(missingFromPathCopy.protectedList.includes("npm"), "SC2: npm should still appear in protected list");
assert(missingFromPathCopy.protectedList.length === 1, "SC2: protected list should contain only npm");

const restartRequiredProtection: PackageManagerProtection = {
  ...baseProtection,
  path_status: "restart_required",
  path_contains_shim_dir: false,
  restart_shell_required: true,
  protected_managers: [],
  unprotected_managers: ["npm", "pip", "cargo"],
};

const restartRequiredCopy = resolvePackageManagerProtectionCopy(restartRequiredProtection);
assert(restartRequiredCopy.pathTone === "attention", "SC2b: restart_required tone should stay attention");
assert(
  restartRequiredCopy.pathLabel.toLowerCase().includes("restart"),
  `SC2b: restart_required label should mention restart — got: "${restartRequiredCopy.pathLabel}"`
);
assert(
  restartRequiredCopy.pathDetail.toLowerCase().includes("restart") || restartRequiredCopy.pathDetail.toLowerCase().includes("new shell"),
  `SC2b: restart_required detail should explain next step — got: "${restartRequiredCopy.pathDetail}"`
);

const absentCopy = resolvePackageManagerProtectionCopy(undefined);
assert(absentCopy.pathTone === "slate", "SC3: absent supply-chain data should use slate tone (no crash)");
assert(absentCopy.pathLabel.length > 0, "SC3: absent supply-chain data should still produce a non-empty label");
assert(absentCopy.protectedList.length === 0, "SC3: absent supply-chain data should return empty protected list");
assert(absentCopy.unprotectedList.length === 0, "SC3: absent supply-chain data should return empty unprotected list");
