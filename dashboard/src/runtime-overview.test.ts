import { resolveCloudIntelCopy, resolveCloudSyncHealthCopy, resolveProtectionLevelCopy, resolveApprovalCenterHealth } from "./runtime-overview";
import type { GuardCloudSyncHealth, GuardRuntimeSnapshot } from "./guard-types";

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
assert(pairedWaitingCopy.label === "Pairing…", "T508: paired_waiting label should be 'Pairing…'");

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
  pending_count: 0,
  receipt_count: 0,
  headline_state: "protected",
  headline_label: "Protected",
  headline_detail: "Guard is active.",
  sync_configured: false,
  cloud_state: "local_only",
  cloud_state_label: "Offline",
  cloud_state_detail: "Running locally.",
  cloud_pairing_state: { state: "local_only", label: "Offline", detail: "No cloud." },
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
assert(offlineApproval.state === "stale", "T738: null runtime_state should be stale");
assert(offlineApproval.label.toLowerCase().includes("offline"), "T738: stale label should mention offline");

const setupSnapshot: GuardRuntimeSnapshot = { ...baseSnapshot, headline_state: "setup" };
const startingApproval = resolveApprovalCenterHealth(setupSnapshot);
assert(startingApproval.state === "starting", "T738: setup headline should be starting");
assert(startingApproval.label.toLowerCase().includes("starting"), "T738: starting label should say starting");

const noUrlSnapshot: GuardRuntimeSnapshot = { ...baseSnapshot, approval_center_url: null };
const repairApproval = resolveApprovalCenterHealth(noUrlSnapshot);
assert(repairApproval.state === "repair_needed", "T738: null approval_center_url should need repair");
assert(repairApproval.label.toLowerCase().includes("unreachable"), "T738: repair label should mention unreachable");
assert(repairApproval.detail.toLowerCase().includes("repair"), "T738: repair detail should suggest repair action");

