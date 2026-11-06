import { resolveSupplyChainPostureAlerts } from "./supply-chain-posture";
import {
  resolveProtectedManagersStat,
  SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS,
} from "./supply-chain-workspace-layout";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS.includes("overflow-x-hidden"),
  "SCSR164: supply chain workspace shell prevents horizontal overflow",
);
assert(
  SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS.includes("min-w-0"),
  "SCSR164: supply chain workspace shell allows flex children to shrink",
);

const stagedStat = resolveProtectedManagersStat({
  stagedManagers: 2,
  repairRequiredManagers: 0,
  protectedManagers: 1,
});
assert(stagedStat.label === "Ready after restart", "SCSR165: staged managers use plain restart copy");

const repairStat = resolveProtectedManagersStat({
  stagedManagers: 0,
  repairRequiredManagers: 1,
  protectedManagers: 0,
});
assert(repairStat.label === "Needs path fix", "SCSR165: repair stat avoids PATH jargon in label");

const partialAlerts = resolveSupplyChainPostureAlerts({
  generated_at: new Date().toISOString(),
  approval_center_url: null,
  runtime_state: null,
  device: {
    installation_id: "install-1",
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
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  cloud_state_detail: "",
  cloud_pairing_state: {
    state: "paired_active",
    label: "Connected",
    detail: "",
    sync_configured: true,
    dashboard_url: "",
    inbox_url: "",
    fleet_url: "",
    connect_url: "",
  },
  cloud_sync_health: {
    state: "healthy",
    label: "Healthy",
    detail: "",
    pending_events: 0,
    last_synced_at: new Date().toISOString(),
    next_retry_after: null,
  },
  dashboard_url: "",
  inbox_url: "",
  fleet_url: "",
  connect_url: "",
  items: [],
  latest_receipts: [],
  managed_installs: [],
  supply_chain: {
    package_manager_protection: {
      path_status: "in_path",
      path_contains_shim_dir: true,
      restart_shell_required: false,
      shell_profile_configured: true,
      shell_profile_path: null,
      shim_dir: "/shims",
      supported_managers: ["npm", "pip"],
      installed_managers: ["npm"],
      active_managers: ["npm"],
      missing_shims: [],
      protected_managers: ["npm"],
      unprotected_managers: ["pip"],
    },
  },
});

const partialCopy = partialAlerts.find((alert) => alert.kind === "partial_protection");
assert(partialCopy !== undefined, "SCSR165: partial protection alert still resolves");
assert(
  partialCopy.title.includes("package tools"),
  "SCSR165: partial protection title uses plain language",
);
assert(
  !partialCopy.detail.toLowerCase().includes("shim"),
  "SCSR165: partial protection detail avoids shim jargon",
);

console.log("scsr-phase09f-mobile-polish.test.ts: all assertions passed");
