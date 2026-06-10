import { resolveSupplyChainPostureAlerts } from "./supply-chain-posture";
import type { GuardRuntimeSnapshot, PackageManagerProtection } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const makeProtection = (
  overrides: Partial<PackageManagerProtection> = {},
): PackageManagerProtection => ({
  path_status: "in_path",
  path_contains_shim_dir: true,
  restart_shell_required: false,
  shell_profile_configured: true,
  shell_profile_path: null,
  shim_dir: "/shims",
  supported_managers: ["npm", "pip"],
  installed_managers: [],
  active_managers: [],
  missing_shims: [],
  protected_managers: [],
  unprotected_managers: ["npm", "pip"],
  ...overrides,
});

const baseSnapshot: GuardRuntimeSnapshot = {
  generated_at: new Date().toISOString(),
  approval_center_url: null,
  runtime_state: {},
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
  cloud_state_detail: "Live cloud feed",
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
  supply_chain: undefined,
};

const partialAlerts = resolveSupplyChainPostureAlerts({
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection({
      protected_managers: ["npm"],
      unprotected_managers: ["pip"],
      installed_managers: ["npm"],
    }),
  },
});
assert(
  partialAlerts.some((alert) => alert.kind === "partial_protection"),
  "SCSR160: partial protection surfaces posture banner",
);

const repairAlerts = resolveSupplyChainPostureAlerts({
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection({
      installed_managers: ["pnpm"],
      protected_managers: [],
      unprotected_managers: ["pnpm", "npm"],
      supported_managers: ["pnpm", "npm"],
      path_status: "in_path",
    }),
  },
});
assert(
  repairAlerts.some((alert) => alert.kind === "path_repair" && alert.tone === "attention"),
  "SCSR161: path repair required surfaces repair banner",
);

const missingPathAlerts = resolveSupplyChainPostureAlerts({
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection({
      path_status: "missing_from_path",
      installed_managers: [],
      protected_managers: [],
      unprotected_managers: ["npm", "pip"],
    }),
  },
});
assert(
  missingPathAlerts.some(
    (alert) =>
      alert.kind === "path_repair" &&
      alert.title === "Guard shims are missing from PATH" &&
      !alert.detail.includes("0 manager"),
  ),
  "SCSR161-C: missing PATH with no installed managers uses shim-missing copy",
);

const restartAlerts = resolveSupplyChainPostureAlerts({
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection({
      installed_managers: ["npm"],
      protected_managers: ["npm"],
      unprotected_managers: [],
      path_status: "restart_required",
      restart_shell_required: true,
    }),
  },
});
assert(
  restartAlerts.some((alert) => alert.kind === "path_repair" && alert.tone === "blue"),
  "SCSR161-B: restart-required PATH surfaces staged repair banner",
);

const staleDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
const staleAlerts = resolveSupplyChainPostureAlerts({
  ...baseSnapshot,
  latest_receipts: [
    {
      receipt_id: "receipt-stale",
      harness: "claude",
      artifact_id: "artifact",
      artifact_hash: "hash",
      policy_decision: "allow",
      capabilities_summary: "",
      changed_capabilities: [],
      provenance_summary: "",
      user_override: null,
      source_scope: null,
      timestamp: staleDate,
    },
  ],
});
assert(
  staleAlerts.some((alert) => alert.kind === "stale_intel"),
  "SCSR162: stale paired intel surfaces stale banner",
);

const localOnlyStale = resolveSupplyChainPostureAlerts({
  ...baseSnapshot,
  cloud_state: "local_only",
  latest_receipts: [
    {
      receipt_id: "receipt-stale-local",
      harness: "claude",
      artifact_id: "artifact",
      artifact_hash: "hash",
      policy_decision: "allow",
      capabilities_summary: "",
      changed_capabilities: [],
      provenance_summary: "",
      user_override: null,
      source_scope: null,
      timestamp: staleDate,
    },
  ],
});
assert(
  !localOnlyStale.some((alert) => alert.kind === "stale_intel"),
  "SCSR162-B: local-only mode skips stale intel banner",
);

console.log("scsr-phase09e-posture-banners.test.ts: all assertions passed");
