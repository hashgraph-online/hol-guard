import { resolveSupplyChainCloudCapabilities } from "./supply-chain-cloud-capabilities";
import type { GuardRuntimeSnapshot } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const baseSnapshot: GuardRuntimeSnapshot = {
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
  cloud_state: "local_only",
  cloud_state_label: "Local only",
  cloud_state_detail: "",
  cloud_pairing_state: {
    state: "local_only",
    label: "Local only",
    detail: "",
    sync_configured: false,
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

const localOnly = resolveSupplyChainCloudCapabilities(baseSnapshot);
assert(localOnly.mode === "local_only", "SCSR156: local-only mode resolves free vs cloud capabilities");
assert(
  localOnly.localCapabilities.every((item) => item.available),
  "SCSR156: local free capabilities are marked available",
);
assert(
  localOnly.cloudCapabilities.every((item) => !item.available),
  "SCSR156: cloud capabilities stay unavailable without pairing",
);

const pairedActive = resolveSupplyChainCloudCapabilities({
  ...baseSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  cloud_state_detail: "Live feed active",
});
assert(pairedActive.mode === "paired_active", "SCSR155: paired active resolves connected state");
assert(
  pairedActive.detail.includes("Local protection still runs"),
  "SCSR155: paired active copy keeps local protection visible",
);
assert(
  pairedActive.cloudCapabilities.every((item) => item.available),
  "SCSR155: paired active marks cloud capabilities available",
);

const pairedWaiting = resolveSupplyChainCloudCapabilities({
  ...baseSnapshot,
  cloud_state: "paired_waiting",
  cloud_state_label: "Pairing",
});
assert(pairedWaiting.mode === "paired_waiting", "SCSR155-B: paired waiting resolves in-progress state");
assert(
  pairedWaiting.localCapabilities.every((item) => item.available),
  "SCSR155-B: pairing state keeps local capabilities available",
);

console.log("scsr-phase09g-cloud-capabilities.test.ts: all assertions passed");
