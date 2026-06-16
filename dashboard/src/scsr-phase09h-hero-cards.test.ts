import { normalizeSupplyChainAuditSnapshot } from "./supply-chain-audit-normalize";
import { resolveSupplyChainWorkspaceHero } from "./supply-chain-workspace-hero-state";
import type { GuardRuntimeSnapshot, PackageShimEntry } from "./guard-types";

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
  cloud_state_label: "On this device only",
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

const localHero = resolveSupplyChainWorkspaceHero(baseSnapshot);
assert(localHero.cloudMode === "local_only", "SCSR151: local-only cloud mode surfaces in hero");
assert(localHero.title.length > 0, "SCSR151: hero title resolves");

const pairedHero = resolveSupplyChainWorkspaceHero({
  ...baseSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  supply_chain: {
    package_manager_protection: {
      path_status: "in_path",
      path_contains_shim_dir: true,
      restart_shell_required: false,
      shell_profile_configured: true,
      shell_profile_path: null,
      shim_dir: "/shims",
      supported_managers: ["npm"],
      installed_managers: ["npm"],
      active_managers: ["npm"],
      missing_shims: [],
      protected_managers: ["npm"],
      unprotected_managers: [],
    },
  },
});
assert(pairedHero.cloudMode === "paired_active", "SCSR151-B: paired active cloud mode surfaces in hero");
assert(pairedHero.protectionStatus === "protected", "SCSR151-B: protected state surfaces in hero");

const shim: PackageShimEntry = {
  active: true,
  activation_state: "protected",
  detected: true,
  installed: true,
  integrity: "ok",
  last_intercept_proof_at: "2026-06-09T12:00:00.000Z",
  manager: "npm",
  path_broken: false,
  path_index: 0,
  path_summary: "/shims/npm",
  real_binary_found: true,
  real_binary_path: "/usr/bin/npm",
  real_binary_path_index: 1,
  shim_path: "/shims/npm",
  tested: true,
};

assert(shim.detected && shim.installed && shim.tested, "SCSR152: manager card truth fields available from shim");

const auditSnapshot = normalizeSupplyChainAuditSnapshot(
  {
    generated_at: "2026-06-09T12:00:00.000Z",
    source: "local",
    inventory: { total_packages: 1, direct_package_count: 1, transitive_package_count: 0, sbom_package_count: 0 },
    evaluation: {
      decision: "warn",
      packages: [
        {
          name: "left-pad",
          ecosystem: "npm",
          namespace: null,
          decision: "warn",
          reasons: [{ code: "outdated", message: "Outdated", severity: "medium" }],
          status: "known",
        },
      ],
    },
  },
  "receipt-audit-local",
);
assert(auditSnapshot !== null && auditSnapshot.findings.length === 1, "SCSR153: audit findings normalize for summary panel");

console.log("scsr-phase09h-hero-cards.test.ts: all assertions passed");
