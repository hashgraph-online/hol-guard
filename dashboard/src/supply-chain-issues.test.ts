import { resolveSupplyChainIssues } from "./supply-chain-issues";
import { resolveSupplyChainWorkspaceHero } from "./supply-chain-workspace-hero-state";
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
  supported_managers: ["npm", "pip", "pnpm"],
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
  cloud_state_detail: "Guard Cloud connection on this machine needs repair before the first shared proof can land.",
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

const localPartialSnapshot: GuardRuntimeSnapshot = {
  ...baseSnapshot,
  supply_chain: {
    package_manager_protection: makeProtection({
      protected_managers: ["npm", "pip", "pnpm", "yarn", "go", "cargo", "gradle"],
      unprotected_managers: ["bun", "bundle", "composer", "mvn", "npx", "pip3", "poetry"],
      installed_managers: ["npm"],
    }),
  },
};

const localPartialIssues = resolveSupplyChainIssues(localPartialSnapshot);
assert(localPartialIssues.length === 2, "SCSR170: local partial setup dedupes to cloud + protection issues");
assert(
  localPartialIssues[0]?.id === "cloud_connect" && localPartialIssues[0]?.action.kind === "connect",
  "SCSR170-A: first issue is connect Guard Cloud with connect action",
);
assert(
  localPartialIssues[1]?.id === "partial_protection" &&
    localPartialIssues[1]?.action.kind === "firewall_unprotected",
  "SCSR170-B: second issue is partial protection with firewall focus action",
);
assert(
  !localPartialIssues.some((issue) => issue.title === "Protection is only partly set up"),
  "SCSR170-C: issue focus avoids repeating hero posture title",
);

const pairedPartialIssues = resolveSupplyChainIssues({
  ...localPartialSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
});
assert(
  pairedPartialIssues.length === 1 && pairedPartialIssues[0]?.id === "partial_protection",
  "SCSR170-D: paired cloud skips connect issue",
);

const restartRequiredIssues = resolveSupplyChainIssues({
  ...baseSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  supply_chain: {
    package_manager_protection: makeProtection({
      installed_managers: ["npm"],
      path_contains_shim_dir: false,
      path_status: "restart_required",
      restart_shell_required: true,
    }),
  },
});
assert(
  restartRequiredIssues.some(
    (issue) => issue.id === "path_restart" && issue.action.kind === "activate_runtime",
  ),
  "SCSR170-E: restart-required recovery activates the Guard runtime instead of opening a terminal",
);

const compactHero = resolveSupplyChainWorkspaceHero(localPartialSnapshot, {
  openIssueCount: localPartialIssues.length,
});
assert(
  compactHero.title === "Work through the steps below",
  "SCSR170-F: compact hero defers detail to issue carousel",
);
assert(
  compactHero.detail.includes("2 setup steps"),
  "SCSR170-G: compact hero summarizes open issue count",
);

const staleDate = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
const staleIssues = resolveSupplyChainIssues({
  ...baseSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
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
  staleIssues.some((issue) => issue.id === "stale_intel" && issue.action.kind === "firewall_audit"),
  "SCSR170-H: stale intel issue routes to workspace audit",
);

console.log("supply-chain-issues.test.ts: all assertions passed");
