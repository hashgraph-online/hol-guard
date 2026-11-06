import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { IDLE_SUPPLY_CHAIN_FIX_ALL_STATE } from "./supply-chain-fix-all";
import { resolveSupplyChainIssues } from "./supply-chain-issues";
import { SupplyChainRecovery } from "./supply-chain-recovery";
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
  detected_managers: ["npm", "pip", "pnpm"],
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
      detected_managers: [
        "npm",
        "pip",
        "pnpm",
        "yarn",
        "go",
        "cargo",
        "gradle",
        "bun",
        "bundle",
        "composer",
        "mvn",
        "npx",
        "pip3",
        "poetry",
      ],
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

const pairedPartialSnapshot: GuardRuntimeSnapshot = {
  ...localPartialSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
};
const pairedPartialIssues = resolveSupplyChainIssues(pairedPartialSnapshot);
assert(
  pairedPartialIssues.length === 1 && pairedPartialIssues[0]?.id === "partial_protection",
  "SCSR170-D: paired cloud skips connect issue",
);
const singleIssueHero = resolveSupplyChainWorkspaceHero(pairedPartialSnapshot, {
  openIssueCount: pairedPartialIssues.length,
});
assert(
  singleIssueHero.detail.includes("1 setup step needs attention"),
  "SCSR170-E: singular setup-step summary uses singular verb agreement",
);

const restartRequiredSnapshot: GuardRuntimeSnapshot = {
  ...baseSnapshot,
  cloud_state: "paired_active",
  cloud_state_label: "Connected",
  supply_chain: {
    package_manager_protection: makeProtection({
      detected_managers: ["npm"],
      installed_managers: ["npm"],
      path_contains_shim_dir: false,
      path_status: "restart_required",
      restart_shell_required: true,
    }),
  },
};
const restartRequiredIssues = resolveSupplyChainIssues(restartRequiredSnapshot);
assert(
  restartRequiredIssues.length === 0,
  "SCSR170-F: staged shell restart is not reported as another repairable Fix all issue",
);
const restartRequiredHero = resolveSupplyChainWorkspaceHero(restartRequiredSnapshot, {
  openIssueCount: restartRequiredIssues.length,
});
assert(
  restartRequiredHero.protectionStatus === "staged" &&
    restartRequiredHero.title === "Finish setup in a new terminal" &&
    restartRequiredHero.detail.includes("Open a new terminal or restart AI apps"),
  "SCSR170-G: staged repair completion gives the non-repair restart instruction",
);

const mixedRestartSnapshot: GuardRuntimeSnapshot = {
  ...restartRequiredSnapshot,
  cloud_state: "local_only",
  cloud_state_label: "On this device only",
};
const mixedRestartIssues = resolveSupplyChainIssues(mixedRestartSnapshot);
assert(
  mixedRestartIssues.some((issue) => issue.id === "cloud_connect"),
  "SCSR170-H: mixed staged state keeps unrelated actionable issues",
);
const mixedRestartHero = resolveSupplyChainWorkspaceHero(mixedRestartSnapshot, {
  openIssueCount: mixedRestartIssues.length,
});
assert(
  mixedRestartHero.title === "Work through the steps below" &&
    mixedRestartHero.detail.includes("Open a new terminal or restart AI apps"),
  "SCSR170-I: mixed staged state preserves restart guidance in resolved state",
);
const mixedRecoveryMarkup = renderToStaticMarkup(
  createElement(SupplyChainRecovery, {
    issues: mixedRestartIssues,
    state: IDLE_SUPPLY_CHAIN_FIX_ALL_STATE,
    onFixAll: () => undefined,
    guidance: mixedRestartHero.stagedGuidance,
  }),
);
assert(
  mixedRecoveryMarkup.includes('data-testid="supply-chain-restart-guidance"') &&
    mixedRecoveryMarkup.includes("Open a new terminal or restart AI apps"),
  "SCSR170-J: mixed recovery UI visibly renders staged restart guidance",
);

const compactHero = resolveSupplyChainWorkspaceHero(localPartialSnapshot, {
  openIssueCount: localPartialIssues.length,
});
assert(
  compactHero.title === "Work through the steps below",
  "SCSR170-K: compact hero defers detail to issue carousel",
);
assert(
  compactHero.detail.includes("2 setup steps need attention"),
  "SCSR170-L: plural setup-step summary uses plural verb agreement",
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
  "SCSR170-M: stale intel issue routes to workspace audit",
);

console.log("supply-chain-issues.test.ts: all assertions passed");
