import { parsePackageFirewallActionResult } from "./supply-chain-firewall-action-result";
import { resolvePackageFirewallNextAction } from "./supply-chain-firewall-next-action";
import type { PackageFirewallStatusResponse, PackageShimEntry } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function makeShim(overrides: Partial<PackageShimEntry> & Pick<PackageShimEntry, "manager">): PackageShimEntry {
  return {
    active: false,
    activation_state: "uninstalled",
    detected: false,
    installed: false,
    integrity: "missing",
    last_intercept_proof_at: null,
    path_broken: false,
    path_index: null,
    path_summary: null,
    real_binary_found: false,
    real_binary_path: null,
    real_binary_path_index: null,
    shim_path: null,
    tested: false,
    ...overrides,
  };
}

const baseStatus: PackageFirewallStatusResponse = {
  operation: "status",
  status: "completed",
  supported_managers: ["npm", "pnpm"],
  detected_managers: ["npm"],
  last_audit_proof_at: null,
  protection: {
    path_status: "in_path",
    path_contains_shim_dir: true,
    restart_shell_required: false,
    shell_profile_configured: true,
    shell_profile_path: null,
    shim_dir: "/shims",
    supported_managers: ["npm", "pnpm"],
    installed_managers: [],
    active_managers: [],
    missing_shims: ["npm"],
    protected_managers: [],
    unprotected_managers: ["npm", "pnpm"],
  },
  package_shims: [
    makeShim({ manager: "npm", detected: true, activation_state: "uninstalled" }),
  ],
  entitlement: {
    allowed: true,
    reason: "ok",
    tier: "team",
    upgrade_cta: null,
    upgrade_url: null,
  },
  actions: {},
  cli_fallback: null,
  connect_flow: null,
};

const protectAction = resolvePackageFirewallNextAction(baseStatus);
assert(protectAction.op === "install", "SCSR151: detected unprotected manager suggests install");
assert(protectAction.manager === "npm", "SCSR151: next action targets detected manager");

const pathBrokenStatus: PackageFirewallStatusResponse = {
  ...baseStatus,
  package_shims: [
    makeShim({
      manager: "pnpm",
      detected: true,
      installed: true,
      integrity: "ok",
      path_broken: true,
      activation_state: "repair_required",
    }),
  ],
};
const repairAction = resolvePackageFirewallNextAction(pathBrokenStatus);
assert(repairAction.op === "repair", "SCSR161: path broken manager suggests repair");

const auditDetail = parsePackageFirewallActionResult("audit", {
  result: {
    decision: "monitor",
    manifest_paths: ["package.json"],
    lockfile_paths: ["package-lock.json"],
    inventory: { packages: 4 },
  },
});
assert(auditDetail !== null, "SCSR153: audit action result parses");
assert(
  auditDetail!.lines.some((line) => line.includes("package-lock.json")),
  "SCSR153: audit result lists scanned lockfiles",
);

console.log("scsr-phase09-next-action.test.ts: all assertions passed");
