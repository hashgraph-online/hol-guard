import { normalizePackageFirewallStatus } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const phase11Payload = normalizePackageFirewallStatus({
  supported_managers: ["npm", "pnpm", "pip"],
  package_shims: {
    detectedManagers: ["npm", "pnpm"],
    installedManagers: ["npm"],
    protectedManagers: ["npm"],
    testedManagers: ["npm"],
    pathBrokenManagers: ["pnpm"],
    path_status: "in_path",
    lastAuditProofAt: "2026-06-07T12:00:00Z",
    lastInterceptProofAt: {
      npm: "2026-06-07T11:30:00Z",
    },
    manager_details: [
      {
        manager: "npm",
        integrity: "ok",
        path_active: true,
        shim_path: "/tmp/guard-shims/npm",
        real_binary_path: "/usr/local/bin/npm",
      },
      {
        manager: "pnpm",
        integrity: "ok",
        path_active: false,
        shim_path: "/tmp/guard-shims/pnpm",
        real_binary_path: "/usr/local/bin/pnpm",
      },
    ],
  },
});

assert(phase11Payload.detected_managers.length === 2, "SCSR151: detected managers surface on status response");
assert(
  phase11Payload.last_audit_proof_at === "2026-06-07T12:00:00Z",
  "SCSR151: last audit proof timestamp surfaces on status response",
);

const npm = phase11Payload.package_shims.find((entry) => entry.manager === "npm");
const pnpm = phase11Payload.package_shims.find((entry) => entry.manager === "pnpm");

assert(npm !== undefined, "SCSR151: npm shim entry exists");
assert(pnpm !== undefined, "SCSR151: pnpm shim entry exists");
assert(npm?.detected === true, "SCSR151: npm marked detected");
assert(npm?.tested === true, "SCSR151: npm marked tested");
assert(
  npm?.last_intercept_proof_at === "2026-06-07T11:30:00Z",
  "SCSR151: npm intercept proof timestamp normalized",
);
assert(
  npm?.path_summary === "/tmp/guard-shims/npm precedes /usr/local/bin/npm",
  "SCSR151: npm path summary built from shim and real binary paths",
);
assert(pnpm?.path_broken === true, "SCSR151: pnpm marked path broken");
assert(pnpm?.activation_state === "repair_required", "SCSR151: path broken manager needs repair");

const nestedPayload = normalizePackageFirewallStatus({
  supported_managers: ["npm"],
  package_shims: {
    detected_managers: ["npm"],
    installed_managers: ["npm"],
    tested_managers: ["npm"],
    path_broken_managers: [],
    path_status: "restart_required",
    last_intercept_proof_at: {
      npm: "2026-06-07T10:00:00Z",
    },
    manager_details: [
      {
        manager: "npm",
        integrity: "ok",
        path_active: false,
        shim_path: "/tmp/guard-shims/npm",
      },
    ],
  },
});

const nestedNpm = nestedPayload.package_shims.find((entry) => entry.manager === "npm");
assert(
  nestedNpm?.activation_state === "restart_required",
  "SCSR151: restart_required path status maps to restart activation state",
);
assert(
  nestedNpm?.last_intercept_proof_at === "2026-06-07T10:00:00Z",
  "SCSR151: snake_case intercept proof map is read",
);

const hiddenManagerPayload = normalizePackageFirewallStatus({
  supported_managers: ["npm", "yarn"],
  package_shims: {
    detectedManagers: ["npm"],
    installedManagers: [],
    testedManagers: [],
    path_status: "in_path",
    manager_details: [],
  },
});

assert(
  hiddenManagerPayload.package_shims.length === 1,
  "SCSR151: undetected unsupported managers stay hidden",
);
assert(
  hiddenManagerPayload.package_shims[0]?.manager === "npm",
  "SCSR151: only detected managers render in shim list",
);

console.log("scsr-phase09-package-firewall-status.test.ts: all assertions passed");
