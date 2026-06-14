import { buildGuardDaemonCandidatePorts, normalizeGuardUpdateStatus } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const normalized = normalizeGuardUpdateStatus({
  current_version: "1.2.3",
  latest_version: "1.2.4",
  installer: "pipx",
  version_check: {
    source: "pypi",
    status: "stale",
    current_version: "1.2.3",
    latest_version: "1.2.4",
    update_available: true,
  },
  auto_updatable: true,
  update_available: true,
  blocked_reason: null,
  update_in_progress: true,
});

assert(normalized.current_version === "1.2.3", "current version should normalize");
assert(normalized.latest_version === "1.2.4", "latest version should normalize");
assert(normalized.installer === "pipx", "installer should normalize");
assert(normalized.update_available === true, "update_available should normalize");
assert(normalized.version_check.update_available === true, "version_check should normalize");
assert(normalized.update_in_progress === true, "update_in_progress should normalize");

const blocked = normalizeGuardUpdateStatus({
  auto_updatable: false,
  update_available: false,
  blocked_reason: "Local install only",
});

assert(blocked.auto_updatable === false, "auto_updatable false should normalize");
assert(blocked.blocked_reason === "Local install only", "blocked_reason should normalize");
assert(blocked.current_version === "unknown", "missing current_version should default to unknown");

const recovery = normalizeGuardUpdateStatus({
  current_version: "1.0.0",
  auto_updatable: false,
  update_available: false,
  blocked_reason: "This install was set up from a local folder. Re-run your usual local install command instead.",
  recovery_reinstall_available: true,
  recovery_reinstall_command: "pipx install --force hol-guard",
});

assert(recovery.recovery_reinstall_available === true, "recovery_reinstall_available should pass through when true");
assert(
  recovery.recovery_reinstall_command === "pipx install --force hol-guard",
  "recovery_reinstall_command should pass through",
);

const noRecovery = normalizeGuardUpdateStatus({
  auto_updatable: false,
  update_available: false,
  blocked_reason: "This install was set up from local source code.",
});

assert(
  noRecovery.recovery_reinstall_available === undefined,
  "editable installs must not expose recovery_reinstall_available",
);
assert(
  noRecovery.recovery_reinstall_command === undefined,
  "editable installs must not expose recovery_reinstall_command",
);

const candidatePorts = buildGuardDaemonCandidatePorts(5474);
assert(candidatePorts.length === 25, "candidate port scan should probe 25 ports");
assert(candidatePorts[0] === 5474, "candidate ports should start from the preferred port");

console.log("guard-update.test.ts: all tests passed");
