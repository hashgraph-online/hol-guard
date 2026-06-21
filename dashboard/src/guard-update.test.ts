import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { buildGuardDaemonCandidatePorts, normalizeGuardUpdateStatus, updateReconnectSucceeded } from "./guard-api";
import { GuardUpdatePanel } from "./guard-update-panel";

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

const currentLocalWheelMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "2.0.855",
      latest_version: "2.0.855",
      auto_updatable: false,
      update_available: false,
      version_check: {
        source: "pypi",
        status: "current",
        current_version: "2.0.855",
        latest_version: "2.0.855",
        update_available: false,
      },
      blocked_reason:
        "This install was set up from a local wheel. Re-run `hol-guard update --wheel <wheel-or-directory>` or your usual local install command instead.",
      recovery_reinstall_available: true,
    }),
    onReinstallGuard: () => undefined,
  }),
);

assert(
  !currentLocalWheelMarkup.includes("Reinstall from PyPI"),
  "current local wheel installs should not keep showing the PyPI recovery CTA",
);
assert(
  !currentLocalWheelMarkup.includes("automatic updates are off"),
  "current local wheel installs should not keep showing the recovery warning",
);

const staleLocalWheelMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "2.0.855",
      latest_version: "2.0.856",
      auto_updatable: false,
      update_available: false,
      version_check: {
        source: "pypi",
        status: "stale",
        current_version: "2.0.855",
        latest_version: "2.0.856",
        update_available: true,
      },
      blocked_reason:
        "This install was set up from a local wheel. Re-run `hol-guard update --wheel <wheel-or-directory>` or your usual local install command instead.",
      recovery_reinstall_available: true,
    }),
    onReinstallGuard: () => undefined,
  }),
);

assert(
  staleLocalWheelMarkup.includes("This install came from a local wheel"),
  "stale local wheel installs should explain the real install source",
);
assert(
  staleLocalWheelMarkup.includes("Reinstall from PyPI"),
  "stale local wheel installs should keep the PyPI recovery CTA",
);

const staleLocalFolderMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "2.0.855",
      latest_version: "2.0.856",
      auto_updatable: false,
      update_available: false,
      version_check: {
        source: "pypi",
        status: "stale",
        current_version: "2.0.855",
        latest_version: "2.0.856",
        update_available: true,
      },
      blocked_reason:
        "This install was set up from a local folder. Re-run your usual local install command instead.",
      recovery_reinstall_available: true,
    }),
    onReinstallGuard: () => undefined,
  }),
);

assert(
  staleLocalFolderMarkup.includes("This install came from a local folder"),
  "stale local folder installs should keep the folder-specific recovery copy",
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

const staleReconnectStatus = normalizeGuardUpdateStatus({
  current_version: "2.0.741",
  latest_version: "2.0.743",
  installer: "pipx",
  version_check: {
    source: "pypi",
    status: "stale",
    current_version: "2.0.741",
    latest_version: "2.0.743",
    update_available: true,
  },
  auto_updatable: true,
  update_available: true,
  update_in_progress: false,
});

assert(
  updateReconnectSucceeded(staleReconnectStatus, {
    expectedPreviousVersion: "2.0.741",
    expectedLatestVersion: "2.0.743",
    sawUpdateInProgress: true,
  }) === true,
  "reconnect should succeed after update cycle when install remains stale",
);
assert(
  updateReconnectSucceeded(staleReconnectStatus, {
    expectedPreviousVersion: "2.0.741",
    expectedLatestVersion: "2.0.743",
    sawUpdateInProgress: false,
  }) === false,
  "reconnect should wait until update cycle starts",
);

const suppressed = normalizeGuardUpdateStatus({
  current_version: "2.0.741",
  latest_version: "2.0.743",
  auto_updatable: true,
  update_available: true,
  update_suppressed: true,
  retry_command: "pipx install --force hol-guard",
  update_attempt_message: "HOL Guard 2.0.741 is behind PyPI 2.0.743 after the update attempt.",
});

assert(suppressed.update_suppressed === true, "update_suppressed should normalize");
assert(suppressed.retry_command === "pipx install --force hol-guard", "retry_command should normalize");

console.log("guard-update.test.ts: all tests passed");
