import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { buildGuardDaemonCandidatePorts, normalizeGuardUpdateStatus, updateReconnectSucceeded } from "./guard-api";
import { AlphaChannelDialog } from "./alpha-update-channel-dialog";
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
assert(normalized.release_channel === "stable", "missing update channel should default to stable");

const alphaMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "1.2.3",
      latest_version: "1.2.4a1",
      installer: "pip",
      version_check: { source: "pypi", status: "stale", current_version: "1.2.3", latest_version: "1.2.4a1", update_available: true },
      auto_updatable: true,
      update_available: true,
      blocked_reason: null,
      release_channel: "alpha",
    }),
    onSetUpdateChannel: () => undefined,
  }),
);
assert(alphaMarkup.includes('aria-label="Alpha updates enabled"'), "sidebar should show the active alpha channel");
assert(alphaMarkup.includes('aria-label="Manage alpha updates"'), "sidebar should expose a compact alpha settings control");
assert(!alphaMarkup.includes("Alpha updates enabled</button>"), "active alpha status should not render as a wide text button");
assert(!alphaMarkup.includes('type="checkbox"'), "sidebar should open alpha confirmation instead of toggling immediately");

const loadingMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    onSetUpdateChannel: () => undefined,
  }),
);
assert(loadingMarkup.includes("Try alpha updates"), "sidebar should expose the alpha confirmation while version status loads");

const rememberedChannelStorage = {
  getItem(key: string): string | null {
    return key === "guard-update-channel" ? "alpha" : null;
  },
  setItem: () => undefined,
};
Object.assign(globalThis, {
  window: {
    sessionStorage: rememberedChannelStorage,
    localStorage: rememberedChannelStorage,
  },
});
const rememberedAlphaMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    onSetUpdateChannel: () => undefined,
  }),
);
assert(
  rememberedAlphaMarkup.includes('aria-label="Alpha updates enabled"'),
  "sidebar should retain a confirmed alpha channel while status is unavailable",
);

const alphaDialogMarkup = renderToStaticMarkup(
  createElement(AlphaChannelDialog, {
    useAlpha: false,
    pending: false,
    error: "Guard could not change the update channel. Try again.",
    approvalGate: null,
    approvalPassword: "",
    approvalTotpCode: "",
    onClose: () => undefined,
    onConfirm: () => undefined,
    onApprovalPasswordChange: () => undefined,
    onApprovalTotpCodeChange: () => undefined,
  }),
);
assert(alphaDialogMarkup.includes("Try alpha updates"), "alpha dialog should explain the selected release channel");
assert(alphaDialogMarkup.includes("This does not install an update immediately."), "alpha dialog should separate enrollment from updating");
assert(alphaDialogMarkup.includes("Enable alpha updates"), "alpha dialog should require explicit confirmation");
assert(alphaDialogMarkup.includes("Guard could not change the update channel"), "channel errors should remain inside the dialog");

const stableDialogMarkup = renderToStaticMarkup(
  createElement(AlphaChannelDialog, {
    useAlpha: true,
    pending: false,
    error: null,
    approvalGate: null,
    approvalPassword: "",
    approvalTotpCode: "",
    onClose: () => undefined,
    onConfirm: () => undefined,
    onApprovalPasswordChange: () => undefined,
    onApprovalTotpCodeChange: () => undefined,
  }),
);
assert(stableDialogMarkup.includes("Return to stable updates"), "alpha users should be able to return to stable updates");
assert(stableDialogMarkup.includes("Use stable updates"), "stable fallback should require explicit confirmation");

const protectedAlphaDialogMarkup = renderToStaticMarkup(
  createElement(AlphaChannelDialog, {
    useAlpha: false,
    pending: false,
    error: null,
    approvalGate: {
      enabled: true,
      configured: true,
      cooldown_seconds: 0,
      cooldown_active: false,
      cooldown_expires_at: null,
      locked_until: null,
      fail_closed: false,
      strict_all_decisions: false,
      totp_enabled: true,
    },
    approvalPassword: "",
    approvalTotpCode: "",
    onClose: () => undefined,
    onConfirm: () => undefined,
    onApprovalPasswordChange: () => undefined,
    onApprovalTotpCodeChange: () => undefined,
  }),
);
assert(protectedAlphaDialogMarkup.includes("Authenticator code"), "protected alpha enrollment should collect a TOTP proof");

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

const currentSeriesMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "3.0.0a239",
      latest_version: "3.0.0a239",
      installer: "desktop",
      version_check: {
        source: "desktop_core",
        status: "current",
        current_version: "3.0.0a239",
        latest_version: "3.0.0a239",
        update_available: false,
      },
      auto_updatable: true,
      update_available: false,
      blocked_reason: null,
      release_channel: "alpha",
    }),
    onUpdateGuard: () => undefined,
  }),
);
assert(currentSeriesMarkup.includes("v3.0.0a239"), "desktop current version should stay visible");
assert(!currentSeriesMarkup.includes("Update Guard"), "desktop should not offer Update Guard when this train is current");

const failedUpdateMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updatePhase: "error",
    updateError: "This Core build is not available for Desktop yet. The installed version stays in place.",
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "3.0.0a239",
      latest_version: "3.0.0a239",
      installer: "desktop",
      auto_updatable: true,
      update_available: false,
    }),
  }),
);
assert(
  failedUpdateMarkup.includes("This Core build is not available for Desktop yet"),
  "failed desktop updates should show the recovery copy",
);
assert(
  failedUpdateMarkup.includes("The installed version stays in place"),
  "failed desktop updates should say the current install remains",
);

// Embedded in the HOL Guard Desktop window, the panel must defer updates to
// the app's own updater instead of offering a second, competing action.
const priorWindow = (globalThis as { window?: unknown }).window;
Object.assign(globalThis, {
  window: {
    location: { search: "?desktop_embed=1", hash: "" },
    sessionStorage: rememberedChannelStorage,
    localStorage: rememberedChannelStorage,
  },
});
const embeddedMarkup = renderToStaticMarkup(
  createElement(GuardUpdatePanel, {
    updateStatus: normalizeGuardUpdateStatus({
      current_version: "3.0.0a239",
      latest_version: "3.0.0a241",
      installer: "desktop",
      version_check: { source: "desktop_core", status: "stale", current_version: "3.0.0a239", latest_version: "3.0.0a241", update_available: true },
      auto_updatable: true,
      update_available: true,
      blocked_reason: null,
    }),
    onUpdateGuard: () => undefined,
  }),
);
assert(!embeddedMarkup.includes("Update Guard"), "embedded dashboard must not offer its own Update Guard button");
assert(
  embeddedMarkup.includes("Check for Updates in the HOL Guard menu-bar"),
  "embedded dashboard should point at the app's updater",
);
assert(embeddedMarkup.includes("v3.0.0a239"), "embedded dashboard should still show the running version");

(globalThis as { window?: unknown }).window = priorWindow;

console.log("guard-update.test.ts: all tests passed");
