import {
  SettingsSaveProofModal,
  isSettingsSaveProofSubmitDisabled,
  requiresSettingsSaveProof,
  resolveSettingsSaveProofKind,
  resolveSettingsSaveProofModalCopy,
} from "./settings-save-proof-modal";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const retainedGate: GuardApprovalGatePublicConfig = {
  enabled: false, configured: true, totp_enabled: true, totp_pending: false,
  cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null,
  locked_until: null, fail_closed: false, strict_all_decisions: false,
};
const reenableMode = resolveSettingsSaveProofKind({
  savedGateEnabled: retainedGate.enabled, wasConfigured: retainedGate.configured,
  draftGateEnabled: true, changingPassword: false,
});
assert(reenableMode === "setup-gate", "retained TOTP must not select a TOTP-only re-enable dialog");
const reenableMarkup = renderToStaticMarkup(createElement(SettingsSaveProofModal, {
  open: true, mode: reenableMode!, gate: retainedGate,
  ...resolveSettingsSaveProofModalCopy({ mode: reenableMode!, gateSettingsChanged: true }),
  error: null, pending: false, onCancel: () => {}, onConfirm: () => {},
}));
assert(reenableMarkup.includes("Confirm password"), "re-enable renders password confirmation");
assert(reenableMarkup.includes('type="password"'), "re-enable renders password fields");
assert(!reenableMarkup.includes("Authenticator code"), "re-enable does not request unsupported TOTP-only proof");
assert(isSettingsSaveProofSubmitDisabled(reenableMode!, { totpCode: "000000" }, true),
  "TOTP alone cannot submit a gate-enable password setup");
assert(!isSettingsSaveProofSubmitDisabled(reenableMode!, {
  newPassword: "synthetic-test-password", confirmPassword: "synthetic-test-password",
}, true), "confirmed password satisfies the gate-enable form contract");

assert(
  resolveSettingsSaveProofKind({
    savedGateEnabled: true,
    wasConfigured: true,
    draftGateEnabled: true,
    changingPassword: false,
  }) === "verify-save",
  "save-proof: enabled gate requires verify modal on save",
);
assert(
  resolveSettingsSaveProofKind({
    savedGateEnabled: false,
    wasConfigured: false,
    draftGateEnabled: true,
    changingPassword: false,
  }) === "setup-gate",
  "save-proof: first-time enable requires setup modal",
);
assert(
  resolveSettingsSaveProofKind({
    savedGateEnabled: false,
    wasConfigured: true,
    draftGateEnabled: true,
    changingPassword: false,
  }) === "setup-gate",
  "save-proof: re-enabling configured gate supplies password setup required by the backend",
);
assert(
  resolveSettingsSaveProofKind({
    savedGateEnabled: false,
    wasConfigured: true,
    draftGateEnabled: false,
    changingPassword: false,
  }) === null,
  "save-proof: disabled unchanged gate does not require proof",
);
assert(
  requiresSettingsSaveProof("verify-save") === true,
  "save-proof: verify mode requires proof",
);
assert(
  requiresSettingsSaveProof(null) === false,
  "save-proof: null kind skips proof",
);
assert(
  resolveSettingsSaveProofModalCopy({ mode: "setup-gate", gateSettingsChanged: false }).title.includes("approval password"),
  "save-proof: setup copy mentions approval password",
);
assert(
  !resolveSettingsSaveProofModalCopy({ mode: "verify-save", gateSettingsChanged: false }).detail.includes("Authenticator setup"),
  "save-proof: verify copy does not mention authenticator setup section",
);
assert(
  isSettingsSaveProofSubmitDisabled("verify-save", { currentPassword: "secret" }, false) === false,
  "save-proof: verify accepts current password only",
);
assert(
  isSettingsSaveProofSubmitDisabled("verify-save", { currentPassword: "" }, false) === true,
  "save-proof: verify rejects empty password",
);
assert(
  isSettingsSaveProofSubmitDisabled("verify-save", { currentPassword: "secret" }, true) === true,
  "save-proof: verify rejects missing totp when enabled",
);

assert(
  isSettingsSaveProofSubmitDisabled("verify-save", { totpCode: "123456" }, true) === false,
  "save-proof: verify accepts totp without password when enabled",
);
assert(
  isSettingsSaveProofSubmitDisabled(
    "change-password",
    { newPassword: "next-secret", confirmPassword: "next-secret", totpCode: "123456" },
    true,
  ) === false,
  "save-proof: change-password accepts totp and matching new password when enabled",
);
assert(
  isSettingsSaveProofSubmitDisabled(
    "change-password",
    { currentPassword: "old", newPassword: "next-secret", confirmPassword: "next-secret", totpCode: "123456" },
    true,
  ) === false,
  "save-proof: change-password ignores current password when totp is enabled",
);
assert(
  isSettingsSaveProofSubmitDisabled("setup-gate", { newPassword: "alpha", confirmPassword: "beta" }, false) === true,
  "save-proof: setup rejects mismatched passwords",
);
assert(
  isSettingsSaveProofSubmitDisabled("change-password", { currentPassword: "old", newPassword: "alpha", confirmPassword: "beta" }, false) === true,
  "save-proof: change-password rejects mismatched passwords",
);

assert(
  resolveSettingsSaveProofModalCopy({ mode: "maintenance", gateSettingsChanged: false, maintenanceAction: "import-settings" }).confirmLabel === "Import settings",
  "save-proof: import settings maintenance copy",
);
assert(
  resolveSettingsSaveProofModalCopy({ mode: "maintenance", gateSettingsChanged: false, maintenanceAction: "reset-settings" }).confirmLabel === "Reset settings",
  "save-proof: reset settings maintenance copy",
);

console.log("settings-save-proof-modal.test.ts: all assertions passed");
