import {
  isSettingsSaveProofSubmitDisabled,
  requiresSettingsSaveProof,
  resolveSettingsSaveProofKind,
  resolveSettingsSaveProofModalCopy,
} from "./settings-save-proof-modal";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

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
  }) === "verify-save",
  "save-proof: re-enabling configured gate requires verify modal",
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
  "save-proof: change-password accepts totp without current password when enabled",
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
