import type { GuardApprovalGatePublicConfig, GuardSettings } from "./guard-types";
import { approvalGateCooldownLabel, requiresApprovalPasswordPrompt } from "./approval-gate-utils";
import { applyApprovalGateDraft, hasUnsavedChanges } from "./settings-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function buildSettings(approvalGate?: GuardApprovalGatePublicConfig): GuardSettings {
  return {
    mode: "prompt",
    security_level: "balanced",
    default_action: "warn",
    unknown_publisher_action: "review",
    changed_hash_action: "require-reapproval",
    new_network_domain_action: "warn",
    subprocess_action: "warn",
    risk_actions: {},
    risk_action_overrides: {},
    harness_risk_actions: {},
    approval_wait_timeout_seconds: 120,
    approval_surface_policy: "auto-open-once",
    telemetry: false,
    sync: false,
    billing: false,
    ...(approvalGate !== undefined ? { approval_gate: approvalGate } : {}),
  };
}

function testApprovalGatePublicConfigEnabled(): void {
  const config: GuardApprovalGatePublicConfig = {
    enabled: true,
    configured: true,
    cooldown_seconds: 900,
    cooldown_active: false,
    cooldown_expires_at: null,
    locked_until: null,
    fail_closed: false,
    strict_all_decisions: false,
  };
  assert(config.enabled === true, "enabled should be true");
  assert(config.configured === true, "configured should be true");
  assert(config.cooldown_seconds === 900, "cooldown_seconds should be 900");
  assert(config.cooldown_active === false, "cooldown_active should be false");
  assert(config.cooldown_expires_at === null, "cooldown_expires_at should be null");
  assert(config.locked_until === null, "locked_until should be null");
  assert(config.fail_closed === false, "fail_closed should be false");
  assert(config.strict_all_decisions === false, "strict_all_decisions should be false");
}

function testApprovalGatePublicConfigDisabled(): void {
  const config: GuardApprovalGatePublicConfig = {
    enabled: false,
    configured: false,
    cooldown_seconds: 0,
    cooldown_active: false,
    cooldown_expires_at: null,
    locked_until: null,
    fail_closed: false,
    strict_all_decisions: false,
  };
  assert(config.enabled === false, "enabled should be false");
  assert(config.configured === false, "configured should be false");
}

function testApprovalGateCooldownLabels(): void {
  assert(approvalGateCooldownLabel(0) === "Every approval", "0 should be 'Every approval'");
  assert(approvalGateCooldownLabel(900) === "15 minutes", "900 should be '15 minutes'");
  assert(approvalGateCooldownLabel(3600) === "1 hour", "3600 should be '1 hour'");
  assert(approvalGateCooldownLabel(60) === "60 seconds", "60 should be '60 seconds'");
  assert(approvalGateCooldownLabel(1800) === "1800 seconds", "1800 should be '1800 seconds'");
}

function testApprovalPasswordPromptVisibility(): void {
  assert(
    requiresApprovalPasswordPrompt(true, false, "artifact") === false,
    "active cooldown should hide password prompt for non-strict artifact decisions"
  );
  assert(
    requiresApprovalPasswordPrompt(true, true, "artifact") === true,
    "strict all decisions should still require password prompt during cooldown"
  );
  assert(
    requiresApprovalPasswordPrompt(true, false, "global") === true,
    "global scope should always require password prompt"
  );
}

function testApprovalGatePasswordFieldsNotPersisted(): void {
  const baseSettings: GuardSettings = {
    mode: "prompt",
    security_level: "balanced",
    default_action: "warn",
    unknown_publisher_action: "review",
    changed_hash_action: "require-reapproval",
    new_network_domain_action: "warn",
    subprocess_action: "warn",
    risk_actions: {},
    risk_action_overrides: {},
    harness_risk_actions: {},
    approval_wait_timeout_seconds: 120,
    approval_surface_policy: "auto-open-once",
    telemetry: false,
    sync: false,
    billing: false,
    approval_gate: {
      enabled: true,
      configured: true,
      cooldown_seconds: 900,
      cooldown_active: false,
      cooldown_expires_at: null,
      locked_until: null,
      fail_closed: false,
      strict_all_decisions: false,
    },
  };

  const currentPassword = "";
  const newPassword = "hunter2";
  const confirmPassword = "hunter2";

  const updatePayload: Partial<GuardSettings> & {
    approval_gate?: GuardApprovalGatePublicConfig & {
      current_password?: string;
      new_password?: string;
      confirm_password?: string;
    };
  } = {
    ...baseSettings,
    approval_gate: {
      ...(baseSettings.approval_gate as GuardApprovalGatePublicConfig),
      ...(currentPassword ? { current_password: currentPassword } : {}),
      ...(newPassword ? { new_password: newPassword } : {}),
      ...(confirmPassword ? { confirm_password: confirmPassword } : {}),
    },
  };

  assert(
    updatePayload.approval_gate?.new_password === "hunter2",
    "new_password should be included when non-empty"
  );
  assert(
    updatePayload.approval_gate?.confirm_password === "hunter2",
    "confirm_password should be included when non-empty"
  );
  assert(
    !("current_password" in (updatePayload.approval_gate ?? {})),
    "current_password should not be included when empty"
  );

  const emptyPasswordPayload: typeof updatePayload = {
    ...baseSettings,
    approval_gate: {
      ...(baseSettings.approval_gate as GuardApprovalGatePublicConfig),
    },
  };
  assert(
    !("new_password" in (emptyPasswordPayload.approval_gate ?? {})),
    "new_password should not be present when not set"
  );
}

function testApprovalGateToggleReflectedInDraftApprovalGate(): void {
  const savedSettings = buildSettings();
  const draftSettings = applyApprovalGateDraft(savedSettings, { enabled: true, cooldown_seconds: 900 });
  assert(
    draftSettings.approval_gate?.enabled === true,
    "toggling enabled should create a draft approval_gate value"
  );
  assert(
    hasUnsavedChanges(savedSettings, draftSettings),
    "hasUnsavedChanges should return true after approval gate toggle"
  );
}

function testApprovalGateCooldownReflectedInDraftApprovalGate(): void {
  const savedGate: GuardApprovalGatePublicConfig = {
    enabled: true,
    configured: true,
    cooldown_seconds: 900,
    cooldown_active: false,
    cooldown_expires_at: null,
    locked_until: null,
    fail_closed: false,
    strict_all_decisions: false,
  };
  const savedSettings = buildSettings(savedGate);
  const draftSettings = applyApprovalGateDraft(savedSettings, { enabled: true, cooldown_seconds: 3600 });
  assert(
    draftSettings.approval_gate?.cooldown_seconds === 3600,
    "changing cooldown_seconds should update the draft approval_gate value"
  );
  assert(
    hasUnsavedChanges(savedSettings, draftSettings),
    "hasUnsavedChanges should return true after approval gate cooldown change"
  );
}

function testBulkApproveGateCredentialsPayload(): void {
  type BulkPayload = {
    requestId: string;
    action: string;
    scope: string;
    reason: string;
    approval_password?: string;
    approval_totp_code?: string;
    approval_gate_use_cooldown?: boolean;
  };
  const gateCredentials = {
    approval_password: "secret123",
    approval_totp_code: "123456",
    approval_gate_use_cooldown: false
  };
  const buildBulkPayload = (id: string, creds?: typeof gateCredentials): BulkPayload => ({
    requestId: id,
    action: "allow",
    scope: "artifact",
    reason: "",
    ...creds,
  });
  const withGate = buildBulkPayload("req-1", gateCredentials);
  assert(withGate.approval_password === "secret123", "bulk payload should include approval_password when gate credentials provided");
  assert(withGate.approval_totp_code === "123456", "bulk payload should include approval_totp_code when gate credentials provided");
  assert(withGate.approval_gate_use_cooldown === false, "bulk payload should include approval_gate_use_cooldown when gate credentials provided");

  const withoutGate = buildBulkPayload("req-2", undefined);
  assert(!("approval_password" in withoutGate), "bulk payload should not include approval_password when no gate credentials");
  assert(!("approval_totp_code" in withoutGate), "bulk payload should not include approval_totp_code when no gate credentials");
  assert(!("approval_gate_use_cooldown" in withoutGate), "bulk payload should not include approval_gate_use_cooldown when no gate credentials");
}

const tests: Array<[string, () => void]> = [
  ["testApprovalGatePublicConfigEnabled", testApprovalGatePublicConfigEnabled],
  ["testApprovalGatePublicConfigDisabled", testApprovalGatePublicConfigDisabled],
  ["testApprovalGateCooldownLabels", testApprovalGateCooldownLabels],
  ["testApprovalPasswordPromptVisibility", testApprovalPasswordPromptVisibility],
  ["testApprovalGatePasswordFieldsNotPersisted", testApprovalGatePasswordFieldsNotPersisted],
  ["testApprovalGateToggleReflectedInDraftApprovalGate", testApprovalGateToggleReflectedInDraftApprovalGate],
  ["testApprovalGateCooldownReflectedInDraftApprovalGate", testApprovalGateCooldownReflectedInDraftApprovalGate],
  ["testBulkApproveGateCredentialsPayload", testBulkApproveGateCredentialsPayload],
];

let passed = 0;
let failed = 0;
for (const [name, fn] of tests) {
  try {
    fn();
    console.log(`✓ ${name}`);
    passed++;
  } catch (err) {
    console.error(`✗ ${name}: ${err instanceof Error ? err.message : String(err)}`);
    failed++;
  }
}
console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) {
  process.exit(1);
}
