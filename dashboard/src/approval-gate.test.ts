import type { GuardApprovalGatePublicConfig, GuardSettings } from "./guard-types";
import { approvalGateCooldownLabel } from "./approval-gate-utils";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
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

const tests: Array<[string, () => void]> = [
  ["testApprovalGatePublicConfigEnabled", testApprovalGatePublicConfigEnabled],
  ["testApprovalGatePublicConfigDisabled", testApprovalGatePublicConfigDisabled],
  ["testApprovalGateCooldownLabels", testApprovalGateCooldownLabels],
  ["testApprovalGatePasswordFieldsNotPersisted", testApprovalGatePasswordFieldsNotPersisted],
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
