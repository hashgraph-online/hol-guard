import { strict as assert } from "node:assert";
import type { GuardSettings } from "./guard-types";
import { isPresentationOnlyChange, presentationOnlySavePayload } from "./settings-presentation";

function baseSettings(overrides: Partial<GuardSettings> = {}): GuardSettings {
  return {
    mode: "observe",
    presentation_mode: "everyday",
    presentation_mode_explicit: false,
    presentation_schema_version: 1,
    presentation_revision: 4,
    security_level: "balanced",
    default_action: "allow",
    unknown_publisher_action: "prompt",
    changed_hash_action: "prompt",
    new_network_domain_action: "prompt",
    subprocess_action: "prompt",
    risk_actions: { destructive: "prompt" },
    risk_action_overrides: {},
    harness_risk_actions: {},
    approval_wait_timeout_seconds: 600,
    approval_surface_policy: "tab",
    approval_browser_delay_seconds: 0,
    approval_browser_immediate_severity: "critical",
    telemetry: false,
    sync: false,
    receipt_redaction_level: "full",
    billing: false,
    ...overrides,
  };
}

const saved = baseSettings();
const presentationOnlyDraft = baseSettings({
  presentation_mode: "technical",
  presentation_mode_explicit: true,
});

assert.equal(isPresentationOnlyChange(presentationOnlyDraft, saved), true);
assert.equal(isPresentationOnlyChange(saved, saved), false);

const payload = presentationOnlySavePayload(presentationOnlyDraft, saved);
assert.ok(payload !== null, "presentation-only save should produce a payload");
assert.deepEqual(Object.keys(payload).sort(), [
  "presentation_mode",
  "presentation_mode_explicit",
  "presentation_revision",
  "presentation_schema_version",
]);
assert.equal(payload.presentation_mode, "technical");
assert.equal(payload.presentation_mode_explicit, true);
assert.equal(payload.presentation_revision, 4);
assert.equal(presentationOnlySavePayload(saved, saved), null);
assert.equal(
  presentationOnlySavePayload(baseSettings({ presentation_mode: "technical", presentation_mode_explicit: true, security_level: "strict" }), saved),
  null,
);

assert.equal(
  isPresentationOnlyChange(
    baseSettings({ presentation_mode: "technical", presentation_mode_explicit: true, security_level: "strict" }),
    saved,
  ),
  false,
);
assert.equal(
  isPresentationOnlyChange(
    baseSettings({
      presentation_mode: "technical",
      presentation_mode_explicit: true,
      approval_gate: {
        enabled: true,
        configured: true,
        cooldown_seconds: 0,
        cooldown_active: false,
        cooldown_expires_at: null,
        locked_until: null,
        fail_closed: false,
        strict_all_decisions: false,
        totp_enabled: false,
        totp_pending: false,
      },
    }),
    saved,
  ),
  false,
);
assert.equal(
  isPresentationOnlyChange(
    baseSettings({
      presentation_mode: "technical",
      presentation_mode_explicit: true,
      risk_actions: { destructive: "deny" },
    }),
    saved,
  ),
  false,
);
assert.equal(isPresentationOnlyChange(presentationOnlyDraft, null), false);
console.log("settings-presentation tests passed");
