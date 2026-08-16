import assert from "node:assert/strict";

import {
  EXTENSION_CLIENT_LIMITS,
  ExtensionControlProtocolError,
  normalizeEffectiveExtensionControls,
  normalizeExtensionCatalog,
} from "./extension-controls-normalize";

const digest = "a".repeat(64);

function permission(id = "command.git.permission.reset-hard") {
  return {
    permission_id: id,
    schema_version: 1,
    extension_id: "command.git",
    implementation_version: "1.2.3",
    label: "Hard reset",
    description: "Controls destructive reset behavior.",
    risk_tier: "high",
    baseline_floor: "review",
    default_enabled: true,
    configurable: true,
    fixed_reason: null,
    typed_capabilities: [],
    action_classes: ["git.history.rewrite"],
    rule_ids: ["command.git.reset-hard"],
    dependencies: [],
    conflicts: [],
    implied_permissions: [],
    introduced_version: "1.0.0",
    deprecated: false,
    replacement_permission_id: null,
    safer_guidance: ["Create a checkpoint first."],
    example_command: "git reset --hard",
    family: "git-destructive",
    additive_future_field: { ignored: true },
  };
}

function rule(id = "command.git.reset-hard") {
  return {
    rule_id: id,
    rule_version: 1,
    title: "Hard reset",
    description: "Detects destructive hard reset.",
    severity: "high",
    risk_classes: ["destructive_shell"],
    action_classes: ["git.history.rewrite"],
    safer_alternatives: ["Use git restore for a narrower change."],
    default_mode: "review",
    matcher_kind: "ExecutableMatcher",
    safe_variants: [{ variant_id: "status", title: "Status", matcher_kind: "ExecutableMatcher" }],
    compatibility_fallback: false,
    additive_future_field: "ignored",
  };
}

function catalog() {
  return {
    schema_version: "guard.extension-controls.catalog.v1",
    control_schema_version: "1.0.0",
    catalog_digest: digest,
    extensions: [{
      schema_version: 2,
      extension_id: "command.git",
      version: "1.2.3",
      name: "Git",
      description: "Protects Git command workflows.",
      enabled: true,
      required: false,
      source: "built-in",
      aliases: ["command.scm"],
      dependencies: [],
      conflicts: [],
      delegated_protection: null,
      ecosystem_ids: ["git"],
      executables: ["git"],
      project_markers: [".git"],
      reference_urls: ["https://git-scm.com/docs"],
      action_classes: ["git.history.rewrite"],
      risk_classes: ["destructive_shell"],
      safer_alternatives: ["Create a checkpoint first."],
      rule_count: 1,
      rules: [rule()],
      permission_count: 1,
      permissions: [permission()],
      additive_future_field: 42,
    }],
    limits: { max_body_bytes: 1000, max_controls: 50, max_observations: 100 },
    additive_future_field: true,
  };
}

function effective() {
  return {
    schema_version: "guard.extension-controls.effective.v1",
    health: "protected",
    revision: 7,
    catalog_digest: digest,
    global_lockdown: false,
    controls: [{ target: { kind: "permission", target_id: "command.git.permission.reset-hard" }, state: "disabled" }],
    layers: [{
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: digest,
      global_lockdown: false,
      controls: [{ target_kind: "permission", target_id: "command.git.permission.reset-hard", state: "disabled" }],
    }],
    failures: [],
    projection: {
      schema_version: "guard.daemon.extension-control-projection.v1",
      revision: 7,
      catalog_digest: digest,
      health: "protected",
      extensions: [],
      permissions: [],
    },
    additive_future_field: "ignored",
  };
}

const normalizedCatalog = normalizeExtensionCatalog(catalog());
assert.equal(normalizedCatalog.extensions[0]?.rules[0]?.rule_id, "command.git.reset-hard");
assert.equal(normalizedCatalog.extensions[0]?.permissions[0]?.safer_guidance[0], "Create a checkpoint first.");
assert.equal(normalizedCatalog.extensions[0]?.permissions[0]?.example_command, "git reset --hard");
assert.equal(normalizedCatalog.extensions[0]?.permissions[0]?.family, "git-destructive");
assert.deepEqual(normalizedCatalog.extensions[0]?.reference_urls, ["https://git-scm.com/docs"]);
assert.equal(normalizeEffectiveExtensionControls(effective()).controls[0]?.state, "disabled");
assert.equal(normalizeEffectiveExtensionControls(effective()).projection?.revision, 7);
const acknowledged = effective();
acknowledged.health = "degraded-acknowledged";
assert.equal(normalizeEffectiveExtensionControls(acknowledged).health, "degraded-acknowledged");

function rejects(mutator: (payload: ReturnType<typeof catalog>) => void, pattern: RegExp): void {
  const payload = catalog();
  mutator(payload);
  assert.throws(() => normalizeExtensionCatalog(payload), (error: unknown) => error instanceof ExtensionControlProtocolError && pattern.test(error.message));
}

rejects((payload) => { payload.extensions[0]!.extension_id = "../../secret"; }, /not canonical/);
rejects((payload) => { payload.extensions[0]!.rules[0]!.severity = "super-critical"; }, /unsupported value/);
rejects((payload) => { payload.extensions[0]!.rules.push(rule()); payload.extensions[0]!.rule_count = 2; }, /duplicate rule IDs/);
rejects((payload) => { payload.extensions[0]!.permissions.push(permission()); payload.extensions[0]!.permission_count = 2; }, /duplicate permission IDs/);
rejects((payload) => { payload.extensions[0]!.permissions[0]!.rule_ids = ["command.git.missing"]; }, /unknown rule/);

{
  const payload = catalog();
  const legacyPermission = payload.extensions[0]!.permissions[0] as Record<string, unknown>;
  delete legacyPermission.example_command;
  delete legacyPermission.family;
  const normalized = normalizeExtensionCatalog(payload);
  assert.equal(normalized.extensions[0]?.permissions[0]?.example_command, null);
  assert.equal(normalized.extensions[0]?.permissions[0]?.family, null);
}
rejects((payload) => { delete (payload.extensions[0] as Record<string, unknown>).name; }, /name must be a string/);

const oversized = catalog();
oversized.extensions = Array.from({ length: EXTENSION_CLIENT_LIMITS.extensions + 1 }, () => catalog().extensions[0]!);
assert.throws(() => normalizeExtensionCatalog(oversized), /exceeds/);

const duplicateEffective = effective();
duplicateEffective.controls.push({ target: { kind: "permission", target_id: "command.git.permission.reset-hard" }, state: "enabled" });
assert.throws(() => normalizeEffectiveExtensionControls(duplicateEffective), /duplicate targets/);

const invalidHealth = effective();
invalidHealth.health = "maybe";
assert.throws(() => normalizeEffectiveExtensionControls(invalidHealth), /unsupported value/);

console.log("extension-controls-normalize.test.ts: all assertions passed");
