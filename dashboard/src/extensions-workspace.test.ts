import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ApprovalProofModal } from "./approval-proof-modal";
import {
  DEFAULT_EXTENSION_DETAIL_URL_STATE,
  extensionDetailHref,
  extensionEffectiveState,
  permissionEffectiveState,
} from "./extension-control-center-model";
import { ExtensionControlApiError, type ExtensionCatalogItem, type EffectiveExtensionControls } from "./extension-controls-api";
import {
  authorityActionErrorMessage,
  buildExtensionMutation,
  ProtectionAuthorityNotice,
  ReviewModal,
  requiresExtensionRecoveryApproval,
} from "./extensions-workspace";
import { fetchResolvedApprovalGate } from "./use-resolved-approval-gate";
import {
  extensionPolicyRadioTabStop,
  isCurrentExtensionPolicyDraft,
  nextExtensionPolicyRadioIndex,
} from "./extension-policy-panel";

// Every authority action failure maps to plain language with a next step;
// raw protocol codes never reach the operator.
assert.match(
  authorityActionErrorMessage(new ExtensionControlApiError("authority_not_recoverable", 409, "authority_not_recoverable")),
  /state changed underneath it/,
);
assert.match(
  authorityActionErrorMessage(new ExtensionControlApiError("authority_not_recoverable", 409, "authority_not_recoverable")),
  /recover-authority.{0,40}in your terminal/,
);
assert.match(
  authorityActionErrorMessage(new ExtensionControlApiError("authority_recovery_failed", 503, "authority_recovery_failed")),
  /could not verify a fully protected state/,
);
assert.doesNotMatch(
  authorityActionErrorMessage(new ExtensionControlApiError("authority_not_recoverable", 409, "authority_not_recoverable")),
  /authority_not_recoverable/,
);
const baseEffective: EffectiveExtensionControls = {
  schema_version: "1.0.0", health: "recovery-required", revision: 4, catalog_digest: "a".repeat(64),
  global_lockdown: false, controls: [], failures: [], layers: [],
};
const repairMarkup = renderToStaticMarkup(createElement(ProtectionAuthorityNotice, {
  effective: baseEffective,
  approvalGate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: false, totp_enabled: false },
  onAction: () => undefined,
  onCheckAgain: () => undefined,
}));
assert.match(repairMarkup, /Protection needs repair/);
assert.match(repairMarkup, /Repair protection/);
assert.match(repairMarkup, /Check again/);
assert.match(repairMarkup, /hol-guard command controls recover-authority/);
assert.match(repairMarkup, /Copy command/);
assert.match(repairMarkup, /bg-amber-50/, "repair states use the warning treatment");
assert.match(repairMarkup, /bg-brand-blue/, "the primary action uses the brand primary button");

const degradedAckMarkup = renderToStaticMarkup(createElement(ProtectionAuthorityNotice, {
  effective: { ...baseEffective, health: "degraded-acknowledged" },
  approvalGate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: false, totp_enabled: false },
  onAction: () => undefined,
  onCheckAgain: () => undefined,
}));
assert.match(degradedAckMarkup, /Protection is limited/);
assert.match(degradedAckMarkup, /Copy repair command/);
assert.doesNotMatch(degradedAckMarkup, /Repair protection/, "dashboard repair is not offered in a state the daemon refuses");

const unenrolledMarkup = renderToStaticMarkup(createElement(ProtectionAuthorityNotice, {
  effective: { ...baseEffective, health: "unenrolled" },
  approvalGate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: false, totp_enabled: false },
  onAction: () => undefined,
  onCheckAgain: () => undefined,
}));
assert.match(unenrolledMarkup, /Finish setting up protection/);
assert.match(unenrolledMarkup, /command controls enroll/);
assert.match(unenrolledMarkup, /Copy setup command/);
assert.doesNotMatch(unenrolledMarkup, /bg-amber-50/, "setup guidance is informational, not a failure");

const protectedMarkup = renderToStaticMarkup(createElement(ProtectionAuthorityNotice, {
  effective: { ...baseEffective, health: "protected" },
  approvalGate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: false, totp_enabled: false },
  onAction: () => undefined,
  onCheckAgain: () => undefined,
}));
assert.equal(protectedMarkup, "", "no authority surface renders when protection is healthy");

const totpRecoveryMarkup = renderToStaticMarkup(createElement(ApprovalProofModal, {
  title: "Repair extension controls",
  detail: "Authenticate this repair on your device.",
  confirmLabel: "Repair controls",
  approvalGate: {
    enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false,
    cooldown_expires_at: null, locked_until: null, fail_closed: true,
    strict_all_decisions: false, totp_enabled: true,
  },
  error: "That authenticator code was not accepted.",
  onCancel: () => undefined,
  onConfirm: () => undefined,
}));
assert.match(totpRecoveryMarkup, /Authenticator code/);
assert.doesNotMatch(totpRecoveryMarkup, /Approval password/);
assert.match(totpRecoveryMarkup, /That authenticator code was not accepted/);
assert.match(totpRecoveryMarkup, /role="alert"/);

const resolvedTotpGate = await fetchResolvedApprovalGate(async () => ({
  settings: { approval_gate: {
    enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false,
    cooldown_expires_at: null, locked_until: null, fail_closed: true,
    strict_all_decisions: false, totp_enabled: true,
  } },
}));
assert.equal(resolvedTotpGate?.totp_enabled, true);
await assert.rejects(fetchResolvedApprovalGate(async () => { throw new Error("settings unavailable"); }, { failClosed: true }), /settings unavailable/);

const mutationState = {
  kind: "ready" as const,
  catalog: { schema_version: "1.0.0", catalog_digest: "a".repeat(64), extensions: [] },
  effective: {
    schema_version: "1.0.0", health: "protected" as const, revision: 8,
    catalog_digest: "a".repeat(64), global_lockdown: false, controls: [], failures: [],
    layers: [{
      schema_version: "1.0.0", kind: "local-admin" as const, catalog_digest: "a".repeat(64),
      global_lockdown: false,
      controls: [{ target_kind: "extension" as const, target_id: "command.existing", state: "disabled" as const }],
    }],
  },
};
const targeted = buildExtensionMutation(mutationState, {
  extension: { extension_id: "command.new-extension", name: "New extension" }, enabled: false,
});
assert.equal(targeted.previous_revision, 8);
assert.deepEqual(targeted.layers[0]?.controls.map((control) => control.target_id), ["command.existing", "command.new-extension"]);
assert.equal(mutationState.effective.layers[0]?.controls.length, 1, "builder must not mutate loaded authority state");

const extension: ExtensionCatalogItem = {
  schema_version: 2, extension_id: "command.git", name: "Git", description: "Protects source-control commands.",
  enabled: true, required: false, source: "built-in", version: "1.2.3", aliases: ["command.scm"],
  dependencies: [], conflicts: [], delegated_protection: null, ecosystem_ids: ["git"], executables: ["git"],
  project_markers: [".git"], reference_urls: [], action_classes: ["git.history.rewrite"],
  risk_classes: ["history-rewrite"], safer_alternatives: [], rule_count: 1,
  rules: [{
    rule_id: "command.git.hard-reset", rule_version: 1, title: "Hard reset",
    description: "Rewrites the worktree and index.", severity: "high", risk_classes: ["history-rewrite"],
    action_classes: ["git.history.rewrite"], safer_alternatives: [], default_mode: "review",
    matcher_kind: "ExecutableMatcher", safe_variants: [], compatibility_fallback: false,
  }],
  permission_count: 1,
  permissions: [{
    permission_id: "command.git.permission.hard-reset", schema_version: 1, extension_id: "command.git",
    implementation_version: "1.2.3", label: "Hard reset", description: "Controls destructive reset behavior.",
    risk_tier: "high", baseline_floor: "review", default_enabled: true, configurable: true, fixed_reason: null,
    typed_capabilities: [], action_classes: ["git.history.rewrite"], rule_ids: ["command.git.hard-reset"],
    dependencies: [], conflicts: [], implied_permissions: [], introduced_version: "1.0.0",
    deprecated: false, replacement_permission_id: null, safer_guidance: [], example_command: null, family: null,
  }],
};
const effective: EffectiveExtensionControls = {
  schema_version: "1.0.0", health: "protected", revision: 7, catalog_digest: "a".repeat(64),
  global_lockdown: false,
  controls: [{ target: { kind: "permission", target_id: "command.git.permission.hard-reset" }, state: "disabled" }],
  layers: [], failures: [],
};
const totpChangeMarkup = renderToStaticMarkup(createElement(ReviewModal, {
  change: { extension, enabled: true }, busy: false, error: null,
  approvalGate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: false, totp_enabled: true },
  onCancel: () => undefined, onConfirm: () => undefined,
}));
assert.match(totpChangeMarkup, /Authenticator code/);
assert.doesNotMatch(totpChangeMarkup, /Approval password/);
const passwordChangeMarkup = renderToStaticMarkup(createElement(ReviewModal, {
  change: { extension, enabled: true }, busy: false, error: null,
  approvalGate: { enabled: true, configured: true, cooldown_seconds: 0, cooldown_active: false, cooldown_expires_at: null, locked_until: null, fail_closed: true, strict_all_decisions: false, totp_enabled: false },
  onCancel: () => undefined, onConfirm: () => undefined,
}));
assert.match(passwordChangeMarkup, /Approval password/);
assert.doesNotMatch(passwordChangeMarkup, /Authenticator code/);

assert.equal(extensionDetailHref("command.git"), "/extensions/command.git");
assert.equal(extensionDetailHref("command.git", { ...DEFAULT_EXTENSION_DETAIL_URL_STATE, tab: "commands", ruleId: "command.git.hard-reset" }), "/extensions/command.git?tab=commands&rule=command.git.hard-reset");
assert.doesNotMatch(extensionDetailHref("command.git"), /#|guard-token/);
assert.equal(extensionEffectiveState(effective, extension), "enabled");
assert.equal(permissionEffectiveState(effective, extension, extension.permissions[0]!), "disabled");
assert.equal(extensionEffectiveState({ ...effective, global_lockdown: true }, { ...extension, required: true }), "disabled");
assert.equal(extensionEffectiveState({ ...effective, health: "tampered" }, extension), "disabled");

assert.equal(extensionPolicyRadioTabStop([
  { value: "inherit" },
  { value: "allow", disabled: true },
  { value: "block" },
], "allow", false), 0, "managed-disabled selected choice must leave an enabled radio tabbable");
assert.equal(extensionPolicyRadioTabStop([{ value: "inherit" }, { value: "block" }], "block", false), 1);
assert.equal(extensionPolicyRadioTabStop([{ value: "inherit" }], "inherit", true), -1);
const radioChoices = [{ disabled: false }, { disabled: true }, { disabled: false }];
assert.equal(nextExtensionPolicyRadioIndex(radioChoices, 0, "ArrowRight", false), 2, "arrows skip disabled choices");
assert.equal(nextExtensionPolicyRadioIndex(radioChoices, 2, "ArrowRight", false), 0, "arrows wrap");
assert.equal(nextExtensionPolicyRadioIndex(radioChoices, 0, "ArrowLeft", false), 2, "reverse arrows wrap");
assert.equal(nextExtensionPolicyRadioIndex(radioChoices, 0, "Enter", false), -1);
assert.equal(nextExtensionPolicyRadioIndex(radioChoices, 0, "ArrowRight", true), -1);
assert.equal(isCurrentExtensionPolicyDraft(4, 4), true);
assert.equal(isCurrentExtensionPolicyDraft(4, 5), false, "stale async completions must not update the active draft");

const policyDetailSource = readFileSync(new URL("./extension-control-center-detail.tsx", import.meta.url), "utf8");
const policyPanelSource = readFileSync(new URL("./extension-policy-panel.tsx", import.meta.url), "utf8");
const policyDraftSource = readFileSync(new URL("./use-extension-policy-draft.ts", import.meta.url), "utf8");
assert.match(policyDetailSource, /id="extension-policy-tabpanel"[\s\S]*role="tabpanel"[\s\S]*aria-labelledby="extension-tab-policy"/);
assert.match(policyDraftSource, /isCurrentExtensionPolicyDraft\(generation, draftGeneration\.current\)\) handleApiError/);
assert.match(policyDraftSource, /isCurrentExtensionPolicyDraft\(generation, draftGeneration\.current\)[\s\S]*Guard could not rebase this draft/);
assert.match(policyPanelSource, /ArrowLeft[\s\S]*ArrowRight[\s\S]*ArrowUp[\s\S]*ArrowDown/);
assert.match(policyPanelSource, /Settings applied\. Editing stays locked/);

console.log("extensions-workspace.test.ts: all assertions passed");
