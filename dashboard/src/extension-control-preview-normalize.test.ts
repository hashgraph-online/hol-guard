import assert from "node:assert/strict";

import {
  normalizeExtensionMutationApply,
  normalizeExtensionMutationPreview,
  normalizeExtensionSemanticPreview,
} from "./extension-control-preview-normalize";

const digest = "a".repeat(64);
const semantic = {
  schema_version: "guard.daemon.extension-control-semantic-preview.v1",
  global_lockdown: { before: false, after: false, changed: false },
  changed_target_count: 1,
  affected_permission_count: 1,
  affected_rule_count: 1,
  approval_required: true,
  changed_targets: [{
    target: { kind: "permission", target_id: "command.git.permission.force-clean" },
    extension_id: "command.git",
    extension_name: "Git",
    label: "Force clean",
    before_explicit: "inherited",
    after_explicit: "disabled",
    before_effective: "allowed",
    after_effective: "blocked",
    baseline_risk: "high",
    baseline_floor: "review",
    affected_permission_ids: ["command.git.permission.force-clean"],
    affected_rule_ids: ["command.git.force-clean"],
    affected_extension_ids: ["command.git"],
    dependency_permission_ids: ["command.git.permission.read"],
    implied_permission_ids: [],
    conflict_permission_ids: [],
    provenance: ["local-admin"],
    warnings: [{ code: "dependent-permissions-affected", message: "Related permissions change.", count: 1 }],
  }],
  summary: { newly_blocked_permissions: 1, newly_allowed_permissions: 0, effective_change_count: 1 },
};

const normalized = normalizeExtensionSemanticPreview(semantic);
assert.equal(normalized.changed_targets[0]?.target.target_id, "command.git.permission.force-clean");
assert.equal(normalized.changed_targets[0]?.baseline_risk, "high");
assert.deepEqual(normalized.changed_targets[0]?.affected_rule_ids, ["command.git.force-clean"]);
assert.deepEqual(normalized.changed_targets[0]?.affected_extension_ids, ["command.git"]);
assert.deepEqual(normalized.changed_targets[0]?.dependency_permission_ids, ["command.git.permission.read"]);
assert.deepEqual(normalized.changed_targets[0]?.provenance, ["local-admin"]);
assert.equal(normalized.approval_required, true);

const preview = normalizeExtensionMutationPreview({
  schema_version: "guard.daemon.extension-controls.v1",
  previous_revision: 4,
  next_revision: 5,
  catalog_digest: digest,
  canonical_diff_digest: "b".repeat(64),
  global_lockdown: false,
  controls: 1,
  semantic_preview: semantic,
});
assert.equal(preview.next_revision, 5);
assert.equal(preview.semantic_preview.summary.newly_blocked_permissions, 1);

const proofPreview = normalizeExtensionMutationPreview({ ...preview, semantic_preview: semantic, proof_id: "proof-123" });
assert.equal(proofPreview.proof_id, "proof-123");

const applied = normalizeExtensionMutationApply({
  schema_version: "guard.daemon.extension-controls.v1",
  status: "applied",
  revision: 5,
  catalog_digest: digest,
});
assert.equal(applied.status, "applied");

assert.throws(() => normalizeExtensionSemanticPreview({ ...semantic, changed_target_count: 2 }), /target count/);
assert.throws(() => normalizeExtensionSemanticPreview({ ...semantic, changed_targets: [{ ...semantic.changed_targets[0], target: { kind: "permission", target_id: "not canonical" } }] }), /target_id/);
assert.throws(() => normalizeExtensionSemanticPreview({ ...semantic, changed_targets: [{ ...semantic.changed_targets[0], provenance: Array(4097).fill("local-admin") }] }), /provenance/);
assert.throws(() => normalizeExtensionMutationPreview({
  schema_version: "guard.daemon.extension-controls.v1",
  previous_revision: 4,
  next_revision: 5,
  catalog_digest: "not-a-digest",
  canonical_diff_digest: "b".repeat(64),
  global_lockdown: false,
  controls: 1,
  semantic_preview: semantic,
}), /catalog_digest/);
assert.throws(() => normalizeExtensionMutationApply({
  schema_version: "guard.daemon.extension-controls.v1",
  status: "previewed",
  revision: 5,
  catalog_digest: digest,
}), /apply status/);

console.log("extension-control-preview-normalize.test.ts: all assertions passed");
