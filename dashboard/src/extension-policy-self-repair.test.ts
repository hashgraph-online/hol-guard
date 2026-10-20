import assert from "node:assert/strict";

import { ExtensionControlApiError } from "./extension-controls-api";
import type {
  EffectiveExtensionControls,
  ExtensionControlLayer,
  ExtensionMutationPreview,
  ExtensionSemanticPreview,
} from "./extension-controls-api";
import {
  extensionPolicyRepairBase,
  isExtensionPolicyConflict,
  sameReviewedExtensionPolicyEffect,
} from "./extension-policy-self-repair";

const digest = "a".repeat(64);
const otherDigest = "b".repeat(64);

function layer(state: "enabled" | "disabled", catalogDigest = digest): ExtensionControlLayer {
  return {
    schema_version: "1.0.0",
    kind: "local-admin",
    catalog_digest: catalogDigest,
    global_lockdown: false,
    controls: [{ target_kind: "permission", target_id: "command.git.permission.force-clean", state }],
  };
}

function authority(overrides: Partial<EffectiveExtensionControls> = {}): EffectiveExtensionControls {
  return {
    schema_version: "guard.daemon.extension-controls.v1",
    health: "protected",
    revision: 7,
    catalog_digest: digest,
    global_lockdown: false,
    controls: [{ target: { kind: "permission", target_id: "command.git.permission.force-clean" }, state: "disabled" }],
    layers: [layer("disabled")],
    failures: [],
    ...overrides,
  };
}

// Only a refusal Guard raised over the authority a draft names can be repaired.
assert.equal(isExtensionPolicyConflict(new ExtensionControlApiError("stale", 409, "revision_conflict")), true);
assert.equal(isExtensionPolicyConflict(new ExtensionControlApiError("stale", 409, "catalog_conflict")), true);
assert.equal(isExtensionPolicyConflict(new ExtensionControlApiError("stale", 409, "authority_conflict")), true);
assert.equal(isExtensionPolicyConflict(new ExtensionControlApiError("denied", 403, "approval_required")), false);
assert.equal(isExtensionPolicyConflict(new ExtensionControlApiError("broken", 500)), false);
assert.equal(isExtensionPolicyConflict(new Error("revision_conflict")), false);

const base = authority();

// A revision that moved on its own carries the same policy, so the draft is re-seeded on it.
const moved = authority({ revision: 9 });
assert.deepEqual(extensionPolicyRepairBase(base, moved), moved);

// A revision that did not move cannot make the retry succeed.
assert.equal(extensionPolicyRepairBase(base, authority()), null);

// Every difference that is a real policy change keeps the draft stale.
assert.equal(extensionPolicyRepairBase(base, authority({ revision: 9, layers: [layer("enabled")] })), null);
assert.equal(extensionPolicyRepairBase(base, authority({ revision: 9, catalog_digest: otherDigest })), null);
assert.equal(extensionPolicyRepairBase(base, authority({ revision: 9, global_lockdown: true })), null);
assert.equal(
  extensionPolicyRepairBase(base, authority({ revision: 9, health: "degraded-unacknowledged" })),
  null,
  "a draft must not be re-seeded on an authority that lost its protected health",
);

const semantic: ExtensionSemanticPreview = {
  schema_version: "guard.daemon.extension-control-semantic-preview.v1",
  global_lockdown: { before: false, after: false, changed: false },
  changed_target_count: 1,
  affected_permission_count: 1,
  affected_rule_count: 1,
  changed_targets: [{
    target: { kind: "permission", target_id: "command.git.permission.force-clean" },
    extension_id: "command.git",
    label: "Force clean",
    before_explicit: "inherited",
    after_explicit: "disabled",
    before_effective: "allowed",
    after_effective: "blocked",
    affected_permission_ids: ["command.git.permission.force-clean"],
    affected_rule_ids: ["command.git.rule.force-clean"],
    warnings: [],
  }],
  summary: { newly_blocked_permissions: 1, newly_allowed_permissions: 0, effective_change_count: 1 },
};

function preview(overrides: Partial<ExtensionMutationPreview> = {}): ExtensionMutationPreview {
  return {
    schema_version: "guard.daemon.extension-control-mutation-preview.v1",
    previous_revision: 7,
    next_revision: 8,
    catalog_digest: digest,
    canonical_diff_digest: "c".repeat(64),
    global_lockdown: false,
    controls: 1,
    semantic_preview: semantic,
    ...overrides,
  };
}

const reviewed = preview();

// On the same revision the canonical digest covers the exact approved bytes.
assert.equal(sameReviewedExtensionPolicyEffect(preview(), reviewed), true);
assert.equal(
  sameReviewedExtensionPolicyEffect(preview({ canonical_diff_digest: "d".repeat(64) }), reviewed),
  false,
  "a draft that changed under the operator must not reuse the review",
);

// A draft re-seeded on a moved revision digests differently by construction, so the
// effect it describes is what has to match.
const reseeded = preview({ previous_revision: 9, next_revision: 10, canonical_diff_digest: "d".repeat(64) });
assert.equal(sameReviewedExtensionPolicyEffect(reseeded, reviewed), true);
assert.equal(
  sameReviewedExtensionPolicyEffect({ ...reseeded, global_lockdown: true }, reviewed),
  false,
);
assert.equal(
  sameReviewedExtensionPolicyEffect({ ...reseeded, catalog_digest: otherDigest }, reviewed),
  false,
);
assert.equal(sameReviewedExtensionPolicyEffect({ ...reseeded, controls: 2 }, reviewed), false);
assert.equal(
  sameReviewedExtensionPolicyEffect(
    {
      ...reseeded,
      semantic_preview: {
        ...semantic,
        changed_targets: [{ ...semantic.changed_targets[0]!, after_effective: "allowed" }],
      },
    },
    reviewed,
  ),
  false,
  "a retry that would land a different effect must not reuse the review",
);

console.log("extension-policy-self-repair.test.ts: all assertions passed");
