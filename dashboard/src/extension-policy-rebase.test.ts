import assert from "node:assert/strict";

import type { EffectiveExtensionControls, ExtensionCatalogItem, ExtensionControlLayer, ExtensionPermission } from "./extension-controls-api";
import { localPermissionDraftState, setLocalPermissionDraftState } from "./extension-policy-draft";
import { keepExtensionPolicyRebaseConflicts, rebaseExtensionPolicyDraft } from "./extension-policy-rebase";

const digestA = "a".repeat(64);
const digestB = "b".repeat(64);

function permission(id: string, extensionId = "command.git"): ExtensionPermission {
  return {
    permission_id: id,
    schema_version: 1,
    extension_id: extensionId,
    implementation_version: "1.0.0",
    label: id,
    description: id,
    risk_tier: "high",
    baseline_floor: "review",
    default_enabled: true,
    configurable: true,
    fixed_reason: null,
    typed_capabilities: [],
    action_classes: [],
    rule_ids: [],
    dependencies: [],
    conflicts: [],
    implied_permissions: [],
    introduced_version: "1.0.0",
    deprecated: false,
    replacement_permission_id: null,
    example_command: null,
    family: null,
    safer_guidance: [],
  };
}

function extension(id: string, permissions: ExtensionPermission[], aliases: string[] = []): ExtensionCatalogItem {
  return {
    schema_version: 2,
    extension_id: id,
    name: id,
    description: id,
    enabled: true,
    required: false,
    source: "built-in",
    version: "1.0.0",
    aliases,
    dependencies: [], conflicts: [], delegated_protection: null, ecosystem_ids: [], executables: [], project_markers: [], reference_urls: [], action_classes: [], risk_classes: [], safer_alternatives: [], rule_count: 0, rules: [], permission_count: permissions.length, permissions,
  };
}

function localLayer(digest: string, controls: ExtensionControlLayer["controls"]): ExtensionControlLayer {
  return { schema_version: "1.0.0", kind: "local-admin", catalog_digest: digest, global_lockdown: false, controls };
}

function effective(digest: string, revision: number, layers: ExtensionControlLayer[]): EffectiveExtensionControls {
  return { schema_version: "v1", health: "protected", revision, catalog_digest: digest, global_lockdown: false, controls: [], layers, failures: [] };
}

const pA = permission("command.git.permission.force-clean");
const pB = permission("command.git.permission.hard-reset");
const oldExtension = extension("command.git", [pA, pB]);
const oldEffective = effective(digestA, 4, [localLayer(digestA, [])]);
let draft = setLocalPermissionDraftState(oldEffective.layers, digestA, pA.permission_id, "block");

const latestNonOverlap = effective(digestA, 5, [localLayer(digestA, [{ target_kind: "permission", target_id: pB.permission_id, state: "disabled" }])]);
const nonOverlap = rebaseExtensionPolicyDraft(oldEffective, latestNonOverlap, oldExtension, oldExtension, draft);
assert.equal(nonOverlap.conflicts.length, 0);
assert.equal(localPermissionDraftState(nonOverlap.draft_layers, pA.permission_id), "block");
assert.equal(localPermissionDraftState(nonOverlap.draft_layers, pB.permission_id), "block");

const latestOverlap = effective(digestA, 5, [localLayer(digestA, [{ target_kind: "permission", target_id: pA.permission_id, state: "enabled" }])]);
const overlap = rebaseExtensionPolicyDraft(oldEffective, latestOverlap, oldExtension, oldExtension, draft);
assert.equal(overlap.conflicts.length, 1);
assert.equal(overlap.conflicts[0]?.kind, "overlap");
assert.equal(localPermissionDraftState(overlap.draft_layers, pA.permission_id), "allow");
const kept = keepExtensionPolicyRebaseConflicts(overlap, latestOverlap);
assert.equal(localPermissionDraftState(kept, pA.permission_id), "block");

const removedExtension = extension("command.git", []);
const removed = rebaseExtensionPolicyDraft(oldEffective, latestNonOverlap, oldExtension, removedExtension, draft);
assert.equal(removed.conflicts[0]?.kind, "removed");

const renamedPermission = permission("command.scm.permission.force-clean", "command.scm");
const renamedExtension = extension("command.scm", [renamedPermission], ["command.git"]);
const renamedEffective = effective(digestB, 6, [localLayer(digestB, [])]);
const renamed = rebaseExtensionPolicyDraft(oldEffective, renamedEffective, oldExtension, renamedExtension, draft);
assert.equal(renamed.conflicts.length, 0);
assert.equal(renamed.remapped_permission_ids[pA.permission_id], renamedPermission.permission_id);
assert.equal(localPermissionDraftState(renamed.draft_layers, renamedPermission.permission_id), "block");

console.log("extension-policy-rebase.test.ts: all assertions passed");
