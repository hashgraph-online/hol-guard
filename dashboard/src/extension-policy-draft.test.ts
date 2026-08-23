import assert from "node:assert/strict";

import {
  buildExtensionPolicyDraftMutation,
  extensionPolicyDraftIsDirty,
  localPermissionDraftState,
  setLocalPermissionDraftState,
  setLocalPermissionDraftStates,
} from "./extension-policy-draft";
import type { EffectiveExtensionControls, ExtensionControlLayer } from "./extension-controls-api";

const digest = "a".repeat(64);
const managed: ExtensionControlLayer = {
  schema_version: "1.0.0",
  kind: "signed-cloud",
  catalog_digest: digest,
  global_lockdown: false,
  controls: [{
    target_kind: "permission",
    target_id: "command.git.permission.force-clean",
    state: "disabled",
  }],
};
const local: ExtensionControlLayer = {
  schema_version: "1.0.0",
  kind: "local-admin",
  catalog_digest: digest,
  global_lockdown: false,
  controls: [{
    target_kind: "extension",
    target_id: "command.git",
    state: "enabled",
  }],
};
const effective: EffectiveExtensionControls = {
  schema_version: "guard.daemon.extension-controls.v1",
  health: "protected",
  revision: 7,
  catalog_digest: digest,
  global_lockdown: false,
  controls: [],
  layers: [local, managed],
  failures: [],
};

assert.equal(localPermissionDraftState(effective.layers, "command.git.permission.force-clean"), "inherit");

const blocked = setLocalPermissionDraftState(
  effective.layers,
  digest,
  "command.git.permission.force-clean",
  "block",
);
assert.equal(localPermissionDraftState(blocked, "command.git.permission.force-clean"), "block");
assert.equal(blocked.find((layer) => layer.kind === "signed-cloud")?.controls[0]?.state, "disabled", "drafting must preserve managed authority exactly");
assert.equal(effective.layers[0]?.controls.length, 1, "drafting must not mutate the authoritative input");
assert.equal(extensionPolicyDraftIsDirty(effective, blocked), true);

const inherited = setLocalPermissionDraftState(
  blocked,
  digest,
  "command.git.permission.force-clean",
  "inherit",
);
assert.equal(localPermissionDraftState(inherited, "command.git.permission.force-clean"), "inherit");
assert.equal(extensionPolicyDraftIsDirty(effective, inherited), false, "reset-to-inherit must reproduce authoritative local policy");

const allowed = setLocalPermissionDraftState(
  effective.layers,
  digest,
  "command.git.permission.force-clean",
  "allow",
);
assert.equal(localPermissionDraftState(allowed, "command.git.permission.force-clean"), "allow");

const bulkBlocked = setLocalPermissionDraftStates(
  effective.layers,
  digest,
  ["command.git.permission.force-clean", "command.git.permission.branch-delete"],
  "block",
);
assert.equal(localPermissionDraftState(bulkBlocked, "command.git.permission.force-clean"), "block");
assert.equal(localPermissionDraftState(bulkBlocked, "command.git.permission.branch-delete"), "block");
assert.equal(effective.layers[0]?.controls.length, 1, "bulk drafting must not mutate authoritative layers");

const mutation = buildExtensionPolicyDraftMutation(effective, digest, allowed, {
  idempotencyKey: "draft-idempotency",
  nonce: "draft-nonce",
});
assert.equal(mutation.previous_revision, 7);
assert.equal(mutation.catalog_digest, digest);
assert.equal(mutation.actor_id, "dashboard-admin");
assert.equal(mutation.idempotency_key, "draft-idempotency");
assert.equal(mutation.nonce, "draft-nonce");
assert.equal(mutation.layers.find((layer) => layer.kind === "signed-cloud")?.controls[0]?.state, "disabled");

mutation.layers[0]!.controls.length = 0;
assert.equal(allowed[0]!.controls.length > 0, true, "mutation construction must clone draft controls");

console.log("extension-policy-draft.test.ts: all assertions passed");
