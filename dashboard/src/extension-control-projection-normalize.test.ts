import assert from "node:assert/strict";

import { normalizeEffectiveExtensionControlProjection } from "./extension-control-projection-normalize";

const digest = "a".repeat(64);
const projection = {
  schema_version: "guard.daemon.extension-control-projection.v1",
  revision: 4,
  catalog_digest: digest,
  health: "protected",
  extensions: [{
    extension_id: "command.git",
    effective_state: "allowed",
    local_state: "inherited",
    managed_state: "inherited",
    required: false,
    reason_codes: [],
  }],
  permissions: [{
    permission_id: "command.git.permission.force-clean",
    extension_id: "command.git",
    effective_state: "blocked",
    local_state: "enabled",
    managed_state: "disabled",
    configurable: true,
    fixed_reason: null,
    reason_codes: ["control.disabled-permission"],
  }],
};

const normalized = normalizeEffectiveExtensionControlProjection(projection);
assert.equal(normalized.extensions[0]?.effective_state, "allowed");
assert.equal(normalized.permissions[0]?.managed_state, "disabled");
assert.equal(normalized.permissions[0]?.effective_state, "blocked");

assert.throws(() => normalizeEffectiveExtensionControlProjection({ ...projection, revision: -1 }), /revision/);
assert.throws(() => normalizeEffectiveExtensionControlProjection({ ...projection, catalog_digest: "bad" }), /catalog_digest/);
assert.throws(() => normalizeEffectiveExtensionControlProjection({ ...projection, health: "healthy" }), /health/);
assert.throws(() => normalizeEffectiveExtensionControlProjection({
  ...projection,
  permissions: [...projection.permissions, projection.permissions[0]],
}), /Duplicate projection permission ID/);

console.log("extension-control-projection-normalize.test.ts: all assertions passed");
