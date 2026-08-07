import assert from "node:assert/strict";

import { buildExtensionMutation } from "./extensions-workspace";

const state = {
  kind: "ready" as const,
  catalog: {
    schema_version: "1.0.0",
    catalog_digest: "a".repeat(64),
    extensions: [],
  },
  effective: {
    schema_version: "1.0.0",
    health: "protected" as const,
    revision: 8,
    catalog_digest: "a".repeat(64),
    global_lockdown: false,
    controls: [],
    failures: [],
    layers: [
      {
        schema_version: "1.0.0",
        kind: "local-admin" as const,
        catalog_digest: "a".repeat(64),
        global_lockdown: false,
        controls: [
          { target_kind: "extension" as const, target_id: "existing", state: "disabled" as const },
        ],
      },
    ],
  },
};

const targeted = buildExtensionMutation(state, {
  extension: {
    extension_id: "new-extension",
    name: "New extension",
    description: "Test extension",
    required: false,
    source: "built-in",
    version: "1.0.0",
    action_classes: [],
    risk_classes: [],
  },
  enabled: false,
});
assert.equal(targeted.previous_revision, 8);
assert.deepEqual(targeted.layers[0]?.controls.map((control) => control.target_id), ["existing", "new-extension"]);
assert.equal(targeted.layers[0]?.controls[1]?.state, "disabled");
assert.equal(state.effective.layers[0]?.controls.length, 1, "builder must not mutate loaded authority state");

const lockdown = buildExtensionMutation(state, { globalLockdown: true });
assert.equal(lockdown.layers[0]?.global_lockdown, true);
assert.equal(lockdown.layers[0]?.controls[0]?.target_id, "existing");

