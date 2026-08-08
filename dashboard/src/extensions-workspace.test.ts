import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  buildExtensionMutation,
  ExtensionStatusBanner,
  extensionRecoveryAction,
  requiresExtensionRecoveryApproval,
} from "./extensions-workspace";
import { ExtensionControlApiError } from "./extension-controls-api";

assert.equal(extensionRecoveryAction("protected"), null);
assert.deepEqual(extensionRecoveryAction("unenrolled"), {
  title: "Finish local enrollment",
  copyLabel: "Copy enrollment command",
  description: "Authenticate in this device's terminal to protect extension settings, then check again.",
  command: "hol-guard guard command controls enroll",
});
assert.deepEqual(extensionRecoveryAction("tampered"), {
  title: "Repair extension controls",
  copyLabel: "Copy repair command",
  description:
    "Guard locked these settings after detecting damaged authority data. Authenticate in this device's terminal to rebuild the trusted authority, then check again.",
  command: "hol-guard guard command controls recover-authority",
});

const recoveryMarkup = renderToStaticMarkup(createElement(ExtensionStatusBanner, {
  effective: {
    schema_version: "1.0.0",
    health: "tampered",
    revision: 4,
    catalog_digest: "a".repeat(64),
    global_lockdown: false,
    controls: [],
    failures: [{ code: "anchor_mismatch", detail: "Authority anchor does not match." }],
    layers: [],
  },
  onRecover: () => undefined,
  onRetry: () => undefined,
}));
assert.match(recoveryMarkup, /hol-guard guard command controls recover-authority/);
assert.match(recoveryMarkup, /Copy repair command/);
assert.match(recoveryMarkup, /Repair now/);
assert.match(recoveryMarkup, /Check again/);
assert.equal(
  requiresExtensionRecoveryApproval(new ExtensionControlApiError("approval_gate_required", 403, "approval_gate_required")),
  true,
);
assert.equal(
  requiresExtensionRecoveryApproval(new ExtensionControlApiError("authority_not_recoverable", 409, "authority_not_recoverable")),
  false,
);

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
