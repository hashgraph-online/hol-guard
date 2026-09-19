import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import {
  FIXED_PROTECTION_PERMISSION,
  PROTECTION_AUTHORITY_FIXTURES,
  protectionModuleFixture,
} from "../protection-center/fixtures/protection-fixtures";
import {
  ExtensionManagedControlsPanel,
  extensionLocalProtectionInput,
  extensionProtectionAuthority,
  extensionProtectionSource,
} from "./extension-managed-controls-panel";

const extension = protectionModuleFixture({
  permission_count: 1,
  permissions: [{
    ...FIXED_PROTECTION_PERMISSION,
    permission_id: "command.git.permission.force-push",
  }],
});
const effective = {
  ...PROTECTION_AUTHORITY_FIXTURES.managedBlock,
  managed_controls: {
    control_set_id: "managed-git-safety",
    control_set_name: "Managed Git safety",
    bundle_version: 7,
    workspace_id: "workspace-managed-controls",
    authority_mode: "managed-restrictive" as const,
    catalog_digest: "a".repeat(64),
    issued_at: "2026-08-21T12:00:00.000Z",
    expires_at: "2026-09-21T12:00:00.000Z",
    acknowledgement: {
      extension_authority_revision: 3,
      effective_projection_digest: "b".repeat(64),
      status: "applied",
    },
  },
};

assert.equal(extensionProtectionSource(effective, extension), "Managed by workspace-managed-controls");

const markup = renderToStaticMarkup(createElement(ExtensionManagedControlsPanel, {
  extension,
  effective,
  onRefresh: () => undefined,
}));
assert.match(markup, /Active managed control/);
assert.match(markup, /Managed by workspace-managed-controls/);
assert.match(markup, /Managed Git safety/);
assert.match(markup, /managed-restrictive/);
assert.match(markup, /cannot weaken this workspace restriction/);
assert.match(markup, /Local protection and local tightening remain available/);
assert.match(markup, /Connect Guard Cloud/, "disconnected local view keeps the supported connection action");

const mixedEffective = {
  ...effective,
  controls: [{
    target: { kind: "permission" as const, target_id: "command.git.permission.force-push" },
    state: "disabled" as const,
  }],
  layers: [{
    schema_version: "1.0.0",
    kind: "signed-cloud" as const,
    catalog_digest: "a".repeat(64),
    global_lockdown: false,
    controls: [{
      target_kind: "permission" as const,
      target_id: "command.git.permission.force-push",
      state: "enabled" as const,
    }],
  }, {
    schema_version: "1.0.0",
    kind: "local-admin" as const,
    catalog_digest: "a".repeat(64),
    global_lockdown: false,
    controls: [{
      target_kind: "permission" as const,
      target_id: "command.git.permission.force-push",
      state: "disabled" as const,
    }],
  }],
  projection: {
    schema_version: "guard.daemon.extension-control-projection.v1" as const,
    revision: 3,
    catalog_digest: "a".repeat(64),
    health: "protected" as const,
    extensions: [{
      extension_id: "command.git",
      effective_state: "allowed" as const,
      local_state: "inherited" as const,
      managed_state: "inherited" as const,
      required: false,
      reason_codes: [],
    }],
    permissions: [{
      permission_id: "command.git.permission.force-push",
      extension_id: "command.git",
      effective_state: "blocked" as const,
      local_state: "disabled" as const,
      managed_state: "enabled" as const,
      configurable: true,
      fixed_reason: null,
      reason_codes: ["control.disabled-permission"],
    }],
  },
};
const mixedAuthority = extensionProtectionAuthority(mixedEffective, extension);
assert.equal(mixedAuthority.effectiveState, "blocked");
assert.equal(mixedAuthority.source, "Set on this device");
assert.deepEqual(mixedAuthority.sources, ["Managed by workspace-managed-controls", "Set on this device"]);
const multiPermissionExtension = {
  ...extension,
  permission_count: 2,
  permissions: [
    ...extension.permissions,
    { ...FIXED_PROTECTION_PERMISSION, permission_id: "command.git.permission.hard-reset" },
  ],
};
const partialEffective = {
  ...mixedEffective,
  projection: {
    ...mixedEffective.projection,
    permissions: [
      ...mixedEffective.projection.permissions,
      {
        ...mixedEffective.projection.permissions[0],
        permission_id: "command.git.permission.hard-reset",
        effective_state: "allowed" as const,
        local_state: "inherited" as const,
        managed_state: "inherited" as const,
        reason_codes: [],
      },
    ],
  },
};
assert.equal(extensionProtectionAuthority(partialEffective, multiPermissionExtension).effectiveState, "partial");
const mixedMarkup = renderToStaticMarkup(createElement(ExtensionManagedControlsPanel, {
  extension,
  effective: mixedEffective,
  onRefresh: () => undefined,
}));
assert.match(mixedMarkup, /Set on this device/);
assert.match(mixedMarkup, /Managed by workspace-managed-controls · Set on this device/);

const degradedInput = extensionLocalProtectionInput({ ...extension }, {
  ...mixedEffective,
  health: "degraded-acknowledged",
  failures: [],
});
assert.equal(degradedInput.recovery, "degraded");
assert.equal(degradedInput.source, "Set on this device");
assert.deepEqual(degradedInput.sources, ["Managed by workspace-managed-controls", "Set on this device"]);

const catalogMismatchInput = extensionLocalProtectionInput(extension, {
  ...mixedEffective,
  failures: [{ code: "catalog-digest-mismatch", layer_kind: "signed-cloud" }],
});
assert.equal(catalogMismatchInput.recovery, "catalog-mismatch");

const unsupportedInput = extensionLocalProtectionInput(extension, {
  ...mixedEffective,
  failures: [{ code: "unsupported-control-schema", layer_kind: "signed-cloud" }],
});
assert.equal(unsupportedInput.recovery, "unsupported-version");
const unsupportedMarkup = renderToStaticMarkup(createElement(ExtensionManagedControlsPanel, {
  extension,
  effective: {
    ...mixedEffective,
    failures: [{ code: "unsupported-control-schema", layer_kind: "signed-cloud" }],
  },
  onRefresh: () => undefined,
}));
assert.match(unsupportedMarkup, /uses a newer control schema/);
assert.match(unsupportedMarkup, /Managed Git safety/);

const catalogMismatchMarkup = renderToStaticMarkup(createElement(ExtensionManagedControlsPanel, {
  extension,
  effective: {
    ...mixedEffective,
    failures: [{ code: "catalog-digest-mismatch", layer_kind: "signed-cloud" }],
  },
  onRefresh: () => undefined,
}));
assert.match(catalogMismatchMarkup, /local Extension catalog do not match/);
assert.match(catalogMismatchMarkup, /Managed by workspace-managed-controls · Set on this device/);

const staleMarkup = renderToStaticMarkup(createElement(ExtensionManagedControlsPanel, {
  extension,
  effective: {
    ...mixedEffective,
    failures: [{ code: "cloud_sync_stale", layer_kind: "signed-cloud" }],
  },
  onRefresh: () => undefined,
}));
assert.match(staleMarkup, /Guard Cloud data is stale/);
assert.match(staleMarkup, /Local protection continues with the last verified authority/);
assert.match(staleMarkup, /Check again/);
assert.doesNotMatch(staleMarkup, /fresh acknowledgement succeeds/);

console.log("extension-managed-controls-panel.test.tsx: all assertions passed");
