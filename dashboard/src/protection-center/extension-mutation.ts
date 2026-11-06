import type { EffectiveExtensionControls, ExtensionMutationPayload } from "../extension-controls-api";
import type { ProtectionPendingChange } from "./protection-change-review";

export function randomToken(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

export function buildExtensionMutation(
  state: { catalog: { catalog_digest: string }; effective: EffectiveExtensionControls },
  change: ProtectionPendingChange,
): ExtensionMutationPayload {
  const layers = structuredClone(state.effective.layers);
  let local = layers.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: state.catalog.catalog_digest,
      global_lockdown: false,
      controls: [],
    };
    layers.push(local);
  }
  if ("globalLockdown" in change) {
    local.global_lockdown = change.globalLockdown;
  } else {
    local.controls = local.controls.filter(
      (control) => control.target_kind !== "extension" || control.target_id !== change.extension.extension_id,
    );
    local.controls.push({
      target_kind: "extension",
      target_id: change.extension.extension_id,
      state: change.enabled ? "enabled" : "disabled",
    });
    local.controls.sort((left, right) =>
      `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`),
    );
  }
  return {
    previous_revision: state.effective.revision,
    catalog_digest: state.catalog.catalog_digest,
    layers,
    actor_id: "dashboard-admin",
    idempotency_key: randomToken(),
    nonce: randomToken(),
  };
}
