import type {
  EffectiveExtensionControls,
  ExtensionControlLayer,
  ExtensionMutationPayload,
} from "./extension-controls-api";

export type PermissionDraftState = "inherit" | "allow" | "block";

function cloneLayers(layers: ExtensionControlLayer[]): ExtensionControlLayer[] {
  return layers.map((layer) => ({
    ...layer,
    controls: layer.controls.map((control) => ({ ...control })),
  }));
}

function sortedControls(layer: ExtensionControlLayer): ExtensionControlLayer {
  return {
    ...layer,
    controls: [...layer.controls].sort((left, right) =>
      `${left.target_kind}:${left.target_id}`.localeCompare(`${right.target_kind}:${right.target_id}`),
    ),
  };
}

export function localPermissionDraftState(
  layers: ExtensionControlLayer[],
  permissionId: string,
): PermissionDraftState {
  const local = layers.find((layer) => layer.kind === "local-admin");
  const control = local?.controls.find(
    (item) => item.target_kind === "permission" && item.target_id === permissionId,
  );
  if (!control) return "inherit";
  return control.state === "enabled" ? "allow" : "block";
}

export function setLocalPermissionDraftState(
  layers: ExtensionControlLayer[],
  catalogDigest: string,
  permissionId: string,
  state: PermissionDraftState,
): ExtensionControlLayer[] {
  const next = cloneLayers(layers);
  let local = next.find((layer) => layer.kind === "local-admin");
  if (!local) {
    local = {
      schema_version: "1.0.0",
      kind: "local-admin",
      catalog_digest: catalogDigest,
      global_lockdown: false,
      controls: [],
    };
    next.push(local);
  }
  local.controls = local.controls.filter(
    (control) => control.target_kind !== "permission" || control.target_id !== permissionId,
  );
  if (state !== "inherit") {
    local.controls.push({
      target_kind: "permission",
      target_id: permissionId,
      state: state === "allow" ? "enabled" : "disabled",
    });
  }
  const normalized = next.map((layer) => sortedControls(layer));
  normalized.sort((left, right) => left.kind.localeCompare(right.kind));
  return normalized;
}

export function setLocalPermissionDraftStates(
  layers: ExtensionControlLayer[],
  catalogDigest: string,
  permissionIds: readonly string[],
  state: PermissionDraftState,
): ExtensionControlLayer[] {
  return permissionIds.reduce(
    (next, permissionId) => setLocalPermissionDraftState(next, catalogDigest, permissionId, state),
    layers,
  );
}

function canonicalLayerValue(layers: ExtensionControlLayer[]): string {
  return JSON.stringify(
    [...layers]
      .map((layer) => sortedControls(layer))
      .sort((left, right) => left.kind.localeCompare(right.kind)),
  );
}

export function extensionPolicyDraftIsDirty(
  effective: EffectiveExtensionControls,
  draftLayers: ExtensionControlLayer[],
): boolean {
  return canonicalLayerValue(effective.layers) !== canonicalLayerValue(draftLayers);
}

export function buildExtensionPolicyDraftMutation(
  effective: EffectiveExtensionControls,
  catalogDigest: string,
  draftLayers: ExtensionControlLayer[],
  identity: { idempotencyKey: string; nonce: string },
): ExtensionMutationPayload {
  return {
    previous_revision: effective.revision,
    catalog_digest: catalogDigest,
    layers: cloneLayers(draftLayers),
    actor_id: "dashboard-admin",
    idempotency_key: identity.idempotencyKey,
    nonce: identity.nonce,
  };
}

export function newExtensionPolicyDraftIdentity(): { idempotencyKey: string; nonce: string } {
  return {
    idempotencyKey: crypto.randomUUID().replaceAll("-", ""),
    nonce: crypto.randomUUID().replaceAll("-", ""),
  };
}

export function isCurrentExtensionPolicyDraft(generation: number, current: number): boolean {
  return generation === current;
}
