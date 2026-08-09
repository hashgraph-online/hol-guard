import type {
  EffectiveExtensionControls,
  ExtensionCatalogItem,
  ExtensionControlLayer,
} from "./extension-controls-api";
import {
  localPermissionDraftState,
  setLocalPermissionDraftState,
  type PermissionDraftState,
} from "./extension-policy-draft";

export type ExtensionPolicyRebaseConflict = {
  original_permission_id: string;
  latest_permission_id: string | null;
  kind: "overlap" | "removed";
  base_state: PermissionDraftState;
  latest_state: PermissionDraftState;
  requested_state: PermissionDraftState;
};

export type ExtensionPolicyRebaseResult = {
  draft_layers: ExtensionControlLayer[];
  conflicts: ExtensionPolicyRebaseConflict[];
  remapped_permission_ids: Record<string, string>;
};

function permissionSuffix(permissionId: string): string | null {
  const marker = ".permission.";
  const index = permissionId.indexOf(marker);
  return index < 0 ? null : permissionId.slice(index + marker.length);
}

function latestPermissionId(
  original: string,
  oldExtension: ExtensionCatalogItem,
  latestExtension: ExtensionCatalogItem,
): string | null {
  if (latestExtension.permissions.some((permission) => permission.permission_id === original)) return original;
  if (
    latestExtension.extension_id !== oldExtension.extension_id &&
    latestExtension.aliases.includes(oldExtension.extension_id)
  ) {
    const suffix = permissionSuffix(original);
    if (!suffix) return null;
    const candidate = `${latestExtension.extension_id}.permission.${suffix}`;
    if (latestExtension.permissions.some((permission) => permission.permission_id === candidate)) return candidate;
  }
  return null;
}

export function rebaseExtensionPolicyDraft(
  oldEffective: EffectiveExtensionControls,
  latestEffective: EffectiveExtensionControls,
  oldExtension: ExtensionCatalogItem,
  latestExtension: ExtensionCatalogItem,
  draftLayers: ExtensionControlLayer[],
): ExtensionPolicyRebaseResult {
  let rebased = latestEffective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
  const conflicts: ExtensionPolicyRebaseConflict[] = [];
  const remapped: Record<string, string> = {};

  for (const permission of oldExtension.permissions) {
    const baseState = localPermissionDraftState(oldEffective.layers, permission.permission_id);
    const requestedState = localPermissionDraftState(draftLayers, permission.permission_id);
    if (baseState === requestedState) continue;
    const mapped = latestPermissionId(permission.permission_id, oldExtension, latestExtension);
    if (!mapped) {
      conflicts.push({
        original_permission_id: permission.permission_id,
        latest_permission_id: null,
        kind: "removed",
        base_state: baseState,
        latest_state: "inherit",
        requested_state: requestedState,
      });
      continue;
    }
    remapped[permission.permission_id] = mapped;
    const latestState = localPermissionDraftState(latestEffective.layers, mapped);
    if (latestState !== baseState && latestState !== requestedState) {
      conflicts.push({
        original_permission_id: permission.permission_id,
        latest_permission_id: mapped,
        kind: "overlap",
        base_state: baseState,
        latest_state: latestState,
        requested_state: requestedState,
      });
      continue;
    }
    rebased = setLocalPermissionDraftState(rebased, latestEffective.catalog_digest, mapped, requestedState);
  }

  return { draft_layers: rebased, conflicts, remapped_permission_ids: remapped };
}

export function keepExtensionPolicyRebaseConflicts(
  result: ExtensionPolicyRebaseResult,
  latestEffective: EffectiveExtensionControls,
): ExtensionControlLayer[] {
  let layers = result.draft_layers;
  for (const conflict of result.conflicts) {
    if (conflict.kind !== "overlap" || !conflict.latest_permission_id) continue;
    layers = setLocalPermissionDraftState(
      layers,
      latestEffective.catalog_digest,
      conflict.latest_permission_id,
      conflict.requested_state,
    );
  }
  return layers;
}
