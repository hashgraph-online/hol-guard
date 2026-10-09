import {
  applyExtensionMutation,
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  previewExtensionMutation,
  type EffectiveExtensionControls,
  type ExtensionMutationApplyResponse,
  type ExtensionMutationPayload,
  type ExtensionMutationPreview,
} from "./extension-controls-api";
import {
  buildExtensionPolicyDraftMutation,
  localPermissionDraftState,
  newExtensionPolicyDraftIdentity,
  setLocalPermissionDraftStates,
} from "./extension-policy-draft";

export type ExtensionAllowCredentials = { approval_password?: string; approval_totp_code?: string };

export type ExtensionAllowDeps = {
  fetchEffective: () => Promise<EffectiveExtensionControls>;
  preview: (payload: ExtensionMutationPayload) => Promise<ExtensionMutationPreview>;
  apply: (payload: ExtensionMutationPayload) => Promise<ExtensionMutationApplyResponse>;
  resolve: (credentials: ExtensionAllowCredentials) => Promise<void>;
  sessionNonce?: () => string;
};

export type ExtensionAllowOutcome =
  | { status: "approved"; revision: number }
  | { status: "saved_only"; revision: number; message: string };

export const defaultExtensionAllowDeps: Omit<ExtensionAllowDeps, "resolve"> = {
  fetchEffective: fetchEffectiveExtensionControls,
  preview: previewExtensionMutation,
  apply: applyExtensionMutation,
};

const CONFLICT_CODES = new Set(["revision_conflict", "catalog_conflict"]);

function isConflict(caught: unknown): boolean {
  return caught instanceof ExtensionControlApiError && CONFLICT_CODES.has(caught.code ?? "");
}

function randomNonce(): string {
  return crypto.randomUUID().replaceAll("-", "");
}

async function enablePermissions(
  deps: ExtensionAllowDeps,
  permissionIds: readonly string[],
  credentials: ExtensionAllowCredentials,
): Promise<number> {
  const effective = await deps.fetchEffective();
  if (effective.health !== "protected") {
    throw new Error("Protection settings need attention before Guard can change them. Open the extension page for details.");
  }
  const pending = permissionIds.filter((id) => localPermissionDraftState(effective.layers, id) !== "allow");
  if (pending.length === 0) return effective.revision;
  const draftLayers = setLocalPermissionDraftStates(effective.layers, effective.catalog_digest, pending, "allow");
  const mutation = buildExtensionPolicyDraftMutation(
    effective,
    effective.catalog_digest,
    draftLayers,
    newExtensionPolicyDraftIdentity(),
  );
  const proof = await deps.preview({ ...mutation, ...credentials, session_nonce: (deps.sessionNonce ?? randomNonce)() });
  if (!proof.proof_id) throw new Error("Guard did not issue an approval proof for this setting change.");
  const applied = await deps.apply({ ...mutation, proof_id: proof.proof_id });
  if (applied.revision <= effective.revision) {
    throw new Error("Guard did not save the extension setting. Nothing was approved.");
  }
  return applied.revision;
}

/**
 * Turn the recommended permissions to Allow, then approve this one request.
 *
 * Order matters: the setting is saved first so a failed proof never approves
 * the request on its own. A stale revision is retried once against fresh
 * state. If the setting saves but the approval fails, the caller is told so
 * the request can still be decided normally.
 */
export async function approveWithExtensionAllow(
  deps: ExtensionAllowDeps,
  permissionIds: readonly string[],
  credentials: ExtensionAllowCredentials,
): Promise<ExtensionAllowOutcome> {
  if (permissionIds.length === 0) throw new Error("There is no extension setting to change.");
  let revision: number;
  try {
    revision = await enablePermissions(deps, permissionIds, credentials);
  } catch (caught) {
    if (!isConflict(caught)) throw caught;
    revision = await enablePermissions(deps, permissionIds, credentials);
  }
  try {
    await deps.resolve(credentials);
  } catch (caught) {
    const reason = caught instanceof Error && caught.message ? ` ${caught.message}` : "";
    return {
      status: "saved_only",
      revision,
      message: `The extension setting was saved, so future matching commands run automatically. This request still needs a decision.${reason}`,
    };
  }
  return { status: "approved", revision };
}
