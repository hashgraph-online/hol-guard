import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import {
  applyExtensionMutation,
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  previewExtensionMutation,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionMutationPreview,
} from "./extension-controls-api";
import {
  buildExtensionPolicyDraftMutation,
  extensionPolicyDraftIsDirty,
  isCurrentExtensionPolicyDraft,
  localPermissionDraftState,
  newExtensionPolicyDraftIdentity,
  setLocalPermissionDraftState,
  setLocalPermissionDraftStates,
  type PermissionDraftState,
} from "./extension-policy-draft";
import {
  keepExtensionPolicyRebaseConflicts,
  rebaseExtensionPolicyDraft,
  type ExtensionPolicyRebaseConflict,
  type ExtensionPolicyRebaseResult,
} from "./extension-policy-rebase";

export type PendingPolicyRebase = {
  result: ExtensionPolicyRebaseResult;
  latestEffective: EffectiveExtensionControls;
  latestExtensions: ExtensionCatalogItem[];
};

export type AppliedPolicySnapshot = {
  revision: number;
  previousLayers: EffectiveExtensionControls["layers"];
  changedPermissionIds: string[];
};

export type PolicyDraftMutationCredentials = {
  approval_password?: string;
  approval_totp_code?: string;
};

function cloneLayers(effective: EffectiveExtensionControls) {
  return effective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
}

/**
 * Extension-agnostic protection-setting draft state machine.
 *
 * One draft spans every permission the surface shows: the tool page lists one
 * extension's permissions while the landing console can mix patterns from
 * several tools. Preview, approval-proof binding, rebase, and apply behave
 * identically in both surfaces.
 */
export function useExtensionPolicyDraft(props: {
  effective: EffectiveExtensionControls;
  onRefresh: () => Promise<void> | void;
}) {
  const [baseEffective, setBaseEffective] = useState(props.effective);
  const [draftLayers, setDraftLayers] = useState(() => cloneLayers(props.effective));
  const [identity, setIdentity] = useState(() => newExtensionPolicyDraftIdentity());
  const [preview, setPreview] = useState<ExtensionMutationPreview | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [applyBusy, setApplyBusy] = useState(false);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [pendingRebase, setPendingRebase] = useState<PendingPolicyRebase | null>(null);
  const [refreshRequired, setRefreshRequired] = useState(false);
  const [lastApplied, setLastApplied] = useState<AppliedPolicySnapshot | null>(null);
  const draftGeneration = useRef(0);
  const { onRefresh } = props;
  const dirty = useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);

  useEffect(() => {
    draftGeneration.current += 1;
    setBaseEffective(props.effective);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setRefreshRequired(false);
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest]);

  const changeCountFor = useCallback((permissionIds: readonly string[]) => {
    return permissionIds.filter((permissionId) =>
      localPermissionDraftState(baseEffective.layers, permissionId) !== localPermissionDraftState(draftLayers, permissionId),
    ).length;
  }, [baseEffective, draftLayers]);

  const changedPermissionCount = useMemo(
    () => changeCountFor(
      baseEffective.layers.flatMap((layer) => layer.controls)
        .map((control) => (control.target_kind === "permission" ? control.target_id : null))
        .filter((id): id is string => Boolean(id)),
    ),
    [baseEffective, changeCountFor],
  );

  const resetDraft = useCallback(() => {
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective]);

  const setPermissionState = useCallback((permissionId: string, state: PermissionDraftState) => {
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftState(current, baseEffective.catalog_digest, permissionId, state));
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);

  const setPermissionStates = useCallback((permissionIds: readonly string[], state: PermissionDraftState) => {
    if (!permissionIds.length) return;
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftStates(
      current,
      baseEffective.catalog_digest,
      permissionIds,
      state,
    ));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective.catalog_digest]);

  const mutation = useCallback(
    () => buildExtensionPolicyDraftMutation(baseEffective, baseEffective.catalog_digest, draftLayers, identity),
    [baseEffective, draftLayers, identity],
  );

  const handleApiError = useCallback((caught: unknown, fallback: string) => {
    if (caught instanceof ExtensionControlApiError && ["revision_conflict", "catalog_conflict", "authority_conflict"].includes(caught.code ?? "")) {
      setStale(true);
      setError("The authoritative extension policy changed while this draft was open. Rebase the draft before applying; Guard will not silently overwrite security policy.");
      return;
    }
    setError(caught instanceof Error ? caught.message : fallback);
  }, []);

  const runPreview = useCallback(async () => {
    if (!dirty) return;
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    setStale(false);
    try {
      const next = await previewExtensionMutation(mutation());
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) return;
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not preview this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [dirty, handleApiError, mutation]);

  const apply = useCallback(async (credentials: PolicyDraftMutationCredentials) => {
    if (!preview || !dirty || stale) return;
    setApplyBusy(true);
    setError(null);
    try {
      const base = mutation();
      const appliedLayersBefore = cloneLayers(baseEffective);
      const proofPreview = await previewExtensionMutation({ ...base, ...credentials, session_nonce: crypto.randomUUID().replaceAll("-", "") });
      if (!proofPreview.proof_id) throw new Error("Guard did not issue an approval proof for this exact draft.");
      if (proofPreview.canonical_diff_digest !== preview.canonical_diff_digest) throw new Error("The policy draft changed after preview. Preview it again before applying.");
      const applied = await applyExtensionMutation({ ...base, proof_id: proofPreview.proof_id });
      setApprovalOpen(false);
      setPreview(null);
      setReviewOpen(false);
      setError(null);
      setStale(false);
      if (applied.revision <= baseEffective.revision) throw new Error("Guard did not advance the committed extension-control revision.");
      const changedPermissionIds = baseEffective.layers
        .flatMap((layer) => layer.controls)
        .concat(draftLayers.flatMap((layer) => layer.controls))
        .map((control) => (control.target_kind === "permission" ? control.target_id : null))
        .filter((id): id is string => Boolean(id));
      const previouslyRequested = new Set(
        draftLayers.flatMap((layer) => layer.controls)
          .map((control) => (control.target_kind === "permission" ? control.target_id : null))
          .filter((id): id is string => Boolean(id)),
      );
      setLastApplied({
        revision: applied.revision,
        previousLayers: appliedLayersBefore,
        changedPermissionIds: [...new Set(changedPermissionIds)].filter((id) => previouslyRequested.has(id) || localPermissionDraftState(baseEffective.layers, id) !== localPermissionDraftState(draftLayers, id)),
      });
      draftGeneration.current += 1;
      setDraftLayers(cloneLayers(baseEffective));
      setIdentity(newExtensionPolicyDraftIdentity());
      setRefreshRequired(true);
      try {
        await onRefresh();
      } catch {
        setError("The policy was applied, but Guard could not refresh the latest state. Refresh this page to confirm the committed policy.");
      }
    } catch (caught) {
      handleApiError(caught, "Guard could not apply this draft.");
    } finally {
      setApplyBusy(false);
    }
  }, [baseEffective.revision, dirty, handleApiError, mutation, onRefresh, preview, stale]);

  const rebaseDraft = useCallback(async (oldExtensions: readonly ExtensionCatalogItem[]) => {
    const generation = draftGeneration.current;
    setPreviewBusy(true);
    setError(null);
    try {
      const [latestCatalog, latestEffective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      const pairs = oldExtensions
        .map((oldExtension) => {
          const exact = latestCatalog.extensions.find((item) => item.extension_id === oldExtension.extension_id);
          if (exact) return { oldExtension, latestExtension: exact };
          const aliasMatches = latestCatalog.extensions.filter((item) => item.aliases.includes(oldExtension.extension_id));
          return aliasMatches.length === 1 ? { oldExtension, latestExtension: aliasMatches[0]! } : null;
        })
        .filter((pair): pair is { oldExtension: ExtensionCatalogItem; latestExtension: ExtensionCatalogItem } => Boolean(pair));
      if (!pairs.length) {
        setError("These extensions no longer exist in the authoritative catalog. Discard the draft and refresh before continuing.");
        return;
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError("The draft changed while Guard was loading current policy. Rebase again to preserve the latest edits.");
        return;
      }
      const chained = pairs.reduce<ExtensionPolicyRebaseResult | null>((result, { oldExtension, latestExtension }) => {
        const next = rebaseExtensionPolicyDraft(
          baseEffective,
          latestEffective,
          oldExtension,
          latestExtension,
          result ? result.draft_layers : draftLayers,
        );
        return {
          draft_layers: next.draft_layers,
          conflicts: [...(result?.conflicts ?? []), ...next.conflicts],
          remapped_permission_ids: { ...(result?.remapped_permission_ids ?? {}), ...next.remapped_permission_ids },
        };
      }, null);
      if (!chained) {
        setError("Guard could not rebase this draft against the current catalog.");
        return;
      }
      const result: ExtensionPolicyRebaseResult = chained;
      setBaseEffective(latestEffective);
      setIdentity(newExtensionPolicyDraftIdentity());
      setPreview(null);
      setReviewOpen(false);
      if (result.conflicts.length) {
        setPendingRebase({ result, latestEffective, latestExtensions: pairs.map((pair) => pair.latestExtension) });
        setDraftLayers(result.draft_layers);
        setStale(true);
        setError("The latest policy overlaps this draft. Choose whether to keep your overlapping changes or use current authoritative values. Removed permissions cannot be restored.");
      } else {
        setDraftLayers(result.draft_layers);
        setPendingRebase(null);
        setStale(false);
        setError(null);
      }
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not rebase this draft.");
    } finally {
      setPreviewBusy(false);
    }
  }, [baseEffective, draftLayers]);

  const keepConflicts = useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(keepExtensionPolicyRebaseConflicts(pendingRebase.result, pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);

  const useCurrent = useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(cloneLayers(pendingRebase.latestEffective));
    setPendingRebase(null);
    setStale(false);
    setError(null);
    setPreview(null);
    setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);

  const applyProfile = useCallback((permissions: readonly { permission_id: string; configurable: boolean }[], profile: "recommended" | "stricter" | "custom") => {
    if (profile === "custom") return;
    draftGeneration.current += 1;
    let next = cloneLayers(baseEffective);
    for (const permission of permissions) {
      if (!permission.configurable) continue;
      const state: PermissionDraftState = profile === "recommended" ? "inherit" : "block";
      next = setLocalPermissionDraftState(next, baseEffective.catalog_digest, permission.permission_id, state);
    }
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
  }, [baseEffective]);

  const useHistoricalDraft = useCallback((historicalLayers: EffectiveExtensionControls["layers"]) => {
    draftGeneration.current += 1;
    const historicalLocal = historicalLayers.find((layer) => layer.kind === "local-admin");
    const next = baseEffective.layers.flatMap((layer) => (layer.kind === "local-admin" ? (historicalLocal ? [historicalLocal] : []) : [layer]));
    if (historicalLocal && !baseEffective.layers.some((layer) => layer.kind === "local-admin")) next.push(historicalLocal);
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
  }, [baseEffective.layers]);

  const undoLastApplied = useCallback(() => {
    if (!lastApplied) return false;
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers({ ...baseEffective, layers: lastApplied.previousLayers }));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null);
    setReviewOpen(false);
    setError(null);
    setStale(false);
    setPendingRebase(null);
    setLastApplied(null);
    return true;
  }, [baseEffective, lastApplied]);

  return {
    baseEffective,
    draftLayers,
    dirty,
    preview,
    previewBusy,
    applyBusy,
    reviewOpen,
    approvalOpen,
    error,
    stale,
    pendingRebase,
    refreshRequired,
    lastApplied,
    undoLastApplied,
    changedPermissionCount,
    setReviewOpen,
    setApprovalOpen,
    permissionState: useCallback((permissionId: string) => localPermissionDraftState(draftLayers, permissionId), [draftLayers]),
    changeCountFor,
    setPermissionState,
    setPermissionStates,
    resetDraft,
    runPreview,
    apply,
    rebaseDraft,
    keepConflicts,
    useCurrent,
    applyProfile,
    useHistoricalDraft,
  };
}
