import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import { ApprovalProofModal } from "./approval-proof-modal";
import {
  applyExtensionMutation,
  ExtensionControlApiError,
  fetchEffectiveExtensionControls,
  fetchExtensionCatalog,
  previewExtensionMutation,
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionMutationPreview,
  type ExtensionPermission,
} from "./extension-controls-api";
import {
  buildExtensionPolicyDraftMutation,
  extensionPolicyDraftIsDirty,
  localPermissionDraftState,
  newExtensionPolicyDraftIdentity,
  setLocalPermissionDraftState,
  type PermissionDraftState,
} from "./extension-policy-draft";
import {
  keepExtensionPolicyRebaseConflicts,
  rebaseExtensionPolicyDraft,
  type ExtensionPolicyRebaseConflict,
  type ExtensionPolicyRebaseResult,
} from "./extension-policy-rebase";
import { controlProvenance, groupPermissionsByFamily, treatmentLabel } from "./extension-control-center-model";
import { useModalDialog } from "./use-modal-dialog";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";
import { ProtectionSettingsHistory } from "./protection-center/protection-settings-history";

const RISK_TONE: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-950",
  high: "border-orange-200 bg-orange-50 text-orange-950",
  medium: "border-amber-200 bg-amber-50 text-amber-950",
  low: "border-[rgba(63,65,116,0.16)] text-brand-dark",
};

function Pill(props: { children: React.ReactNode; tone?: string }) {
  return (
    <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${props.tone ?? "border-[rgba(63,65,116,0.16)] text-brand-dark"}`}>
      {props.children}
    </span>
  );
}

function cloneLayers(effective: EffectiveExtensionControls) {
  return effective.layers.map((layer) => ({ ...layer, controls: layer.controls.map((control) => ({ ...control })) }));
}

function managedPermissionState(effective: EffectiveExtensionControls, permissionId: string): "enabled" | "disabled" | null {
  const projected = effective.projection?.permissions.find((item) => item.permission_id === permissionId)?.managed_state;
  if (projected && projected !== "inherited") return projected;
  for (const layer of effective.layers) {
    if (layer.kind !== "signed-cloud") continue;
    const control = layer.controls.find((item) => item.target_kind === "permission" && item.target_id === permissionId);
    if (control) return control.state;
  }
  return null;
}

export function extensionPolicyRadioTabStop(
  choices: Array<{ value: PermissionDraftState; disabled?: boolean }>,
  state: PermissionDraftState,
  groupDisabled: boolean,
): number {
  if (groupDisabled) return -1;
  const selected = choices.findIndex((choice) => choice.value === state && !choice.disabled);
  return selected >= 0 ? selected : choices.findIndex((choice) => !choice.disabled);
}

export function nextExtensionPolicyRadioIndex(
  choices: Array<{ disabled?: boolean }>,
  index: number,
  key: string,
  groupDisabled: boolean,
): number {
  if (groupDisabled || !["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(key)) return -1;
  const direction = key === "ArrowLeft" || key === "ArrowUp" ? -1 : 1;
  for (let offset = 1; offset <= choices.length; offset += 1) {
    const next = (index + direction * offset + choices.length) % choices.length;
    if (!choices[next]?.disabled) return next;
  }
  return -1;
}

export function isCurrentExtensionPolicyDraft(generation: number, current: number): boolean {
  return generation === current;
}

function draftChangeCount(effective: EffectiveExtensionControls, extension: ExtensionCatalogItem, draftLayers: EffectiveExtensionControls["layers"]): number {
  return extension.permissions.filter((permission) =>
    localPermissionDraftState(effective.layers, permission.permission_id) !== localPermissionDraftState(draftLayers, permission.permission_id),
  ).length;
}

function DraftControl(props: {
  permission: ExtensionPermission;
  effective: EffectiveExtensionControls;
  state: PermissionDraftState;
  disabled: boolean;
  onChange: (state: PermissionDraftState) => void;
}) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const choices: Array<{ value: PermissionDraftState; label: string; disabled?: boolean }> = [
    { value: "inherit", label: "Recommended" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" },
  ];
  const tabStopIndex = extensionPolicyRadioTabStop(choices, props.state, props.disabled);
  const chooseAdjacent = (event: React.KeyboardEvent<HTMLButtonElement>, index: number) => {
    const next = nextExtensionPolicyRadioIndex(choices, index, event.key, props.disabled);
    if (next < 0) return;
    event.preventDefault();
    props.onChange(choices[next]!.value);
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>('[role="radio"]')[next]?.focus();
  };
  return (
    <div role="radiogroup" aria-label={`${props.permission.label} protection setting`} className="guard-segmented">
      {choices.map((choice, index) => (
        <button
          key={choice.value}
          type="button"
          role="radio"
          aria-checked={props.state === choice.value}
          tabIndex={!props.disabled && index === tabStopIndex ? 0 : -1}
          disabled={props.disabled || choice.disabled}
          title={choice.disabled ? "Your organization already blocks this capability; this device cannot weaken it." : undefined}
          onKeyDown={(event) => chooseAdjacent(event, index)}
          onClick={() => props.onChange(choice.value)}
          className="disabled:cursor-not-allowed disabled:opacity-45"
        >
          {choice.label}
        </button>
      ))}
    </div>
  );
}

function PermissionPolicyRow(props: {
  permission: ExtensionPermission;
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  draftState: PermissionDraftState;
  disabled: boolean;
  onChange: (state: PermissionDraftState) => void;
}) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const provenance = controlProvenance(props.effective, "permission", props.permission.permission_id);
  const example = props.permission.example_command ?? (props.extension.executables[0]?.trim() || props.permission.label);
  return (
    <article className="guard-pattern-row" data-permission-id={props.permission.permission_id}>
      <div className="min-w-0">
        <h3 className="text-sm font-semibold text-brand-dark">{props.permission.label}</h3>
        <p className="guard-pattern-example mt-1">{example}</p>
        {!props.permission.configurable ? (
          <p className="mt-2 text-xs leading-5 text-brand-dark">
            Why this cannot be changed: {props.permission.fixed_reason ?? "Guard marks this safety permission as immutable."}
          </p>
        ) : null}
        {managed === "disabled" ? (
          <p className="mt-2 flex items-start gap-2 text-xs leading-5 text-indigo-950">
            <HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />
            Your organization blocks this capability. You can keep the organization setting or add a local block, but this device cannot weaken it.
          </p>
        ) : null}
        <details className="mt-2 text-xs text-brand-dark">
          <summary className="cursor-pointer font-semibold">Technical setting details</summary>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1">
            <span>Minimum protection: <strong>{treatmentLabel(props.permission.baseline_floor)}</strong></span>
            <span>{props.permission.rule_ids.length} governed rule{props.permission.rule_ids.length === 1 ? "" : "s"}</span>
            <span>Managed by: {provenance.join(" · ")}</span>
          </div>
          <code className="mt-2 block break-all text-[11px] text-brand-dark/80">{props.permission.permission_id}</code>
        </details>
      </div>
      <DraftControl
        permission={props.permission}
        effective={props.effective}
        state={props.draftState}
        disabled={props.disabled || !props.permission.configurable || props.effective.health !== "protected"}
        onChange={props.onChange}
      />
    </article>
  );
}

function PreviewPanel(props: { preview: ExtensionMutationPreview }) {
  const semantic = props.preview.semantic_preview;
  return (
    <div>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Protection review</p>
          <h3 className="mt-1 text-lg font-semibold text-brand-dark">What will change</h3>
        </div>
        <div className="flex flex-wrap gap-2">
          <Pill>{semantic.changed_target_count} target{semantic.changed_target_count === 1 ? "" : "s"}</Pill>
          <Pill>{semantic.affected_permission_count} permissions</Pill>
          <Pill>{semantic.affected_rule_count} rules</Pill>
        </div>
      </div>
      <dl className="mt-4 grid gap-3 sm:grid-cols-3">
        <div>
          <dt className="text-xs text-brand-dark/80">Newly blocked settings</dt>
          <dd className="mt-1 text-2xl font-semibold text-brand-dark">{semantic.summary.newly_blocked_permissions}</dd>
        </div>
        <div>
          <dt className="text-xs text-brand-dark/80">Newly allowed settings</dt>
          <dd className="mt-1 text-2xl font-semibold text-brand-dark">{semantic.summary.newly_allowed_permissions}</dd>
        </div>
        <div>
          <dt className="text-xs text-brand-dark/80">Settings changing</dt>
          <dd className="mt-1 text-2xl font-semibold text-brand-dark">{semantic.summary.effective_change_count}</dd>
        </div>
      </dl>
      <div className="mt-4 space-y-3">
        {semantic.changed_targets.map((target) => (
          <article key={`${target.target.kind}:${target.target.target_id}`} className="border-b border-[rgba(63,65,116,0.12)] py-3">
            <div className="flex flex-wrap items-center gap-2">
              <strong className="text-sm text-brand-dark">{target.label}</strong>
              <Pill>{target.before_explicit} → {target.after_explicit}</Pill>
              <Pill>{target.before_effective} → {target.after_effective}</Pill>
              {target.baseline_risk ? <Pill tone={RISK_TONE[target.baseline_risk]}>{target.baseline_risk} baseline</Pill> : null}
            </div>
            <div className="mt-2 text-xs text-brand-dark/80">
              Affects {target.affected_permission_ids.length} permission{target.affected_permission_ids.length === 1 ? "" : "s"} and {target.affected_rule_ids.length} rule{target.affected_rule_ids.length === 1 ? "" : "s"}.
            </div>
            {target.affected_rule_ids.length ? (
              <details className="mt-3">
                <summary className="cursor-pointer text-xs font-semibold text-brand-blue">Developer details</summary>
                <div className="mt-2 max-h-40 overflow-auto">
                  {target.affected_rule_ids.map((id) => <code key={id} className="block break-all text-[11px] text-brand-dark/80">{id}</code>)}
                </div>
              </details>
            ) : null}
            {target.warnings.map((warning, index) => (
              <p key={`${warning.code}-${index}`} className="mt-3 flex items-start gap-2 text-xs leading-5 text-amber-950">
                <HiMiniExclamationTriangle className="mt-0.5 size-4 shrink-0" />
                <span><strong>{warning.code}:</strong> {warning.message}</span>
              </p>
            ))}
          </article>
        ))}
      </div>
      <details className="mt-4">
        <summary className="cursor-pointer text-xs font-semibold text-brand-dark/80">Developer change identity</summary>
        <code className="mt-2 block break-all text-[11px] text-brand-dark/80">{props.preview.canonical_diff_digest}</code>
      </details>
    </div>
  );
}

function ReviewDrawer(props: { preview: ExtensionMutationPreview; busy: boolean; onClose: () => void; onApply: () => void }) {
  const ref = useModalDialog<HTMLElement>(props.onClose, !props.busy);
  const count = props.preview.semantic_preview.changed_target_count;
  return (
    <div className="fixed inset-0 z-50 bg-brand-dark/40">
      <aside
        ref={ref}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby="extension-policy-review-title"
        className="absolute inset-y-0 right-0 w-full max-w-2xl overflow-y-auto bg-[var(--surface-1)] p-5 focus:outline-none sm:p-6"
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Protection review</p>
            <h2 id="extension-policy-review-title" className="mt-1 text-xl font-semibold text-brand-dark">
              Review {count} protection setting change{count === 1 ? "" : "s"}
            </h2>
          </div>
          <button type="button" disabled={props.busy} aria-label="Close semantic review" onClick={props.onClose} className="grid size-11 place-items-center rounded-full text-brand-dark disabled:opacity-50">
            <HiMiniXMark className="size-5" />
          </button>
        </div>
        <div className="mt-5"><PreviewPanel preview={props.preview} /></div>
        <div className="sticky bottom-0 mt-6 flex flex-wrap justify-end gap-2 border-t border-[rgba(63,65,116,0.12)] bg-[var(--surface-1)] pt-4">
          <button type="button" disabled={props.busy} onClick={props.onClose} className="min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark">Continue editing</button>
          <button type="button" disabled={props.busy || count === 0} onClick={props.onApply} className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40">Continue to approval</button>
        </div>
      </aside>
    </div>
  );
}

type PendingRebase = {
  result: ExtensionPolicyRebaseResult;
  latestEffective: EffectiveExtensionControls;
  latestExtension: ExtensionCatalogItem;
};

export function ExtensionPolicyPanel(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
  onRefresh: () => Promise<void> | void;
  onDirtyChange?: (dirty: boolean) => void;
}) {
  const [baseEffective, setBaseEffective] = useState(props.effective);
  const [policyExtension, setPolicyExtension] = useState(props.extension);
  const [draftLayers, setDraftLayers] = useState(() => cloneLayers(props.effective));
  const [identity, setIdentity] = useState(() => newExtensionPolicyDraftIdentity());
  const [preview, setPreview] = useState<ExtensionMutationPreview | null>(null);
  const [previewBusy, setPreviewBusy] = useState(false);
  const [applyBusy, setApplyBusy] = useState(false);
  const [approvalOpen, setApprovalOpen] = useState(false);
  const [reviewOpen, setReviewOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [stale, setStale] = useState(false);
  const [pendingRebase, setPendingRebase] = useState<PendingRebase | null>(null);
  const [refreshRequired, setRefreshRequired] = useState(false);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const draftGeneration = useRef(0);
  const { onDirtyChange, onRefresh } = props;
  const dirty = useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);
  const changeCount = useMemo(() => draftChangeCount(baseEffective, policyExtension, draftLayers), [baseEffective, draftLayers, policyExtension]);

  useEffect(() => { onDirtyChange?.(dirty); }, [dirty, onDirtyChange]);
  useEffect(() => {
    const beforeUnload = (event: BeforeUnloadEvent) => {
      if (!dirty) return;
      event.preventDefault();
      event.returnValue = "";
    };
    window.addEventListener("beforeunload", beforeUnload);
    return () => window.removeEventListener("beforeunload", beforeUnload);
  }, [dirty]);
  useEffect(() => {
    draftGeneration.current += 1;
    setBaseEffective(props.effective);
    setPolicyExtension(props.extension);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setRefreshRequired(false);
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest, props.extension.extension_id]);

  const resetDraft = useCallback(() => {
    draftGeneration.current += 1;
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [baseEffective]);

  const setPermission = useCallback((permission: ExtensionPermission, state: PermissionDraftState) => {
    if (!permission.configurable) return;
    draftGeneration.current += 1;
    setDraftLayers((current) => setLocalPermissionDraftState(current, baseEffective.catalog_digest, permission.permission_id, state));
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [baseEffective.catalog_digest]);

  const mutation = useCallback(() => buildExtensionPolicyDraftMutation(baseEffective, baseEffective.catalog_digest, draftLayers, identity), [baseEffective, draftLayers, identity]);

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
    setPreviewBusy(true); setError(null); setStale(false);
    try {
      const next = await previewExtensionMutation(mutation());
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) return;
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) handleApiError(caught, "Guard could not preview this draft.");
    }
    finally { setPreviewBusy(false); }
  }, [dirty, handleApiError, mutation]);

  const openApproval = useCallback(async () => {
    if (!preview || !dirty || stale) return;
    try {
      await resolveApprovalGate({ failClosed: true });
      setReviewOpen(false);
      setApprovalOpen(true);
      setError(null);
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Guard could not load the local approval gate."); }
  }, [dirty, preview, resolveApprovalGate, stale]);

  const apply = useCallback(async (credentials: { approval_password?: string; approval_totp_code?: string }) => {
    if (!preview || !dirty || stale) return;
    setApplyBusy(true); setError(null);
    try {
      const base = mutation();
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
      draftGeneration.current += 1;
      setDraftLayers(cloneLayers(baseEffective));
      setIdentity(newExtensionPolicyDraftIdentity());
      setRefreshRequired(true);
      try {
        await onRefresh();
      } catch {
        setError("The policy was applied, but Guard could not refresh the latest state. Refresh this page to confirm the committed policy.");
      }
    } catch (caught) { handleApiError(caught, "Guard could not apply this draft."); }
    finally { setApplyBusy(false); }
  }, [baseEffective.revision, dirty, handleApiError, mutation, onRefresh, preview, stale]);

  const rebaseDraft = useCallback(async () => {
    const generation = draftGeneration.current;
    setPreviewBusy(true); setError(null);
    try {
      const [latestCatalog, latestEffective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      const exactExtension = latestCatalog.extensions.find((item) => item.extension_id === policyExtension.extension_id);
      const aliasMatches = latestCatalog.extensions.filter((item) => item.aliases.includes(policyExtension.extension_id));
      const latestExtension = exactExtension ?? (aliasMatches.length === 1 ? aliasMatches[0] : undefined);
      if (!latestExtension) {
        setError("This extension no longer exists in the authoritative catalog. Discard the draft and refresh before continuing.");
        return;
      }
      if (!isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError("The draft changed while Guard was loading current policy. Rebase again to preserve the latest edits.");
        return;
      }
      const result = rebaseExtensionPolicyDraft(baseEffective, latestEffective, policyExtension, latestExtension, draftLayers);
      setBaseEffective(latestEffective);
      setPolicyExtension(latestExtension);
      setIdentity(newExtensionPolicyDraftIdentity());
      setPreview(null); setReviewOpen(false);
      if (result.conflicts.length) {
        setPendingRebase({ result, latestEffective, latestExtension });
        setDraftLayers(result.draft_layers);
        setStale(true);
        setError("The latest policy overlaps this draft. Choose whether to keep your overlapping changes or use current authoritative values. Removed permissions cannot be restored.");
      } else {
        setDraftLayers(result.draft_layers);
        setPendingRebase(null); setStale(false); setError(null);
      }
    } catch (caught) {
      if (isCurrentExtensionPolicyDraft(generation, draftGeneration.current)) {
        setError(caught instanceof Error ? caught.message : "Guard could not rebase this draft.");
      }
    }
    finally { setPreviewBusy(false); }
  }, [baseEffective, draftLayers, policyExtension]);

  const keepConflicts = useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(keepExtensionPolicyRebaseConflicts(pendingRebase.result, pendingRebase.latestEffective));
    setPendingRebase(null); setStale(false); setError(null); setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);
  const useCurrent = useCallback(() => {
    if (!pendingRebase) return;
    setDraftLayers(cloneLayers(pendingRebase.latestEffective));
    setPendingRebase(null); setStale(false); setError(null); setPreview(null); setIdentity(newExtensionPolicyDraftIdentity());
  }, [pendingRebase]);

  const applyProfile = useCallback((profile: "recommended" | "stricter" | "custom") => {
    if (profile === "custom") return;
    draftGeneration.current += 1;
    let next = cloneLayers(baseEffective);
    for (const permission of policyExtension.permissions) {
      if (!permission.configurable) continue;
      const state: PermissionDraftState = profile === "recommended" ? "inherit" : "block";
      next = setLocalPermissionDraftState(next, baseEffective.catalog_digest, permission.permission_id, state);
    }
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [baseEffective, policyExtension]);

  const useHistoricalDraft = useCallback((historicalLayers: EffectiveExtensionControls["layers"], _revision: number) => {
    draftGeneration.current += 1;
    const historicalLocal = historicalLayers.find((layer) => layer.kind === "local-admin");
    const next = baseEffective.layers.flatMap((layer) => layer.kind === "local-admin" ? (historicalLocal ? [historicalLocal] : []) : [layer]);
    if (historicalLocal && !baseEffective.layers.some((layer) => layer.kind === "local-admin")) next.push(historicalLocal);
    setDraftLayers(next);
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [baseEffective.layers]);

  const managedCount = policyExtension.permissions.filter((permission) => managedPermissionState(baseEffective, permission.permission_id) !== null).length;
  const confirmationCount = preview?.semantic_preview.changed_target_count ?? changeCount;
  return (
    <section id="extension-policy-editor" aria-labelledby="extension-policy-heading">
      <h2 id="extension-policy-heading" className="text-lg font-semibold text-brand-dark">Protection settings</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/80">
        Recommended follows Guard defaults. Allow is available only where built-in safety and organization policy still permit it. Block is a stricter local floor.
      </p>
      <div className="mt-4 flex flex-wrap gap-2">
        <button type="button" disabled={baseEffective.health !== "protected" || refreshRequired} onClick={() => applyProfile("recommended")} className="min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40">Recommended</button>
        <button type="button" disabled={baseEffective.health !== "protected" || refreshRequired} onClick={() => applyProfile("stricter")} className="min-h-10 px-1 text-xs font-semibold text-brand-dark disabled:opacity-40">Stricter</button>
        <button type="button" disabled className="min-h-10 px-1 text-xs font-semibold text-brand-dark/55">Custom</button>
      </div>
      <ProtectionSettingsHistory catalogDigest={baseEffective.catalog_digest} disabled={baseEffective.health !== "protected" || refreshRequired} onUse={useHistoricalDraft} />
      {baseEffective.global_lockdown ? (
        <p role="status" className="mt-4 flex gap-2 text-sm text-brand-dark">
          <HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />
          Emergency Lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active.
        </p>
      ) : null}
      {baseEffective.health !== "protected" ? (
        <p role="alert" className="mt-4 flex gap-2 text-sm text-amber-950">
          <HiMiniExclamationTriangle className="mt-0.5 size-4 shrink-0" />
          Settings cannot be changed until Guard verifies local settings integrity.
        </p>
      ) : null}
      {managedCount ? (
        <p className="mt-4 text-sm text-indigo-950">
          {managedCount} setting{managedCount === 1 ? " is" : "s are"} managed by your organization. This device can add stricter blocks but cannot weaken an organization block.
        </p>
      ) : null}

      {refreshRequired ? (
        <div role="status" className="mt-4 text-sm text-blue-950">Settings applied. Editing stays locked until Guard reloads the current protected state.</div>
      ) : null}

      <div className="mt-4">
        {(() => {
          const { ungrouped, families } = groupPermissionsByFamily(policyExtension.permissions);
          const renderRow = (permission: ExtensionPermission) => (
            <PermissionPolicyRow
              key={permission.permission_id}
              permission={permission}
              extension={policyExtension}
              effective={baseEffective}
              draftState={localPermissionDraftState(draftLayers, permission.permission_id)}
              disabled={refreshRequired}
              onChange={(state) => setPermission(permission, state)}
            />
          );
          return (
            <>
              {ungrouped.map(renderRow)}
              {families.map((group) => (
                <section key={group.family} aria-label={`${group.heading} variants`} className="guard-pattern-family">
                  <h3 className="guard-pattern-family-heading">
                    <code>{group.heading}</code>
                    <span>{group.permissions.length} variant{group.permissions.length === 1 ? "" : "s"}</span>
                  </h3>
                  {group.permissions.map(renderRow)}
                </section>
              ))}
            </>
          );
        })()}
      </div>

      {dirty ? (
        <div className="guard-review-bar">
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
            <div className="text-sm text-brand-dark">{changeCount} unsaved setting change{changeCount === 1 ? "" : "s"}.</div>
            <div className="flex flex-wrap gap-2">
              <button type="button" disabled={previewBusy || applyBusy} onClick={resetDraft} className="min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark">Reset changes</button>
              <button type="button" disabled={previewBusy || applyBusy || baseEffective.health !== "protected" || stale} onClick={() => { void runPreview(); }} className="inline-flex min-h-11 items-center gap-2 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40">
                {previewBusy ? <HiMiniArrowPath className="size-4 animate-spin motion-reduce:animate-none" /> : <HiMiniShieldCheck className="size-4" />}
                Review {changeCount} change{changeCount === 1 ? "" : "s"}
              </button>
            </div>
          </div>
        </div>
      ) : null}

      {error ? (
        <div role="alert" className="mt-4 text-sm text-red-950">
          <div className="flex items-start gap-2">
            <HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0" />
            <span>{error}</span>
          </div>
          {stale && !pendingRebase ? (
            <button type="button" disabled={previewBusy} onClick={() => { void rebaseDraft(); }} className="mt-3 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]">Update draft with latest protection</button>
          ) : null}
          {pendingRebase ? (
            <div className="mt-4">
              <ul className="space-y-2">
                {pendingRebase.result.conflicts.map((conflict: ExtensionPolicyRebaseConflict) => (
                  <li key={conflict.original_permission_id} className="text-xs text-brand-dark">
                    <code className="break-all">{conflict.original_permission_id}</code>
                    <div className="mt-1">{conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.`}</div>
                  </li>
                ))}
              </ul>
              <div className="mt-3 flex flex-wrap gap-2">
                <button type="button" onClick={keepConflicts} className="min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]">Keep my compatible changes</button>
                <button type="button" onClick={useCurrent} className="min-h-11 rounded-xl border border-red-300 px-4 text-sm font-semibold text-red-950">Use current protection</button>
              </div>
            </div>
          ) : null}
        </div>
      ) : dirty && !preview ? (
        <div className="mt-4 flex items-start gap-3 text-sm text-brand-dark">
          <HiMiniInformationCircle className="mt-0.5 size-5 shrink-0" />
          <p>Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change.</p>
        </div>
      ) : null}

      {reviewOpen && preview ? <ReviewDrawer preview={preview} busy={previewBusy || applyBusy} onClose={() => setReviewOpen(false)} onApply={() => { void openApproval(); }} /> : null}
      {approvalOpen && preview ? (
        <ApprovalProofModal
          title={`Apply ${confirmationCount} protection setting change${confirmationCount === 1 ? "" : "s"}`}
          detail="Authenticate the exact settings you just reviewed. Guard uses a one-time local proof and rejects the apply if the reviewed settings changed."
          confirmLabel={`Apply ${confirmationCount} reviewed change${confirmationCount === 1 ? "" : "s"}`}
          approvalGate={resolvedApprovalGate}
          busy={applyBusy}
          error={error}
          onCancel={() => { if (!applyBusy) setApprovalOpen(false); }}
          onConfirm={(credentials) => { void apply(credentials); }}
        />
      ) : null}
    </section>
  );
}
