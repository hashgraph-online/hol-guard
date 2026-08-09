import { useCallback, useEffect, useMemo, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniCheckCircle,
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
import { controlProvenance, permissionStateLabel, treatmentLabel } from "./extension-control-center-model";
import { useModalDialog } from "./use-modal-dialog";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";

const RISK_TONE: Record<string, string> = {
  critical: "border-red-200 bg-red-50 text-red-800",
  high: "border-orange-200 bg-orange-50 text-orange-800",
  medium: "border-amber-200 bg-amber-50 text-amber-800",
  low: "border-slate-200 bg-slate-50 text-slate-700",
};

function Pill(props: { children: React.ReactNode; tone?: string }) {
  return <span className={`inline-flex rounded-full border px-2.5 py-1 text-xs font-semibold ${props.tone ?? "border-slate-200 bg-slate-50 text-slate-700"}`}>{props.children}</span>;
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
    { value: "inherit", label: "Inherit" },
    { value: "allow", label: "Allow", disabled: managed === "disabled" },
    { value: "block", label: "Block" },
  ];
  return <div role="radiogroup" aria-label={`${props.permission.label} local policy`} className="flex flex-wrap gap-1 rounded-xl bg-slate-100 p-1">{choices.map((choice) => <button key={choice.value} type="button" role="radio" aria-checked={props.state === choice.value} disabled={props.disabled || choice.disabled} title={choice.disabled ? "Managed policy already blocks this permission; local policy cannot weaken it." : undefined} onClick={() => props.onChange(choice.value)} className={`min-h-10 rounded-lg px-3 text-xs font-semibold transition motion-reduce:transition-none ${props.state === choice.value ? "bg-white text-brand-blue shadow-sm" : "text-slate-600 hover:bg-white/70"} disabled:cursor-not-allowed disabled:opacity-45`}>{choice.label}</button>)}</div>;
}

function PermissionPolicyRow(props: {
  permission: ExtensionPermission;
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  draftState: PermissionDraftState;
  onChange: (state: PermissionDraftState) => void;
}) {
  const managed = managedPermissionState(props.effective, props.permission.permission_id);
  const provenance = controlProvenance(props.effective, "permission", props.permission.permission_id);
  return <article className="rounded-2xl border border-slate-200 bg-white p-4" data-permission-id={props.permission.permission_id}><div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div className="min-w-0 flex-1"><div className="flex flex-wrap items-center gap-2"><h3 className="font-semibold text-slate-950">{props.permission.label}</h3><Pill tone={RISK_TONE[props.permission.risk_tier]}>{props.permission.risk_tier} baseline risk</Pill><Pill>{permissionStateLabel(props.effective, props.extension, props.permission)}</Pill>{!props.permission.configurable ? <Pill>Fixed</Pill> : null}{managed ? <Pill tone="border-indigo-200 bg-indigo-50 text-indigo-800">Managed {managed === "disabled" ? "block" : "allow"}</Pill> : null}</div><p className="mt-2 text-sm leading-6 text-slate-600">{props.permission.description}</p><div className="mt-3 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate-500"><span>Baseline floor: <strong className="text-slate-700">{treatmentLabel(props.permission.baseline_floor)}</strong></span><span>{props.permission.rule_ids.length} governed rule{props.permission.rule_ids.length === 1 ? "" : "s"}</span><span>Provenance: {provenance.join(" · ")}</span></div><code className="mt-2 block break-all text-[11px] text-slate-400">{props.permission.permission_id}</code>{!props.permission.configurable ? <p className="mt-3 rounded-xl bg-slate-50 p-3 text-xs leading-5 text-slate-600"><strong>Why fixed:</strong> {props.permission.fixed_reason ?? "Guard marks this safety permission as immutable."}</p> : null}{managed === "disabled" ? <p className="mt-3 flex items-start gap-2 rounded-xl border border-indigo-200 bg-indigo-50 p-3 text-xs leading-5 text-indigo-900"><HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />Managed policy blocks this permission. Local policy may inherit or add a block, but it cannot weaken the managed block.</p> : null}</div><DraftControl permission={props.permission} effective={props.effective} state={props.draftState} disabled={!props.permission.configurable || props.effective.health !== "protected"} onChange={props.onChange} /></div></article>;
}

function PreviewPanel(props: { preview: ExtensionMutationPreview }) {
  const semantic = props.preview.semantic_preview;
  return <div><div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Server semantic preview</p><h3 className="mt-1 text-lg font-semibold text-slate-950">Blast radius before apply</h3></div><div className="flex flex-wrap gap-2"><Pill>{semantic.changed_target_count} target{semantic.changed_target_count === 1 ? "" : "s"}</Pill><Pill>{semantic.affected_permission_count} permissions</Pill><Pill>{semantic.affected_rule_count} rules</Pill></div></div><div className="mt-4 grid gap-3 sm:grid-cols-3"><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{semantic.summary.newly_blocked_permissions}</div><div className="text-xs text-slate-500">Newly blocked permissions</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{semantic.summary.newly_allowed_permissions}</div><div className="text-xs text-slate-500">Newly allowed permissions</div></div><div className="rounded-2xl bg-slate-50 p-4"><div className="text-2xl font-semibold text-slate-950">{semantic.summary.effective_change_count}</div><div className="text-xs text-slate-500">Effective changes</div></div></div><div className="mt-4 space-y-3">{semantic.changed_targets.map((target) => <article key={`${target.target.kind}:${target.target.target_id}`} className="rounded-2xl border border-slate-200 p-4"><div className="flex flex-wrap items-center gap-2"><strong className="text-sm text-slate-950">{target.label}</strong><Pill>{target.before_explicit} → {target.after_explicit}</Pill><Pill>{target.before_effective} → {target.after_effective}</Pill>{target.baseline_risk ? <Pill tone={RISK_TONE[target.baseline_risk]}>{target.baseline_risk} baseline</Pill> : null}</div><div className="mt-2 text-xs text-slate-500">Affects {target.affected_permission_ids.length} permission{target.affected_permission_ids.length === 1 ? "" : "s"} and {target.affected_rule_ids.length} rule{target.affected_rule_ids.length === 1 ? "" : "s"}.</div>{target.affected_rule_ids.length ? <details className="mt-3"><summary className="cursor-pointer text-xs font-semibold text-brand-blue">Affected rule IDs</summary><div className="mt-2 max-h-40 overflow-auto rounded-xl bg-slate-50 p-3">{target.affected_rule_ids.map((id) => <code key={id} className="block break-all text-[11px] text-slate-600">{id}</code>)}</div></details> : null}{target.warnings.map((warning, index) => <p key={`${warning.code}-${index}`} className="mt-3 flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-xs leading-5 text-amber-900"><HiMiniExclamationTriangle className="mt-0.5 size-4 shrink-0" /><span><strong>{warning.code}:</strong> {warning.message}</span></p>)}</article>)}</div><p className="mt-4 break-all text-[11px] text-slate-400">Canonical diff: {props.preview.canonical_diff_digest}</p></div>;
}

function ReviewDrawer(props: { preview: ExtensionMutationPreview; busy: boolean; onClose: () => void; onApply: () => void }) {
  const ref = useModalDialog<HTMLElement>(props.onClose, !props.busy);
  const count = props.preview.semantic_preview.changed_target_count;
  return <div className="fixed inset-0 z-50 bg-slate-950/40"><aside ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby="extension-policy-review-title" className="absolute inset-y-0 right-0 w-full max-w-2xl overflow-y-auto bg-white p-5 shadow-2xl focus:outline-none sm:p-6"><div className="flex items-start justify-between gap-4"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Semantic review</p><h2 id="extension-policy-review-title" className="mt-1 text-xl font-semibold text-slate-950">Review {count} permission change{count === 1 ? "" : "s"}</h2></div><button type="button" disabled={props.busy} aria-label="Close semantic review" onClick={props.onClose} className="grid size-11 place-items-center rounded-full text-slate-500 hover:bg-slate-100 disabled:opacity-50"><HiMiniXMark className="size-5" /></button></div><div className="mt-5"><PreviewPanel preview={props.preview} /></div><div className="sticky bottom-0 mt-6 flex flex-wrap justify-end gap-2 border-t border-slate-200 bg-white pt-4"><button type="button" disabled={props.busy} onClick={props.onClose} className="min-h-11 rounded-xl border border-slate-300 px-4 text-sm font-semibold text-slate-700">Continue editing</button><button type="button" disabled={props.busy || count === 0} onClick={props.onApply} className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-white disabled:opacity-40">Apply {count} reviewed change{count === 1 ? "" : "s"}</button></div></aside></div>;
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
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const dirty = useMemo(() => extensionPolicyDraftIsDirty(baseEffective, draftLayers), [baseEffective, draftLayers]);
  const changeCount = useMemo(() => draftChangeCount(baseEffective, policyExtension, draftLayers), [baseEffective, draftLayers, policyExtension]);

  useEffect(() => { props.onDirtyChange?.(dirty); }, [dirty, props]);
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
    setBaseEffective(props.effective);
    setPolicyExtension(props.extension);
    setDraftLayers(cloneLayers(props.effective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [props.effective.revision, props.effective.catalog_digest, props.extension.extension_id]);

  const resetDraft = useCallback(() => {
    setDraftLayers(cloneLayers(baseEffective));
    setIdentity(newExtensionPolicyDraftIdentity());
    setPreview(null); setReviewOpen(false); setError(null); setStale(false); setPendingRebase(null);
  }, [baseEffective]);

  const setPermission = useCallback((permission: ExtensionPermission, state: PermissionDraftState) => {
    if (!permission.configurable) return;
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
    setPreviewBusy(true); setError(null); setStale(false);
    try {
      const next = await previewExtensionMutation(mutation());
      setPreview(next);
      setReviewOpen(true);
    } catch (caught) { handleApiError(caught, "Guard could not preview this draft."); }
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
      await props.onRefresh();
    } catch (caught) { handleApiError(caught, "Guard could not apply this draft."); }
    finally { setApplyBusy(false); }
  }, [baseEffective.revision, dirty, handleApiError, mutation, preview, props, stale]);

  const rebaseDraft = useCallback(async () => {
    setPreviewBusy(true); setError(null);
    try {
      const [latestCatalog, latestEffective] = await Promise.all([fetchExtensionCatalog(), fetchEffectiveExtensionControls()]);
      const latestExtension = latestCatalog.extensions.find((item) => item.extension_id === policyExtension.extension_id)
        ?? latestCatalog.extensions.find((item) => item.aliases.includes(policyExtension.extension_id));
      if (!latestExtension) {
        setError("This extension no longer exists in the authoritative catalog. Discard the draft and refresh before continuing.");
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
    } catch (caught) { setError(caught instanceof Error ? caught.message : "Guard could not rebase this draft."); }
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

  const configurableCount = policyExtension.permissions.filter((permission) => permission.configurable).length;
  const managedCount = policyExtension.permissions.filter((permission) => managedPermissionState(baseEffective, permission.permission_id) !== null).length;
  const confirmationCount = preview?.semantic_preview.changed_target_count ?? changeCount;
  return <section id="extension-policy-editor" aria-labelledby="extension-policy-heading" className="space-y-5"><div className="rounded-3xl border border-slate-200 bg-white p-5 sm:p-6"><div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div><p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Local policy draft</p><h2 id="extension-policy-heading" className="mt-1 text-lg font-semibold text-slate-950">Permission controls</h2><p className="mt-2 max-w-3xl text-sm leading-6 text-slate-600">Choose Inherit, Allow, or Block for independently configurable capabilities. A blocked capability makes Guard block matching actions; it does not turn detection off. Detector severity and baseline floors never change.</p></div><div className="flex flex-wrap gap-2"><Pill>{configurableCount} configurable</Pill><Pill>{policyExtension.permissions.length - configurableCount} fixed</Pill>{dirty ? <Pill tone="border-blue-200 bg-blue-50 text-blue-800">{changeCount} staged</Pill> : <Pill>Authoritative</Pill>}</div></div>{baseEffective.global_lockdown ? <p role="status" className="mt-4 flex gap-2 rounded-xl bg-slate-950 p-3 text-sm text-white"><HiMiniLockClosed className="mt-0.5 size-4 shrink-0" />Global lockdown remains dominant. You can prepare a local draft, but matching commands stay blocked while lockdown is active.</p> : null}{baseEffective.health !== "protected" ? <p role="alert" className="mt-4 flex gap-2 rounded-xl border border-amber-200 bg-amber-50 p-3 text-sm text-amber-900"><HiMiniExclamationTriangle className="mt-0.5 size-4 shrink-0" />Permission editing is disabled until extension-control authority is protected.</p> : null}{managedCount ? <p className="mt-4 rounded-xl border border-indigo-200 bg-indigo-50 p-3 text-sm text-indigo-900">{managedCount} permission{managedCount === 1 ? " is" : "s are"} governed by signed organization policy. Local policy cannot weaken a managed block. Managed exception requests must be made through the organization policy workflow.</p> : null}</div>

    <div className="space-y-3">{policyExtension.permissions.map((permission) => <PermissionPolicyRow key={permission.permission_id} permission={permission} extension={policyExtension} effective={baseEffective} draftState={localPermissionDraftState(draftLayers, permission.permission_id)} onChange={(state) => setPermission(permission, state)} />)}</div>

    <div className="sticky bottom-4 z-20 rounded-2xl border border-slate-200 bg-white/95 p-4 shadow-xl backdrop-blur supports-[backdrop-filter]:bg-white/85"><div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between"><div className="text-sm text-slate-600">{dirty ? `${changeCount} staged permission change${changeCount === 1 ? "" : "s"}.` : "No local policy changes drafted."}</div><div className="flex flex-wrap gap-2"><button type="button" disabled={!dirty || previewBusy || applyBusy} onClick={resetDraft} className="min-h-11 rounded-xl border border-slate-300 bg-white px-4 text-sm font-semibold text-slate-700 disabled:opacity-40">Discard draft</button><button type="button" disabled={!dirty || previewBusy || applyBusy || baseEffective.health !== "protected" || stale} onClick={() => { void runPreview(); }} className="inline-flex min-h-11 items-center gap-2 rounded-xl border border-brand-blue/30 bg-blue-50 px-4 text-sm font-semibold text-brand-blue disabled:opacity-40">{previewBusy ? <HiMiniArrowPath className="size-4 animate-spin motion-reduce:animate-none" /> : <HiMiniShieldCheck className="size-4" />}Review {changeCount} change{changeCount === 1 ? "" : "s"}</button></div></div></div>

    {error ? <div role="alert" className="rounded-2xl border border-red-200 bg-red-50 p-4 text-sm text-red-800"><div className="flex items-start gap-2"><HiMiniExclamationTriangle className="mt-0.5 size-5 shrink-0" /><span>{error}</span></div>{stale && !pendingRebase ? <button type="button" disabled={previewBusy} onClick={() => { void rebaseDraft(); }} className="mt-3 min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white">Rebase draft onto current policy</button> : null}{pendingRebase ? <div className="mt-4"><ul className="space-y-2">{pendingRebase.result.conflicts.map((conflict: ExtensionPolicyRebaseConflict) => <li key={conflict.original_permission_id} className="rounded-xl bg-white p-3 text-xs"><code className="break-all">{conflict.original_permission_id}</code><div className="mt-1">{conflict.kind === "removed" ? "Target removed from the current catalog." : `Current ${conflict.latest_state}; your draft requests ${conflict.requested_state}.`}</div></li>)}</ul><div className="mt-3 flex flex-wrap gap-2"><button type="button" onClick={keepConflicts} className="min-h-11 rounded-xl bg-red-700 px-4 text-sm font-semibold text-white">Keep my remaining draft changes</button><button type="button" onClick={useCurrent} className="min-h-11 rounded-xl border border-red-300 bg-white px-4 text-sm font-semibold text-red-800">Use current policy</button></div></div> : null}</div> : dirty && !preview ? <div className="flex items-start gap-3 rounded-2xl border border-slate-200 bg-slate-50 p-4 text-sm text-slate-600"><HiMiniInformationCircle className="mt-0.5 size-5 shrink-0" /><p>Review is required before apply. Guard calculates effective blast radius server-side from the canonical registry, dependencies, managed policy, and global lockdown.</p></div> : null}

    {reviewOpen && preview ? <ReviewDrawer preview={preview} busy={previewBusy || applyBusy} onClose={() => setReviewOpen(false)} onApply={() => { void openApproval(); }} /> : null}
    {approvalOpen && preview ? <ApprovalProofModal title={`Apply ${confirmationCount} extension permission change${confirmationCount === 1 ? "" : "s"}`} detail="Authenticate this exact reviewed draft. Guard issues a one-use proof bound to the canonical mutation digest." confirmLabel={`Apply ${confirmationCount} reviewed change${confirmationCount === 1 ? "" : "s"}`} approvalGate={resolvedApprovalGate} busy={applyBusy} error={error} onCancel={() => { if (!applyBusy) setApprovalOpen(false); }} onConfirm={(credentials) => { void apply(credentials); }} /> : null}
  </section>;
}
