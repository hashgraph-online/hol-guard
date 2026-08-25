import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniArrowPath,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniLockClosed,
  HiMiniShieldCheck,
  HiMiniXMark,
} from "react-icons/hi2";

import { ApprovalProofFieldInputs, buildApprovalProofCredentials, isApprovalProofSubmitDisabled } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";
import { useModalDialog } from "./use-modal-dialog";
import {
  type EffectiveExtensionControls,
  type ExtensionCatalogItem,
  type ExtensionMutationPreview,
  type ExtensionPermission,
} from "./extension-controls-api";
import { isCurrentExtensionPolicyDraft, localPermissionDraftState, type PermissionDraftState } from "./extension-policy-draft";
import { type ExtensionPolicyRebaseConflict } from "./extension-policy-rebase";
import { useExtensionPolicyDraft } from "./use-extension-policy-draft";
import { controlProvenance, groupPermissionsByFamily, treatmentLabel } from "./extension-control-center-model";
import { useResolvedApprovalGate } from "./use-resolved-approval-gate";
import { ProtectionSettingsHistory } from "./protection-center/protection-settings-history";
import { AppliedPolicyToast, appliedPolicyCloudHref } from "./extension-policy-applied-toast";

export const RISK_TONE: Record<string, string> = {
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

export function managedPermissionState(effective: EffectiveExtensionControls, permissionId: string): "enabled" | "disabled" | null {
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

export { isCurrentExtensionPolicyDraft } from "./extension-policy-draft";

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

export function PermissionPolicyRow(props: {
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
    <article id={`pattern-${props.permission.permission_id}`} className="guard-pattern-row" data-permission-id={props.permission.permission_id}>
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

export function PreviewPanel(props: { preview: ExtensionMutationPreview }) {
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

export function PolicyReviewSheet(props: {
  preview: ExtensionMutationPreview;
  approvalGate: GuardApprovalGatePublicConfig | null;
  busy: boolean;
  error: string | null;
  onClose: () => void;
  onApply: (credentials: { approval_password?: string; approval_totp_code?: string }) => void;
}) {
  const ref = useModalDialog<HTMLFormElement>(props.onClose, !props.busy);
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const count = props.preview.semantic_preview.changed_target_count;
  const submitDisabled = isApprovalProofSubmitDisabled(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }, props.busy);
  const handleSubmit = (event: React.FormEvent) => {
    event.preventDefault();
    if (submitDisabled) return;
    props.onApply(buildApprovalProofCredentials(props.approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  };
  return <div className="fixed inset-0 z-50 bg-brand-dark/40">
    <form
      ref={ref}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-labelledby="extension-policy-review-title"
      onSubmit={handleSubmit}
      className="absolute inset-y-0 right-0 flex w-full max-w-2xl flex-col overflow-y-auto bg-[var(--surface-1)] p-5 focus:outline-none sm:p-6"
    >
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-xs font-bold uppercase tracking-[0.18em] text-brand-blue">Protection review</p>
          <h2 id="extension-policy-review-title" className="mt-1 text-xl font-semibold text-brand-dark">
            Review and apply {count} protection setting change{count === 1 ? "" : "s"}
          </h2>
        </div>
        <button type="button" disabled={props.busy} aria-label="Close protection review" onClick={props.onClose} className="grid size-11 place-items-center rounded-full text-brand-dark disabled:opacity-50">
          <HiMiniXMark className="size-5" />
        </button>
      </div>
      <div className="mt-5 flex-1"><PreviewPanel preview={props.preview} /></div>
      <div className="mt-5 border-t border-[rgba(63,65,116,0.12)] pt-4">
        <p className="text-sm font-semibold text-brand-dark">Authenticate this exact change</p>
        <p className="mt-1 text-xs leading-5 text-brand-dark/75">Guard uses a one-time local proof and rejects the apply if the reviewed settings changed.</p>
        <div className="mt-3">
          <ApprovalProofFieldInputs
            approvalGate={props.approvalGate}
            approvalPassword={password}
            approvalTotpCode={totpCode}
            onApprovalPasswordChange={(event) => setPassword(event.target.value)}
            onApprovalTotpCodeChange={(event) => setTotpCode(event.target.value)}
          />
        </div>
        {props.error ? <p role="alert" className="mt-3 text-sm text-red-950">{props.error}</p> : null}
        <div className="sticky bottom-0 mt-4 flex flex-wrap justify-end gap-2 bg-[var(--surface-1)] pb-1 pt-3">
          <button type="button" disabled={props.busy} onClick={props.onClose} className="min-h-11 rounded-xl border border-[rgba(63,65,116,0.2)] px-4 text-sm font-semibold text-brand-dark">Continue editing</button>
          <button type="submit" disabled={submitDisabled} className="min-h-11 rounded-xl bg-brand-blue px-4 text-sm font-semibold text-[#f4f7fb] disabled:opacity-40">
            {props.busy ? "Applying…" : `Apply ${count} reviewed change${count === 1 ? "" : "s"}`}
          </button>
        </div>
      </div>
    </form>
  </div>;
}

export function ExtensionPolicyPanel(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  catalogDigest: string;
  onRefresh: () => Promise<void> | void;
  onDirtyChange?: (dirty: boolean) => void;
  cloudControlsUrl?: string;
}) {
  const [policyExtension, setPolicyExtension] = useState(props.extension);
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const {
    baseEffective, dirty, preview, previewBusy, applyBusy, reviewOpen,
    error, stale, pendingRebase, refreshRequired, lastApplied, undoLastApplied,
    setReviewOpen, setPermissionState, resetDraft, runPreview, apply, rebaseDraft,
    keepConflicts, useCurrent, applyProfile, useHistoricalDraft, permissionState,
  } = draft;
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);

  useEffect(() => { props.onDirtyChange?.(dirty); }, [dirty, props.onDirtyChange]);
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
    setPolicyExtension(props.extension);
    resetDraft();
  }, [props.extension.extension_id]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      /* the review sheet renders the gate resolution failure inline */
    });
  }, [reviewOpen, resolveApprovalGate]);

  const managedCount = policyExtension.permissions.filter((permission) => managedPermissionState(baseEffective, permission.permission_id) !== null).length;
  const changeCount = draft.changeCountFor(policyExtension.permissions.map((permission) => permission.permission_id));
  const applyAcrossHref = appliedPolicyCloudHref({
    extensionName: policyExtension.name,
    extensionId: policyExtension.extension_id,
    changedPermissionIds: lastApplied?.changedPermissionIds ?? [],
    cloudControlsUrl: props.cloudControlsUrl,
  });
  return (
    <section id="extension-policy-editor" aria-labelledby="extension-policy-heading">
      <h2 id="extension-policy-heading" className="text-lg font-semibold text-brand-dark">Protection settings</h2>
      <p className="mt-2 max-w-2xl text-sm leading-6 text-brand-dark/80">
        Recommended follows Guard defaults. Allow is available only where built-in safety and organization policy still permit it. Block is a stricter local floor.
      </p>
      <div className="mt-4 flex flex-wrap items-center gap-x-3 gap-y-2">
        <span className="text-xs font-semibold text-brand-dark/60">Apply to every pattern you can change:</span>
        <button type="button" disabled={baseEffective.health !== "protected" || refreshRequired} onClick={() => applyProfile(policyExtension.permissions, "recommended")} className="min-h-10 px-1 text-xs font-semibold text-brand-blue disabled:opacity-40">Reset to Recommended</button>
        <button type="button" disabled={baseEffective.health !== "protected" || refreshRequired} onClick={() => applyProfile(policyExtension.permissions, "stricter")} className="min-h-10 px-1 text-xs font-semibold text-brand-dark disabled:opacity-40">Block all changeable variants</button>
      </div>
      <div id="extension-settings-history"><ProtectionSettingsHistory catalogDigest={baseEffective.catalog_digest} disabled={baseEffective.health !== "protected" || refreshRequired} onUse={(layers) => useHistoricalDraft(layers)} /></div>
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

      {lastApplied ? (
        <AppliedPolicyToast
          revision={lastApplied.revision}
          applyAcrossHref={applyAcrossHref}
          onUndo={() => { undoLastApplied(); }}
          onViewHistory={() => { document.getElementById("extension-settings-history")?.scrollIntoView({ behavior: "smooth", block: "start" }); }}
        />
      ) : refreshRequired ? (
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
              draftState={permissionState(permission.permission_id)}
              disabled={refreshRequired}
              onChange={(state) => setPermissionState(permission.permission_id, state)}
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
            <button type="button" disabled={previewBusy} onClick={() => { void rebaseDraft([policyExtension]); }} className="mt-3 min-h-11 rounded-xl bg-red-800 px-4 text-sm font-semibold text-[#f4f7fb]">Update draft with latest protection</button>
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
      {reviewOpen && preview ? (
        <PolicyReviewSheet
          preview={preview}
          approvalGate={resolvedApprovalGate}
          busy={applyBusy}
          error={error}
          onClose={() => { if (!applyBusy) setReviewOpen(false); }}
          onApply={(credentials) => { void apply(credentials); }}
        />
      ) : null}
    </section>
  );
}
