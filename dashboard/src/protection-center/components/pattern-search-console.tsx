import { useEffect, useMemo, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniExclamationTriangle, HiMiniInformationCircle, HiMiniMagnifyingGlass, HiMiniShieldCheck } from "react-icons/hi2";

import type { EffectiveExtensionControls, ExtensionCatalogItem } from "../../extension-controls-api";
import {
  managedPermissionState,
  PermissionPolicyRow,
  ReviewDrawer,
} from "../../extension-policy-panel";
import { ApprovalProofModal } from "../../approval-proof-modal";
import { useResolvedApprovalGate } from "../../use-resolved-approval-gate";
import { useExtensionPolicyDraft } from "../../use-extension-policy-draft";
import { searchCommandPatterns } from "../model/protection-landing";

/**
 * Search-first command-pattern console for the Extensions landing page.
 *
 * One query searches every tool's patterns by label, example command, flag,
 * or ID; matched rows render with the same inline Recommended / Allow / Block
 * control used on the tool page, and the same review + proof flow commits the
 * change without leaving the page.
 */
export function PatternSearchConsole(props: {
  catalog: readonly ExtensionCatalogItem[];
  effective: EffectiveExtensionControls;
  onRefresh: () => Promise<void> | void;
}) {
  const [query, setQuery] = useState("");
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const {
    baseEffective, dirty, preview, previewBusy, applyBusy, reviewOpen, approvalOpen,
    error, stale, refreshRequired, setReviewOpen, setApprovalOpen,
    setPermissionState, resetDraft, runPreview, apply, permissionState, changeCountFor,
  } = draft;

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.defaultPrevented) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const matches = useMemo(() => searchCommandPatterns(props.catalog, query), [props.catalog, query]);
  const grouped = useMemo(() => {
    const groups = new Map<string, { extension: ExtensionCatalogItem; permissionIds: string[] }>();
    for (const match of matches) {
      const group = groups.get(match.extension.extension_id) ?? { extension: match.extension, permissionIds: [] };
      group.permissionIds.push(match.permission.permission_id);
      groups.set(match.extension.extension_id, group);
    }
    return [...groups.values()];
  }, [matches]);
  const involvedPermissions = useMemo(() => matches.map((match) => match.permission), [matches]);
  const changeCount = changeCountFor(involvedPermissions.map((permission) => permission.permission_id));
  const confirmationCount = preview?.semantic_preview.changed_target_count ?? changeCount;
  const showResults = query.trim().length > 0;

  const openApproval = async () => {
    if (!preview || !dirty || stale) return;
    try {
      await resolveApprovalGate({ failClosed: true });
      setReviewOpen(false);
      setApprovalOpen(true);
    } catch {
      /* the proof modal surfaces gate resolution failures */
    }
  };

  const managedCount = involvedPermissions.filter((permission) =>
    managedPermissionState(baseEffective, permission.permission_id) !== null,
  ).length;

  return <section aria-labelledby="pattern-search-heading" className="mt-6">
    <h2 id="pattern-search-heading" className="sr-only">Search command patterns</h2>
    <label className="relative block">
      <span className="sr-only">Search command patterns</span>
      <HiMiniMagnifyingGlass className="pointer-events-none absolute left-3 top-1/2 size-4 -translate-y-1/2 text-brand-dark/55" aria-hidden="true" />
      <input
        ref={inputRef}
        type="search"
        value={query}
        onFocus={() => setFocused(true)}
        onChange={(event) => setQuery(event.target.value.slice(0, 160))}
        placeholder='Search any command Guard watches — "squash", "git push --force", "kubectl"…'
        aria-describedby="pattern-search-hint"
        className="min-h-12 w-full rounded-2xl border border-[rgba(63,65,116,0.14)] bg-white/85 py-2.5 pl-9 pr-3 text-sm text-brand-dark shadow-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
      />
    </label>
    <p id="pattern-search-hint" className={`mt-2 text-xs text-brand-dark/60 ${focused || showResults ? "" : "sr-only"}`}>
      Matches patterns across every tool. Press / to focus search from anywhere on this page.
    </p>

    {showResults ? (
      matches.length ? (
        <div className="mt-3">
          {grouped.map((group) => (
            <section key={group.extension.extension_id} aria-label={`${group.extension.name} patterns`} className="guard-pattern-family">
              <h3 className="guard-pattern-family-heading">
                <code>{group.extension.executables[0] ?? group.extension.extension_id}</code>
                <span>{group.extension.name}</span>
              </h3>
              {group.permissionIds.map((permissionId) => {
                const permission = group.extension.permissions.find((item) => item.permission_id === permissionId);
                if (!permission) return null;
                return <PermissionPolicyRow
                  key={permission.permission_id}
                  permission={permission}
                  extension={group.extension}
                  effective={baseEffective}
                  draftState={permissionState(permission.permission_id)}
                  disabled={refreshRequired}
                  onChange={(state) => setPermissionState(permission.permission_id, state)}
                />;
              })}
            </section>
          ))}
          {managedCount ? (
            <p className="mt-3 text-xs text-indigo-950">{managedCount} matched setting{managedCount === 1 ? "" : "s are"} managed by your organization and cannot be weakened on this device.</p>
          ) : null}
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
            </div>
          ) : dirty && !preview ? (
            <div className="mt-4 flex items-start gap-3 text-sm text-brand-dark">
              <HiMiniInformationCircle className="mt-0.5 size-5 shrink-0" />
              <p>Review is required before approval. Guard calculates the real outcome from current protections, dependencies, organization settings, and Emergency Lockdown before anything can change.</p>
            </div>
          ) : null}
        </div>
      ) : (
        <p className="mt-3 text-sm text-brand-dark/75">No command patterns match this search.</p>
      )
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
  </section>;
}
