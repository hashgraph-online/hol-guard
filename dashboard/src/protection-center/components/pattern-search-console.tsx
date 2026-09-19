import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { HiMiniArrowPath, HiMiniCheckCircle, HiMiniExclamationTriangle, HiMiniInformationCircle, HiMiniMagnifyingGlass, HiMiniNoSymbol, HiMiniShieldCheck, HiMiniSparkles, HiMiniXMark } from "react-icons/hi2";

import {
  catalogRowSecondLine,
  extensionDisplayName,
  extensionStateLabel,
} from "../../extension-control-center-model";
import type { EffectiveExtensionControls, ExtensionCatalogItem, ExtensionPermission } from "../../extension-controls-api";
import type { PermissionDraftState } from "../../extension-policy-draft";
import {
  managedPermissionState,
  PermissionPolicyRow,
  PolicyReviewSheet,
} from "../../extension-policy-panel";
import { AppliedPolicyToast } from "../../extension-policy-applied-toast";
import { useResolvedApprovalGate } from "../../use-resolved-approval-gate";
import { useExtensionPolicyDraft } from "../../use-extension-policy-draft";
import { COMMAND_PATTERN_DISPLAY_LIMIT, searchCommandPatterns } from "../model/protection-landing";
import { ProtectionModuleRow } from "./protection-primitives";
import { ExtensionBrandMark } from "./extension-brand-mark";

type QuickApplyChoice = {
  state: PermissionDraftState;
  label: string;
  detail: string;
  icon: typeof HiMiniSparkles;
};

const QUICK_APPLY_CHOICES: readonly QuickApplyChoice[] = [
  {
    state: "inherit",
    label: "Recommended",
    detail: "Use Guard defaults for every matching capability.",
    icon: HiMiniSparkles,
  },
  {
    state: "allow",
    label: "Allow all",
    detail: "Allow every matching capability that organization policy permits.",
    icon: HiMiniCheckCircle,
  },
  {
    state: "block",
    label: "Deny all",
    detail: "Add a local block to every matching capability.",
    icon: HiMiniNoSymbol,
  },
];

export function quickApplyPermissionIds(
  permissions: readonly { permission_id: string; configurable: boolean }[],
  effective: EffectiveExtensionControls,
  state: PermissionDraftState,
): string[] {
  return permissions
    .filter((permission) => permission.configurable)
    .filter((permission) => state !== "allow" || managedPermissionState(effective, permission.permission_id) !== "disabled")
    .map((permission) => permission.permission_id);
}

function CatalogSearchRow(props: {
  extension: ExtensionCatalogItem;
  effective: EffectiveExtensionControls;
  onOpen: (extension: ExtensionCatalogItem) => void;
}) {
  const handleOpen = useCallback(() => {
    props.onOpen(props.extension);
  }, [props]);
  return (
    <ProtectionModuleRow
      extensionId={props.extension.extension_id}
      name={extensionDisplayName(props.extension.name)}
      description={props.extension.description}
      behavior={catalogRowSecondLine(props.extension, extensionStateLabel(props.effective, props.extension))}
      required={props.extension.required}
      mcp={props.extension.surface === "mcp"}
      external={props.extension.trust_class === "external"}
      executables={props.extension.executables}
      ecosystemIds={props.extension.ecosystem_ids}
      onOpen={handleOpen}
    />
  );
}

function QuickApplyToolbar(props: {
  permissions: readonly ExtensionPermission[];
  effective: EffectiveExtensionControls;
  disabled: boolean;
  permissionState: (permissionId: string) => PermissionDraftState;
  onApply: (permissionIds: readonly string[], state: PermissionDraftState) => void;
}) {
  const configurableCount = props.permissions.filter((permission) => permission.configurable).length;
  const managedBlockCount = props.permissions.filter((permission) =>
    permission.configurable && managedPermissionState(props.effective, permission.permission_id) === "disabled"
  ).length;
  let managedBlockCopy = "";
  if (managedBlockCount) {
    const subject = managedBlockCount === 1 ? "block stays" : "blocks stay";
    managedBlockCopy = ` ${managedBlockCount} organization ${subject} enforced.`;
  }
  if (!configurableCount) return null;
  return (
    <div className="mt-4 flex flex-col gap-3 border-y border-[rgba(63,65,116,0.12)] bg-[rgba(85,153,254,0.045)] px-3 py-3 sm:flex-row sm:items-center sm:justify-between sm:px-4">
      <div className="min-w-0">
        <p className="text-sm font-semibold text-brand-dark">Quick apply to {configurableCount} matching {configurableCount === 1 ? "capability" : "capabilities"}</p>
        <p className="mt-0.5 text-xs leading-5 text-brand-dark/65">
          Changes stay in draft until you review and approve them.
          {managedBlockCopy}
        </p>
      </div>
      <div role="group" aria-label={`Quick apply to ${configurableCount} matching capabilities`} className="flex flex-wrap gap-2">
        {QUICK_APPLY_CHOICES.map((choice) => (
          <QuickApplyButton
            key={choice.state}
            choice={choice}
            permissionIds={quickApplyPermissionIds(props.permissions, props.effective, choice.state)}
            disabled={props.disabled}
            permissionState={props.permissionState}
            onApply={props.onApply}
          />
        ))}
      </div>
    </div>
  );
}

function QuickApplyButton(props: {
  choice: QuickApplyChoice;
  permissionIds: readonly string[];
  disabled: boolean;
  permissionState: (permissionId: string) => PermissionDraftState;
  onApply: (permissionIds: readonly string[], state: PermissionDraftState) => void;
}) {
  const active = props.permissionIds.length > 0
    && props.permissionIds.every((permissionId) => props.permissionState(permissionId) === props.choice.state);
  const handleClick = useCallback(() => {
    props.onApply(props.permissionIds, props.choice.state);
  }, [props.choice.state, props.onApply, props.permissionIds]);
  const Icon = props.choice.icon;
  return (
    <button
      type="button"
      aria-pressed={active}
      title={props.choice.detail}
      disabled={props.disabled || props.permissionIds.length === 0}
      onClick={handleClick}
      className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-[rgba(63,65,116,0.18)] bg-white px-3 text-xs font-semibold text-brand-dark shadow-sm transition-colors hover:border-brand-blue hover:text-brand-blue disabled:cursor-not-allowed disabled:opacity-45 aria-pressed:border-brand-blue aria-pressed:bg-brand-blue aria-pressed:text-white"
    >
      <Icon className="size-4" aria-hidden="true" />
      {props.choice.label}
    </button>
  );
}

/**
 * Search-first command-pattern console for the Extensions landing page.
 *
 * One query searches every tool's patterns by label, example command, flag,
 * or ID; matched rows render with the same inline Recommended / Allow / Block
 * control used on the tool page, and the same review + proof flow commits the
 * change without leaving the page. Tools whose names match the query render
 * as a final group so a query like "kubernetes" finds both patterns and tools.
 * While a query is active the parent hides the full catalogs: the results are
 * the page.
 */
export function PatternSearchConsole(props: {
  catalog: readonly ExtensionCatalogItem[];
  effective: EffectiveExtensionControls;
  onRefresh: () => Promise<void> | void;
  onOpenExtension: (extension: ExtensionCatalogItem) => void;
  active?: boolean;
  query?: string;
  onQueryChange?: (query: string) => void;
  /** Rendered under the input while the parent hides its own header actions. */
  actionSlot?: ReactNode;
}) {
  const [internalQuery, setInternalQuery] = useState("");
  const query = props.query ?? internalQuery;
  const setQuery = props.onQueryChange ?? setInternalQuery;
  const [focused, setFocused] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const searchActive = props.active ?? true;
  const draft = useExtensionPolicyDraft({ effective: props.effective, onRefresh: props.onRefresh });
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(null);
  const {
    baseEffective, dirty, preview, previewBusy, applyBusy, reviewOpen,
    error, stale, refreshRequired, lastApplied, undoLastApplied,
    changedPermissionCount, setReviewOpen, setPermissionState, setPermissionStates,
    resetDraft, runPreview, apply, permissionState,
  } = draft;

  useEffect(() => {
    if (!searchActive) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== "/" || event.defaultPrevented) return;
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.isContentEditable)) return;
      event.preventDefault();
      inputRef.current?.focus();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [searchActive]);

  const totalPermissionCount = useMemo(
    () => props.catalog.reduce((total, extension) => total + extension.permissions.length, 0),
    [props.catalog],
  );
  const allMatches = useMemo(
    () => searchCommandPatterns(props.catalog, query, totalPermissionCount),
    [props.catalog, query, totalPermissionCount],
  );
  const matches = useMemo(() => allMatches.slice(0, COMMAND_PATTERN_DISPLAY_LIMIT), [allMatches]);
  const toolMatches = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    if (!terms.length) return [];
    return props.catalog.filter((extension) => {
      const text = [extension.name, extension.extension_id, ...extension.executables, ...extension.aliases].join(" ").toLowerCase();
      return terms.every((term) => text.includes(term));
    });
  }, [props.catalog, query]);
  const grouped = useMemo(() => {
    const groups = new Map<string, { extension: ExtensionCatalogItem; permissionIds: string[] }>();
    for (const match of matches) {
      const group = groups.get(match.extension.extension_id) ?? { extension: match.extension, permissionIds: [] };
      group.permissionIds.push(match.permission.permission_id);
      groups.set(match.extension.extension_id, group);
    }
    return [...groups.values()];
  }, [matches]);
  const involvedPermissions = useMemo(() => allMatches.map((match) => match.permission), [allMatches]);
  const changeCount = changedPermissionCount;
  const showResults = query.trim().length > 0;

  useEffect(() => {
    if (!reviewOpen) return;
    void resolveApprovalGate({ failClosed: true }).catch(() => {
      /* the review sheet renders the gate resolution failure inline */
    });
  }, [reviewOpen, resolveApprovalGate]);

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
        type="text"
        role="searchbox"
        enterKeyHint="search"
        value={query}
        onFocus={() => setFocused(true)}
        onChange={(event) => setQuery(event.target.value.slice(0, 160))}
        placeholder='Search any command Guard watches — "squash", "git push --force", "kubectl"…'
        aria-describedby="pattern-search-hint"
        className="min-h-12 w-full rounded-2xl border border-[rgba(63,65,116,0.14)] bg-white/85 py-2.5 pl-9 pr-10 text-sm text-brand-dark shadow-sm focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-blue-100"
      />
      {showResults ? (
        <button
          type="button"
          onClick={() => { setQuery(""); inputRef.current?.focus(); }}
          aria-label="Clear search"
          className="absolute right-2 top-1/2 grid size-8 -translate-y-1/2 place-items-center rounded-lg text-brand-dark/55 hover:bg-[rgba(63,65,116,0.06)] hover:text-brand-dark"
        >
          <HiMiniXMark className="size-4" aria-hidden="true" />
        </button>
      ) : null}
    </label>
    <p id="pattern-search-hint" className={`mt-2 text-xs text-brand-dark/60 ${focused || showResults ? "" : "sr-only"}`}>
      Matches patterns across every tool. Press / to focus search from anywhere on this page.
    </p>

    {props.actionSlot ? <div className="mt-3">{props.actionSlot}</div> : null}

    {showResults ? (
      matches.length || toolMatches.length ? (
        <div className="mt-3">
          {matches.length ? (
            <>
              <QuickApplyToolbar
                permissions={involvedPermissions}
                effective={baseEffective}
                disabled={refreshRequired || previewBusy || applyBusy || baseEffective.health !== "protected"}
                permissionState={permissionState}
                onApply={setPermissionStates}
              />
              {allMatches.length > matches.length ? (
                <p role="status" className="mt-3 text-xs text-brand-dark/65">
                  Showing {matches.length} of {allMatches.length} matching capabilities. Quick actions apply to all {allMatches.length}.
                </p>
              ) : null}
            </>
          ) : null}
          {grouped.map((group) => (
            <section key={group.extension.extension_id} aria-label={`${group.extension.name} patterns`} className="guard-pattern-family">
              <h3 className="guard-pattern-family-heading">
                <ExtensionBrandMark
                  extension_id={group.extension.extension_id}
                  name={group.extension.name}
                  executables={group.extension.executables}
                  ecosystem_ids={group.extension.ecosystem_ids}
                  size="sm"
                />
                {group.extension.executables.length ? <code>{group.extension.executables[0]}</code> : null}
                <span>{extensionDisplayName(group.extension.name)}</span>
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
          {toolMatches.length ? (
            <section aria-label="Matching tools" className="guard-pattern-family">
              <h3 className="guard-pattern-family-heading"><span>Tools</span></h3>
              {toolMatches.map((extension) => (
                <CatalogSearchRow
                  key={extension.extension_id}
                  extension={extension}
                  effective={props.effective}
                  onOpen={props.onOpenExtension}
                />
              ))}
            </section>
          ) : null}
          {managedCount ? (
            <p className="mt-3 text-xs text-indigo-950">{managedCount} matched setting{managedCount === 1 ? "" : "s are"} managed by your organization and cannot be weakened on this device.</p>
          ) : null}
        </div>
      ) : (
        <p className="mt-3 text-sm text-brand-dark/75">No command patterns or tools match this search.</p>
      )
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
    {lastApplied ? (
      <AppliedPolicyToast
        revision={lastApplied.revision}
        onUndo={() => { undoLastApplied(); }}
        onViewHistory={() => { document.getElementById("pattern-search-heading")?.scrollIntoView({ behavior: "smooth", block: "start" }); }}
      />
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
  </section>;
}
