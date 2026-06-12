import { useCallback } from "react";
import {
  HiMiniCheckCircle,
  HiMiniTrash,
  HiMiniDocumentText,
  HiMiniCloudArrowUp,
  HiMiniInbox,
  HiMiniCog6Tooth,
  HiMiniBarsArrowUp,
  HiMiniBarsArrowDown,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, policyActionLabel, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision, GuardRuntimeSnapshot } from "./guard-types";
import {
  isCloudManagedPolicy,
  policyTargetLabel,
  resolvePolicyEvidenceHref,
  resolvePolicyRuleSummary,
  resolvePolicySourceLabel,
} from "./policy-workspace-helpers";

export type PolicySortKey = "app" | "scope" | "action" | "target" | "updated";
export type PolicySortDirection = "asc" | "desc";
export type PolicySortState = { key: PolicySortKey; direction: PolicySortDirection } | null;

function resolveActionTone(action: string): "success" | "destructive" | "warning" | "default" {
  if (action === "allow") {
    return "success";
  }
  if (action === "block") {
    return "destructive";
  }
  if (action === "warn" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}

function resolveSortDirectionHint(isActive: boolean, direction: PolicySortDirection | undefined): string {
  if (!isActive) {
    return "ascending";
  }
  if (direction === "asc") {
    return "descending";
  }
  return "ascending";
}

type PolicyRowProps = {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClear?: (policy: GuardPolicyDecision) => void;
};

export function PolicyRow({ policy, cloudControlsUrl, onClear }: PolicyRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const summary = resolvePolicyRuleSummary(policy, {
    appName: harnessDisplayName(policy.harness),
    scopeLabel: scopeLabel(policy.scope),
    actionLabel: policyActionLabel(policy.action),
  });
  const target = policyTargetLabel(policy);
  const canClear = onClear !== undefined && !cloudManaged;

  return (
    <tr className="border-b border-slate-100 last:border-b-0 align-top hover:bg-slate-50/40 transition-colors">
      <td className="px-4 py-3 text-sm text-brand-dark min-w-[120px]">
        <span className="font-medium">{harnessDisplayName(policy.harness)}</span>
        <p className="mt-1 text-xs text-slate-400">{policy.scope} scope</p>
      </td>
      <td className="px-4 py-3 min-w-[240px]">
        <div className="flex flex-wrap items-center gap-2">
          <Badge tone={resolveActionTone(policy.action)}>{policyActionLabel(policy.action)}</Badge>
          <Tag tone={cloudManaged ? "blue" : "green"}>{resolvePolicySourceLabel(policy.source)}</Tag>
        </div>
        <p className="mt-2 text-sm leading-relaxed text-brand-dark">{summary}</p>
        <details className="mt-2 text-xs text-slate-500">
          <summary className="cursor-pointer font-medium text-brand-blue hover:underline">Rule details</summary>
          <dl className="mt-2 space-y-1.5 rounded-lg border border-slate-100 bg-slate-50/70 px-3 py-2">
            <div>
              <dt className="font-semibold text-slate-600">Target</dt>
              <dd className="font-mono break-all text-slate-700">{target}</dd>
            </div>
            {policy.workspace ? (
              <div>
                <dt className="font-semibold text-slate-600">Project</dt>
                <dd className="break-all text-slate-700">{policy.workspace}</dd>
              </div>
            ) : null}
            {policy.publisher ? (
              <div>
                <dt className="font-semibold text-slate-600">Publisher</dt>
                <dd className="break-all text-slate-700">{policy.publisher}</dd>
              </div>
            ) : null}
            {policy.reason ? (
              <div>
                <dt className="font-semibold text-slate-600">Reason</dt>
                <dd className="text-slate-700">{policy.reason}</dd>
              </div>
            ) : null}
            {policy.artifact_hash ? (
              <div>
                <dt className="font-semibold text-slate-600">Artifact hash</dt>
                <dd className="font-mono break-all text-slate-700">{policy.artifact_hash}</dd>
              </div>
            ) : null}
          </dl>
        </details>
      </td>
      <td className="px-4 py-3 text-xs text-slate-400 whitespace-nowrap">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : null}
      </td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap items-center gap-1">
          {!cloudManaged ? (
            <a
              href={guardAwareHref(resolvePolicyEvidenceHref(policy))}
              className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:border-brand-blue/30 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors"
            >
              <HiMiniDocumentText className="h-3.5 w-3.5" aria-hidden="true" />
              View evidence
            </a>
          ) : null}
          {cloudManaged && cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-brand-blue/20 bg-brand-blue/[0.05] px-2.5 py-1.5 text-xs font-medium text-brand-blue hover:bg-brand-blue/[0.1] focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors"
            >
              <HiMiniCloudArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
              View on cloud
            </a>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              aria-label={`Clear policy for ${harnessDisplayName(policy.harness)}`}
              className="inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-500 focus:outline-none focus:ring-2 focus:ring-red-300/50 transition-colors"
              title="Clear policy"
            >
              <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
            </button>
          ) : null}
        </div>
      </td>
    </tr>
  );
}

type SortHeaderProps = {
  label: string;
  sortKey: PolicySortKey;
  activeSort: PolicySortState;
  onSort: (key: PolicySortKey) => void;
  className?: string;
  sortable?: boolean;
};

export function SortHeader({
  label,
  sortKey,
  activeSort,
  onSort,
  className,
  sortable = true,
}: SortHeaderProps) {
  const isActive = activeSort?.key === sortKey;
  let ariaSort: "ascending" | "descending" | "none" = "none";
  if (isActive) {
    ariaSort = activeSort.direction === "asc" ? "ascending" : "descending";
  }
  const directionHint = resolveSortDirectionHint(isActive, activeSort?.direction);

  if (!sortable) {
    return (
      <th scope="col" className={`px-4 py-2.5 text-left ${className ?? ""}`}>
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">{label}</span>
      </th>
    );
  }

  return (
    <th scope="col" aria-sort={ariaSort} className={`px-4 py-2.5 text-left ${className ?? ""}`}>
      <button
        type="button"
        onClick={() => onSort(sortKey)}
        className="group inline-flex items-center gap-1 rounded px-1 -ml-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 transition-colors hover:text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
        aria-label={`Sort by ${label}, ${directionHint}`}
      >
        {label}
        <span className="inline-flex h-3.5 w-3.5 items-center justify-center" aria-hidden="true">
          {isActive && activeSort.direction === "asc" ? (
            <HiMiniBarsArrowUp className="h-3 w-3 text-brand-blue" />
          ) : null}
          {isActive && activeSort.direction === "desc" ? (
            <HiMiniBarsArrowDown className="h-3 w-3 text-brand-blue" />
          ) : null}
          {!isActive ? (
            <HiMiniBarsArrowUp className="h-3 w-3 text-slate-300 opacity-0 transition-opacity group-hover:opacity-100" />
          ) : null}
        </span>
      </button>
    </th>
  );
}

type PolicyTableSectionProps = {
  title: string;
  description: string;
  policies: GuardPolicyDecision[];
  sort: PolicySortState;
  onSort: (key: PolicySortKey) => void;
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  emptyTitle: string;
  emptyBody: string;
  sortable?: boolean;
};

export function PolicyTableSection({
  title,
  description,
  policies,
  sort,
  onSort,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  sortable = true,
}: PolicyTableSectionProps) {
  if (policies.length === 0) {
    return (
      <section className="space-y-2">
        <div>
          <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
          <p className="text-sm text-slate-500">{description}</p>
        </div>
        <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />
      </section>
    );
  }

  return (
    <section className="space-y-3">
      <div>
        <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
        <p className="text-sm text-slate-500">{description}</p>
      </div>
      <div className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div className="overflow-x-auto">
          <table className="w-full min-w-[760px] text-sm" aria-label={title}>
            <thead>
              <tr className="border-b border-slate-100 bg-slate-50">
                <SortHeader label="App" sortKey="app" activeSort={sort} onSort={onSort} sortable={sortable} />
                <th scope="col" className="px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                  What this rule does
                </th>
                <SortHeader label="Updated" sortKey="updated" activeSort={sort} onSort={onSort} sortable={sortable} />
                <th scope="col" className="px-4 py-2.5">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <PolicyRow
                  key={`${policy.harness}-${policy.scope}-${policyTargetLabel(policy)}-${policy.updated_at ?? ""}-${policy.source}`}
                  policy={policy}
                  cloudControlsUrl={cloudControlsUrl}
                  onClear={onClearPolicy}
                />
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </section>
  );
}

export function ExceptionsView({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onOpenInbox,
  onOpenSettings,
  sort,
  onSort,
}: {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onOpenInbox?: () => void;
  onOpenSettings?: () => void;
  sort: PolicySortState;
  onSort: (key: PolicySortKey) => void;
}) {
  if (policies.length === 0) {
    return (
      <div className="space-y-4">
        <EmptyState
          title="No exceptions yet"
          body="Exceptions are created when Inbox decisions use custom responses such as Warn or Require review, or when repo and environment overrides are configured."
          tone="teach"
        />
        <div className="flex flex-wrap gap-2">
          {onOpenInbox ? (
            <ActionButton variant="primary" onClick={onOpenInbox}>
              <HiMiniInbox className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Review Inbox
            </ActionButton>
          ) : null}
          {onOpenSettings ? (
            <ActionButton variant="secondary" onClick={onOpenSettings}>
              <HiMiniCog6Tooth className="mr-1.5 h-4 w-4" aria-hidden="true" />
              Configure in Settings
            </ActionButton>
          ) : null}
          {cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 rounded-lg border border-brand-blue/20 bg-white px-4 py-2 text-sm font-medium text-brand-blue hover:bg-brand-blue/[0.05]"
            >
              <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
              View on cloud
            </a>
          ) : null}
        </div>
      </div>
    );
  }

  return (
    <PolicyTableSection
      title="Active exceptions"
      description="Custom responses and overrides that are not simple allow or block rules."
      policies={policies}
      sort={sort}
      onSort={onSort}
      cloudControlsUrl={cloudControlsUrl}
      onClearPolicy={onClearPolicy}
      emptyTitle="No exceptions configured"
      emptyBody="Exceptions appear after custom Inbox decisions or repo overrides."
    />
  );
}

export function StrictModeView({
  snapshot,
  onOpenSettings,
}: {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
}) {
  const securityLevel = snapshot.security_level;
  const isStrict = securityLevel === "strict";
  return (
    <div className="space-y-4">
      <div
        className={`rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`}
      >
        <div className="mb-2 flex items-center gap-2">
          <SectionLabel>Strict mode</SectionLabel>
          <Tag tone={isStrict ? "green" : "slate"}>{isStrict ? "Enabled" : "Disabled"}</Tag>
        </div>
        <p className="mb-4 text-sm text-brand-dark/75">
          Strict mode enables maximum coverage. Guard asks before new network connections, subprocess launches, file writes, and all harness starts.
        </p>
        {!isStrict && onOpenSettings ? (
          <ActionButton variant="secondary" onClick={onOpenSettings}>
            Enable strict mode
          </ActionButton>
        ) : null}
        {isStrict ? (
          <div className="flex items-center gap-2 text-sm text-brand-green">
            <HiMiniCheckCircle className="h-4 w-4" aria-hidden="true" />
            Strict mode is active
          </div>
        ) : null}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
        <SectionLabel>Repo and environment rules</SectionLabel>
        <p className="mt-1 mb-3 text-sm text-slate-500">
          Per-repo and per-environment policy overrides can be set in your Guard config file or Guard Cloud Controls.
        </p>
        <div className="rounded-lg border border-slate-100 bg-slate-50/60 px-4 py-3">
          <p className="font-mono text-xs text-slate-600">~/.config/hol-guard/guard.yaml</p>
          <p className="mt-1 text-xs text-slate-400">See repo_rules and env_rules in the Guard docs.</p>
        </div>
      </div>
    </div>
  );
}
