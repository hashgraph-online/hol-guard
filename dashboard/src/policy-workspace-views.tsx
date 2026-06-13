import { useCallback, useMemo, useState } from "react";
import { HiMiniTrash, HiMiniCloudArrowUp, HiMiniChevronDown, HiMiniChevronUp } from "react-icons/hi2";
import { Badge, Tag, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, policyActionLabel, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision } from "./guard-types";
import {
  isCloudManagedPolicy,
  resolvePolicyDisplay,
  resolvePolicyEvidenceHref,
  resolvePolicyMatcherFamily,
  resolvePolicySourceLabel,
} from "./policy-workspace-helpers";

export type PolicySortKey = "app" | "updated";
export type PolicySortState = { key: PolicySortKey; direction: "asc" | "desc" } | null;

const PAGE_SIZE = 30;

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

type PolicyRuleCardProps = {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClear?: (policy: GuardPolicyDecision) => void;
};

export function PolicyRuleCard({ policy, cloudControlsUrl, onClear }: PolicyRuleCardProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== undefined && !cloudManaged;

  return (
    <article className="rounded-2xl border border-slate-100 bg-white px-4 py-3.5 shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={resolveActionTone(policy.action)}>{policyActionLabel(policy.action)}</Badge>
            <Tag tone={cloudManaged ? "blue" : "green"}>{resolvePolicySourceLabel(policy.source)}</Tag>
            <Tag tone="slate">{scopeLabel(policy.scope)}</Tag>
            <span className="text-xs text-slate-400">{harnessDisplayName(policy.harness)}</span>
          </div>
          <h3 className="text-base font-semibold leading-snug text-brand-dark">{display.headline}</h3>
          <p className="text-sm text-slate-600">{display.subtitle}</p>
          {display.technicalId ? (
            <details className="text-xs text-slate-500">
              <summary className="cursor-pointer text-brand-blue hover:underline">Technical id</summary>
              <p className="mt-1 break-all font-mono text-[11px] text-slate-600">{display.technicalId}</p>
            </details>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2 text-right">
          <span className="text-xs text-slate-400">
            {policy.updated_at ? formatRelativeTime(policy.updated_at) : null}
          </span>
          {!cloudManaged ? (
            <a
              href={guardAwareHref(resolvePolicyEvidenceHref(policy))}
              className="text-sm font-medium text-brand-blue hover:underline"
            >
              See approval record
            </a>
          ) : null}
          {cloudManaged && cloudControlsUrl ? (
            <a
              href={cloudControlsUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline"
            >
              <HiMiniCloudArrowUp className="h-4 w-4" aria-hidden="true" />
              View on cloud
            </a>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              className="inline-flex items-center gap-1 text-xs font-medium text-slate-500 hover:text-red-600"
            >
              <HiMiniTrash className="h-3.5 w-3.5" aria-hidden="true" />
              Remove rule
            </button>
          ) : null}
        </div>
      </div>
    </article>
  );
}

type PolicyRuleListProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  emptyTitle: string;
  emptyBody: string;
};

export function PolicyRuleList({ policies, cloudControlsUrl, onClearPolicy, emptyTitle, emptyBody }: PolicyRuleListProps) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  const visiblePolicies = useMemo(() => policies.slice(0, visibleCount), [policies, visibleCount]);
  const hasMore = policies.length > visibleCount;

  const handleShowMore = useCallback(() => {
    setVisibleCount((current) => current + PAGE_SIZE);
  }, []);

  if (policies.length === 0) {
    return <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />;
  }

  return (
    <div className="space-y-3">
      {visiblePolicies.map((policy) => (
        <PolicyRuleCard
          key={`${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`}
          policy={policy}
          cloudControlsUrl={cloudControlsUrl}
          onClear={onClearPolicy}
        />
      ))}
      {hasMore ? (
        <div className="flex justify-center pt-1">
          <button
            type="button"
            onClick={handleShowMore}
            className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50"
          >
            Show {Math.min(PAGE_SIZE, policies.length - visibleCount)} more ({policies.length - visibleCount} remaining)
          </button>
        </div>
      ) : null}
    </div>
  );
}

type GroupedPolicySectionProps = {
  title: string;
  description: string;
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  emptyTitle: string;
  emptyBody: string;
  defaultOpen?: boolean;
};

export function GroupedPolicySection({
  title,
  description,
  policies,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  defaultOpen = true,
}: GroupedPolicySectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  const handleToggle = useCallback(() => setOpen((current) => !current), []);

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
      <button
        type="button"
        onClick={handleToggle}
        className="flex w-full items-center justify-between gap-3 rounded-xl border border-slate-100 bg-slate-50/70 px-4 py-3 text-left"
        aria-expanded={open}
      >
        <div>
          <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
          <p className="text-sm text-slate-500">{description}</p>
        </div>
        <div className="flex items-center gap-2">
          <Tag tone="slate">{policies.length}</Tag>
          {open ? (
            <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
          )}
        </div>
      </button>
      {open ? (
        <PolicyRuleList
          policies={policies}
          cloudControlsUrl={cloudControlsUrl}
          onClearPolicy={onClearPolicy}
          emptyTitle={emptyTitle}
          emptyBody={emptyBody}
        />
      ) : null}
    </section>
  );
}

export function resolveFamilyFilterLabel(family: string): string {
  switch (family) {
    case "package-request":
      return "Package installs";
    case "tool-action":
      return "Commands";
    case "tool-output":
      return "Output";
    case "prompt":
      return "Prompts";
    default:
      return family.replace(/-/g, " ");
  }
}

export function groupPoliciesByFamily(policies: GuardPolicyDecision[]): Map<string, number> {
  const counts = new Map<string, number>();
  for (const policy of policies) {
    const family = resolvePolicyMatcherFamily(policy) ?? "other";
    counts.set(family, (counts.get(family) ?? 0) + 1);
  }
  return counts;
}
