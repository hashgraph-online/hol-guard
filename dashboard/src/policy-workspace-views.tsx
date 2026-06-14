import { useCallback, useMemo, useState } from "react";
import {
  HiMiniTrash,
  HiMiniCloudArrowUp,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniCommandLine,
  HiMiniCube,
  HiMiniDocumentText,
  HiMiniGlobeAlt,
  HiMiniLockClosed,
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { Badge, Tag, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, policyActionLabel, scopeLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision } from "./guard-types";
import {
  isCloudManagedPolicy,
  resolvePolicyApprovalRecordLabel,
  resolvePolicyDisplay,
  resolvePolicyEvidenceHref,
  resolvePolicyMatcherFamily,
  resolvePolicyRowSourceLabel,
  resolvePolicyRowTitle,
} from "./policy-workspace-helpers";

export type PolicySortKey = "app" | "updated";
export type PolicySortState = { key: PolicySortKey; direction: "asc" | "desc" } | null;

const PAGE_SIZE = 30;

const RULE_GRID_CLASS =
  "grid grid-cols-[minmax(0,1fr)] items-start gap-x-3 gap-y-3 border-b border-slate-100 px-4 py-3 last:border-0 hover:bg-slate-50/80 md:grid-cols-[72px_minmax(220px,1.4fr)_100px_96px_88px_104px_minmax(120px,1fr)]";

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

function resolveFamilyIcon(family: string | null) {
  if (family === "package-request") {
    return HiMiniCube;
  }
  if (family === "tool-action" || family === "tool-output") {
    return HiMiniCommandLine;
  }
  if (family === "prompt" || family === "prompt-env-read") {
    return HiMiniDocumentText;
  }
  if (family === "mcp") {
    return HiMiniGlobeAlt;
  }
  return HiMiniShieldCheck;
}

type PolicyRuleRowProps = {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClear?: (policy: GuardPolicyDecision) => void;
  cloudVariant?: boolean;
};

function PolicyRuleRow({ policy, cloudControlsUrl, onClear, cloudVariant = false }: PolicyRuleRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = cloudVariant || isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== undefined && !cloudManaged;
  const family = resolvePolicyMatcherFamily(policy);
  const Icon = resolveFamilyIcon(family);
  const title = resolvePolicyRowTitle(policy, display);
  const scopeTag = scopeLabel(policy.scope, "policy");

  return (
    <article className={RULE_GRID_CLASS} role="listitem">
      <div className="flex items-start gap-2 md:col-start-1">
        <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
          <Icon className="h-4 w-4" aria-hidden="true" />
        </span>
        <Badge tone={resolveActionTone(policy.action)}>{policyActionLabel(policy.action)}</Badge>
      </div>

      <div className="min-w-0 md:col-start-2">
        <p className="text-sm font-semibold leading-snug text-brand-dark">{title}</p>
        {display.kindLine ? <p className="mt-1 text-xs text-slate-500">{display.kindLine}</p> : null}
        {display.pathLine ? (
          <p className="mt-1 break-all font-mono text-[11px] leading-relaxed text-slate-500">{display.pathLine}</p>
        ) : null}
        <div className="mt-2 flex flex-wrap gap-3 text-xs text-slate-600 md:hidden">
          <span>{resolvePolicyRowSourceLabel(policy)}</span>
          <span>{scopeTag}</span>
          <span>{harnessDisplayName(policy.harness)}</span>
        </div>
      </div>

      <div className="hidden text-sm text-brand-dark md:col-start-3 md:block">
        {cloudManaged ? <Tag tone="blue">{resolvePolicyRowSourceLabel(policy)}</Tag> : resolvePolicyRowSourceLabel(policy)}
      </div>

      <div className="hidden md:col-start-4 md:block">
        <Tag tone="blue">{scopeTag}</Tag>
      </div>

      <div className="hidden text-sm text-brand-dark md:col-start-5 md:block">
        {harnessDisplayName(policy.harness)}
      </div>

      <div className="hidden whitespace-nowrap text-xs text-slate-500 md:col-start-6 md:block">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : "—"}
      </div>

      <div className="flex min-w-0 flex-col items-start gap-2 md:col-start-7 md:items-end">
        {!cloudManaged ? (
          <a
            href={guardAwareHref(resolvePolicyEvidenceHref(policy))}
            className="max-w-full truncate font-mono text-xs font-medium text-brand-blue hover:underline"
            title={resolvePolicyApprovalRecordLabel(policy)}
          >
            {resolvePolicyApprovalRecordLabel(policy)}
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
        {cloudManaged ? (
          <span className="inline-flex items-center gap-1 text-xs font-medium text-slate-500" title="Read-only Cloud policy">
            <HiMiniLockClosed className="h-3.5 w-3.5" aria-hidden="true" />
            Policy
          </span>
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
    </article>
  );
}

type PolicyRuleTableProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  emptyTitle: string;
  emptyBody: string;
  cloudVariant?: boolean;
  totalCount?: number;
};

export function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  cloudVariant = false,
  totalCount,
}: PolicyRuleTableProps) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);

  const visiblePolicies = useMemo(() => policies.slice(0, visibleCount), [policies, visibleCount]);
  const remaining = policies.length - visibleCount;
  const hasMore = remaining > 0;
  const listTotal = totalCount ?? policies.length;

  const handleShowMore = useCallback(() => {
    setVisibleCount((current) => current + PAGE_SIZE);
  }, []);

  if (policies.length === 0) {
    return <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />;
  }

  return (
    <div className="space-y-3">
      <div className="overflow-x-auto rounded-2xl border border-slate-100 bg-white shadow-sm">
        <div
          className="hidden border-b border-slate-100 bg-slate-50/80 px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider text-slate-500 md:grid md:grid-cols-[72px_minmax(220px,1.4fr)_100px_96px_88px_104px_minmax(120px,1fr)] md:gap-x-3"
          aria-hidden="true"
        >
          <span>Action</span>
          <span>Rule</span>
          <span>Source</span>
          <span>Scope</span>
          <span>{cloudVariant ? "Applies to" : "Harness"}</span>
          <span>Last updated</span>
          <span className="text-right">{cloudVariant ? "Policy" : "Approval record"}</span>
        </div>
        <div role="list">
          {visiblePolicies.map((policy) => (
            <PolicyRuleRow
              key={`${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`}
              policy={policy}
              cloudControlsUrl={cloudControlsUrl}
              onClear={onClearPolicy}
              cloudVariant={cloudVariant}
            />
          ))}
        </div>
      </div>
      {hasMore ? (
        <div className="flex justify-center pt-1">
          <button
            type="button"
            onClick={handleShowMore}
            className="text-sm font-medium text-brand-blue hover:underline"
          >
            Show {Math.min(PAGE_SIZE, remaining)} more ({remaining} remaining)
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
  cloudVariant?: boolean;
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
  cloudVariant = false,
}: GroupedPolicySectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  const handleToggle = useCallback(() => setOpen((current) => !current), []);
  const ruleLabel = policies.length === 1 ? "1 rule" : `${policies.length} rules`;

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
          <Tag tone="slate">{ruleLabel}</Tag>
          {open ? (
            <HiMiniChevronUp className="h-4 w-4 text-slate-400" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-4 w-4 text-slate-400" aria-hidden="true" />
          )}
        </div>
      </button>
      {open ? (
        <PolicyRuleTable
          policies={policies}
          cloudControlsUrl={cloudControlsUrl}
          onClearPolicy={onClearPolicy}
          emptyTitle={emptyTitle}
          emptyBody={emptyBody}
          cloudVariant={cloudVariant}
          totalCount={policies.length}
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
