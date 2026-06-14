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
  HiMiniShieldCheck,
} from "react-icons/hi2";
import { Badge, Tag, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, policyActionLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision } from "./guard-types";
import {
  isCloudManagedPolicy,
  policyScopeLabel,
  resolvePolicyApprovalRecordLabel,
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
};

function PolicyRuleRow({ policy, cloudControlsUrl, onClear }: PolicyRuleRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== undefined && !cloudManaged;
  const family = resolvePolicyMatcherFamily(policy);
  const Icon = resolveFamilyIcon(family);

  return (
    <tr className="border-b border-slate-100 last:border-0 hover:bg-slate-50/80">
      <td className="w-12 px-2 py-3 align-top">
        <div className="flex flex-col items-center gap-1.5">
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-xl bg-slate-100 text-slate-500">
            <Icon className="h-4 w-4" aria-hidden="true" />
          </span>
          <Badge tone={resolveActionTone(policy.action)}>{policyActionLabel(policy.action)}</Badge>
        </div>
      </td>
      <td className="min-w-[220px] px-3 py-3 align-top">
        <p className="break-all font-mono text-sm font-semibold leading-snug text-brand-dark">{display.headline}</p>
        {display.kindLine ? <p className="mt-1 text-xs text-slate-500">{display.kindLine}</p> : null}
        {display.pathLine ? (
          <p className="mt-1 break-all font-mono text-[11px] leading-relaxed text-slate-500">{display.pathLine}</p>
        ) : null}
      </td>
      <td className="hidden min-w-[100px] px-3 py-3 align-top text-sm text-brand-dark md:table-cell">
        {display.projectLabel ?? "—"}
      </td>
      <td className="hidden px-3 py-3 align-top md:table-cell">
        <Tag tone={cloudManaged ? "blue" : "green"}>{resolvePolicySourceLabel(policy.source)}</Tag>
      </td>
      <td className="hidden px-3 py-3 align-top text-sm text-slate-700 lg:table-cell">
        {policyScopeLabel(policy.scope)}
      </td>
      <td className="hidden px-3 py-3 align-top text-sm text-slate-700 xl:table-cell">
        {harnessDisplayName(policy.harness)}
      </td>
      <td className="hidden whitespace-nowrap px-3 py-3 align-top text-xs text-slate-500 sm:table-cell">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : "—"}
      </td>
      <td className="min-w-[120px] px-3 py-3 align-top text-right">
        <div className="flex flex-col items-end gap-2">
          {!cloudManaged ? (
            <a
              href={guardAwareHref(resolvePolicyEvidenceHref(policy))}
              className="max-w-[160px] truncate font-mono text-xs font-medium text-brand-blue hover:underline"
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
      </td>
    </tr>
  );
}

type PolicyRuleTableProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  emptyTitle: string;
  emptyBody: string;
};

export function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
}: PolicyRuleTableProps) {
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
      <div className="overflow-x-auto rounded-2xl border border-slate-100 bg-white shadow-sm">
        <table className="min-w-[960px] w-full border-collapse text-left">
          <thead className="border-b border-slate-100 bg-slate-50/80 text-xs font-semibold uppercase tracking-wide text-slate-500">
            <tr>
              <th className="px-2 py-3">Action</th>
              <th className="px-3 py-3">Command</th>
              <th className="hidden px-3 py-3 md:table-cell">Project</th>
              <th className="hidden px-3 py-3 md:table-cell">Source</th>
              <th className="hidden px-3 py-3 lg:table-cell">Scope</th>
              <th className="hidden px-3 py-3 xl:table-cell">App</th>
              <th className="hidden px-3 py-3 sm:table-cell">Updated</th>
              <th className="px-3 py-3 text-right">Record</th>
            </tr>
          </thead>
          <tbody>
            {visiblePolicies.map((policy) => (
              <PolicyRuleRow
                key={`${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`}
                policy={policy}
                cloudControlsUrl={cloudControlsUrl}
                onClear={onClearPolicy}
              />
            ))}
          </tbody>
        </table>
      </div>
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
        <PolicyRuleTable
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
