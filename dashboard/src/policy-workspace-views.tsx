import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";
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
  HiMiniNoSymbol,
  HiMiniCheckCircle,
} from "react-icons/hi2";
import { Tag, EmptyState } from "./approval-center-primitives";
import { harnessDisplayName, formatRelativeTime, scopeLabel, policyActionLabel } from "./approval-center-utils";
import { guardAwareHref } from "./guard-api";
import type { GuardPolicyDecision } from "./guard-types";
import {
  EvidenceTable,
  EvidenceTableBody,
  EvidenceTableCell,
  EvidenceTableHead,
  EvidenceTableHeader,
  EvidenceTableRow,
} from "./evidence/evidence-table";
import {
  isCloudManagedPolicy,
  resolvePolicyApprovalRecordLabel,
  resolvePolicyDisplay,
  resolvePolicyEvidenceHref,
  resolvePolicyMatcherFamily,
  resolvePolicyRowFolder,
  resolvePolicyRowFrequency,
  resolvePolicyRowSourceLabel,
  resolvePolicyRowSubtitle,
  resolvePolicyRowTitle,
} from "./policy-workspace-helpers";

export type PolicySortKey = "app" | "updated";
export type PolicySortState = { key: PolicySortKey; direction: "asc" | "desc" } | null;

const PAGE_SIZE = 5;
const TABLE_MIN_WIDTH_CLASS = "min-w-[980px]";

function PolicyActionBadge({ action }: { action: string }) {
  if (action === "allow") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-300 bg-emerald-50 px-2.5 py-0.5 text-xs font-semibold text-emerald-800">
        <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" />
        Allow
      </span>
    );
  }
  if (action === "block") {
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-rose-300 bg-rose-50 px-2.5 py-0.5 text-xs font-semibold text-rose-800">
        <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" />
        Block
      </span>
    );
  }
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-amber-300 bg-amber-50 px-2.5 py-0.5 text-xs font-semibold text-amber-900">
      {policyActionLabel(action)}
    </span>
  );
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

function PolicyEvidenceLink({
  policy,
  onNavigate,
}: {
  policy: GuardPolicyDecision;
  onNavigate?: (pathname: string) => void;
}) {
  const href = resolvePolicyEvidenceHref(policy);
  const label = resolvePolicyApprovalRecordLabel(policy);
  const handleClick = useCallback(
    (event: MouseEvent<HTMLAnchorElement>) => {
      if (!onNavigate) {
        return;
      }
      event.preventDefault();
      onNavigate(href);
    },
    [href, onNavigate],
  );

  return (
    <a
      href={guardAwareHref(href)}
      onClick={handleClick}
      className="inline-flex max-w-full items-center gap-1 font-mono text-xs font-medium text-brand-blue hover:underline"
      title={`Open receipt ${policy.source_receipt_id ?? label} in Evidence`}
    >
      {label}
    </a>
  );
}

type PolicyRuleRowProps = {
  policy: GuardPolicyDecision;
  cloudControlsUrl: string | null;
  onClear?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
  cloudVariant?: boolean;
};

function PolicyRuleRow({ policy, cloudControlsUrl, onClear, onNavigate, cloudVariant = false }: PolicyRuleRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = cloudVariant || isCloudManagedPolicy(policy.source);
  const display = resolvePolicyDisplay(policy);
  const canClear = onClear !== undefined && !cloudManaged;
  const family = resolvePolicyMatcherFamily(policy);
  const Icon = resolveFamilyIcon(family);
  const title = resolvePolicyRowTitle(policy, display);
  const subtitle = resolvePolicyRowSubtitle(policy, display);
  const folder = resolvePolicyRowFolder(policy);
  const frequency = resolvePolicyRowFrequency(policy);
  const scopeTag = scopeLabel(policy.scope, "policy");

  return (
    <EvidenceTableRow>
      <EvidenceTableCell className="w-10">
        <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500">
          <Icon className="h-4 w-4" aria-hidden="true" />
        </span>
      </EvidenceTableCell>

      <EvidenceTableCell className="w-[88px] whitespace-nowrap">
        <PolicyActionBadge action={policy.action} />
      </EvidenceTableCell>

      <EvidenceTableCell className="min-w-[240px] max-w-[360px]">
        <p className="font-semibold leading-snug text-brand-dark">{title}</p>
        {subtitle ? <p className="mt-1 text-xs leading-relaxed text-slate-500">{subtitle}</p> : null}
        <div className="mt-2 space-y-1 text-xs text-slate-600 lg:hidden">
          <p>
            <span className="font-medium text-slate-700">Folder:</span> {folder ?? "Not recorded"}
          </p>
          <p>
            <span className="font-medium text-slate-700">Frequency:</span> {frequency}
          </p>
          <p>
            <span className="font-medium text-slate-700">App:</span> {harnessDisplayName(policy.harness)}
          </p>
        </div>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[96px] lg:table-cell">
        {cloudManaged ? (
          <Tag tone="blue">{resolvePolicyRowSourceLabel(policy)}</Tag>
        ) : (
          <span className="text-sm text-brand-dark">{resolvePolicyRowSourceLabel(policy)}</span>
        )}
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[104px] lg:table-cell">
        <Tag tone="blue">{scopeTag}</Tag>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[96px] lg:table-cell">
        <span className="font-medium text-brand-blue">{harnessDisplayName(policy.harness)}</span>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[104px] whitespace-nowrap text-xs text-slate-500 lg:table-cell">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : "—"}
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden min-w-[120px] lg:table-cell">
        {!cloudManaged ? <PolicyEvidenceLink policy={policy} onNavigate={onNavigate} /> : null}
        {cloudManaged && cloudControlsUrl ? (
          <a
            href={cloudControlsUrl}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline"
          >
            <HiMiniCloudArrowUp className="h-3.5 w-3.5" aria-hidden="true" />
            View on cloud
          </a>
        ) : null}
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[88px] text-right lg:table-cell">
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
            Remove
          </button>
        ) : null}
      </EvidenceTableCell>
    </EvidenceTableRow>
  );
}

type PolicyRuleTableProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
  emptyTitle: string;
  emptyBody: string;
  cloudVariant?: boolean;
  totalCount?: number;
  viewAllLabel?: string;
};

export function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  emptyTitle,
  emptyBody,
  cloudVariant = false,
  totalCount,
  viewAllLabel,
}: PolicyRuleTableProps) {
  const [visibleCount, setVisibleCount] = useState(PAGE_SIZE);
  const [expanded, setExpanded] = useState(false);

  useEffect(() => {
    setExpanded(false);
    setVisibleCount(PAGE_SIZE);
  }, [policies]);

  const visiblePolicies = useMemo(
    () => (expanded ? policies : policies.slice(0, visibleCount)),
    [expanded, policies, visibleCount],
  );
  const remaining = policies.length - visiblePolicies.length;
  const hasMore = !expanded && remaining > 0;
  const listTotal = totalCount ?? policies.length;

  const handleShowMore = useCallback(() => {
    setVisibleCount((current) => current + PAGE_SIZE);
  }, []);

  const handleViewAll = useCallback(() => {
    setExpanded(true);
  }, []);

  if (policies.length === 0) {
    return <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />;
  }

  return (
    <div className="space-y-3">
      <EvidenceTable label={cloudVariant ? "Cloud policy rules" : "Remembered policy rules"} tableClassName={TABLE_MIN_WIDTH_CLASS}>
          <EvidenceTableHead>
            <EvidenceTableHeader className="w-10" />
            <EvidenceTableHeader>Action</EvidenceTableHeader>
            <EvidenceTableHeader>Rule</EvidenceTableHeader>
            <EvidenceTableHeader className="hidden lg:table-cell">Source</EvidenceTableHeader>
            <EvidenceTableHeader className="hidden lg:table-cell">Scope</EvidenceTableHeader>
            <EvidenceTableHeader className="hidden lg:table-cell">
              {cloudVariant ? "Applies to" : "App"}
            </EvidenceTableHeader>
            <EvidenceTableHeader className="hidden lg:table-cell">Updated</EvidenceTableHeader>
            <EvidenceTableHeader className="hidden lg:table-cell">
              {cloudVariant ? "Policy" : "Approval record"}
            </EvidenceTableHeader>
            <EvidenceTableHeader className="hidden text-right lg:table-cell">
              {cloudVariant ? "" : "Actions"}
            </EvidenceTableHeader>
          </EvidenceTableHead>
          <EvidenceTableBody>
            {visiblePolicies.map((policy) => (
              <PolicyRuleRow
                key={`${policy.harness}-${policy.scope}-${policy.artifact_id ?? policy.publisher ?? "global"}-${policy.updated_at ?? ""}-${policy.source}`}
                policy={policy}
                cloudControlsUrl={cloudControlsUrl}
                onClear={onClearPolicy}
                onNavigate={onNavigate}
                cloudVariant={cloudVariant}
              />
            ))}
          </EvidenceTableBody>
      </EvidenceTable>

      {hasMore && viewAllLabel ? (
        <div className="flex justify-center pt-1">
          <button
            type="button"
            onClick={handleViewAll}
            className="text-sm font-medium text-brand-blue hover:underline"
          >
            {viewAllLabel.replace("{count}", String(listTotal))}
          </button>
        </div>
      ) : hasMore ? (
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
  badge?: string;
  description: string;
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
  emptyTitle: string;
  emptyBody: string;
  defaultOpen?: boolean;
  cloudVariant?: boolean;
  viewAllLabel?: string;
};

export function GroupedPolicySection({
  title,
  badge,
  description,
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  emptyTitle,
  emptyBody,
  defaultOpen = true,
  cloudVariant = false,
  viewAllLabel,
}: GroupedPolicySectionProps) {
  const [open, setOpen] = useState(defaultOpen);
  const handleToggle = useCallback(() => setOpen((current) => !current), []);
  const ruleLabel = policies.length === 1 ? "1 rule" : `${policies.length} rules`;

  if (policies.length === 0) {
    return (
      <section className="space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
          {badge ? <Tag tone="slate">{badge}</Tag> : null}
        </div>
        <p className="text-sm text-slate-500">{description}</p>
        <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />
      </section>
    );
  }

  return (
    <section className="space-y-3">
      <button
        type="button"
        onClick={handleToggle}
        className="flex w-full items-start justify-between gap-3 text-left"
        aria-expanded={open}
      >
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-brand-dark">{title}</h2>
            {badge ? <Tag tone="slate">{badge}</Tag> : null}
          </div>
          <p className="mt-1 text-sm text-slate-500">{description}</p>
        </div>
        <div className="flex shrink-0 items-center gap-2 pt-0.5">
          <span className="text-sm text-slate-500">{ruleLabel}</span>
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
          onNavigate={onNavigate}
          emptyTitle={emptyTitle}
          emptyBody={emptyBody}
          cloudVariant={cloudVariant}
          totalCount={policies.length}
          viewAllLabel={viewAllLabel}
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
