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
  HiMiniShieldCheck,
  HiMiniNoSymbol,
  HiMiniCheckCircle,
  HiMiniEllipsisVertical,
  HiMiniArrowTopRightOnSquare,
} from "react-icons/hi2";
import { EmptyState, PaginationControls, Tag } from "./approval-center-primitives";
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
  resolvePolicyRowSourceLabel,
  resolvePolicyRowTitle,
  sortPolicyDecisions,
  type PolicySortKey,
  type PolicySortState,
} from "./policy-workspace-helpers";

export type { PolicySortKey, PolicySortState };

const PAGE_SIZE = 10;
const TABLE_MIN_WIDTH_CLASS = "min-w-[1040px]";

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

function PolicySortHeader({
  label,
  sortKey,
  sort,
  onSortChange,
  className = "",
}: {
  label: string;
  sortKey: PolicySortKey;
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
  className?: string;
}) {
  const active = sort?.key === sortKey;
  const ascending = active && sort?.direction === "asc";

  const handleClick = useCallback(() => {
    if (!active) {
      onSortChange({ key: sortKey, direction: sortKey === "updated" ? "desc" : "asc" });
      return;
    }
    onSortChange({ key: sortKey, direction: ascending ? "desc" : "asc" });
  }, [active, ascending, onSortChange, sortKey]);

  return (
    <EvidenceTableHeader className={className}>
      <button
        type="button"
        onClick={handleClick}
        className="inline-flex items-center gap-1 transition-colors hover:text-brand-dark"
        aria-label={`Sort by ${label}${active ? (ascending ? ", ascending" : ", descending") : ""}`}
      >
        {label}
        {active ? (
          ascending ? (
            <HiMiniChevronUp className="h-3 w-3" aria-hidden="true" />
          ) : (
            <HiMiniChevronDown className="h-3 w-3" aria-hidden="true" />
          )
        ) : null}
      </button>
    </EvidenceTableHeader>
  );
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
      title={`Open ${label} in Evidence`}
    >
      <span className="truncate">{label}</span>
      <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
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
  const kindLine = display.kindLine;
  const scopeTag = scopeLabel(policy.scope, "policy");
  const folder = resolvePolicyRowFolder(policy);

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

      <EvidenceTableCell className="min-w-[220px] max-w-[320px]">
        <p className="truncate font-semibold leading-snug text-brand-dark" title={title}>
          {title}
        </p>
        {kindLine ? (
          <p className="mt-0.5 truncate text-xs leading-relaxed text-slate-500" title={kindLine}>
            {kindLine}
          </p>
        ) : null}
        <div className="mt-2 space-y-1 text-xs text-slate-600 lg:hidden">
          <p>
            <span className="font-medium text-slate-700">Source:</span> {resolvePolicyRowSourceLabel(policy)}
          </p>
          <p>
            <span className="font-medium text-slate-700">Scope:</span> {scopeTag}
          </p>
          {folder ? (
            <p>
              <span className="font-medium text-slate-700">Folder:</span> {folder}
            </p>
          ) : null}
          <p>
            <span className="font-medium text-slate-700">App:</span> {harnessDisplayName(policy.harness)}
          </p>
        </div>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[88px] lg:table-cell">
        <span className="text-sm text-brand-dark">{resolvePolicyRowSourceLabel(policy)}</span>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[104px] lg:table-cell">
        <button type="button" className="text-sm font-medium text-brand-blue hover:underline">
          {scopeTag}
        </button>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[96px] lg:table-cell">
        <span className="font-medium text-brand-blue">{harnessDisplayName(policy.harness)}</span>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[104px] whitespace-nowrap text-xs text-slate-500 lg:table-cell">
        {policy.updated_at ? formatRelativeTime(policy.updated_at) : "—"}
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden min-w-[132px] lg:table-cell">
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

      <EvidenceTableCell className="hidden w-[108px] text-right lg:table-cell">
        <div className="flex items-center justify-end gap-2">
          {cloudManaged ? (
            <span className="text-xs font-medium text-slate-500">Read-only</span>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              className="inline-flex items-center gap-1 text-xs font-medium text-rose-600 hover:text-rose-700"
            >
              Remove rule
            </button>
          ) : null}
          {!cloudManaged ? (
            <button
              type="button"
              className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-brand-dark"
              aria-label="More actions"
            >
              <HiMiniEllipsisVertical className="h-4 w-4" aria-hidden="true" />
            </button>
          ) : null}
        </div>
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
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
};

export function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  emptyTitle,
  emptyBody,
  cloudVariant = false,
  sort,
  onSortChange,
}: PolicyRuleTableProps) {
  const [page, setPage] = useState(1);

  const sortedPolicies = useMemo(() => sortPolicyDecisions(policies, sort), [policies, sort]);

  useEffect(() => {
    setPage(1);
  }, [policies, sort]);

  const totalPages = Math.max(1, Math.ceil(sortedPolicies.length / PAGE_SIZE));
  const safePage = Math.min(page, totalPages);
  const pageStart = (safePage - 1) * PAGE_SIZE;
  const visiblePolicies = sortedPolicies.slice(pageStart, pageStart + PAGE_SIZE);

  const handlePrevious = useCallback(() => {
    setPage((current) => Math.max(1, current - 1));
  }, []);

  const handleNext = useCallback(() => {
    setPage((current) => Math.min(totalPages, current + 1));
  }, [totalPages]);

  if (policies.length === 0) {
    return <EmptyState title={emptyTitle} body={emptyBody} tone="teach" />;
  }

  return (
    <div className="space-y-3">
      <EvidenceTable label={cloudVariant ? "Cloud policy rules" : "Remembered policy rules"} tableClassName={TABLE_MIN_WIDTH_CLASS}>
        <EvidenceTableHead>
          <EvidenceTableHeader className="w-10" />
          <PolicySortHeader label="Action" sortKey="action" sort={sort} onSortChange={onSortChange} className="w-[88px]" />
          <PolicySortHeader label="Rule" sortKey="rule" sort={sort} onSortChange={onSortChange} className="min-w-[220px]" />
          <PolicySortHeader
            label="Source"
            sortKey="source"
            sort={sort}
            onSortChange={onSortChange}
            className="hidden lg:table-cell"
          />
          <PolicySortHeader
            label="Scope"
            sortKey="scope"
            sort={sort}
            onSortChange={onSortChange}
            className="hidden lg:table-cell"
          />
          <PolicySortHeader
            label={cloudVariant ? "Applies to" : "App"}
            sortKey="app"
            sort={sort}
            onSortChange={onSortChange}
            className="hidden lg:table-cell"
          />
          <PolicySortHeader
            label="Updated"
            sortKey="updated"
            sort={sort}
            onSortChange={onSortChange}
            className="hidden lg:table-cell"
          />
          <PolicySortHeader
            label={cloudVariant ? "Policy" : "Approval record"}
            sortKey="approval"
            sort={sort}
            onSortChange={onSortChange}
            className="hidden lg:table-cell"
          />
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

      {sortedPolicies.length > PAGE_SIZE ? (
        <PaginationControls
          page={safePage}
          totalPages={totalPages}
          totalItems={sortedPolicies.length}
          pageSize={PAGE_SIZE}
          onPrevious={handlePrevious}
          onNext={handleNext}
        />
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
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
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
  sort,
  onSortChange,
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
          sort={sort}
          onSortChange={onSortChange}
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
