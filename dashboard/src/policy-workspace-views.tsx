import { useCallback, useEffect, useMemo, useState } from "react";
import { HiMiniTrash, HiMiniChevronDown, HiMiniChevronUp } from "react-icons/hi2";
import { EmptyState, PaginationControls, Tag } from "./approval-center-primitives";
import type { GuardPolicyDecision } from "./guard-types";
import {
  EvidenceTable,
  EvidenceTableBody,
  EvidenceTableHead,
  EvidenceTableHeader,
} from "./evidence/evidence-table";
import {
  resolvePolicyMatcherFamily,
  sortPolicyDecisions,
  type PolicySortKey,
  type PolicySortState,
} from "./policy-workspace-helpers";
import { policySelectionKey } from "./policy-rules-overview-model";
import { PolicyRuleRow } from "./policy-workspace-row";
export type { PolicySortKey, PolicySortState };
const PAGE_SIZE = 10;
const TABLE_MIN_WIDTH_CLASS = "min-w-[500px] lg:min-w-[680px]";

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

type PolicyRuleTableProps = {
  policies: GuardPolicyDecision[];
  cloudControlsUrl: string | null;
  onClearPolicy?: (policy: GuardPolicyDecision) => void;
  onNavigate?: (pathname: string) => void;
  emptyTitle: string;
  emptyBody: string;
  emptyAction?: React.ReactNode;
  cloudVariant?: boolean;
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
  selectedKeys?: ReadonlySet<string>;
  onToggleSelect?: (policy: GuardPolicyDecision) => void;
  onClearSelection?: () => void;
  onRemoveSelected?: () => void;
  removingSelected?: boolean;
  removeError?: string | null;
  onInspect?: (policy: GuardPolicyDecision) => void;
};

export function PolicyRuleTable({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onNavigate,
  emptyTitle,
  emptyBody,
  emptyAction,
  cloudVariant = false,
  sort,
  onSortChange,
  selectedKeys,
  onToggleSelect,
  onClearSelection,
  onRemoveSelected,
  removingSelected = false,
  removeError = null,
  onInspect,
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
  const selectedCount = selectedKeys?.size ?? 0;

  const handlePrevious = useCallback(() => {
    setPage((current) => Math.max(1, current - 1));
  }, []);

  const handleNext = useCallback(() => {
    setPage((current) => Math.min(totalPages, current + 1));
  }, [totalPages]);

  if (policies.length === 0) {
    return <EmptyState title={emptyTitle} body={emptyBody} tone="teach" action={emptyAction} />;
  }

  return (
    <div className="space-y-3">
      {selectedCount > 0 ? (
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-3 py-2" role="status">
          <p className="text-sm font-medium text-brand-dark">
            {selectedCount} {selectedCount === 1 ? "rule" : "rules"} selected
          </p>
          <div className="flex flex-wrap items-center gap-2">
            <button type="button" onClick={onClearSelection} disabled={removingSelected} className="min-h-9 rounded-lg px-2 text-sm font-medium text-slate-600 hover:text-brand-dark disabled:opacity-50">
              Clear selection
            </button>
            <button
              type="button"
              onClick={onRemoveSelected}
              disabled={removingSelected}
              className="inline-flex min-h-9 items-center gap-1.5 rounded-lg bg-rose-600 px-3 text-sm font-medium text-white hover:bg-rose-700 focus:outline-none focus:ring-2 focus:ring-rose-600/30 disabled:opacity-50"
            >
              <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
              {removingSelected ? "Removing…" : "Remove selected"}
            </button>
          </div>
          {removeError ? (
            <p className="w-full text-sm text-rose-700" role="alert">{removeError}</p>
          ) : null}
        </div>
      ) : null}
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
            label={cloudVariant ? "Applies to" : "App"}
            sortKey="app"
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
              key={policySelectionKey(policy)}
              policy={policy}
              cloudControlsUrl={cloudControlsUrl}
              onClear={onClearPolicy}
              onNavigate={onNavigate}
              cloudVariant={cloudVariant}
              selected={selectedKeys?.has(policySelectionKey(policy)) ?? false}
              onToggleSelect={onToggleSelect}
              onInspect={onInspect}
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
  emptyAction?: React.ReactNode;
  defaultOpen?: boolean;
  cloudVariant?: boolean;
  sort: PolicySortState;
  onSortChange: (sort: PolicySortState) => void;
  selectedKeys?: ReadonlySet<string>;
  onToggleSelect?: (policy: GuardPolicyDecision) => void;
  onClearSelection?: () => void;
  onRemoveSelected?: () => void;
  removingSelected?: boolean;
  removeError?: string | null;
  onInspect?: (policy: GuardPolicyDecision) => void;
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
  emptyAction,
  defaultOpen = true,
  cloudVariant = false,
  sort,
  onSortChange,
  selectedKeys,
  onToggleSelect,
  onClearSelection,
  onRemoveSelected,
  removingSelected,
  removeError,
  onInspect,
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
        <EmptyState title={emptyTitle} body={emptyBody} tone="teach" action={emptyAction} />
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
          emptyAction={emptyAction}
          cloudVariant={cloudVariant}
          sort={sort}
          onSortChange={onSortChange}
          selectedKeys={selectedKeys}
          onToggleSelect={onToggleSelect}
          onClearSelection={onClearSelection}
          onRemoveSelected={onRemoveSelected}
          removingSelected={removingSelected}
          removeError={removeError}
          onInspect={onInspect}
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
