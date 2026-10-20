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
  resolvePolicyRowTitle,
  sortPolicyDecisions,
  type PolicySortKey,
  type PolicySortState,
} from "./policy-workspace-helpers";
import { resolvePolicyRowSourceLabel } from "./policy-managed-authority";
import { GoverningExtensionLink } from "./policy-governing-extension-link";
import { isBulkRemovablePolicy, policySelectionKey } from "./policy-rules-overview-model";
import { isBroadAllow, isStaleRule } from "./policy-rules-hero-model";
export type { PolicySortKey, PolicySortState };
const PAGE_SIZE = 10;
const TABLE_MIN_WIDTH_CLASS = "min-w-[520px] lg:min-w-[820px]";

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
  selected?: boolean;
  onToggleSelect?: (policy: GuardPolicyDecision) => void;
  onInspect?: (policy: GuardPolicyDecision) => void;
};

function PolicyRuleRow({ policy, cloudControlsUrl, onClear, onNavigate, cloudVariant = false, selected = false, onToggleSelect, onInspect }: PolicyRuleRowProps) {
  const handleClear = useCallback(() => onClear?.(policy), [onClear, policy]);
  const handleInspect = useCallback(() => onInspect?.(policy), [onInspect, policy]);
  const handleToggleSelect = useCallback(() => onToggleSelect?.(policy), [onToggleSelect, policy]);
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
        <div className="flex items-center gap-2">
          {canClear && onToggleSelect && isBulkRemovablePolicy(policy) ? (
            <input
              type="checkbox"
              checked={selected}
              onChange={handleToggleSelect}
              aria-label={`Select rule ${title} for removal`}
              className="h-4 w-4 shrink-0 rounded border-slate-300 accent-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30"
            />
          ) : null}
          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-slate-100 text-slate-500">
            <Icon className="h-4 w-4" aria-hidden="true" />
          </span>
        </div>
      </EvidenceTableCell>

      <EvidenceTableCell className="w-[88px] whitespace-nowrap">
        <PolicyActionBadge action={policy.action} />
      </EvidenceTableCell>

      <EvidenceTableCell className="min-w-[150px] max-w-[260px] sm:min-w-[200px]">
        <p className="truncate font-semibold leading-snug text-brand-dark" title={title}>
          {title}
        </p>
        {kindLine ? (
          <p className="mt-0.5 truncate text-xs leading-relaxed text-slate-500" title={kindLine}>
            {kindLine}
          </p>
        ) : null}
        <p className="mt-1 break-words text-xs leading-relaxed text-slate-600">{display.rememberSentence}</p>
        {isBroadAllow(policy) || isStaleRule(policy, new Date()) ? (
          <span className="guard-state-pill mt-1.5" data-tone="attention">
            <span className="guard-state-pill-dot" aria-hidden="true" />
            {isBroadAllow(policy) ? "Broad allow" : "Not changed in 90+ days"}
          </span>
        ) : null}
        <div className="mt-2 flex flex-wrap gap-x-3 gap-y-1 text-xs text-slate-600 lg:hidden">
          <span>
            <span className="font-medium text-slate-700">Source:</span> {resolvePolicyRowSourceLabel(policy)}
          </span>
          <span>
            <span className="font-medium text-slate-700">Scope:</span> {scopeTag}
          </span>
          {folder ? (
            <span>
              <span className="font-medium text-slate-700">Folder:</span> {folder}
            </span>
          ) : null}
          <span>
            <span className="font-medium text-slate-700">App:</span> {harnessDisplayName(policy.harness)}
          </span>
          {policy.updated_at ? (
            <span>
              <span className="font-medium text-slate-700">Updated:</span> {formatRelativeTime(policy.updated_at)}
            </span>
          ) : null}
          {onInspect ? (
            <button type="button" onClick={handleInspect} className="font-semibold text-brand-blue" aria-label={`Inspect rule ${title}`}>
              Inspect
            </button>
          ) : null}
        </div>
        <GoverningExtensionLink policy={policy} onNavigate={onNavigate} />
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[88px] whitespace-nowrap lg:table-cell">
        <Tag tone={cloudManaged ? "slate" : "blue"}>{resolvePolicyRowSourceLabel(policy)}</Tag>
      </EvidenceTableCell>

      <EvidenceTableCell className="hidden w-[96px] whitespace-nowrap lg:table-cell">
        <span className="font-medium text-brand-blue">{harnessDisplayName(policy.harness)}</span>
        <span className="mt-0.5 block text-xs font-normal text-slate-500">{scopeTag}</span>
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

      <EvidenceTableCell className="hidden w-[150px] text-right lg:table-cell">
        <div className="flex items-center justify-end gap-2">
          {cloudManaged ? (
            <span className="whitespace-nowrap text-xs font-medium text-slate-500">Read-only</span>
          ) : null}
          {onInspect ? (
            <button
              type="button"
              onClick={handleInspect}
              className="inline-flex min-h-8 items-center whitespace-nowrap rounded-lg px-2 text-xs font-semibold text-brand-blue hover:bg-brand-blue/[0.06]"
              aria-label={`Inspect rule ${title}`}
            >
              Inspect
            </button>
          ) : null}
          {canClear ? (
            <button
              type="button"
              onClick={handleClear}
              className="inline-flex items-center gap-1 whitespace-nowrap text-xs font-medium text-rose-600 hover:text-rose-700"
            >
              Remove rule
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
