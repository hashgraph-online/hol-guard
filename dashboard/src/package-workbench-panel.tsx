import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent, ReactNode } from "react";
import {
  HiMiniArrowDown,
  HiMiniArrowUp,
  HiMiniArrowPath,
  HiMiniBugAnt,
  HiMiniChevronLeft,
  HiMiniChevronRight,
  HiMiniExclamationTriangle,
  HiMiniMagnifyingGlass,
  HiMiniXMark,
} from "react-icons/hi2";
import { SectionLabel, Tag, ActionButton, EmptyState, IconActionButton } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import { GuardModalLayer } from "./guard-modal-layer";
import { AuditProgressStepList, auditProgressActive } from "./audit-run-progress";
import type { AuditRunPhase } from "./use-supply-chain-audit-session";
import type {
  PackageWorkbenchFilters,
  PackageWorkbenchSortKey,
  SupplyChainAuditDecision,
  SupplyChainAuditFinding,
  SupplyChainAuditSeverity,
  SupplyChainAuditSnapshot,
} from "./guard-types";
import {
  filterPackageWorkbenchFindings,
  packageWorkbenchEcosystems,
  sortPackageWorkbenchFindings,
} from "./supply-chain-audit-normalize";
import { ConnectFlowCard } from "./supply-chain-firewall-views";
import type { AuditConnectGateViewState } from "./supply-chain-firewall-panel";

const WORKBENCH_PAGE_SIZE = 25;

type PackageViewMode = "all" | "review";

type PackageWorkbenchPanelProps = {
  auditConnectGate?: AuditConnectGateViewState | null;
  auditError?: string | null;
  auditSnapshot: SupplyChainAuditSnapshot | null;
  onRunAudit?: () => void;
  auditRunning?: boolean;
  auditPhase?: AuditRunPhase;
  cloudState?: string | null;
};

const decisionTone = (
  decision: SupplyChainAuditDecision,
): "destructive" | "attention" | "warning" | "info" | "green" | "default" => {
  if (decision === "block") {
    return "destructive";
  }
  if (decision === "ask") {
    return "attention";
  }
  if (decision === "warn") {
    return "warning";
  }
  if (decision === "monitor") {
    return "info";
  }
  if (decision === "allow") {
    return "green";
  }
  return "default";
};

const severityTone = (
  severity: SupplyChainAuditSeverity,
): "destructive" | "attention" | "warning" | "info" | "default" => {
  if (severity === "critical") {
    return "destructive";
  }
  if (severity === "high") {
    return "attention";
  }
  if (severity === "medium") {
    return "warning";
  }
  if (severity === "low") {
    return "info";
  }
  return "default";
};

function humanizeReasonMessage(code: string, message: string): string {
  if (code === "unknown_package") {
    return "Guard Cloud has not indexed this package yet. It is not treated as a security finding.";
  }
  if (code === "no_cached_match") {
    return "No local intel match yet. Sync Guard Cloud or retry after the next bundle refresh.";
  }
  return message;
}

type WorkbenchHeaderProps = {
  auditSnapshot: SupplyChainAuditSnapshot;
  flaggedCount: number;
  packageCount: number;
  cloudState?: string | null;
};

function cloudIntelLabel(cloudState: string | null | undefined, source: string | null): string {
  if (cloudState === "local_only") {
    return "Local intel only";
  }
  if (source !== null && source.length > 0) {
    return `${source} intel`;
  }
  return "Guard Cloud";
}

function cloudIntelTone(cloudState: string | null | undefined): "attention" | "green" | "info" {
  if (cloudState === "local_only") {
    return "attention";
  }
  if (cloudState === "paired_active") {
    return "green";
  }
  return "info";
}

function WorkbenchHeader({
  auditSnapshot,
  flaggedCount,
  packageCount,
  cloudState,
}: WorkbenchHeaderProps) {
  const manifestSummary =
    auditSnapshot.manifestPaths.length > 0
      ? `${auditSnapshot.manifestPaths.length} manifest${auditSnapshot.manifestPaths.length === 1 ? "" : "s"}`
      : null;
  const lockfileSummary =
    auditSnapshot.lockfilePaths.length > 0
      ? `${auditSnapshot.lockfilePaths.length} lockfile${auditSnapshot.lockfilePaths.length === 1 ? "" : "s"}`
      : null;
  const scanSummary = [manifestSummary, lockfileSummary].filter((entry) => entry !== null).join(" · ");

  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-center gap-2 text-xs text-slate-500">
        <Tag tone={decisionTone(auditSnapshot.decision)}>{auditSnapshot.decision}</Tag>
        <Tag tone={cloudIntelTone(cloudState)}>{cloudIntelLabel(cloudState, auditSnapshot.source)}</Tag>
        <span>
          {auditSnapshot.inventory.totalPackages} package
          {auditSnapshot.inventory.totalPackages === 1 ? "" : "s"} indexed
        </span>
        <span aria-hidden="true">·</span>
        <span>
          {packageCount} in table
        </span>
        <span aria-hidden="true">·</span>
        <span>
          {flaggedCount} need review
        </span>
        <span aria-hidden="true">·</span>
        <span>Last audit {formatRelativeTime(auditSnapshot.generatedAt)}</span>
      </div>
      {scanSummary.length > 0 ? (
        <p className="text-[11px] text-slate-400">Scanned {scanSummary} across this workspace.</p>
      ) : null}
    </div>
  );
}

type FindingDetailPanelProps = {
  finding: SupplyChainAuditFinding;
  onClose: () => void;
};

function FindingDetailPanel({ finding, onClose }: FindingDetailPanelProps) {
  const handleClose = useCallback(() => {
    onClose();
  }, [onClose]);

  return (
    <div className="max-h-[min(85vh,40rem)] overflow-y-auto rounded-2xl border border-slate-100 bg-white shadow-xl">
      <div className="sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-slate-100 bg-white/95 px-4 py-3 backdrop-blur-sm">
        <div className="min-w-0">
          <p className="text-base font-semibold text-brand-dark">{finding.packageName}</p>
          <p className="mt-0.5 text-xs text-slate-500">
            {finding.ecosystem}
            {finding.namespace !== null ? ` · ${finding.namespace}` : ""}
          </p>
        </div>
        <IconActionButton
          variant="ghost"
          label="Close finding detail"
          icon={<HiMiniXMark className="h-4 w-4" />}
          onClick={handleClose}
        />
      </div>
      <div className="px-4 py-4">
        <div className="flex flex-wrap items-center gap-2">
          <Tag tone={decisionTone(finding.decision)}>{finding.decision}</Tag>
          <Tag tone={severityTone(finding.severity)}>{finding.severity}</Tag>
        </div>
        {finding.reasons.length > 0 ? (
          <ul className="mt-4 space-y-3">
            {finding.reasons.map((reason) => (
              <li
                key={`${finding.id}-${reason.code}`}
                className="rounded-xl border border-slate-100 bg-slate-50/80 px-3 py-2.5 text-xs leading-relaxed text-slate-600"
              >
                <span className="font-semibold text-slate-700">{reason.code}</span>
                <span className="text-slate-400"> · </span>
                {humanizeReasonMessage(reason.code, reason.message)}
              </li>
            ))}
          </ul>
        ) : (
          <p className="mt-4 text-xs text-slate-500">No advisory detail recorded for this package yet.</p>
        )}
        <div className="mt-5">
          <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
            Advisory aliases
          </p>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {finding.advisoryAliases.map((alias) => (
              <span
                key={`${finding.id}-${alias}`}
                className="rounded-full border border-slate-200 bg-white px-2.5 py-0.5 font-mono text-[11px] text-slate-600"
              >
                {alias}
              </span>
            ))}
          </div>
          {finding.advisoryAliases.length === 0 ? (
            <p className="mt-2 text-[11px] text-slate-500">
              No linked CVE or GHSA aliases for this finding.
            </p>
          ) : null}
        </div>
      </div>
    </div>
  );
}

type FindingRowProps = {
  finding: SupplyChainAuditFinding;
  selected: boolean;
  onSelect: (id: string) => void;
};

function FindingRow({ finding, selected, onSelect }: FindingRowProps) {
  const handleSelect = useCallback(() => {
    onSelect(finding.id);
  }, [finding.id, onSelect]);

  return (
    <button
      type="button"
      onClick={handleSelect}
      aria-pressed={selected}
      className={`flex w-full items-center justify-between gap-3 border-b border-slate-100 px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-slate-50/70 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30 ${
        selected ? "bg-brand-blue/[0.04]" : ""
      }`}
    >
      <div className="min-w-0">
        <p className="truncate text-sm font-medium text-brand-dark">{finding.packageName}</p>
        <p className="mt-0.5 truncate text-xs text-slate-500">
          {finding.ecosystem}
          {finding.namespace !== null ? ` · ${finding.namespace}` : ""}
        </p>
      </div>
      <div className="flex shrink-0 items-center gap-2">
        <Tag tone={decisionTone(finding.decision)}>{finding.decision}</Tag>
        <Tag tone={severityTone(finding.severity)}>{finding.severity}</Tag>
      </div>
    </button>
  );
}

type WorkbenchPaginationProps = {
  page: number;
  pageCount: number;
  total: number;
  onPageChange: (page: number) => void;
};

function WorkbenchPagination({ page, pageCount, total, onPageChange }: WorkbenchPaginationProps) {
  const handlePrevious = useCallback(() => {
    onPageChange(Math.max(0, page - 1));
  }, [onPageChange, page]);
  const handleNext = useCallback(() => {
    onPageChange(Math.min(pageCount - 1, page + 1));
  }, [onPageChange, page, pageCount]);

  if (pageCount <= 1) {
    return (
      <p className="text-xs text-slate-500">
        Showing {total} finding{total === 1 ? "" : "s"}
      </p>
    );
  }

  return (
    <div className="flex flex-wrap items-center justify-between gap-2">
      <p className="text-xs text-slate-500">
        Page {page + 1} of {pageCount} · {total} finding{total === 1 ? "" : "s"}
      </p>
      <div className="flex items-center gap-1">
        <ActionButton variant="outline" onClick={handlePrevious} disabled={page === 0}>
          <HiMiniChevronLeft className="h-4 w-4" aria-hidden="true" />
          Previous
        </ActionButton>
        <ActionButton variant="outline" onClick={handleNext} disabled={page >= pageCount - 1}>
          Next
          <HiMiniChevronRight className="h-4 w-4" aria-hidden="true" />
        </ActionButton>
      </div>
    </div>
  );
}

type SortButtonProps = {
  label: string;
  sortKey: PackageWorkbenchSortKey;
  activeSort: PackageWorkbenchSortKey;
  direction: "asc" | "desc";
  onSort: (sortKey: PackageWorkbenchSortKey) => void;
};

function SortButton({ label, sortKey, activeSort, direction, onSort }: SortButtonProps) {
  const handleClick = useCallback(() => {
    onSort(sortKey);
  }, [onSort, sortKey]);
  const active = activeSort === sortKey;
  let sortIcon: ReactNode = null;
  if (active) {
    sortIcon =
      direction === "desc" ? (
        <HiMiniArrowDown className="h-3 w-3" aria-hidden="true" />
      ) : (
        <HiMiniArrowUp className="h-3 w-3" aria-hidden="true" />
      );
  }
  return (
    <button
      type="button"
      onClick={handleClick}
      aria-pressed={active}
      className={`inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
        active
          ? "bg-brand-blue text-white"
          : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
      }`}
    >
      {label}
      {sortIcon}
    </button>
  );
}

type FilterChipProps = {
  label: string;
  active: boolean;
  onSelect: () => void;
};

function FilterChip({ label, active, onSelect }: FilterChipProps) {
  return (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={active}
      className={`rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
        active
          ? "bg-brand-dark text-white"
          : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
      }`}
    >
      {label}
    </button>
  );
}

type WorkbenchControlsProps = {
  filters: PackageWorkbenchFilters;
  ecosystems: string[];
  sortKey: PackageWorkbenchSortKey;
  sortDirection: "asc" | "desc";
  onSearchChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onEcosystemChange: (ecosystem: string) => void;
  onDecisionChange: (decision: PackageWorkbenchFilters["decision"]) => void;
  onSeverityChange: (severity: PackageWorkbenchFilters["severity"]) => void;
  onSortChange: (sortKey: PackageWorkbenchSortKey) => void;
};

function WorkbenchControls({
  filters,
  ecosystems,
  sortKey,
  sortDirection,
  onSearchChange,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange,
  onSortChange,
}: WorkbenchControlsProps) {
  const handleEcosystemAll = useCallback(() => onEcosystemChange("all"), [onEcosystemChange]);
  const handleDecisionAll = useCallback(() => onDecisionChange("all"), [onDecisionChange]);
  const handleDecisionBlock = useCallback(() => onDecisionChange("block"), [onDecisionChange]);
  const handleDecisionAsk = useCallback(() => onDecisionChange("ask"), [onDecisionChange]);
  const handleDecisionWarn = useCallback(() => onDecisionChange("warn"), [onDecisionChange]);
  const handleSeverityAll = useCallback(() => onSeverityChange("all"), [onSeverityChange]);
  const handleSeverityCritical = useCallback(() => onSeverityChange("critical"), [onSeverityChange]);
  const handleSeverityHigh = useCallback(() => onSeverityChange("high"), [onSeverityChange]);
  const handleSeverityMedium = useCallback(() => onSeverityChange("medium"), [onSeverityChange]);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5">
          <HiMiniMagnifyingGlass className="h-3.5 w-3.5 text-slate-400" aria-hidden="true" />
          <input
            type="search"
            placeholder="Search packages…"
            value={filters.search}
            onChange={onSearchChange}
            aria-label="Search package findings"
            className="w-44 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
          />
        </div>
        <FilterChip label="All ecosystems" active={filters.ecosystem === "all"} onSelect={handleEcosystemAll} />
        {ecosystems.map((ecosystem) => (
          <EcosystemChip
            key={ecosystem}
            ecosystem={ecosystem}
            active={filters.ecosystem === ecosystem}
            onSelect={onEcosystemChange}
          />
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <FilterChip label="All decisions" active={filters.decision === "all"} onSelect={handleDecisionAll} />
        <FilterChip label="Block" active={filters.decision === "block"} onSelect={handleDecisionBlock} />
        <FilterChip label="Ask" active={filters.decision === "ask"} onSelect={handleDecisionAsk} />
        <FilterChip label="Warn" active={filters.decision === "warn"} onSelect={handleDecisionWarn} />
        <span className="mx-1 h-4 w-px bg-slate-200" aria-hidden="true" />
        <FilterChip label="All severities" active={filters.severity === "all"} onSelect={handleSeverityAll} />
        <FilterChip label="Critical" active={filters.severity === "critical"} onSelect={handleSeverityCritical} />
        <FilterChip label="High" active={filters.severity === "high"} onSelect={handleSeverityHigh} />
        <FilterChip label="Medium" active={filters.severity === "medium"} onSelect={handleSeverityMedium} />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">Sort</span>
        <SortButton label="Severity" sortKey="severity" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
        <SortButton label="Package" sortKey="package" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
        <SortButton label="Ecosystem" sortKey="ecosystem" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
        <SortButton label="Decision" sortKey="decision" activeSort={sortKey} direction={sortDirection} onSort={onSortChange} />
      </div>
    </div>
  );
}

type EcosystemChipProps = {
  ecosystem: string;
  active: boolean;
  onSelect: (ecosystem: string) => void;
};

function EcosystemChip({ ecosystem, active, onSelect }: EcosystemChipProps) {
  const handleSelect = useCallback(() => {
    onSelect(ecosystem);
  }, [ecosystem, onSelect]);
  return <FilterChip label={ecosystem} active={active} onSelect={handleSelect} />;
}

type WorkbenchEmptyStateProps = {
  auditConnectGate?: AuditConnectGateViewState | null;
  auditError?: string | null;
};

function WorkbenchAuditErrorBanner({ message }: { message: string }) {
  return (
    <div
      className="mb-4 flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5"
      role="alert"
      aria-live="assertive"
      data-testid="workbench-audit-error"
    >
      <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">Workspace audit could not start</p>
        <p className="mt-0.5 text-xs leading-relaxed text-slate-600">{message}</p>
      </div>
    </div>
  );
}

function WorkbenchEmptyState({ auditConnectGate, auditError }: WorkbenchEmptyStateProps) {
  if (auditConnectGate !== null && auditConnectGate !== undefined) {
    return (
      <ConnectFlowCard
        compact
        connectError={auditConnectGate.connectError}
        connectStarting={auditConnectGate.connectStarting}
        connectFlow={auditConnectGate.connectFlow}
        detail={auditConnectGate.gate.detail}
        headline={auditConnectGate.gate.headline}
        mode={auditConnectGate.gate.mode}
        onStartConnect={auditConnectGate.onStartConnect}
        purpose="audit"
      />
    );
  }

  return (
    <>
      {auditError ? <WorkbenchAuditErrorBanner message={auditError} /> : null}
      <EmptyState
        title="No workspace audit yet"
        body="Run a workspace audit to index dependencies across npm, pnpm, PyPI, and other ecosystems found in this project."
        tone="teach"
      />
    </>
  );
}

type ViewModeChipProps = {
  label: string;
  active: boolean;
  onSelect: () => void;
};

function ViewModeChip({ label, active, onSelect }: ViewModeChipProps) {
  return <FilterChip label={label} active={active} onSelect={onSelect} />;
}

function ecosystemSummary(packages: SupplyChainAuditFinding[]): Array<{ ecosystem: string; count: number }> {
  const counts = new Map<string, number>();
  for (const pkg of packages) {
    counts.set(pkg.ecosystem, (counts.get(pkg.ecosystem) ?? 0) + 1);
  }
  return [...counts.entries()]
    .map(([ecosystem, count]) => ({ ecosystem, count }))
    .sort((left, right) => right.count - left.count || left.ecosystem.localeCompare(right.ecosystem));
}

export function PackageWorkbenchPanel({
  auditConnectGate = null,
  auditError = null,
  auditSnapshot,
  onRunAudit,
  auditRunning = false,
  auditPhase = "idle",
  cloudState = null,
}: PackageWorkbenchPanelProps) {
  const [viewMode, setViewMode] = useState<PackageViewMode>("all");
  const [filters, setFilters] = useState<PackageWorkbenchFilters>({
    ecosystem: "all",
    decision: "all",
    severity: "all",
    search: "",
  });
  const [sortState, setSortState] = useState<{
    sortKey: PackageWorkbenchSortKey;
    sortDirection: "asc" | "desc";
  }>({ sortKey: "severity", sortDirection: "desc" });
  const { sortKey, sortDirection } = sortState;
  const [selectedId, setSelectedId] = useState("");
  const [page, setPage] = useState(0);

  const findings = auditSnapshot?.findings ?? [];
  const packages = auditSnapshot?.packages ?? [];
  const tableSource = viewMode === "review" ? findings : packages;
  const progressActive = auditProgressActive(auditPhase, auditRunning);
  const showResults = auditSnapshot !== null && !progressActive && (auditConnectGate === null || auditConnectGate === undefined);
  const ecosystems = useMemo(() => packageWorkbenchEcosystems(tableSource), [tableSource]);
  const ecosystemBreakdown = useMemo(() => ecosystemSummary(packages), [packages]);
  const filteredFindings = useMemo(
    () => filterPackageWorkbenchFindings(tableSource, filters),
    [tableSource, filters],
  );
  const sortedFindings = useMemo(() => {
    const sorted = sortPackageWorkbenchFindings(filteredFindings, sortKey);
    if (sortDirection === "asc") {
      return [...sorted].reverse();
    }
    return sorted;
  }, [filteredFindings, sortDirection, sortKey]);
  const selectedFinding = useMemo(
    () => sortedFindings.find((finding) => finding.id === selectedId) ?? null,
    [selectedId, sortedFindings],
  );
  const pageCount = Math.max(1, Math.ceil(sortedFindings.length / WORKBENCH_PAGE_SIZE));
  const safePage = page >= pageCount ? 0 : page;
  const pagedFindings = useMemo(() => {
    const start = safePage * WORKBENCH_PAGE_SIZE;
    return sortedFindings.slice(start, start + WORKBENCH_PAGE_SIZE);
  }, [safePage, sortedFindings]);

  const handleSearchChange = useCallback((event: ChangeEvent<HTMLInputElement>) => {
    setFilters((prev) => ({ ...prev, search: event.target.value }));
    setSelectedId("");
    setPage(0);
  }, []);

  const handleEcosystemChange = useCallback((ecosystem: string) => {
    setFilters((prev) => ({ ...prev, ecosystem }));
    setSelectedId("");
    setPage(0);
  }, []);

  const handleDecisionChange = useCallback((decision: PackageWorkbenchFilters["decision"]) => {
    setFilters((prev) => ({ ...prev, decision }));
    setSelectedId("");
    setPage(0);
  }, []);

  const handleSeverityChange = useCallback((severity: PackageWorkbenchFilters["severity"]) => {
    setFilters((prev) => ({ ...prev, severity }));
    setSelectedId("");
    setPage(0);
  }, []);

  const handleSortChange = useCallback((nextSortKey: PackageWorkbenchSortKey) => {
    setSortState((prev) => {
      if (prev.sortKey === nextSortKey) {
        return {
          sortKey: prev.sortKey,
          sortDirection: prev.sortDirection === "desc" ? "asc" : "desc",
        };
      }
      return { sortKey: nextSortKey, sortDirection: "desc" };
    });
    setPage(0);
  }, []);

  const handleSelectFinding = useCallback((id: string) => {
    setSelectedId(id);
  }, []);

  const handleCloseFinding = useCallback(() => {
    setSelectedId("");
  }, []);

  const handlePageChange = useCallback((nextPage: number) => {
    setPage(nextPage);
    setSelectedId("");
  }, []);

  const handleViewAll = useCallback(() => {
    setViewMode("all");
    setPage(0);
    setSelectedId("");
  }, []);

  const handleViewReview = useCallback(() => {
    setViewMode("review");
    setPage(0);
    setSelectedId("");
  }, []);

  const handleRunAudit = useCallback(() => {
    onRunAudit?.();
  }, [onRunAudit]);

  const headerTitle = progressActive ? "Auditing workspace" : "Workspace audit";
  const headerBody = progressActive
    ? "Guard is scanning manifests, lockfiles, and package intel for this workspace."
    : "Browse indexed packages, filter by ecosystem, and open any row for advisory detail.";

  return (
    <div className="rounded-2xl border border-slate-100 bg-white shadow-sm" data-testid="workspace-audit-panel">
      <div className="border-b border-slate-100 px-4 py-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <SectionLabel>{headerTitle}</SectionLabel>
            <p className="mt-0.5 text-sm text-slate-500">{headerBody}</p>
          </div>
          {onRunAudit !== undefined ? (
            <ActionButton
              variant="outline"
              onClick={handleRunAudit}
              disabled={auditRunning}
              aria-busy={auditRunning}
            >
              {auditRunning ? (
                <HiMiniArrowPath className="mr-1.5 h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <HiMiniBugAnt className="mr-1.5 h-4 w-4" aria-hidden="true" />
              )}
              {auditSnapshot === null ? "Run audit" : "Run audit again"}
            </ActionButton>
          ) : null}
        </div>
        {auditSnapshot !== null && showResults ? (
          <div className="mt-2">
            <WorkbenchHeader
              auditSnapshot={auditSnapshot}
              flaggedCount={findings.length}
              packageCount={packages.length}
              cloudState={cloudState}
            />
          </div>
        ) : null}
      </div>

      <div className="px-4 py-4 space-y-4">
        {auditConnectGate !== null && auditConnectGate !== undefined ? (
          <WorkbenchEmptyState auditConnectGate={auditConnectGate} auditError={auditError} />
        ) : (
          <>
            {auditError ? <WorkbenchAuditErrorBanner message={auditError} /> : null}

            {progressActive ? (
              <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.03] px-4 py-4">
                <AuditProgressStepList phase={auditPhase} running={auditRunning} />
              </div>
            ) : null}

            {auditSnapshot === null && !progressActive ? (
              <WorkbenchEmptyState auditConnectGate={null} auditError={auditError} />
            ) : null}

        {showResults && auditSnapshot !== null && packages.length === 0 && auditSnapshot.inventory.totalPackages > 0 ? (
          <EmptyState
            title="Package list not loaded"
            body="This audit indexed packages, but the detailed list was not stored yet. Run audit again to load the full inventory table."
            tone="teach"
          />
        ) : null}

        {showResults && packages.length > 0 ? (
          <>
            <div className="flex flex-wrap gap-2">
              {ecosystemBreakdown.map((entry) => (
                <Tag key={entry.ecosystem} tone="default">
                  {entry.ecosystem} · {entry.count}
                </Tag>
              ))}
            </div>
            <div className="flex flex-wrap gap-2">
              <ViewModeChip label={`All packages (${packages.length})`} active={viewMode === "all"} onSelect={handleViewAll} />
              <ViewModeChip
                label={`Needs review (${findings.length})`}
                active={viewMode === "review"}
                onSelect={handleViewReview}
              />
            </div>
            {cloudState === "local_only" ? (
              <p className="text-xs leading-relaxed text-slate-500">
                This device is using local intel only. Connect Guard Cloud and sync supply-chain intel for live CVE and malware coverage.
              </p>
            ) : null}
            <WorkbenchControls
              filters={filters}
              ecosystems={ecosystems}
              sortKey={sortKey}
              sortDirection={sortDirection}
              onSearchChange={handleSearchChange}
              onEcosystemChange={handleEcosystemChange}
              onDecisionChange={handleDecisionChange}
              onSeverityChange={handleSeverityChange}
              onSortChange={handleSortChange}
            />
            <WorkbenchPagination
              page={safePage}
              pageCount={pageCount}
              total={sortedFindings.length}
              onPageChange={handlePageChange}
            />
            {sortedFindings.length === 0 ? (
              <p className="py-6 text-center text-sm text-slate-500">
                {viewMode === "review"
                  ? "No packages need review in this audit."
                  : "No packages match the current filters."}
              </p>
            ) : (
              <div
                className="overflow-hidden rounded-xl border border-slate-100"
                role="table"
                aria-label={viewMode === "review" ? "Packages needing review" : "Indexed packages"}
              >
                <div
                  className="sticky top-0 z-[1] hidden border-b border-slate-100 bg-slate-50 px-4 py-2 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-3"
                  role="row"
                >
                  <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                    Package
                  </span>
                  <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400" role="columnheader">
                    Decision · Severity
                  </span>
                </div>
                <div className="max-h-[min(60vh,32rem)] overflow-y-auto overscroll-y-contain" role="rowgroup">
                  {pagedFindings.map((finding) => (
                    <FindingRow
                      key={finding.id}
                      finding={finding}
                      selected={selectedId === finding.id}
                      onSelect={handleSelectFinding}
                    />
                  ))}
                </div>
              </div>
            )}
          </>
        ) : null}
          </>
        )}
      </div>
      {selectedFinding !== null ? (
        <GuardModalLayer
          ariaLabel={`Finding detail for ${selectedFinding.packageName}`}
          onClose={handleCloseFinding}
          panelClassName="w-full max-w-2xl"
        >
          <FindingDetailPanel finding={selectedFinding} onClose={handleCloseFinding} />
        </GuardModalLayer>
      ) : null}
    </div>
  );
}
