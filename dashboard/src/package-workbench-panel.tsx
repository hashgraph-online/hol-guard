import { useCallback, useMemo, useState } from "react";
import type { ChangeEvent } from "react";
import { HiMiniAdjustmentsHorizontal, HiMiniArrowPath, HiMiniBugAnt, HiMiniExclamationTriangle } from "react-icons/hi2";
import { SectionLabel, ActionButton, EmptyState } from "./approval-center-primitives";
import { GuardModalLayer } from "./guard-modal-layer";
import { AuditProgressStepList, auditProgressActive } from "./audit-run-progress";
import type { AuditRunPhase } from "./use-supply-chain-audit-session";
import type {
  PackageWorkbenchFilters,
  PackageWorkbenchSortKey,
  SupplyChainAuditFinding,
  SupplyChainAuditSnapshot,
} from "./guard-types";
import {
  filterPackageWorkbenchFindings,
  packageWorkbenchEcosystems,
  sortPackageWorkbenchFindings,
} from "./supply-chain-audit-normalize";
import { ConnectFlowCard } from "./supply-chain-firewall-views";
import type { AuditConnectGateViewState } from "./supply-chain-firewall-panel";
import { FindingDetailPanel, FindingRow } from "./package-workbench-finding-detail";
import { ActiveFilterChip, FilterModal, buildFilterSummary } from "./package-workbench-filter-modal";
import { WorkbenchHeader, WorkbenchPagination } from "./package-workbench-common";

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

type FilterChipProps = {
  label: string;
  active: boolean;
  count?: number;
  onSelect: () => void;
};

function FilterChip({ label, active, count, onSelect }: FilterChipProps) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={active}
      onClick={onSelect}
      className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${
        active ? "bg-brand-dark text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"
      }`}
    >
      <span>{label}</span>
      {count !== undefined ? (
        <span
          className={`rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${
            active ? "bg-white/20 text-white" : "bg-slate-100 text-slate-500"
          }`}
          aria-label={`${count} result${count === 1 ? "" : "s"}`}
        >
          {count}
        </span>
      ) : null}
    </button>
  );
}

type WorkbenchEmptyStateProps = {
  auditConnectGate?: AuditConnectGateViewState | null;
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

function WorkbenchEmptyState({ auditConnectGate }: WorkbenchEmptyStateProps) {
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
    <EmptyState
      title="No workspace audit yet"
      body="Run a workspace audit to index dependencies across npm, pnpm, PyPI, and other ecosystems found in this project."
      tone="teach"
    />
  );
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
  const [filterModalOpen, setFilterModalOpen] = useState(false);

  const findings = auditSnapshot?.findings ?? [];
  const packages = auditSnapshot?.packages ?? [];
  const tableSource = viewMode === "review" ? findings : packages;
  const progressActive = auditProgressActive(auditPhase, auditRunning);
  const showResults = auditSnapshot !== null && !progressActive && (auditConnectGate === null || auditConnectGate === undefined);
  const ecosystems = useMemo(() => packageWorkbenchEcosystems(tableSource), [tableSource]);
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

  const handleResetSort = useCallback(() => {
    setSortState({ sortKey: "severity", sortDirection: "desc" });
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

  const openFilterModal = useCallback(() => setFilterModalOpen(true), []);
  const closeFilterModal = useCallback(() => setFilterModalOpen(false), []);
  const handleClearFilters = useCallback(() => {
    setFilters({ ecosystem: "all", decision: "all", severity: "all", search: "" });
    setPage(0);
    setSelectedId("");
  }, []);

  const activeFilterCount =
    (filters.ecosystem !== "all" ? 1 : 0) +
    (filters.decision !== "all" ? 1 : 0) +
    (filters.severity !== "all" ? 1 : 0) +
    (filters.search.trim().length > 0 ? 1 : 0);

  const filterSummary = useMemo(
    () => buildFilterSummary(filters, sortKey, sortDirection),
    [filters, sortKey, sortDirection],
  );

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
          <WorkbenchEmptyState auditConnectGate={auditConnectGate} />
        ) : (
          <>
            {auditError ? <WorkbenchAuditErrorBanner message={auditError} /> : null}

            {progressActive ? (
              <div className="rounded-xl border border-brand-blue/15 bg-brand-blue/[0.03] px-4 py-4">
                <AuditProgressStepList phase={auditPhase} running={auditRunning} />
              </div>
            ) : null}

            {auditSnapshot === null && !progressActive ? (
              <WorkbenchEmptyState auditConnectGate={null} />
            ) : null}

            {showResults && auditSnapshot !== null && packages.length === 0 && auditSnapshot.inventory.totalPackages > 0 ? (
              <EmptyState
                title="Package list not loaded"
                body="This audit indexed packages, but the detailed list was not stored yet. Run audit again to load the full inventory table."
                tone="teach"
              />
            ) : null}

            {showResults && auditSnapshot !== null && packages.length === 0 && auditSnapshot.inventory.totalPackages === 0 ? (
              <EmptyState
                title="No packages indexed"
                body="The latest workspace audit completed, but no supported package manifests or lockfiles were found."
                tone="teach"
              />
            ) : null}

            {showResults && packages.length > 0 ? (
              <>
                {cloudState === "local_only" ? (
                  <p className="text-xs leading-relaxed text-slate-500">
                    This device is using local intel only. Connect Guard Cloud and sync supply-chain intel for live CVE and malware coverage.
                  </p>
                ) : null}
                <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                  <div className="flex flex-wrap items-center gap-2">
                    <FilterChip
                      label="All packages"
                      count={packages.length}
                      active={viewMode === "all"}
                      onSelect={handleViewAll}
                    />
                    <FilterChip
                      label="Needs review"
                      count={findings.length}
                      active={viewMode === "review"}
                      onSelect={handleViewReview}
                    />
                  </div>
                  <div className="flex items-center gap-2">
                    <ActionButton variant="outline" onClick={openFilterModal}>
                      <HiMiniAdjustmentsHorizontal className="mr-1.5 h-4 w-4" aria-hidden="true" />
                      Filters
                      {activeFilterCount > 0 ? (
                        <span className="ml-1.5 rounded-full bg-brand-blue px-1.5 py-0.5 text-[10px] font-semibold text-white">
                          {activeFilterCount}
                        </span>
                      ) : null}
                    </ActionButton>
                  </div>
                </div>
                {filterSummary.length > 1 ? (
                  <div className="flex flex-wrap items-center gap-2">
                    {filterSummary.map((item) => (
                      <ActiveFilterChip
                        key={item.key}
                        label={item.label}
                        onRemove={() => {
                          if (item.key === "ecosystem") handleEcosystemChange("all");
                          else if (item.key === "decision") handleDecisionChange("all");
                          else if (item.key === "severity") handleSeverityChange("all");
                          else if (item.key === "search") handleSearchChange({ target: { value: "" } } as ChangeEvent<HTMLInputElement>);
                          else if (item.key === "sort") handleResetSort();
                        }}
                      />
                    ))}
                  </div>
                ) : null}
                <WorkbenchPagination
                  page={safePage}
                  pageCount={pageCount}
                  total={sortedFindings.length}
                  onPageChange={handlePageChange}
                />
                {filterModalOpen ? (
                  <FilterModal
                    filters={filters}
                    activeFilterCount={activeFilterCount}
                    ecosystems={ecosystems}
                    sortKey={sortKey}
                    sortDirection={sortDirection}
                    onClose={closeFilterModal}
                    onSearchChange={handleSearchChange}
                    onEcosystemChange={handleEcosystemChange}
                    onDecisionChange={handleDecisionChange}
                    onSeverityChange={handleSeverityChange}
                    onSortChange={handleSortChange}
                    onClearFilters={handleClearFilters}
                  />
                ) : null}
                {sortedFindings.length === 0 ? (
                  <p className="py-6 text-center text-sm text-slate-500">
                    {viewMode === "review" && findings.length === 0
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
