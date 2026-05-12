import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  HiMiniListBullet,
  HiMiniChartBar,
  HiMiniComputerDesktop,
  HiMiniArrowDownTray,
  HiMiniClock,
} from "react-icons/hi2";

import { EmptyState } from "./approval-center-primitives";
import type { GuardReceipt } from "./guard-types";
import type { EvidenceFilterState, EvidenceView } from "./evidence/evidence-types";
import { filterEvidence } from "./evidence/evidence-filters";
import { sortEvidence } from "./evidence/evidence-sort";
import { computeMetrics } from "./evidence/evidence-metrics";
import {
  readEvidenceUrlState,
  writeEvidenceUrlState,
  DEFAULT_FILTER_STATE,
} from "./evidence/evidence-url-state";
import { EvidenceFilterBar } from "./evidence/evidence-filter-bar";
import { EvidenceActionList } from "./evidence/evidence-action-list";
import { EvidenceActionDetail } from "./evidence/evidence-action-detail";
import { EvidenceInsightStrip } from "./evidence/evidence-insight-strip";
import { EvidenceAnalyticsPanel } from "./evidence/evidence-analytics-panel";
import { EvidenceExportDrawer } from "./evidence/evidence-export-drawer";
import { EvidenceClearModal } from "./evidence/evidence-clear-modal";

export type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

const PAGE_SIZE = 50;

const VIEW_TABS: { key: EvidenceView; label: string; icon: React.ElementType }[] = [
  { key: "actions", label: "All actions", icon: HiMiniListBullet },
  { key: "insights", label: "Insights", icon: HiMiniChartBar },
  { key: "apps", label: "Apps", icon: HiMiniComputerDesktop },
  { key: "export", label: "Export", icon: HiMiniArrowDownTray },
];

function EvidenceLoadingState() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading evidence">
      <div className="guard-skeleton h-8 w-64" />
      <div className="guard-skeleton h-32 w-full" />
    </div>
  );
}

function EvidenceErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4">
      <p className="text-sm text-brand-dark">{message}</p>
    </div>
  );
}

interface EvidenceHeaderProps {
  totalCount: number;
  lastActivityAt: string | null;
  onExport: () => void;
  onClear?: () => void;
}

function EvidenceHeader({
  totalCount,
  lastActivityAt,
  onExport,
  onClear,
}: EvidenceHeaderProps) {
  const lastActivityLabel = lastActivityAt
    ? new Date(lastActivityAt).toLocaleDateString(undefined, {
        month: "short",
        day: "numeric",
        year: "numeric",
      })
    : null;

  return (
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div className="space-y-1 min-w-0">
        <h1 className="text-xl font-bold text-brand-dark">Evidence</h1>
        <p className="text-sm text-slate-500">
          See every action HOL Guard reviewed on this machine.
        </p>
        {lastActivityLabel && (
          <p className="flex items-center gap-1 text-xs text-slate-400">
            <HiMiniClock className="h-3.5 w-3.5" aria-hidden="true" />
            Last activity: {lastActivityLabel}
          </p>
        )}
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <button
          type="button"
          onClick={onExport}
          aria-label="Export evidence"
          className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50 transition-colors"
        >
          <HiMiniArrowDownTray className="h-4 w-4" aria-hidden="true" />
          Export
        </button>
        {onClear && totalCount > 0 && (
          <button
            type="button"
            onClick={onClear}
            aria-label="Clear all evidence"
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2 text-sm font-medium text-slate-500 hover:bg-slate-50 hover:text-brand-attention transition-colors"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}

interface ViewTabBarProps {
  view: EvidenceView;
  onViewChange: (view: EvidenceView) => void;
}

function ViewTabBar({ view, onViewChange }: ViewTabBarProps) {
  return (
    <div
      className="flex gap-1 rounded-xl border border-slate-200/70 bg-white/80 p-1 shadow-sm"
      role="tablist"
      aria-label="Evidence views"
    >
      {VIEW_TABS.map((tab) => {
        const Icon = tab.icon;
        const isActive = view === tab.key;
        return (
          <ViewTabButton
            key={tab.key}
            tabKey={tab.key}
            label={tab.label}
            icon={Icon}
            isActive={isActive}
            onSelect={onViewChange}
          />
        );
      })}
    </div>
  );
}

interface ViewTabButtonProps {
  tabKey: EvidenceView;
  label: string;
  icon: React.ElementType;
  isActive: boolean;
  onSelect: (key: EvidenceView) => void;
}

function ViewTabButton({
  tabKey,
  label,
  icon: Icon,
  isActive,
  onSelect,
}: ViewTabButtonProps) {
  const handleClick = useCallback(() => {
    onSelect(tabKey);
  }, [tabKey, onSelect]);

  return (
    <button
      key={tabKey}
      role="tab"
      aria-selected={isActive}
      aria-controls={`tabpanel-${tabKey}`}
      id={`tab-${tabKey}`}
      onClick={handleClick}
      className={`flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${
        isActive
          ? "bg-brand-blue text-white shadow-sm"
          : "text-brand-dark hover:bg-slate-50"
      }`}
    >
      <Icon className="h-4 w-4" aria-hidden="true" />
      <span className="hidden sm:inline">{label}</span>
    </button>
  );
}

interface EvidenceWorkbenchProps {
  receiptItems: GuardReceipt[];
  onClearEvidence?: () => void;
}

function EvidenceWorkbench({ receiptItems, onClearEvidence }: EvidenceWorkbenchProps) {
  const initial = useMemo(() => readEvidenceUrlState(), []);
  const [filters, setFilters] = useState<EvidenceFilterState>(initial);
  const [debouncedSearch, setDebouncedSearch] = useState(initial.search);
  const [page, setPage] = useState(0);
  const [exportOpen, setExportOpen] = useState(false);
  const [clearOpen, setClearOpen] = useState(false);

  const urlSyncTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const harnesses = useMemo(
    () => Array.from(new Set(receiptItems.map((r) => r.harness))).sort(),
    [receiptItems]
  );

  const searchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    searchTimerRef.current = setTimeout(() => {
      setDebouncedSearch(filters.search);
    }, 300);
    return () => {
      if (searchTimerRef.current) clearTimeout(searchTimerRef.current);
    };
  }, [filters.search]);

  useEffect(() => {
    if (urlSyncTimerRef.current) clearTimeout(urlSyncTimerRef.current);
    urlSyncTimerRef.current = setTimeout(() => {
      writeEvidenceUrlState({ ...filters, search: debouncedSearch });
    }, 100);
    return () => {
      if (urlSyncTimerRef.current) clearTimeout(urlSyncTimerRef.current);
    };
  }, [filters, debouncedSearch]);

  useEffect(() => {
    if (filters.harness !== "all" && !harnesses.includes(filters.harness)) {
      setFilters((prev) => ({ ...prev, harness: "all" }));
    }
  }, [harnesses, filters.harness]);

  useEffect(() => {
    setPage(0);
  }, [filters, debouncedSearch]);

  const effectiveFilters = useMemo(
    () => ({ ...filters, search: debouncedSearch }),
    [filters, debouncedSearch]
  );

  const filtered = useMemo(
    () => filterEvidence(receiptItems, effectiveFilters),
    [receiptItems, effectiveFilters]
  );

  const sorted = useMemo(
    () => sortEvidence(filtered, filters.sort),
    [filtered, filters.sort]
  );

  const metrics = useMemo(
    () => computeMetrics(filtered),
    [filtered]
  );

  const selectedReceipt = useMemo(() => {
    if (!filters.selectedId) return null;
    const found = filtered.find((r) => r.receipt_id === filters.selectedId);
    return found ?? null;
  }, [filtered, filters.selectedId]);

  const handleFilterChange = useCallback((patch: Partial<EvidenceFilterState>) => {
    setFilters((prev) => ({ ...prev, ...patch }));
  }, []);

  const handleSelectId = useCallback((id: string) => {
    setFilters((prev) => ({
      ...prev,
      selectedId: prev.selectedId === id ? "" : id,
    }));
  }, []);

  const handleCloseDetail = useCallback(() => {
    setFilters((prev) => ({ ...prev, selectedId: "" }));
  }, []);

  const handleFilterHarness = useCallback((harness: string) => {
    setFilters((prev) => ({ ...prev, harness }));
  }, []);

  const handleFilterCategory = useCallback((category: string) => {
    setFilters((prev) => ({ ...prev, category }));
  }, []);

  const handleLoadMore = useCallback(() => {
    setPage((prev) => prev + 1);
  }, []);

  const handleViewChange = useCallback((view: EvidenceView) => {
    setFilters((prev) => ({ ...prev, view }));
  }, []);

  const handleOpenExport = useCallback(() => {
    setExportOpen(true);
  }, []);

  const handleCloseExport = useCallback(() => {
    setExportOpen(false);
  }, []);

  const handleOpenClear = useCallback(() => {
    setClearOpen(true);
  }, []);

  const handleCloseClear = useCallback(() => {
    setClearOpen(false);
  }, []);

  const handleConfirmClear = useCallback(() => {
    setFilters(DEFAULT_FILTER_STATE);
    if (onClearEvidence) onClearEvidence();
  }, [onClearEvidence]);

  if (receiptItems.length === 0) {
    return (
      <EmptyState
        title="No evidence yet"
        body="Saved choices appear here after HOL Guard reviews or blocks an action."
        tone="teach"
      />
    );
  }

  return (
    <div className="space-y-4">
      <EvidenceHeader
        totalCount={receiptItems.length}
        lastActivityAt={metrics.lastActivityAt}
        onExport={handleOpenExport}
        onClear={handleOpenClear}
      />

      <EvidenceInsightStrip metrics={metrics} />

      <EvidenceFilterBar
        filters={filters}
        onChange={handleFilterChange}
        totalCount={receiptItems.length}
        filteredCount={filtered.length}
        harnesses={harnesses}
      />

      <ViewTabBar view={filters.view} onViewChange={handleViewChange} />

      <div className="min-h-[300px]">
        {filters.view === "actions" && (
          <div
            id="tabpanel-actions"
            role="tabpanel"
            aria-labelledby="tab-actions"
            className={selectedReceipt ? "grid grid-cols-1 gap-4 lg:grid-cols-[1fr_360px]" : ""}
          >
            <EvidenceActionList
              receipts={sorted}
              selectedId={filters.selectedId}
              onSelectId={handleSelectId}
              onFilterHarness={handleFilterHarness}
              onFilterCategory={handleFilterCategory}
              sort={filters.sort}
              onSortChange={(sort) => handleFilterChange({ sort })}
              page={page}
              pageSize={PAGE_SIZE}
              onLoadMore={handleLoadMore}
            />
            {selectedReceipt && (
              <div className="rounded-xl border border-slate-200 bg-white overflow-hidden">
                <EvidenceActionDetail
                  receipt={selectedReceipt}
                  onClose={handleCloseDetail}
                />
              </div>
            )}
          </div>
        )}

        {filters.view === "insights" && (
          <div
            id="tabpanel-insights"
            role="tabpanel"
            aria-labelledby="tab-insights"
          >
            <EvidenceAnalyticsPanel
              metrics={metrics}
              onFilterHarness={handleFilterHarness}
              onFilterCategory={handleFilterCategory}
            />
          </div>
        )}

        {filters.view === "apps" && (
          <div
            id="tabpanel-apps"
            role="tabpanel"
            aria-labelledby="tab-apps"
          >
            <EvidenceAnalyticsPanel
              metrics={metrics}
              onFilterHarness={handleFilterHarness}
              onFilterCategory={handleFilterCategory}
            />
          </div>
        )}

        {filters.view === "export" && (
          <div
            id="tabpanel-export"
            role="tabpanel"
            aria-labelledby="tab-export"
            className="rounded-xl border border-slate-200 bg-white p-6"
          >
            <p className="text-sm text-slate-500 mb-4">
              Download your evidence records as CSV or JSON.
            </p>
            <button
              type="button"
              onClick={handleOpenExport}
              className="inline-flex items-center gap-2 rounded-lg bg-brand-blue px-4 py-2.5 text-sm font-semibold text-white hover:bg-brand-blue/90 transition-colors"
            >
              <HiMiniArrowDownTray className="h-4 w-4" aria-hidden="true" />
              Open export options
            </button>
          </div>
        )}
      </div>

      <EvidenceExportDrawer
        receipts={sorted}
        filters={effectiveFilters}
        isOpen={exportOpen}
        onClose={handleCloseExport}
      />

      <EvidenceClearModal
        count={receiptItems.length}
        isOpen={clearOpen}
        onClose={handleCloseClear}
        onCleared={handleConfirmClear}
      />
    </div>
  );
}

export function ReceiptsWorkspace(props: { receipts: ReceiptsState }) {
  if (props.receipts.kind === "loading") {
    return <EvidenceLoadingState />;
  }
  if (props.receipts.kind === "error") {
    return <EvidenceErrorState message={props.receipts.message} />;
  }
  return <EvidenceWorkbench receiptItems={props.receipts.items} />;
}

export function filterReceiptItems(
  items: GuardReceipt[],
  searchTerm: string,
  harnessFilter: string,
  decisionFilter: string,
  dateRange: string
): GuardReceipt[] {
  const normalizedSearchTerm = searchTerm.trim().toLowerCase();
  const now = Date.now();
  const todayStart = new Date();
  todayStart.setHours(0, 0, 0, 0);
  const todayStartMs = todayStart.getTime();
  const last7Start = now - 7 * 24 * 60 * 60 * 1000;
  return items.filter((receipt) => {
    const matchesHarness =
      harnessFilter === "all" || receipt.harness === harnessFilter;
    const matchesDecision =
      decisionFilter === "all" || receipt.policy_decision === decisionFilter;
    if (!matchesHarness || !matchesDecision) {
      return false;
    }
    if (dateRange === "today" || dateRange === "last7") {
      const ts = new Date(receipt.timestamp).getTime();
      if (dateRange === "today" && ts < todayStartMs) {
        return false;
      } else if (dateRange === "last7" && ts < last7Start) {
        return false;
      }
    }
    if (normalizedSearchTerm.length === 0) {
      return true;
    }
    const name = (receipt.artifact_name ?? receipt.artifact_id).toLowerCase();
    return name.includes(normalizedSearchTerm);
  });
}
