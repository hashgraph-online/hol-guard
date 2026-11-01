import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HiMiniArrowDownTray, HiMiniDocumentText, HiMiniXMark } from "react-icons/hi2";

import { EmptyState, ActionButton, SectionLabel, IconActionButton } from "./approval-center-primitives";
import { isDisplayableHarness } from "./approval-center-utils";
import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";
import { useReceiptAnalytics, invalidateReceiptAnalyticsCache } from "./evidence/use-receipt-analytics";
import type { EvidenceFilterState, EvidenceView, EvidenceSortKey } from "./evidence/evidence-types";
import { filterEvidence } from "./evidence/evidence-filters";
import { sortEvidence } from "./evidence/evidence-sort";
import { computeMetrics } from "./evidence/evidence-metrics";
import {
  readEvidenceUrlState,
  writeEvidenceUrlState,
  DEFAULT_FILTER_STATE,
} from "./evidence/evidence-url-state";
import {
  EvidenceLoadingState,
  EvidenceErrorState,
  EvidenceHero,
  VIEW_TABS,
} from "./evidence/evidence-view-shell";
import { EvidenceFilterBar } from "./evidence/evidence-filter-bar";
import { EvidenceActionList } from "./evidence/evidence-action-list";
import { EvidenceActionDetail } from "./evidence/evidence-action-detail";
import { EvidenceInsightStrip } from "./evidence/evidence-insight-strip";
import { EvidenceAnalyticsPanel } from "./evidence/evidence-analytics-panel";
import { formatEvidenceCount } from "./evidence/evidence-format";
import { EvidenceExportDrawer } from "./evidence/evidence-export-drawer";
import { EvidenceClearModal } from "./evidence/evidence-clear-modal";
import { AppTab } from "./evidence/app-tab";
import { CategoryTab } from "./evidence/category-tab";
import { WorkspacePageHeader } from "./workspace-page-header";
import { CommandActivityWorkspace } from "./command-activity/command-activity-workspace";
import { ContextHistoryPanel } from "./context-assistance/history-panel";
export { filterReceiptItems } from "./evidence/filter-receipt-items";

export type ReceiptsState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardReceipt[] };

const PAGE_SIZE = 50;

interface EvidenceWorkbenchProps {
  receiptItems: GuardReceipt[];
  runtime: GuardRuntimeSnapshot | null;
  onClearEvidence?: () => void;
  onNavigate?: (pathname: string) => void;
}

function evidenceTitleForView(view: EvidenceView): string {
  return VIEW_TABS.find((tab) => tab.key === view)?.label ?? "Evidence";
}

function EvidenceWorkbench({ receiptItems, runtime, onClearEvidence, onNavigate }: EvidenceWorkbenchProps) {
  const initial = useMemo(() => readEvidenceUrlState(), []);
  const [filters, setFilters] = useState<EvidenceFilterState>(() => {
    const linkedReceipt = initial.selectedId
      ? receiptItems.find((receipt) => receipt.receipt_id === initial.selectedId)
      : undefined;
    if (!linkedReceipt) {
      return initial;
    }
    return {
      ...initial,
      view: "actions",
      harness: linkedReceipt.harness,
    };
  });
  const [debouncedSearch, setDebouncedSearch] = useState(initial.search);
  const [page, setPage] = useState(0);
  const [exportOpen, setExportOpen] = useState(false);
  const [clearOpen, setClearOpen] = useState(false);
  const analytics = useReceiptAnalytics(true);

  const urlSyncTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const harnesses = useMemo(
    () =>
      Array.from(
        new Set(receiptItems.map((r) => r.harness).filter(isDisplayableHarness))
      ).sort(),
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
  }, [debouncedSearch, filters.harness, filters.decision, filters.time, filters.category, filters.sourceScope, filters.day]);

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
    return (
      receiptItems.find((receipt) => receipt.receipt_id === filters.selectedId) ??
      filtered.find((receipt) => receipt.receipt_id === filters.selectedId) ??
      null
    );
  }, [filtered, filters.selectedId, receiptItems]);

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

  const handleSortChange = useCallback((sort: EvidenceSortKey) => {
    handleFilterChange({ sort });
  }, [handleFilterChange]);

  const handleLoadMore = useCallback(() => {
    setPage((prev) => prev + 1);
  }, []);

  const handleViewChange = useCallback((view: EvidenceView) => {
    setFilters((prev) => ({
      ...prev,
      view,
      ...(view !== "actions" ? { day: "" } : {}),
    }));
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
    invalidateReceiptAnalyticsCache();
    if (onClearEvidence) onClearEvidence();
  }, [onClearEvidence]);

  const handleViewActions = useCallback(() => {
    setFilters((prev) => ({ ...prev, view: "actions", day: "" }));
  }, []);

  const handleFilterDay = useCallback((dateKey: string) => {
    setFilters((prev) => ({
      ...prev,
      view: "actions",
      day: dateKey,
      time: "all",
    }));
  }, []);

  const handleFilterHarnessFromInsights = useCallback((harness: string) => {
    setFilters((prev) => ({ ...prev, view: "actions", harness, day: "" }));
  }, []);

  useEffect(() => {
    function handlePopState() {
      const urlState = readEvidenceUrlState();
      setFilters(urlState);
      setDebouncedSearch(urlState.search);
      setPage(0);
    }
    window.addEventListener("popstate", handlePopState);
    return () => window.removeEventListener("popstate", handlePopState);
  }, []);

  const tabOptions = VIEW_TABS.map((t) => ({ value: t.key, label: t.label, id: t.key }));

  const totalReceiptCount = analytics.kind === "ready" ? analytics.data.total : receiptItems.length;

  const insightsHeaderDescription = useMemo(() => {
    if (filters.view !== "insights") return undefined;
    if (analytics.kind !== "ready") return "Loading analytics from your local evidence store.";
    const total = analytics.data.total;
    return `${formatEvidenceCount(total)} actions in your full local store.`;
  }, [filters.view, analytics]);

  const headerActions = useMemo(
    () => (
      <>
        <IconActionButton
          label="Export"
          icon={<HiMiniDocumentText className="h-4 w-4" />}
          variant="outline"
          onClick={handleOpenExport}
          aria-label="Export evidence"
        />
        {onClearEvidence && receiptItems.length > 0 && (
          <IconActionButton
            label="Clear"
            icon={<HiMiniXMark className="h-4 w-4" />}
            variant="ghost"
            onClick={handleOpenClear}
            aria-label="Clear all evidence"
          />
        )}
      </>
    ),
    [handleOpenExport, handleOpenClear, onClearEvidence, receiptItems.length],
  );

  if (receiptItems.length === 0 && filters.view !== "commands") {
    return (
      <div className="space-y-6"><EmptyState
        title="No evidence yet"
        body="Saved choices appear here after HOL Guard reviews or blocks an action."
        tone="teach"
      /><ContextHistoryPanel /></div>
    );
  }

  return (
    <div className="min-w-0 max-w-full space-y-6">
      <WorkspacePageHeader
        eyebrow="Evidence"
        title={evidenceTitleForView(filters.view)}
        description={insightsHeaderDescription}
        tabs={tabOptions}
        activeTab={filters.view}
        onTabChange={handleViewChange}
        actions={filters.view === "commands" ? undefined : headerActions}
      />

      {filters.view !== "insights" && filters.view !== "commands" && <EvidenceHero totalCount={totalReceiptCount} lastActivityAt={metrics.lastActivityAt} />}

      <div className="pt-1">
        {filters.view === "commands" && <div id="tabpanel-commands" role="tabpanel" aria-labelledby="tab-commands" className="guard-fade-in"><CommandActivityWorkspace /></div>}
        {filters.view === "actions" && (
          <div
            id="tabpanel-actions"
            role="tabpanel"
            aria-labelledby="tab-actions"
            className={`guard-fade-in ${selectedReceipt ? "grid grid-cols-1 gap-3 lg:grid-cols-[1fr_340px]" : ""}`}
          >
            <div className="space-y-3">
              <EvidenceFilterBar
                filters={filters}
                onChange={handleFilterChange}
                totalCount={totalReceiptCount}
                filteredCount={filtered.length}
                harnesses={harnesses}
              />
              <EvidenceInsightStrip metrics={metrics} />
              <EvidenceActionList
                receipts={sorted}
                selectedId={filters.selectedId}
                onSelectId={handleSelectId}
                onFilterHarness={handleFilterHarness}
                onFilterCategory={handleFilterCategory}
                sort={filters.sort}
                onSortChange={handleSortChange}
                page={page}
                pageSize={PAGE_SIZE}
                onLoadMore={handleLoadMore}
              />
              {!selectedReceipt ? <ContextHistoryPanel /> : null}
            </div>
            {selectedReceipt && (
              <div className="overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm">
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
            className="guard-fade-in"
          >
            {analytics.kind === "loading" || analytics.kind === "idle" ? (
              <div className="flex items-center justify-center py-16 text-sm text-slate-500">Loading insights…</div>
            ) : analytics.kind === "error" ? (
              <div className="rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
                {analytics.message}
              </div>
            ) : (
              <EvidenceAnalyticsPanel
                analytics={analytics.data}
                runtime={runtime}
                sampleCount={receiptItems.length}
                onFilterHarness={handleFilterHarnessFromInsights}
                onFilterDay={handleFilterDay}
                onViewActions={handleViewActions}
              />
            )}
          </div>
        )}

        {filters.view === "apps" && (
          <div
            id="tabpanel-apps"
            role="tabpanel"
            aria-labelledby="tab-apps"
            className="guard-fade-in"
          >
            <AppTab receipts={filtered} />
          </div>
        )}

        {filters.view === "categories" && (
          <div
            id="tabpanel-categories"
            role="tabpanel"
            aria-labelledby="tab-categories"
            className="guard-fade-in"
          >
            <CategoryTab receipts={filtered} onFilterCategory={handleFilterCategory} />
          </div>
        )}

        {filters.view === "export" && (
          <div
            id="tabpanel-export"
            role="tabpanel"
            aria-labelledby="tab-export"
            className="guard-fade-in space-y-4"
          >
            <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
              <SectionLabel>Export Evidence</SectionLabel>
              <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">
                Download your evidence records as CSV or JSON for analysis or backup.
              </p>
              <div className="mt-4">
                <ActionButton onClick={handleOpenExport}>
                  <HiMiniArrowDownTray className="h-4 w-4" aria-hidden="true" />
                  Open export options
                </ActionButton>
              </div>
            </div>
            <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
              <SectionLabel>Cloud Sync</SectionLabel>
              <p className="mt-2 text-sm leading-relaxed text-brand-dark/70">
                Keep evidence in sync across devices. Cloud backup lets you access your evidence history from any device. Available in HOL Guard Cloud.
              </p>
            </div>
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
        count={totalReceiptCount}
        isOpen={clearOpen}
        onClose={handleCloseClear}
        onCleared={handleConfirmClear}
      />
    </div>
  );
}

export function ReceiptsWorkspace(props: {
  receipts: ReceiptsState;
  runtime?: { kind: "ready"; snapshot: GuardRuntimeSnapshot } | { kind: "loading" | "error" };
  onClearEvidence?: () => void;
  onNavigate?: (pathname: string) => void;
}) {
  if (readEvidenceUrlState().view === "commands") {
    return (
      <EvidenceWorkbench
        receiptItems={props.receipts.kind === "ready" ? props.receipts.items : []}
        runtime={props.runtime?.kind === "ready" ? props.runtime.snapshot : null}
        onClearEvidence={props.onClearEvidence}
        onNavigate={props.onNavigate}
      />
    );
  }
  if (props.receipts.kind === "loading") {
    return <EvidenceLoadingState />;
  }
  if (props.receipts.kind === "error") {
    return <EvidenceErrorState message={props.receipts.message} />;
  }
  const runtime = props.runtime?.kind === "ready" ? props.runtime.snapshot : null;
  return (
    <EvidenceWorkbench
      receiptItems={props.receipts.items}
      runtime={runtime}
      onClearEvidence={props.onClearEvidence}
      onNavigate={props.onNavigate}
    />
  );
}
