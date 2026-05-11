import { useState, memo } from "react";
import { HiMiniChevronDown, HiMiniChevronUp, HiMiniChartBar, HiMiniCalendarDays, HiMiniArrowPathRoundedSquare, HiOutlineArrowDownTray } from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { HistoryInsights, ActivityCalendar, TopActions } from "../history-analytics";
import { HistoryCharts } from "../history-charts";
import { CompareTimePeriods } from "../compare-time-periods";
import { exportReceiptsAsCsv, exportReceiptsAsJson, downloadBlob } from "../history-export";
import { EmptyState, SectionLabel } from "../approval-center-primitives";

type SubTab = "overview" | "calendar" | "compare" | "export";

interface ExploreTabProps {
  receipts: GuardReceipt[];
  filteredReceipts: GuardReceipt[];
  filters: {
    search: string;
    time: string;
    decision: string;
    harness: string;
  };
  onFilterDay: (day: string) => void;
  onFilterHarness: (harness: string) => void;
  onFilterAction: (name: string) => void;
}

function ExploreTabRaw({ receipts, filteredReceipts, filters, onFilterDay, onFilterHarness, onFilterAction }: ExploreTabProps) {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>("overview");
  const [showAnalytics, setShowAnalytics] = useState(false);

  if (!showAnalytics) {
    return (
      <div className="space-y-6">
        <button
          onClick={() => setShowAnalytics(true)}
          className="w-full rounded-2xl border border-dashed border-brand-blue/30 bg-brand-blue/[0.03] p-6 text-center transition-colors hover:bg-brand-blue/[0.06]"
        >
          <HiMiniChartBar className="mx-auto h-6 w-6 text-brand-blue" aria-hidden="true" />
          <p className="mt-2 text-sm font-medium text-brand-dark">Show analytics</p>
          <p className="mt-1 text-xs text-slate-500">Charts, comparisons, and exports</p>
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2">
        {(
          [
            { key: "overview" as SubTab, label: "Overview", icon: HiMiniChartBar },
            { key: "calendar" as SubTab, label: "Calendar", icon: HiMiniCalendarDays },
            { key: "compare" as SubTab, label: "Compare", icon: HiMiniArrowPathRoundedSquare },
            { key: "export" as SubTab, label: "Export", icon: HiOutlineArrowDownTray },
          ] as const
        ).map((t) => {
          const Icon = t.icon;
          const isActive = activeSubTab === t.key;
          return (
            <button
              key={t.key}
              onClick={() => setActiveSubTab(t.key)}
              className={`inline-flex items-center gap-2 rounded-lg px-4 py-2 text-sm font-medium transition-all ${
                isActive
                  ? "bg-brand-blue text-white shadow-sm"
                  : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"
              }`}
            >
              <Icon className="h-4 w-4" aria-hidden="true" />
              {t.label}
            </button>
          );
        })}
      </div>

      {activeSubTab === "overview" && (
        <div className="space-y-6">
          <HistoryInsights
            receipts={receipts}
            onFilterHarness={onFilterHarness}
            onFilterDay={onFilterDay}
          />
          <HistoryCharts receipts={filteredReceipts} />
          <TopActions receipts={filteredReceipts} onFilterAction={onFilterAction} />
        </div>
      )}

      {activeSubTab === "calendar" && (
        <ActivityCalendar receipts={filteredReceipts} onSelectDay={onFilterDay} />
      )}

      {activeSubTab === "compare" && (
        <CompareTimePeriods receipts={receipts} />
      )}

      {activeSubTab === "export" && (
        <ExportPanel receipts={filteredReceipts} filters={filters} />
      )}
    </div>
  );
}

function ExportPanel({
  receipts,
  filters,
}: {
  receipts: GuardReceipt[];
  filters: { search: string; time: string; decision: string; harness: string };
}) {
  const handleExportCsv = () => {
    const { blob, filename } = exportReceiptsAsCsv(receipts, filters);
    downloadBlob(blob, filename);
  };

  const handleExportJson = () => {
    const { blob, filename } = exportReceiptsAsJson(receipts, filters);
    downloadBlob(blob, filename);
  };

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5">
      <SectionLabel>Export</SectionLabel>
      <p className="mt-2 text-sm text-slate-500">
        Download {receipts.length} decision{receipts.length !== 1 ? "s" : ""} as CSV or JSON.
      </p>
      <div className="mt-4 flex gap-3">
        <button
          onClick={handleExportCsv}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
        >
          <HiOutlineArrowDownTray className="h-4 w-4" aria-hidden="true" />
          Download CSV
        </button>
        <button
          onClick={handleExportJson}
          className="inline-flex min-h-10 items-center gap-2 rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
        >
          <HiOutlineArrowDownTray className="h-4 w-4" aria-hidden="true" />
          Download JSON
        </button>
      </div>
    </div>
  );
}

export const ExploreTab = memo(ExploreTabRaw);
