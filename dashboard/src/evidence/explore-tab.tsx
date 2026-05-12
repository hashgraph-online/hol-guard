import { useState, memo } from "react";
import {
  HiMiniChartBar,
  HiMiniCalendarDays,
  HiMiniArrowPathRoundedSquare,
  HiOutlineArrowDownTray,
} from "react-icons/hi2";
import type { GuardReceipt } from "../guard-types";
import { HistoryInsights, ActivityCalendar, TopActions } from "../history-analytics";
import { HistoryCharts } from "../history-charts";
import { CompareTimePeriods } from "../compare-time-periods";
import { exportReceiptsAsCsv, exportReceiptsAsJson, downloadBlob } from "../history-export";
import { SectionLabel } from "../approval-center-primitives";

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

const SUB_TABS: { key: SubTab; label: string; icon: React.ElementType }[] = [
  { key: "overview", label: "Overview", icon: HiMiniChartBar },
  { key: "calendar", label: "Calendar", icon: HiMiniCalendarDays },
  { key: "compare", label: "Compare", icon: HiMiniArrowPathRoundedSquare },
  { key: "export", label: "Export", icon: HiOutlineArrowDownTray },
];

function ExploreTabRaw({ receipts, filteredReceipts, filters, onFilterDay, onFilterHarness, onFilterAction }: ExploreTabProps) {
  const [activeSubTab, setActiveSubTab] = useState<SubTab>("overview");

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap gap-2" role="tablist" aria-label="Analytics views">
        {SUB_TABS.map((t) => {
          const Icon = t.icon;
          const isActive = activeSubTab === t.key;
          return (
            <button
              key={t.key}
              role="tab"
              aria-selected={isActive}
              aria-controls={`subtabpanel-${t.key}`}
              id={`subtab-${t.key}`}
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
        <div id="subtabpanel-overview" role="tabpanel" aria-labelledby="subtab-overview" className="space-y-6">
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
        <div id="subtabpanel-calendar" role="tabpanel" aria-labelledby="subtab-calendar">
          <ActivityCalendar receipts={filteredReceipts} onSelectDay={onFilterDay} />
        </div>
      )}

      {activeSubTab === "compare" && (
        <div id="subtabpanel-compare" role="tabpanel" aria-labelledby="subtab-compare">
          <CompareTimePeriods receipts={receipts} />
        </div>
      )}

      {activeSubTab === "export" && (
        <div id="subtabpanel-export" role="tabpanel" aria-labelledby="subtab-export">
          <ExportPanel receipts={filteredReceipts} filters={filters} />
        </div>
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
