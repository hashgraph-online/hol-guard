import { useCallback } from "react";
import type { ElementType } from "react";
import {
  HiMiniListBullet,
  HiMiniChartBar,
  HiMiniComputerDesktop,
  HiMiniArrowDownTray,
  HiMiniClock,
  HiMiniCalendarDays,
  HiMiniSquares2X2,
} from "react-icons/hi2";
import type { EvidenceView } from "./evidence-types";

export const VIEW_TABS: { key: EvidenceView; label: string; icon: ElementType }[] = [
  { key: "actions", label: "All actions", icon: HiMiniListBullet },
  { key: "insights", label: "Insights", icon: HiMiniChartBar },
  { key: "apps", label: "Apps", icon: HiMiniComputerDesktop },
  { key: "story", label: "Story", icon: HiMiniCalendarDays },
  { key: "categories", label: "Categories", icon: HiMiniSquares2X2 },
  { key: "export", label: "Export", icon: HiMiniArrowDownTray },
];

export function EvidenceLoadingState() {
  return (
    <div className="space-y-4" aria-busy="true" aria-label="Loading evidence">
      <div className="guard-skeleton h-8 w-64" />
      <div className="guard-skeleton h-32 w-full" />
    </div>
  );
}

export function EvidenceErrorState({ message }: { message: string }) {
  return (
    <div className="rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4">
      <p className="text-sm text-brand-dark">{message}</p>
    </div>
  );
}

export interface EvidenceHeaderProps {
  totalCount: number;
  lastActivityAt: string | null;
  onExport: () => void;
  onClear?: () => void;
}

export function EvidenceHeader({
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
      <div className="space-y-0.5 min-w-0">
        <h1 className="text-lg font-semibold text-brand-dark">Evidence</h1>
        <p className="text-xs text-slate-500">
          Every action Guard reviewed on this machine.
        </p>
        {lastActivityLabel && (
          <p className="flex items-center gap-1 text-[11px] text-slate-400">
            <HiMiniClock className="h-3 w-3" aria-hidden="true" />
            Last activity: {lastActivityLabel}
          </p>
        )}
      </div>
      <div className="flex items-center gap-1.5 shrink-0">
        <button
          type="button"
          onClick={onExport}
          aria-label="Export evidence"
          className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-brand-dark hover:bg-slate-50 transition-colors"
        >
          <HiMiniArrowDownTray className="h-3.5 w-3.5" aria-hidden="true" />
          Export
        </button>
        {onClear && totalCount > 0 && (
          <button
            type="button"
            onClick={onClear}
            aria-label="Clear all evidence"
            className="inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-500 hover:bg-slate-50 hover:text-brand-attention transition-colors"
          >
            Clear
          </button>
        )}
      </div>
    </div>
  );
}

export interface ViewTabBarProps {
  view: EvidenceView;
  onViewChange: (view: EvidenceView) => void;
}

export function ViewTabBar({ view, onViewChange }: ViewTabBarProps) {
  return (
    <div
      className="flex gap-1 border-b border-slate-200/60"
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
  icon: ElementType;
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
      role="tab"
      aria-selected={isActive}
      aria-controls={`tabpanel-${tabKey}`}
      id={`tab-${tabKey}`}
      onClick={handleClick}
      className={`relative flex items-center gap-1 px-2.5 py-1.5 text-xs font-medium transition-colors ${
        isActive
          ? "text-brand-dark"
          : "text-slate-500 hover:text-brand-dark"
      }`}
    >
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      <span className="hidden sm:inline">{label}</span>
      {isActive && (
        <span className="absolute bottom-0 left-1 right-1 h-0.5 rounded-full bg-brand-blue" />
      )}
    </button>
  );
}
