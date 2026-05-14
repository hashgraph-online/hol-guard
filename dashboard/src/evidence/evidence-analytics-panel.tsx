import { useCallback } from "react";
import type { EvidenceMetrics, TrendBucket, PeriodComparison } from "./evidence-metrics";
import { harnessDisplayName } from "../approval-center-utils";
import { getCategoryInfo } from "./categories";
import type { ReceiptCategory } from "./categories";

interface EvidenceAnalyticsPanelProps {
  metrics: EvidenceMetrics;
  onFilterHarness: (harness: string) => void;
  onFilterCategory: (category: string) => void;
}

interface TrendBarProps {
  bucket: TrendBucket;
  maxTotal: number;
}

function TrendBar({ bucket, maxTotal }: TrendBarProps) {
  const total = bucket.allowed + bucket.blocked + bucket.reviewed;
  const heightPct = maxTotal > 0 ? Math.max(4, (total / maxTotal) * 100) : 4;
  const blockedPct = total > 0 ? (bucket.blocked / total) * 100 : 0;
  const allowedPct = total > 0 ? (bucket.allowed / total) * 100 : 0;

  return (
    <div className="flex flex-col items-center gap-1 flex-1 min-w-0">
      <div
        className="w-full rounded-sm overflow-hidden flex flex-col-reverse bg-slate-100"
        style={{ height: 48 }}
        aria-label={`${bucket.label}: ${total} actions`}
      >
        <div
          className="w-full bg-emerald-300 transition-all"
          style={{ height: `${heightPct * (allowedPct / 100)}%` }}
          aria-hidden="true"
        />
        {bucket.blocked > 0 && (
          <div
            className="w-full bg-amber-400 transition-all"
            style={{ height: `${heightPct * (blockedPct / 100)}%` }}
            aria-hidden="true"
          />
        )}
      </div>
      <span className="text-[10px] text-slate-400 truncate w-full text-center">
        {bucket.label}
      </span>
    </div>
  );
}

interface AppBreakdownRowProps {
  harness: string;
  total: number;
  blocked: number;
  maxTotal: number;
  onFilter: (harness: string) => void;
}

function AppBreakdownRow({
  harness,
  total,
  blocked,
  maxTotal,
  onFilter,
}: AppBreakdownRowProps) {
  const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;

  const handleClick = useCallback(() => {
    onFilter(harness);
  }, [harness, onFilter]);

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-label={`Filter by app ${harnessDisplayName(harness)}`}
      className="w-full flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-slate-50 transition-colors text-left"
    >
      <span className="text-sm font-medium text-brand-dark w-28 shrink-0 truncate">
        {harnessDisplayName(harness)}
      </span>
      <div className="flex-1 bg-slate-100 rounded-full h-1.5 overflow-hidden">
        <div
          className="bg-brand-blue h-1.5 rounded-full transition-all"
          style={{ width: `${pct}%` }}
          aria-hidden="true"
        />
      </div>
      <span className="text-xs tabular-nums text-slate-500 shrink-0 w-6 text-right">{total}</span>
      {blocked > 0 && (
        <span className="text-[10px] font-medium text-brand-attention shrink-0">
          {blocked} blocked
        </span>
      )}
    </button>
  );
}

interface CategoryBreakdownRowProps {
  categoryKey: string;
  total: number;
  blocked: number;
  maxTotal: number;
  onFilter: (category: string) => void;
}

function CategoryBreakdownRow({
  categoryKey,
  total,
  blocked,
  maxTotal,
  onFilter,
}: CategoryBreakdownRowProps) {
  const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  const catInfo = getCategoryInfo(categoryKey as ReceiptCategory);

  const handleClick = useCallback(() => {
    onFilter(categoryKey);
  }, [categoryKey, onFilter]);

  return (
    <button
      type="button"
      onClick={handleClick}
      aria-label={`Filter by category ${catInfo.label}`}
      className="w-full flex items-center gap-3 px-2 py-1.5 rounded-lg hover:bg-slate-50 transition-colors text-left"
    >
      <span className={`shrink-0 ${catInfo.color}`} aria-hidden="true">
        {catInfo.icon}
      </span>
      <span className="text-sm font-medium text-brand-dark w-24 shrink-0 truncate">
        {catInfo.label}
      </span>
      <div className="flex-1 bg-slate-100 rounded-full h-1.5 overflow-hidden">
        <div
          className="bg-brand-purple h-1.5 rounded-full transition-all"
          style={{ width: `${pct}%` }}
          aria-hidden="true"
        />
      </div>
      <span className="text-xs tabular-nums text-slate-500 shrink-0 w-6 text-right">{total}</span>
      {blocked > 0 && (
        <span className="text-[10px] font-medium text-brand-attention shrink-0">
          {blocked} blocked
        </span>
      )}
    </button>
  );
}

interface SectionHeadingProps {
  children: React.ReactNode;
}

function SectionHeading({ children }: SectionHeadingProps) {
  return (
    <h3 className="text-[11px] font-semibold uppercase tracking-wide text-slate-400 px-2">
      {children}
    </h3>
  );
}

interface PeriodComparisonCardProps {
  comparison: PeriodComparison;
  label: string;
}

function PeriodComparisonCard({ comparison, label }: PeriodComparisonCardProps) {
  const blockedDeltaSign = comparison.blockedDelta > 0 ? "+" : "";
  const totalDeltaSign = comparison.totalDelta > 0 ? "+" : "";
  let blockedColor = "text-slate-400";
  if (comparison.blockedDelta > 0) {
    blockedColor = "text-brand-attention";
  } else if (comparison.blockedDelta < 0) {
    blockedColor = "text-emerald-600";
  }

  return (
    <div className="rounded-xl bg-slate-50 px-3 py-2.5 space-y-1">
      <p className="text-[11px] font-semibold uppercase tracking-wide text-slate-400">{label}</p>
      <div className="flex items-baseline gap-3">
        <span className="text-sm font-medium text-brand-dark tabular-nums">
          {comparison.currentTotal} actions
          <span className="ml-1.5 text-xs text-slate-400">({totalDeltaSign}{comparison.totalDelta})</span>
        </span>
        <span className={`text-xs font-medium tabular-nums ${blockedColor}`}>
          {comparison.currentBlocked} stopped
          <span className="ml-1">({blockedDeltaSign}{comparison.blockedDelta})</span>
        </span>
      </div>
    </div>
  );
}

export function EvidenceAnalyticsPanel({
  metrics,
  onFilterHarness,
  onFilterCategory,
}: EvidenceAnalyticsPanelProps) {
  const maxBucketTotal = Math.max(
    ...metrics.trendBuckets.map((b) => b.allowed + b.blocked),
    1
  );

  const sortedHarnesses = Array.from(metrics.byHarness.entries()).sort(
    (a, b) => b[1].total - a[1].total
  );
  const maxHarnessTotal = sortedHarnesses[0]?.[1].total ?? 1;

  const sortedCategories = Array.from(metrics.byCategory.entries()).sort(
    (a, b) => b[1].total - a[1].total
  );
  const maxCatTotal = sortedCategories[0]?.[1].total ?? 1;

  if (metrics.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-sm font-medium text-brand-dark">No data yet</p>
        <p className="mt-1 text-xs text-slate-500">
          Insights will appear once actions are recorded.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="space-y-2">
        <SectionHeading>7-day trend</SectionHeading>
        <div className="flex items-end gap-1.5 px-2 pt-1">
          {metrics.trendBuckets.map((bucket) => (
            <TrendBar
              key={bucket.dateKey}
              bucket={bucket}
              maxTotal={maxBucketTotal}
            />
          ))}
        </div>
        <div className="flex items-center gap-3 px-2 text-[11px] text-slate-400">
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm bg-emerald-300" aria-hidden="true" />
            Allowed
          </span>
          <span className="flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm bg-amber-400" aria-hidden="true" />
            Stopped
          </span>
        </div>
      </div>

      <div className="space-y-2">
        <SectionHeading>Period comparison</SectionHeading>
        <PeriodComparisonCard comparison={metrics.periodComparison7d} label="vs. prior 7 days" />
        <PeriodComparisonCard comparison={metrics.periodComparison30d} label="vs. prior 30 days" />
      </div>

      {sortedHarnesses.length > 0 && (
        <div className="space-y-1">
          <SectionHeading>By app</SectionHeading>
          <div className="space-y-0.5">
            {sortedHarnesses.map(([harness, counts]) => (
              <AppBreakdownRow
                key={harness}
                harness={harness}
                total={counts.total}
                blocked={counts.blocked}
                maxTotal={maxHarnessTotal}
                onFilter={onFilterHarness}
              />
            ))}
          </div>
        </div>
      )}

      {sortedCategories.length > 0 && (
        <div className="space-y-1">
          <SectionHeading>By category</SectionHeading>
          <div className="space-y-0.5">
            {sortedCategories.map(([cat, counts]) => (
              <CategoryBreakdownRow
                key={cat}
                categoryKey={cat}
                total={counts.total}
                blocked={counts.blocked}
                maxTotal={maxCatTotal}
                onFilter={onFilterCategory}
              />
            ))}
          </div>
        </div>
      )}

      {metrics.topRecurring.length > 0 && (
        <div className="space-y-1">
          <SectionHeading>Top recurring actions</SectionHeading>
          <div className="divide-y divide-slate-100/60">
            {metrics.topRecurring.slice(0, 5).map((action) => (
              <div
                key={action.name}
                className="flex items-center justify-between px-2 py-1.5"
              >
                <span className="text-sm text-brand-dark truncate">{action.name}</span>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-xs tabular-nums text-slate-500">
                    {action.total}×
                  </span>
                  {action.blocked > 0 && (
                    <span className="text-[10px] font-medium text-brand-attention">
                      {action.blocked} blocked
                    </span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
