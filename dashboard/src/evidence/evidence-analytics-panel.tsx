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

function StatCard({
  label,
  value,
  subtext,
  tone,
}: {
  label: string;
  value: string;
  subtext?: string;
  tone: "blue" | "green" | "amber" | "purple" | "slate";
}) {
  const toneStyles: Record<string, { bg: string; text: string; accent: string }> = {
    blue: { bg: "bg-brand-blue/[0.04]", text: "text-brand-blue", accent: "bg-brand-blue" },
    green: { bg: "bg-emerald-50", text: "text-emerald-700", accent: "bg-emerald-500" },
    amber: { bg: "bg-amber-50", text: "text-amber-700", accent: "bg-amber-500" },
    purple: { bg: "bg-purple-50", text: "text-purple-700", accent: "bg-purple-500" },
    slate: { bg: "bg-slate-50", text: "text-slate-700", accent: "bg-slate-500" },
  };
  const style = toneStyles[tone];

  return (
    <div className={`rounded-2xl ${style.bg} p-5`}>
      <p className={`text-[11px] font-semibold uppercase tracking-wider ${style.text} opacity-70`}>
        {label}
      </p>
      <p className={`mt-1 text-3xl font-bold tabular-nums ${style.text}`}>{value}</p>
      {subtext && <p className="mt-1 text-xs text-slate-500">{subtext}</p>}
    </div>
  );
}

function TrendChart({ buckets }: { buckets: TrendBucket[] }) {
  const maxTotal = Math.max(...buckets.map((b) => b.allowed + b.blocked + b.reviewed), 1);

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-4">
        7-Day Activity
      </p>
      <div className="flex items-end gap-2 h-40">
        {buckets.map((bucket) => {
          const total = bucket.allowed + bucket.blocked + bucket.reviewed;
          const heightPct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
          const blockedHeight = total > 0 ? (bucket.blocked / total) * heightPct : 0;
          const allowedHeight = total > 0 ? (bucket.allowed / total) * heightPct : 0;

          return (
            <div key={bucket.dateKey} className="flex-1 flex flex-col items-center gap-1.5 min-w-0">
              <div className="w-full flex-1 flex items-end rounded-lg overflow-hidden bg-slate-50">
                <div className="w-full flex flex-col-reverse">
                  {bucket.blocked > 0 && (
                    <div
                      className="w-full bg-amber-400 rounded-b-sm"
                      style={{ height: `${Math.max(blockedHeight, 2)}%` }}
                    />
                  )}
                  {bucket.allowed > 0 && (
                    <div
                      className="w-full bg-emerald-400"
                      style={{ height: `${Math.max(allowedHeight, 2)}%` }}
                    />
                  )}
                  {bucket.reviewed > 0 && (
                    <div
                      className="w-full bg-brand-blue rounded-t-sm"
                      style={{
                        height: `${Math.max(heightPct - blockedHeight - allowedHeight, 2)}%`,
                      }}
                    />
                  )}
                </div>
              </div>
              <span className="text-[10px] text-slate-400 truncate w-full text-center">
                {bucket.label}
              </span>
            </div>
          );
        })}
      </div>
      <div className="mt-3 flex items-center gap-4 text-[11px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-emerald-400" />
          Allowed
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-amber-400" />
          Stopped
        </span>
        <span className="flex items-center gap-1.5">
          <span className="inline-block h-2 w-2 rounded-full bg-brand-blue" />
          Reviewed
        </span>
      </div>
    </div>
  );
}

function PeriodComparisonCard({ comparison, label }: { comparison: PeriodComparison; label: string }) {
  const blockedDeltaSign = comparison.blockedDelta > 0 ? "+" : "";
  const totalDeltaSign = comparison.totalDelta > 0 ? "+" : "";
  const blockedColor = comparison.blockedDelta > 0 ? "text-amber-600" : comparison.blockedDelta < 0 ? "text-emerald-600" : "text-slate-400";
  const totalColor = comparison.totalDelta > 0 ? "text-brand-blue" : comparison.totalDelta < 0 ? "text-slate-400" : "text-slate-400";

  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-5">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-3">
        {label}
      </p>
      <div className="grid grid-cols-2 gap-4">
        <div>
          <p className="text-2xl font-bold text-brand-dark tabular-nums">{comparison.currentTotal}</p>
          <p className="text-xs text-slate-500 mt-0.5">Total actions</p>
          <p className={`text-xs font-medium mt-1 ${totalColor}`}>
            {totalDeltaSign}{comparison.totalDelta} from prior period
          </p>
        </div>
        <div>
          <p className="text-2xl font-bold text-brand-dark tabular-nums">{comparison.currentBlocked}</p>
          <p className="text-xs text-slate-500 mt-0.5">Stopped</p>
          <p className={`text-xs font-medium mt-1 ${blockedColor}`}>
            {blockedDeltaSign}{comparison.blockedDelta} from prior period
          </p>
        </div>
      </div>
    </div>
  );
}

function AppBreakdownCard({
  harness,
  total,
  blocked,
  allowed,
  maxTotal,
  onFilter,
}: {
  harness: string;
  total: number;
  blocked: number;
  allowed: number;
  maxTotal: number;
  onFilter: (harness: string) => void;
}) {
  const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  const handleClick = useCallback(() => onFilter(harness), [harness, onFilter]);

  return (
    <button
      type="button"
      onClick={handleClick}
      className="w-full rounded-xl border border-slate-200 bg-white p-4 text-left transition-all hover:shadow-md hover:border-slate-300"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-sm font-semibold text-brand-dark">{harnessDisplayName(harness)}</span>
        <span className="text-xs tabular-nums text-slate-500">{total} actions</span>
      </div>
      <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden mb-2">
        <div
          className="bg-brand-blue h-2 rounded-full transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="flex items-center gap-3 text-[11px] text-slate-500">
        <span className="text-emerald-600">{allowed} allowed</span>
        {blocked > 0 && <span className="text-amber-600">{blocked} stopped</span>}
      </div>
    </button>
  );
}

function CategoryBreakdownCard({
  categoryKey,
  total,
  blocked,
  maxTotal,
  onFilter,
}: {
  categoryKey: string;
  total: number;
  blocked: number;
  maxTotal: number;
  onFilter: (category: string) => void;
}) {
  const pct = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
  const catInfo = getCategoryInfo(categoryKey as ReceiptCategory);
  const handleClick = useCallback(() => onFilter(categoryKey), [categoryKey, onFilter]);

  return (
    <button
      type="button"
      onClick={handleClick}
      className="w-full rounded-xl border border-slate-200 bg-white p-4 text-left transition-all hover:shadow-md hover:border-slate-300"
    >
      <div className="flex items-center gap-3 mb-2">
        <span className={`${catInfo.color}`} aria-hidden="true">{catInfo.icon}</span>
        <span className="text-sm font-semibold text-brand-dark">{catInfo.label}</span>
        <span className="ml-auto text-xs tabular-nums text-slate-500">{total} actions</span>
      </div>
      <div className="w-full bg-slate-100 rounded-full h-2 overflow-hidden mb-2">
        <div
          className="bg-purple-500 h-2 rounded-full transition-all"
          style={{ width: `${pct}%` }}
        />
      </div>
      {blocked > 0 && (
        <p className="text-[11px] text-amber-600">{blocked} stopped</p>
      )}
    </button>
  );
}

export function EvidenceAnalyticsPanel({
  metrics,
  onFilterHarness,
  onFilterCategory,
}: EvidenceAnalyticsPanelProps) {
  const sortedHarnesses = Array.from(metrics.byHarness.entries()).sort(
    (a, b) => b[1].total - a[1].total
  );
  const maxHarnessTotal = sortedHarnesses[0]?.[1].total ?? 1;

  const sortedCategories = Array.from(metrics.byCategory.entries()).sort(
    (a, b) => b[1].total - a[1].total
  );
  const maxCatTotal = sortedCategories[0]?.[1].total ?? 1;

  const appCount = metrics.byHarness.size;
  const catCount = metrics.byCategory.size;
  const stopRate = metrics.total > 0 ? Math.round((metrics.blocked / metrics.total) * 100) : 0;

  if (metrics.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-sm font-medium text-brand-dark">No data yet</p>
        <p className="mt-1 text-xs text-slate-500">Insights will appear once actions are recorded.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
        <StatCard label="Total Actions" value={String(metrics.total)} tone="blue" />
        <StatCard label="Stopped" value={String(metrics.blocked)} tone="amber" subtext={`${stopRate}% of total`} />
        <StatCard label="Allowed" value={String(metrics.allowed)} tone="green" />
        <StatCard label="Apps Seen" value={String(appCount)} tone="purple" />
        <StatCard label="Categories" value={String(catCount)} tone="slate" />
      </div>

      <TrendChart buckets={metrics.trendBuckets} />

      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        <PeriodComparisonCard comparison={metrics.periodComparison7d} label="vs. Prior 7 Days" />
        <PeriodComparisonCard comparison={metrics.periodComparison30d} label="vs. Prior 30 Days" />
      </div>

      {sortedHarnesses.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-3 px-1">
            By App
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {sortedHarnesses.map(([harness, counts]) => (
              <AppBreakdownCard
                key={harness}
                harness={harness}
                total={counts.total}
                blocked={counts.blocked}
                allowed={counts.allowed}
                maxTotal={maxHarnessTotal}
                onFilter={onFilterHarness}
              />
            ))}
          </div>
        </div>
      )}

      {sortedCategories.length > 0 && (
        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-3 px-1">
            By Category
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {sortedCategories.map(([cat, counts]) => (
              <CategoryBreakdownCard
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
        <div className="rounded-2xl border border-slate-200 bg-white p-5">
          <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400 mb-3">
            Top Recurring Actions
          </p>
          <div className="divide-y divide-slate-100">
            {metrics.topRecurring.slice(0, 5).map((action) => (
              <div
                key={action.name}
                className="flex items-center justify-between py-2.5"
              >
                <span className="text-sm text-brand-dark truncate pr-4">{action.name}</span>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-xs tabular-nums text-slate-500">{action.total}×</span>
                  {action.blocked > 0 && (
                    <span className="text-[10px] font-medium text-amber-600">{action.blocked} stopped</span>
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
