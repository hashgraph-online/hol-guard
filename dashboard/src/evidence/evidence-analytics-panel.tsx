import { useState } from "react";
import type { EvidenceMetrics, TrendBucket, PeriodComparison } from "./evidence-metrics";
import { SectionLabel, Badge } from "../approval-center-primitives";
import { AppBreakdownCard, CategoryBreakdownCard } from "./breakdown-card";
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
  const toneColor = tone === "blue" ? "text-brand-blue" : tone === "green" ? "text-emerald-600" : tone === "amber" ? "text-amber-600" : tone === "purple" ? "text-brand-purple" : "text-slate-600";

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
      <SectionLabel>{label}</SectionLabel>
      <p className={`mt-2 text-3xl font-bold tabular-nums tracking-tight ${toneColor}`}>{value}</p>
      {subtext && <p className="mt-1 text-xs text-slate-500">{subtext}</p>}
    </div>
  );
}

function TrendChart({ buckets }: { buckets: TrendBucket[] }) {
  const [hoveredBucket, setHoveredBucket] = useState<string | null>(null);
  const maxTotal = Math.max(...buckets.map((b) => b.allowed + b.blocked + b.reviewed), 1);
  const hasAnyData = buckets.some((b) => b.allowed + b.blocked + b.reviewed > 0);

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
      <SectionLabel>7-Day Activity</SectionLabel>

      {!hasAnyData ? (
        <div className="flex flex-col items-center justify-center h-40 text-center">
          <p className="text-sm text-slate-400">No activity in the last 7 days</p>
        </div>
      ) : (
        <>
          <div className="flex gap-2 h-44 mt-4">
            {buckets.map((bucket) => {
              const total = bucket.allowed + bucket.blocked + bucket.reviewed;
              const heightPct = maxTotal > 0 ? Math.max((total / maxTotal) * 100, 6) : 0;
              const blockedPct = total > 0 ? (bucket.blocked / total) * 100 : 0;
              const allowedPct = total > 0 ? (bucket.allowed / total) * 100 : 0;
              const reviewedPct = total > 0 ? (bucket.reviewed / total) * 100 : 0;
              const isHovered = hoveredBucket === bucket.dateKey;

              return (
                <div
                  key={bucket.dateKey}
                  className="relative flex-1 flex flex-col justify-end gap-1 min-w-0"
                  onMouseEnter={() => setHoveredBucket(bucket.dateKey)}
                  onMouseLeave={() => setHoveredBucket(null)}
                >
                  {total > 0 && (
                    <span className="text-[10px] font-semibold text-brand-dark tabular-nums text-center">
                      {total}
                    </span>
                  )}
                  <div
                    className={`relative w-full flex-1 flex items-end rounded-lg overflow-hidden ${
                      total > 0 ? "bg-slate-100/60 ring-1 ring-inset ring-slate-200" : "bg-slate-50 ring-1 ring-inset ring-slate-200"
                    }`}
                  >
                    {total > 0 ? (
                      <div className="w-full flex flex-col-reverse rounded-lg overflow-hidden" style={{ height: `${heightPct}%` }}>
                        {bucket.blocked > 0 && (
                          <div
                            className="w-full bg-amber-500 transition-all"
                            style={{ height: `${Math.max(blockedPct, 4)}%` }}
                            aria-label={`${bucket.blocked} stopped`}
                          />
                        )}
                        {bucket.allowed > 0 && (
                          <div
                            className="w-full bg-emerald-500 transition-all"
                            style={{ height: `${Math.max(allowedPct, 4)}%` }}
                            aria-label={`${bucket.allowed} allowed`}
                          />
                        )}
                        {bucket.reviewed > 0 && (
                          <div
                            className="w-full bg-brand-blue transition-all"
                            style={{ height: `${Math.max(reviewedPct, 4)}%` }}
                            aria-label={`${bucket.reviewed} reviewed`}
                          />
                        )}
                      </div>
                    ) : (
                      <div className="w-full h-full" />
                    )}
                    {isHovered && total > 0 && (
                      <div className="absolute inset-0 flex items-center justify-center bg-black/5" />
                    )}
                  </div>
                  <span className="text-[10px] text-slate-500 truncate w-full text-center font-medium">
                    {bucket.label}
                  </span>
                  {isHovered && total > 0 && (
                    <div
                      className="absolute z-10 bg-brand-dark text-white text-xs rounded-lg px-3 py-2 shadow-lg whitespace-nowrap mb-2"
                      style={{ bottom: "100%", left: "50%", transform: "translateX(-50%)" }}
                    >
                      <div className="font-semibold">{bucket.label}</div>
                      <div className="flex gap-3 mt-1">
                        {bucket.allowed > 0 && <span className="text-emerald-300">{bucket.allowed} allowed</span>}
                        {bucket.blocked > 0 && <span className="text-amber-300">{bucket.blocked} stopped</span>}
                        {bucket.reviewed > 0 && <span className="text-blue-300">{bucket.reviewed} reviewed</span>}
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
          <div className="mt-3 flex items-center gap-4 text-[11px] text-slate-500">
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-emerald-500" />
              Allowed
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-amber-500" />
              Stopped
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-brand-blue" />
              Reviewed
            </span>
          </div>
        </>
      )}
    </div>
  );
}

function PeriodComparisonCard({ comparison, label }: { comparison: PeriodComparison; label: string }) {
  const blockedDeltaSign = comparison.blockedDelta > 0 ? "+" : "";
  const totalDeltaSign = comparison.totalDelta > 0 ? "+" : "";
  const blockedColor = comparison.blockedDelta > 0 ? "text-amber-600" : comparison.blockedDelta < 0 ? "text-emerald-600" : "text-slate-400";
  const totalColor = comparison.totalDelta > 0 ? "text-brand-blue" : comparison.totalDelta < 0 ? "text-slate-400" : "text-slate-400";

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
      <SectionLabel>{label}</SectionLabel>
      <div className="grid grid-cols-2 gap-4 mt-3">
        <div>
          <p className="text-2xl font-bold text-brand-dark tabular-nums tracking-tight">{comparison.currentTotal}</p>
          <p className="text-xs text-slate-500 mt-0.5">Total actions</p>
          <p className={`text-xs font-medium mt-1 ${totalColor}`}>
            {totalDeltaSign}{comparison.totalDelta} from prior period
          </p>
        </div>
        <div>
          <p className="text-2xl font-bold text-brand-dark tabular-nums tracking-tight">{comparison.currentBlocked}</p>
          <p className="text-xs text-slate-500 mt-0.5">Stopped</p>
          <p className={`text-xs font-medium mt-1 ${blockedColor}`}>
            {blockedDeltaSign}{comparison.blockedDelta} from prior period
          </p>
        </div>
      </div>
    </div>
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
          <div className="px-1 mb-3">
            <SectionLabel>By App</SectionLabel>
          </div>
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
          <div className="px-1 mb-3">
            <SectionLabel>By Category</SectionLabel>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {sortedCategories.map(([cat, counts]) => (
              <CategoryBreakdownCard
                key={cat}
                categoryKey={cat as ReceiptCategory}
                total={counts.total}
                blocked={counts.blocked}
                maxTotal={maxCatTotal}
                onFilter={(c) => onFilterCategory(c as string)}
              />
            ))}
          </div>
        </div>
      )}

      {metrics.topRecurring.length > 0 && (
        <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
          <SectionLabel>Top Recurring Actions</SectionLabel>
          <div className="divide-y divide-slate-100 mt-3">
            {metrics.topRecurring.slice(0, 5).map((action) => (
              <div
                key={action.name}
                className="flex items-center justify-between py-2.5"
              >
                <span className="text-sm text-brand-dark truncate pr-4">{action.name}</span>
                <div className="flex items-center gap-3 shrink-0">
                  <Badge tone="default">{action.total}×</Badge>
                  {action.blocked > 0 && (
                    <Badge tone="attention">{action.blocked} stopped</Badge>
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
