import { useState } from "react";
import type { GuardReceiptAnalyticsBucket } from "../guard-types";

export function selectRecentTrendBuckets(
  buckets: GuardReceiptAnalyticsBucket[],
  dayCount: number,
): GuardReceiptAnalyticsBucket[] {
  if (dayCount <= 0) {
    return [];
  }
  return buckets.slice(-dayCount);
}

function bucketTotal(bucket: GuardReceiptAnalyticsBucket): number {
  return bucket.allowed + bucket.blocked + bucket.reviewed;
}

interface EvidenceTrendChartProps {
  buckets: GuardReceiptAnalyticsBucket[];
  variant?: "full" | "mini";
  dayCount?: number;
}

export function EvidenceTrendChart({
  buckets,
  variant = "full",
  dayCount,
}: EvidenceTrendChartProps) {
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const visibleBuckets =
    variant === "mini" ? selectRecentTrendBuckets(buckets, dayCount ?? 4) : buckets;
  const maxTotal = Math.max(...visibleBuckets.map((bucket) => bucketTotal(bucket)), 1);
  const chartHeight = variant === "mini" ? 52 : 100;
  const hasAnyData = visibleBuckets.some((bucket) => bucketTotal(bucket) > 0);

  if (!hasAnyData) {
    return (
      <p className={`text-sm text-slate-400 ${variant === "mini" ? "py-2" : "px-5 py-6"}`}>
        No activity in this period.
      </p>
    );
  }

  const chart = (
    <div
      className={`flex items-end ${variant === "mini" ? "gap-1.5" : "gap-2"}`}
      style={{ minHeight: chartHeight }}
      role="img"
      aria-label={variant === "mini" ? "Last four days of Guard activity" : "Seven day activity chart"}
    >
      {visibleBuckets.map((bucket) => {
        const total = bucketTotal(bucket);
        const barHeight = total > 0 ? Math.max(Math.round((total / maxTotal) * chartHeight), variant === "mini" ? 4 : 6) : 0;
        const blockedHeight = total > 0 ? Math.round((bucket.blocked / total) * barHeight) : 0;
        const allowedHeight = total > 0 ? Math.round((bucket.allowed / total) * barHeight) : 0;
        const reviewedHeight = Math.max(barHeight - blockedHeight - allowedHeight, 0);
        const isHovered = hoveredKey === bucket.date_key;

        return (
          <div
            key={bucket.date_key}
            className="relative flex min-w-0 flex-1 flex-col items-center justify-end"
            onMouseEnter={() => setHoveredKey(bucket.date_key)}
            onMouseLeave={() => setHoveredKey(null)}
          >
            {variant === "full" && total > 0 && (
              <span className="mb-1 text-[10px] font-semibold tabular-nums text-brand-dark">{total}</span>
            )}
            <div className="flex w-full flex-col justify-end" style={{ height: chartHeight }}>
              {total > 0 ? (
                <div
                  className={`flex w-full flex-col-reverse overflow-hidden ${
                    variant === "mini" ? "rounded-[4px]" : "rounded-md"
                  } transition-opacity ${
                    isHovered ? "opacity-100 ring-1 ring-inset ring-slate-200" : "opacity-95"
                  }`}
                  style={{ height: barHeight }}
                >
                  {bucket.blocked > 0 && (
                    <div className="w-full evidence-chart-stopped" style={{ height: blockedHeight }} />
                  )}
                  {bucket.allowed > 0 && (
                    <div className="w-full evidence-chart-allowed" style={{ height: allowedHeight }} />
                  )}
                  {bucket.reviewed > 0 && (
                    <div className="w-full evidence-chart-reviewed" style={{ height: reviewedHeight }} />
                  )}
                </div>
              ) : (
                <div className="mx-auto h-1.5 w-1.5 rounded-full bg-slate-200" aria-hidden="true" />
              )}
            </div>
            <span
              className={`mt-1.5 w-full truncate text-center font-medium text-slate-500 ${
                variant === "mini" ? "text-[9px] tracking-[0.02em]" : "mt-2 text-[10px]"
              }`}
            >
              {bucket.label}
            </span>
            {isHovered && total > 0 && (
              <div className="absolute bottom-full z-10 mb-2 rounded-lg bg-brand-dark px-3 py-2 text-xs text-white shadow-lg">
                <div className="font-semibold">{bucket.label}</div>
                <div className="mt-1 flex gap-3">
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
  );

  if (variant === "mini") {
    return (
      <div className="space-y-2">
        {chart}
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[10px] text-slate-500">
          <span className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm evidence-chart-allowed" />
            Allowed
          </span>
          <span className="inline-flex items-center gap-1">
            <span className="inline-block h-2 w-2 rounded-sm evidence-chart-stopped" />
            Stopped
          </span>
        </div>
      </div>
    );
  }

  return (
    <div className="px-5 py-5">
      {chart}
      <div className="mt-3 flex flex-wrap items-center gap-3 text-[11px] text-slate-500">
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm evidence-chart-allowed" />
          Allowed
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm evidence-chart-stopped" />
          Stopped
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span className="inline-block h-2.5 w-2.5 rounded-sm evidence-chart-reviewed" />
          Reviewed
        </span>
      </div>
    </div>
  );
}
