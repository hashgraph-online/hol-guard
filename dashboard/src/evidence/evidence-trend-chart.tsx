import { useState } from "react";
import type { GuardReceiptAnalyticsBucket } from "../guard-types";

function bucketTotal(bucket: GuardReceiptAnalyticsBucket): number {
  return bucket.allowed + bucket.blocked + bucket.reviewed;
}

interface EvidenceTrendChartProps {
  buckets: GuardReceiptAnalyticsBucket[];
}

export function EvidenceTrendChart({ buckets }: EvidenceTrendChartProps) {
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const maxTotal = Math.max(...buckets.map((bucket) => bucketTotal(bucket)), 1);
  const chartHeight = 100;
  const hasAnyData = buckets.some((bucket) => bucketTotal(bucket) > 0);

  if (!hasAnyData) {
    return <p className="px-5 py-6 text-sm text-slate-400">No activity in this period.</p>;
  }

  return (
    <div className="px-5 py-5">
      <div
        className="flex items-end gap-2"
        style={{ minHeight: chartHeight }}
        role="img"
        aria-label="Seven day activity chart"
      >
        {buckets.map((bucket) => {
          const total = bucketTotal(bucket);
          const barHeight = total > 0 ? Math.max(Math.round((total / maxTotal) * chartHeight), 6) : 0;
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
              {total > 0 && (
                <span className="mb-1 text-[10px] font-semibold tabular-nums text-brand-dark">{total}</span>
              )}
              <div className="flex w-full flex-col justify-end" style={{ height: chartHeight }}>
                {total > 0 ? (
                  <div
                    className={`flex w-full flex-col-reverse overflow-hidden rounded-md transition-opacity ${
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
              <span className="mt-2 w-full truncate text-center text-[10px] font-medium text-slate-500">
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
