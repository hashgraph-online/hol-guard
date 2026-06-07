import { useEffect, useMemo, useState } from "react";
import type {
  GuardReceiptAnalytics,
  GuardReceiptAnalyticsBucket,
  GuardReceiptArtifactStat,
  GuardReceiptHarnessStat,
  GuardRuntimeSnapshot,
} from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { SectionLabel } from "../approval-center-primitives";
import { EvidenceActivityHeatmap } from "./evidence-activity-heatmap";
import { EvidenceDataProvenanceStrip } from "./evidence-data-provenance-strip";
import { EvidenceShareBar } from "./evidence-share-bar";
import { formatEvidenceCount } from "./evidence-format";

interface EvidenceInsightsSurfaceProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  sampleCount: number;
  onFilterHarness: (harness: string) => void;
  onFilterDay?: (dateKey: string) => void;
  onViewActions: () => void;
}

function HeadlineMetrics({ analytics }: { analytics: GuardReceiptAnalytics }) {
  const stopRate = analytics.total > 0 ? Math.round((analytics.blocked / analytics.total) * 100) : 0;
  const dominantApp = analytics.by_harness[0]
    ? harnessDisplayName(analytics.by_harness[0].harness)
    : "None yet";

  const items = [
    {
      label: "Current streak",
      value: `${analytics.active_day_streak}`,
      unit: analytics.active_day_streak === 1 ? "day" : "days",
      emphasis: "hero" as const,
    },
    {
      label: "Peak day",
      value: formatEvidenceCount(analytics.peak_day_total),
      unit: "actions",
      emphasis: "hero" as const,
    },
    {
      label: "Lifetime actions",
      value: formatEvidenceCount(analytics.total),
      unit: null,
      emphasis: "medium" as const,
    },
    {
      label: "Stopped",
      value: formatEvidenceCount(analytics.blocked),
      unit: `${stopRate}% of total`,
      emphasis: "medium" as const,
    },
    {
      label: "Top app",
      value: dominantApp,
      unit: null,
      emphasis: "quiet" as const,
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-px bg-slate-100 sm:grid-cols-3 lg:grid-cols-5">
      {items.map((item, index) => (
        <div
          key={item.label}
          className={`bg-white px-4 py-4 sm:py-5 evidence-metric-enter ${item.emphasis === "hero" ? "sm:py-6" : ""}`}
          style={{ animationDelay: `${index * 60}ms` }}
        >
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
          <p
            className={`mt-1 font-semibold tabular-nums tracking-tight text-brand-dark ${
              item.emphasis === "hero" ? "text-3xl" : item.emphasis === "medium" ? "text-xl" : "text-base truncate"
            }`}
          >
            {item.value}
            {item.emphasis === "hero" && item.unit ? (
              <span className="ml-1 text-sm font-medium text-slate-500">{item.unit}</span>
            ) : null}
          </p>
          {item.emphasis !== "hero" && item.unit ? (
            <p className="mt-0.5 text-xs text-slate-500">{item.unit}</p>
          ) : null}
        </div>
      ))}
    </div>
  );
}

function TrendChart({ buckets }: { buckets: GuardReceiptAnalyticsBucket[] }) {
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const maxTotal = Math.max(...buckets.map((bucket) => bucket.allowed + bucket.blocked + bucket.reviewed), 1);
  const chartHeight = 100;
  const hasAnyData = buckets.some((bucket) => bucket.allowed + bucket.blocked + bucket.reviewed > 0);

  if (!hasAnyData) {
    return <p className="px-5 py-6 text-sm text-slate-400">No activity in the last 7 days.</p>;
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
          const total = bucket.allowed + bucket.blocked + bucket.reviewed;
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

function HarnessShareList(props: {
  items: GuardReceiptHarnessStat[];
  total: number;
  onFilterHarness: (harness: string) => void;
}) {
  if (props.items.length === 0) {
    return <p className="text-sm text-slate-400">No app activity yet.</p>;
  }
  return (
    <div className="space-y-0.5">
      {props.items.slice(0, 6).map((item) => (
        <EvidenceShareBar
          key={item.harness}
          label={harnessDisplayName(item.harness)}
          count={item.total}
          shareOfTotal={props.total > 0 ? (item.total / props.total) * 100 : 0}
          onClick={() => props.onFilterHarness(item.harness)}
        />
      ))}
    </div>
  );
}

function ArtifactShareList(props: { items: GuardReceiptArtifactStat[]; total: number }) {
  if (props.items.length === 0) {
    return <p className="text-sm text-slate-400">No recurring actions yet.</p>;
  }
  return (
    <div className="space-y-0.5">
      {props.items.slice(0, 6).map((item) => (
        <EvidenceShareBar
          key={item.name}
          label={item.name}
          count={item.total}
          shareOfTotal={props.total > 0 ? (item.total / props.total) * 100 : 0}
        />
      ))}
    </div>
  );
}

export function EvidenceInsightsSurface({
  analytics,
  runtime,
  sampleCount,
  onFilterHarness,
  onFilterDay,
  onViewActions,
}: EvidenceInsightsSurfaceProps) {
  const [mounted, setMounted] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);

  const artifactTotal = useMemo(
    () => analytics.top_artifacts.reduce((sum, item) => sum + item.total, 0),
    [analytics.top_artifacts],
  );

  if (analytics.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-sm font-medium text-brand-dark">No data yet</p>
        <p className="mt-1 text-xs text-slate-500">Insights appear once Guard records actions on this machine.</p>
      </div>
    );
  }

  return (
    <div className={`overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm ${mounted ? "evidence-insights-mounted" : ""}`}>
      <HeadlineMetrics analytics={analytics} />

      <div className="border-t border-slate-100 px-5 py-5">
        <SectionLabel>90-Day Activity</SectionLabel>
        <div className="mt-4 min-h-[120px]">
          <EvidenceActivityHeatmap days={analytics.daily_activity} onSelectDay={onFilterDay} />
        </div>
      </div>

      <div className="grid grid-cols-1 border-t border-slate-100 lg:grid-cols-2 lg:divide-x lg:divide-slate-100">
        <div className="px-5 py-5">
          <SectionLabel>Most Active Apps</SectionLabel>
          <div className="mt-3">
            <HarnessShareList
              items={analytics.by_harness}
              total={analytics.total}
              onFilterHarness={onFilterHarness}
            />
          </div>
        </div>
        <div className="border-t border-slate-100 px-5 py-5 lg:border-t-0">
          <SectionLabel>Top Recurring Actions</SectionLabel>
          <div className="mt-3">
            <ArtifactShareList items={analytics.top_artifacts} total={artifactTotal || analytics.total} />
          </div>
        </div>
      </div>

      <div className="border-t border-slate-100">
        <div className="px-5 pt-5">
          <SectionLabel>Last 7 Days</SectionLabel>
        </div>
        <TrendChart buckets={analytics.trend_buckets} />
      </div>

      <EvidenceDataProvenanceStrip
        analytics={analytics}
        sampleCount={sampleCount}
        runtime={runtime}
        onViewActions={onViewActions}
      />
    </div>
  );
}
