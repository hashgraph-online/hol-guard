import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { SectionLabel } from "../approval-center-primitives";
import { GuardStatMetric, type GuardStatMetricTone } from "./guard-stat-metric";
import { HomeInsightsMetrics } from "./evidence-insights-headline-bento";
import { EvidenceInsightsShareButton } from "./evidence-insights-share-button";
import { EvidenceActivityHeatmapMini, getHeatmapLevel } from "./evidence-activity-heatmap-mini";

export type HomeOverviewStatTone = GuardStatMetricTone;

export interface HomeOverviewStat {
  label: string;
  value: string;
  tone?: HomeOverviewStatTone;
}

interface EvidenceInsightsHomePreviewProps {
  overviewStats: [HomeOverviewStat, HomeOverviewStat, HomeOverviewStat];
  analytics: GuardReceiptAnalytics | null;
  analyticsLoading?: boolean;
  runtime: GuardRuntimeSnapshot | null;
  onOpenInsights?: () => void;
  onShare?: () => void;
}

function HomeInsightsSkeleton() {
  return (
    <>
      <div className="grid grid-cols-2 gap-px border-t border-slate-100 bg-slate-100 sm:grid-cols-4">
        {Array.from({ length: 4 }, (_, index) => (
          <div key={index} className="space-y-2 bg-white px-4 py-3.5 sm:py-4">
            <div className="guard-skeleton h-3 w-16 rounded" />
            <div className="guard-skeleton h-6 w-20 rounded" />
          </div>
        ))}
      </div>
      <div className="border-t border-slate-100 px-5 py-4">
        <div className="guard-skeleton mb-3 h-3 w-28 rounded" />
        <div className="grid grid-cols-5 gap-2">
          {Array.from({ length: 5 }, (_, index) => (
            <div key={index} className="flex flex-col items-center gap-1.5">
              <div className="guard-skeleton h-5 w-full max-w-5 rounded-[3px]" />
              <div className="guard-skeleton h-2.5 w-7 rounded" />
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

export function EvidenceInsightsHomePreview({
  overviewStats,
  analytics,
  analyticsLoading = false,
  onOpenInsights,
  onShare,
}: EvidenceInsightsHomePreviewProps) {
  const insightsAvailable = analytics !== null && analytics.total > 0;
  const showInsightsSection = analyticsLoading || insightsAvailable;
  const showInsightsFooter = Boolean(onOpenInsights) && (analyticsLoading || insightsAvailable);

  const miniHeatmapDays = analytics?.daily_activity?.slice(-5).map((day) => ({
    date: day.date_key,
    level: getHeatmapLevel(day.total, analytics?.peak_day_total || 1),
  })) ?? [];

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <div className="min-w-0 flex-1">
          <SectionLabel>Your Guard stats</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            What needs you now, plus patterns from recorded actions on this machine.
          </p>
        </div>
        {onShare && insightsAvailable ? (
          <EvidenceInsightsShareButton onClick={onShare} className="shrink-0" />
        ) : null}
      </div>

      <div className="grid grid-cols-3 gap-px bg-slate-100">
        {overviewStats.map((item, index) => (
          <GuardStatMetric
            key={item.label}
            label={item.label}
            value={item.value}
            tone={item.tone}
            compact
            animationDelayMs={index * 40}
          />
        ))}
      </div>

      {showInsightsSection ? (
        analyticsLoading ? (
          <HomeInsightsSkeleton />
        ) : analytics !== null && analytics.total > 0 ? (
          <>
            <HomeInsightsMetrics analytics={analytics} />
            <div className="border-t border-slate-100 px-5 py-4">
              <SectionLabel>Last 5 days</SectionLabel>
              <div className="mt-3">
                <EvidenceActivityHeatmapMini cells={miniHeatmapDays} />
              </div>
            </div>
          </>
        ) : null
      ) : null}

      {showInsightsFooter ? (
        <div className="border-t border-slate-100 px-5 py-4">
          {insightsAvailable && onOpenInsights ? (
            <button
              type="button"
              onClick={onOpenInsights}
              className="text-sm font-semibold text-brand-blue transition-colors hover:text-brand-blue/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 focus-visible:ring-offset-2"
            >
              See all insights →
            </button>
          ) : analyticsLoading ? (
            <div className="guard-skeleton h-4 w-36 rounded" />
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
