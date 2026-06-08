import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { formatBlockedShare, formatEvidenceCount } from "./evidence-format";
import { GuardStatMetric, type GuardStatMetricTone } from "./guard-stat-metric";

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
    <div className="grid grid-cols-2 gap-px border-t border-slate-100 bg-slate-100 sm:grid-cols-4">
      {Array.from({ length: 4 }, (_, index) => (
        <div key={index} className="space-y-2 bg-white px-4 py-3.5 sm:py-4">
          <div className="guard-skeleton h-3 w-16 rounded" />
          <div className="guard-skeleton h-6 w-20 rounded" />
        </div>
      ))}
    </div>
  );
}

function HomeInsightsMetrics({ analytics }: { analytics: GuardReceiptAnalytics }) {
  const topApp = analytics.by_harness[0] ? harnessDisplayName(analytics.by_harness[0].harness) : "None yet";
  const streakUnit = analytics.active_day_streak === 1 ? "day" : "days";

  return (
    <div className="grid grid-cols-2 gap-px border-t border-slate-100 bg-slate-100 sm:grid-cols-4">
      <GuardStatMetric
        label="Current streak"
        value={
          <>
            {analytics.active_day_streak}
            <span className="ml-1 text-sm font-medium text-slate-500">{streakUnit}</span>
          </>
        }
        compact
        animationDelayMs={120}
      />
      <GuardStatMetric
        label="Peak day"
        value={formatEvidenceCount(analytics.peak_day_total)}
        detail="Most actions in one day"
        compact
        animationDelayMs={160}
      />
      <GuardStatMetric
        label="Stopped"
        value={formatEvidenceCount(analytics.blocked)}
        detail={formatBlockedShare(analytics.blocked, analytics.total)}
        compact
        animationDelayMs={200}
      />
      <GuardStatMetric
        label="Top app"
        value={topApp}
        detail="Most recorded actions"
        compact
        animationDelayMs={240}
      />
    </div>
  );
}

export function EvidenceInsightsHomePreview({
  overviewStats,
  analytics,
  analyticsLoading = false,
  runtime,
  onOpenInsights,
  onShare,
}: EvidenceInsightsHomePreviewProps) {
  const cloudConnected = runtime?.cloud_state === "paired_active";
  const insightsAvailable = analytics !== null && analytics.total > 0;
  const showInsightsSection = analyticsLoading || insightsAvailable;
  const showInsightsFooter = Boolean(onOpenInsights) && (analyticsLoading || insightsAvailable);

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <div className="min-w-0 flex-1">
          <SectionLabel>Your Guard stats</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            What needs you now, plus patterns from recorded actions on this machine.
          </p>
        </div>
        {cloudConnected && onShare && insightsAvailable ? (
          <ActionButton variant="outline" onClick={onShare} className="shrink-0">
            Share stats
          </ActionButton>
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
        ) : insightsAvailable ? (
          <HomeInsightsMetrics analytics={analytics} />
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
