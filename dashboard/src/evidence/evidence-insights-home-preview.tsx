import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { EvidenceInsightsHeadlineBento } from "./evidence-insights-headline-bento";
import { EvidenceInsightsShareButton } from "./evidence-insights-share-button";

export type HomeOverviewStatTone = "blue" | "green" | "purple" | "slate";

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

function overviewValueClass(tone: HomeOverviewStatTone | undefined): string {
  switch (tone) {
    case "blue":
      return "text-brand-blue";
    case "green":
      return "text-emerald-600";
    case "purple":
      return "text-brand-purple";
    default:
      return "text-brand-dark";
  }
}

function HomeOverviewStatsRow({ items }: { items: HomeOverviewStat[] }) {
  return (
    <div className="grid grid-cols-3 gap-px bg-slate-100">
      {items.map((item, index) => (
        <div
          key={item.label}
          className="bg-white px-4 py-3.5 sm:py-4 evidence-metric-enter"
          style={{ animationDelay: `${index * 40}ms` }}
        >
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
          <p className={`mt-1 text-lg font-semibold tabular-nums tracking-tight ${overviewValueClass(item.tone)}`}>
            {item.value}
          </p>
        </div>
      ))}
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
          <p className="mt-1 text-sm text-slate-500">Queue, apps, and insights from this machine.</p>
        </div>
        {cloudConnected && onShare && insightsAvailable ? (
          <EvidenceInsightsShareButton onClick={onShare} className="shrink-0" />
        ) : null}
      </div>

      <HomeOverviewStatsRow items={overviewStats} />

      {showInsightsSection ? (
        analyticsLoading ? (
          <div className="border-t border-slate-100 px-5 py-5">
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              {Array.from({ length: 4 }, (_, index) => (
                <div key={index} className="space-y-2">
                  <div className="guard-skeleton h-3 w-16 rounded" />
                  <div className="guard-skeleton h-6 w-20 rounded" />
                </div>
              ))}
            </div>
          </div>
        ) : insightsAvailable ? (
          <div className="border-t border-slate-100">
            <EvidenceInsightsHeadlineBento analytics={analytics} variant="compact" />
          </div>
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
