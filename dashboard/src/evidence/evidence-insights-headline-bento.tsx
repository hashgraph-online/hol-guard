import type { GuardReceiptAnalytics } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { formatBlockedShare, formatEvidenceCount } from "./evidence-format";
import { GuardStatMetric } from "./guard-stat-metric";

type BentoEmphasis = "hero" | "medium" | "quiet";

export interface GuardInsightMetric {
  label: string;
  value: string;
  detail: string | null;
  heroUnit: string | null;
  emphasis: BentoEmphasis;
}

function dominantHarnessName(analytics: GuardReceiptAnalytics): string {
  const firstHarness = analytics.by_harness?.[0];
  return firstHarness ? harnessDisplayName(firstHarness.harness) : "None yet";
}

function streakPresentation(streak: number): { value: string; heroUnit: string | null } {
  if (streak <= 0) {
    return { value: "—", heroUnit: "No active streak" };
  }
  return {
    value: `${streak}`,
    heroUnit: streak === 1 ? "day" : "days",
  };
}

export function buildInsightMetrics(analytics: GuardReceiptAnalytics, variant: "full" | "compact"): GuardInsightMetric[] {
  const blockedShare = formatBlockedShare(analytics.blocked, analytics.total);
  const streak = streakPresentation(analytics.active_day_streak);
  const dominantApp = dominantHarnessName(analytics);

  const fullItems: GuardInsightMetric[] = [
    {
      label: "Current streak",
      value: streak.value,
      detail: null,
      heroUnit: streak.heroUnit,
      emphasis: "hero",
    },
    {
      label: "Peak day",
      value: formatEvidenceCount(analytics.peak_day_total),
      detail: variant === "compact" ? "Most actions in one day" : "actions",
      heroUnit: variant === "full" ? "actions" : null,
      emphasis: "hero",
    },
    {
      label: "Lifetime actions",
      value: formatEvidenceCount(analytics.total),
      detail: null,
      heroUnit: null,
      emphasis: "medium",
    },
    {
      label: "Stopped",
      value: formatEvidenceCount(analytics.blocked),
      detail: blockedShare,
      heroUnit: null,
      emphasis: "medium",
    },
    {
      label: "Top app",
      value: dominantApp,
      detail: variant === "compact" ? "Most recorded actions" : null,
      heroUnit: null,
      emphasis: "quiet",
    },
  ];

  if (variant === "full") {
    return fullItems;
  }

  return [fullItems[0], fullItems[1], fullItems[3], fullItems[4]];
}

/** @deprecated Use buildInsightMetrics for new code paths. */
export function buildBentoItems(analytics: GuardReceiptAnalytics, variant: "full" | "compact") {
  return buildInsightMetrics(analytics, variant).map((item) => ({
    label: item.label,
    value: item.value,
    unit: item.emphasis === "hero" ? item.heroUnit : item.detail,
    emphasis: item.emphasis,
  }));
}

function renderInsightMetric(item: GuardInsightMetric, index: number, compact: boolean) {
  const showHeroUnitInline = item.emphasis === "hero" && item.heroUnit && item.value !== "—";

  return (
    <GuardStatMetric
      key={item.label}
      label={item.label}
      value={
        showHeroUnitInline ? (
          <>
            {item.value}
            <span className="ml-1 text-sm font-medium text-slate-500">{item.heroUnit}</span>
          </>
        ) : (
          item.value
        )
      }
      detail={item.emphasis === "hero" && item.value === "—" ? item.heroUnit : item.detail}
      compact={compact}
      animationDelayMs={index * 60}
    />
  );
}

interface EvidenceInsightsHeadlineBentoProps {
  analytics: GuardReceiptAnalytics;
  variant?: "full" | "compact";
}

export function EvidenceInsightsHeadlineBento({
  analytics,
  variant = "full",
}: EvidenceInsightsHeadlineBentoProps) {
  const items = buildInsightMetrics(analytics, variant);
  const gridClass =
    variant === "compact"
      ? "grid grid-cols-2 gap-px bg-slate-100 sm:grid-cols-4"
      : "grid grid-cols-2 gap-px bg-slate-100 sm:grid-cols-3 lg:grid-cols-5";

  return <div className={gridClass}>{items.map((item, index) => renderInsightMetric(item, index, variant === "compact"))}</div>;
}

export function HomeInsightsMetrics({ analytics }: { analytics: GuardReceiptAnalytics }) {
  const items = buildInsightMetrics(analytics, "compact");

  return (
    <div className="grid grid-cols-2 gap-px border-t border-slate-100 bg-slate-100 sm:grid-cols-4">
      {items.map((item, index) => renderInsightMetric(item, index, true))}
    </div>
  );
}
