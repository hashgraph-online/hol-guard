import type { GuardReceiptAnalytics } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { formatBlockedShare, formatEvidenceCount } from "./evidence-format";
import { GuardStatMetric } from "./guard-stat-metric";

type BentoEmphasis = "hero" | "medium" | "quiet";

interface BentoItem {
  label: string;
  value: string;
  unit: string | null;
  emphasis: BentoEmphasis;
}

export function buildBentoItems(analytics: GuardReceiptAnalytics, variant: "full" | "compact"): BentoItem[] {
  const blockedShare = formatBlockedShare(analytics.blocked, analytics.total);
  const dominantApp = analytics.by_harness[0]
    ? harnessDisplayName(analytics.by_harness[0].harness)
    : "None yet";

  const fullItems: BentoItem[] = [
    {
      label: "Current streak",
      value: `${analytics.active_day_streak}`,
      unit: analytics.active_day_streak === 1 ? "day" : "days",
      emphasis: "hero",
    },
    {
      label: "Peak day",
      value: formatEvidenceCount(analytics.peak_day_total),
      unit: "actions",
      emphasis: "hero",
    },
    {
      label: "Lifetime actions",
      value: formatEvidenceCount(analytics.total),
      unit: null,
      emphasis: "medium",
    },
    {
      label: "Stopped",
      value: formatEvidenceCount(analytics.blocked),
      unit: blockedShare,
      emphasis: "medium",
    },
    {
      label: "Top app",
      value: dominantApp,
      unit: null,
      emphasis: "quiet",
    },
  ];

  if (variant === "full") {
    return fullItems;
  }

  return [
    fullItems[0],
    fullItems[1],
    fullItems[3],
    fullItems[4],
  ];
}

interface EvidenceInsightsHeadlineBentoProps {
  analytics: GuardReceiptAnalytics;
  variant?: "full" | "compact";
}

export function EvidenceInsightsHeadlineBento({
  analytics,
  variant = "full",
}: EvidenceInsightsHeadlineBentoProps) {
  const items = buildBentoItems(analytics, variant);
  const gridClass =
    variant === "compact"
      ? "grid grid-cols-2 gap-px bg-slate-100 sm:grid-cols-4"
      : "grid grid-cols-2 gap-px bg-slate-100 sm:grid-cols-3 lg:grid-cols-5";

  return (
    <div className={gridClass}>
      {items.map((item, index) => (
        <GuardStatMetric
          key={item.label}
          label={item.label}
          value={
            item.emphasis === "hero" && item.unit ? (
              <>
                {item.value}
                <span className="ml-1 text-sm font-medium text-slate-500">{item.unit}</span>
              </>
            ) : (
              item.value
            )
          }
          detail={item.emphasis !== "hero" ? item.unit : null}
          compact={variant === "compact"}
          animationDelayMs={index * 60}
        />
      ))}
    </div>
  );
}
