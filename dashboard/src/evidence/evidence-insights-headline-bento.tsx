import type { GuardReceiptAnalytics } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { formatEvidenceCount } from "./evidence-format";

type BentoEmphasis = "hero" | "medium" | "quiet";

interface BentoItem {
  label: string;
  value: string;
  unit: string | null;
  emphasis: BentoEmphasis;
}

function buildBentoItems(analytics: GuardReceiptAnalytics, variant: "full" | "compact"): BentoItem[] {
  const stopRate = analytics.total > 0 ? Math.round((analytics.blocked / analytics.total) * 100) : 0;
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
      unit: `${stopRate}% of total`,
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
    fullItems[2],
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
        <div
          key={item.label}
          className={`bg-white px-4 py-4 sm:py-5 evidence-metric-enter ${
            variant === "full" && item.emphasis === "hero" ? "sm:py-6" : variant === "compact" ? "py-3.5" : ""
          }`}
          style={{ animationDelay: `${index * 60}ms` }}
        >
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
          <p
            className={`mt-1 font-semibold tabular-nums tracking-tight text-brand-dark ${
              variant === "compact"
                ? "text-lg"
                : item.emphasis === "hero"
                  ? "text-3xl"
                  : item.emphasis === "medium"
                    ? "text-xl"
                    : "text-base truncate"
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
