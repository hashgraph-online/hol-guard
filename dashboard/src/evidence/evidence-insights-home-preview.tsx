import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { formatNumber } from "../approval-center-utils";
import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { EvidenceInsightsHeadlineBento } from "./evidence-insights-headline-bento";

export type HomeGuardOverviewStats = {
  pending: number;
  apps: number;
  history: number;
};

type OverviewTone = "blue" | "green" | "purple" | "slate";

function overviewToneClass(tone: OverviewTone): string {
  if (tone === "blue") return "text-brand-blue";
  if (tone === "green") return "text-emerald-600";
  if (tone === "purple") return "text-brand-purple";
  return "text-brand-dark";
}

function HomeGuardOverviewRow(props: { overview: HomeGuardOverviewStats }) {
  const items: Array<{ label: string; value: string; tone: OverviewTone }> = [
    {
      label: "Pending",
      value: formatNumber(props.overview.pending),
      tone: props.overview.pending > 0 ? "blue" : "slate",
    },
    {
      label: "Apps",
      value: formatNumber(props.overview.apps),
      tone: props.overview.apps > 0 ? "green" : "slate",
    },
    {
      label: "History",
      value: formatNumber(props.overview.history),
      tone: "purple",
    },
  ];

  return (
    <div
      className="grid grid-cols-3 gap-px border-b border-slate-100 bg-slate-100"
      aria-label="Guard overview"
    >
      {items.map((item) => (
        <div key={item.label} className="bg-white px-4 py-3.5 sm:py-4">
          <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">
            {item.label}
          </p>
          <p className={`mt-1 text-lg font-semibold tabular-nums tracking-tight ${overviewToneClass(item.tone)}`}>
            {item.value}
          </p>
        </div>
      ))}
    </div>
  );
}

interface EvidenceInsightsHomePreviewProps {
  overview: HomeGuardOverviewStats;
  analytics: GuardReceiptAnalytics | null;
  insightsLoading?: boolean;
  runtime: GuardRuntimeSnapshot | null;
  onOpenInsights?: () => void;
  onShare?: () => void;
}

export function EvidenceInsightsHomePreview({
  overview,
  analytics,
  insightsLoading = false,
  runtime,
  onOpenInsights,
  onShare,
}: EvidenceInsightsHomePreviewProps) {
  const cloudConnected = runtime?.cloud_state === "paired_active";
  const hasInsights = analytics !== null && analytics.total > 0;

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <div>
          <SectionLabel>Your Guard stats</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            {hasInsights
              ? "Live counts and full-store insights from this machine."
              : "Live counts from this machine."}
          </p>
        </div>
        {cloudConnected && onShare && hasInsights ? (
          <ActionButton variant="outline" onClick={onShare}>
            Share stats
          </ActionButton>
        ) : null}
      </div>

      <HomeGuardOverviewRow overview={overview} />

      {insightsLoading ? (
        <div className="border-b border-slate-100 px-5 py-5">
          <div className="guard-skeleton h-16 w-full rounded-xl" />
        </div>
      ) : analytics !== null && analytics.total > 0 ? (
        <EvidenceInsightsHeadlineBento analytics={analytics} variant="compact" />
      ) : null}

      {analytics !== null && analytics.total > 0 && onOpenInsights ? (
        <div className="border-t border-slate-100 px-5 py-4">
          <button
            type="button"
            onClick={onOpenInsights}
            className="text-sm font-semibold text-brand-blue hover:text-brand-blue/80"
          >
            See all insights →
          </button>
        </div>
      ) : null}
    </section>
  );
}
