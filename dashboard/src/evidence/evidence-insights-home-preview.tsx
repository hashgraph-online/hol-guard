import type { GuardReceiptAnalytics, GuardRuntimeSnapshot } from "../guard-types";
import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { EvidenceInsightsHeadlineBento } from "./evidence-insights-headline-bento";

interface EvidenceInsightsHomePreviewProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  onOpenInsights: () => void;
  onShare?: () => void;
}

export function EvidenceInsightsHomePreview({
  analytics,
  runtime,
  onOpenInsights,
  onShare,
}: EvidenceInsightsHomePreviewProps) {
  if (analytics.total <= 0) {
    return null;
  }

  const cloudConnected = runtime?.cloud_state === "paired_active";

  return (
    <section className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm">
      <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
        <div>
          <SectionLabel>Your Guard stats</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">Full-store insights from this machine.</p>
        </div>
        {cloudConnected && onShare ? (
          <ActionButton variant="outline" onClick={onShare}>
            Share stats
          </ActionButton>
        ) : null}
      </div>

      <EvidenceInsightsHeadlineBento analytics={analytics} variant="compact" />

      <div className="border-t border-slate-100 px-5 py-4">
        <button
          type="button"
          onClick={onOpenInsights}
          className="text-sm font-semibold text-brand-blue hover:text-brand-blue/80"
        >
          See all insights →
        </button>
      </div>
    </section>
  );
}
