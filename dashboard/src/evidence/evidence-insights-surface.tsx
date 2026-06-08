import { useEffect, useMemo, useState } from "react";
import type {
  GuardReceiptAnalytics,
  GuardReceiptArtifactStat,
  GuardReceiptHarnessStat,
  GuardRuntimeSnapshot,
} from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { SectionLabel } from "../approval-center-primitives";
import { EvidenceActivityHeatmap } from "./evidence-activity-heatmap";
import { EvidenceDataProvenanceStrip } from "./evidence-data-provenance-strip";
import { EvidenceInsightsHeadlineBento } from "./evidence-insights-headline-bento";
import { EvidenceInsightsShareModal } from "./evidence-insights-share-modal";
import { EvidenceInsightsShareButton } from "./evidence-insights-share-button";
import { EvidenceShareBar } from "./evidence-share-bar";
import { EvidenceTrendChart } from "./evidence-trend-chart";

interface EvidenceInsightsSurfaceProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  sampleCount: number;
  onFilterHarness: (harness: string) => void;
  onFilterDay?: (dateKey: string) => void;
  onViewActions: () => void;
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
  const [shareOpen, setShareOpen] = useState(false);
  useEffect(() => {
    setMounted(true);
  }, []);

  const artifactTotal = useMemo(
    () => analytics.top_artifacts.reduce((sum, item) => sum + item.total, 0),
    [analytics.top_artifacts],
  );
  const cloudConnected = runtime?.cloud_state === "paired_active";

  if (analytics.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-sm font-medium text-brand-dark">No data yet</p>
        <p className="mt-1 text-xs text-slate-500">Insights appear once Guard records actions on this machine.</p>
      </div>
    );
  }

  return (
    <>
      {shareOpen ? (
        <EvidenceInsightsShareModal
          analytics={analytics}
          runtime={runtime}
          onClose={() => setShareOpen(false)}
        />
      ) : null}
      <div className={`overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm ${mounted ? "evidence-insights-mounted" : ""}`}>
        <div className="flex items-center justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div>
            <SectionLabel>Your Guard stats</SectionLabel>
            <p className="mt-1 text-sm text-slate-500">All-time local store</p>
          </div>
          {cloudConnected ? (
            <EvidenceInsightsShareButton onClick={() => setShareOpen(true)} />
          ) : null}
        </div>
        <EvidenceInsightsHeadlineBento analytics={analytics} variant="full" />

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
        <EvidenceTrendChart buckets={analytics.trend_buckets} />
      </div>

      <EvidenceDataProvenanceStrip
        analytics={analytics}
        sampleCount={sampleCount}
        runtime={runtime}
        onViewActions={onViewActions}
      />
      </div>
    </>
  );
}
