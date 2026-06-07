import { useMemo, useState } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniChevronRight,
  HiMiniCloudArrowUp,
  HiOutlineShieldCheck,
} from "react-icons/hi2";
import type { GuardReceiptAnalytics, GuardReceiptAnalyticsBucket, GuardRuntimeSnapshot } from "../guard-types";
import { harnessDisplayName } from "../approval-center-utils";
import { SectionLabel, Badge } from "../approval-center-primitives";
import { EvidenceActivityHeatmap } from "./evidence-activity-heatmap";

interface EvidenceAnalyticsPanelProps {
  analytics: GuardReceiptAnalytics;
  runtime: GuardRuntimeSnapshot | null;
  sampleCount: number;
  onFilterHarness: (harness: string) => void;
  onFilterDay: (dateKey: string) => void;
  onViewActions: () => void;
  onOpenCloud?: () => void;
}

function formatCount(value: number): string {
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(1).replace(/\.0$/, "")}M`;
  if (value >= 10_000) return `${Math.round(value / 1_000)}K`;
  if (value >= 1_000) return value.toLocaleString();
  return String(value);
}

function formatDurationSince(iso: string | null): string {
  if (!iso) return "No activity yet";
  const ts = new Date(iso).getTime();
  if (Number.isNaN(ts)) return "Recently";
  const days = Math.max(0, Math.floor((Date.now() - ts) / (24 * 60 * 60 * 1000)));
  if (days === 0) return "Today";
  if (days === 1) return "1 day ago";
  if (days < 30) return `${days} days ago`;
  const months = Math.floor(days / 30);
  return months === 1 ? "1 month ago" : `${months} months ago`;
}

function SummaryRibbon({ analytics }: { analytics: GuardReceiptAnalytics }) {
  const stopRate = analytics.total > 0 ? Math.round((analytics.blocked / analytics.total) * 100) : 0;
  const items = [
    { label: "Lifetime actions", value: formatCount(analytics.total) },
    { label: "Stopped", value: formatCount(analytics.blocked), detail: `${stopRate}% of total` },
    { label: "Allowed", value: formatCount(analytics.allowed) },
    { label: "Current streak", value: `${analytics.active_day_streak} day${analytics.active_day_streak === 1 ? "" : "s"}` },
    { label: "Peak day", value: formatCount(analytics.peak_day_total) },
  ];

  return (
    <div className="rounded-2xl border border-slate-200/80 bg-white shadow-sm overflow-hidden">
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-slate-100">
        {items.map((item) => (
          <div key={item.label} className="px-4 py-4 sm:py-5">
            <p className="text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-500">{item.label}</p>
            <p className="mt-1 text-2xl font-semibold tabular-nums tracking-tight text-brand-dark">{item.value}</p>
            {item.detail && <p className="mt-0.5 text-xs text-slate-500">{item.detail}</p>}
          </div>
        ))}
      </div>
    </div>
  );
}

function TrendChart({ buckets }: { buckets: GuardReceiptAnalyticsBucket[] }) {
  const [hoveredKey, setHoveredKey] = useState<string | null>(null);
  const maxTotal = Math.max(...buckets.map((bucket) => bucket.allowed + bucket.blocked + bucket.reviewed), 1);
  const chartHeight = 160;
  const hasAnyData = buckets.some((bucket) => bucket.allowed + bucket.blocked + bucket.reviewed > 0);

  return (
    <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
      <SectionLabel>Last 7 Days</SectionLabel>
      <p className="mt-1 text-xs text-slate-500">Stacked by decision: allowed, stopped, and reviewed.</p>

      {!hasAnyData ? (
        <div className="flex h-40 items-center justify-center">
          <p className="text-sm text-slate-400">No activity in the last 7 days</p>
        </div>
      ) : (
        <>
          <div
            className="mt-5 flex items-end gap-2"
            style={{ height: chartHeight }}
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
                          <div className="w-full bg-amber-500" style={{ height: blockedHeight }} />
                        )}
                        {bucket.allowed > 0 && (
                          <div className="w-full bg-emerald-500" style={{ height: allowedHeight }} />
                        )}
                        {bucket.reviewed > 0 && (
                          <div className="w-full bg-brand-blue" style={{ height: reviewedHeight }} />
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
          <div className="mt-4 flex flex-wrap items-center gap-4 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-emerald-500" />
              Allowed
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-amber-500" />
              Stopped
            </span>
            <span className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-sm bg-brand-blue" />
              Reviewed
            </span>
          </div>
        </>
      )}
    </div>
  );
}

function LocalDataCard(props: {
  analytics: GuardReceiptAnalytics;
  sampleCount: number;
  onViewActions: () => void;
}) {
  const beyondSample = props.analytics.total > props.sampleCount;

  return (
    <button
      type="button"
      onClick={props.onViewActions}
      className="group w-full rounded-xl border border-slate-200/80 bg-slate-50/60 px-4 py-3.5 text-left transition-colors hover:border-slate-300 hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue sm:flex sm:items-center sm:justify-between sm:gap-4"
    >
      <div className="min-w-0">
        <div className="flex items-center gap-2">
          <HiOutlineShieldCheck className="h-4 w-4 text-brand-blue" aria-hidden="true" />
          <p className="text-sm font-medium text-brand-dark">Local evidence on this device</p>
        </div>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          {formatCount(props.analytics.total)} actions stored locally
          {beyondSample ? ` · list view shows the latest ${formatCount(props.sampleCount)}` : ""}
          {props.analytics.last_activity_at ? ` · last activity ${formatDurationSince(props.analytics.last_activity_at)}` : ""}
        </p>
      </div>
      <span className="mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-blue sm:mt-0">
        Browse actions
        <HiMiniChevronRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5" aria-hidden="true" />
      </span>
    </button>
  );
}

function CloudInsightsCard(props: {
  runtime: GuardRuntimeSnapshot | null;
  onOpenCloud?: () => void;
}) {
  const runtime = props.runtime;
  if (!runtime) return null;

  const isLocalOnly = runtime.cloud_state === "local_only";

  if (isLocalOnly) {
    return (
      <a
        href={runtime.connect_url}
        target="_blank"
        rel="noreferrer"
        className="group flex w-full items-start justify-between gap-4 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3.5 transition-colors hover:bg-brand-blue/[0.07] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
      >
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <HiMiniCloudArrowUp className="h-4 w-4 text-brand-blue" aria-hidden="true" />
            <p className="text-sm font-medium text-brand-dark">Guard Cloud</p>
          </div>
          <p className="mt-1 text-xs leading-relaxed text-slate-500">
            Sync evidence across devices, share fleet visibility, and unlock cross-machine analytics with a Guard Cloud subscription.
          </p>
        </div>
        <HiMiniArrowTopRightOnSquare className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
      </a>
    );
  }

  if (runtime.cloud_state !== "paired_active") {
    return (
      <div className="rounded-xl border border-slate-200/80 bg-white px-4 py-3.5">
        <p className="text-sm font-medium text-brand-dark">{runtime.cloud_state_label}</p>
        <p className="mt-1 text-xs text-slate-500">{runtime.cloud_state_detail}</p>
      </div>
    );
  }

  const sync = runtime.cloud_sync_health;
  return (
    <div className="rounded-xl border border-slate-200/80 bg-white px-4 py-3.5 sm:flex sm:items-center sm:justify-between sm:gap-4">
      <div className="min-w-0">
        <p className="text-sm font-medium text-brand-dark">Guard Cloud connected</p>
        <p className="mt-1 text-xs text-slate-500">
          {sync.label}
          {sync.last_synced_at ? ` · last sync ${formatDurationSince(sync.last_synced_at)}` : ""}
          {sync.pending_events > 0 ? ` · ${sync.pending_events} pending` : ""}
        </p>
        {runtime.cloud_policy_rollout_state && (
          <p className="mt-1 text-xs text-slate-500">
            Policy rollout: {runtime.cloud_policy_rollout_state}
            {runtime.cloud_policy_bundle_version ? ` · bundle ${runtime.cloud_policy_bundle_version}` : ""}
          </p>
        )}
      </div>
      {props.onOpenCloud && (
        <button
          type="button"
          onClick={props.onOpenCloud}
          className="mt-3 inline-flex min-h-10 items-center gap-1 rounded-lg border border-slate-200 px-3 text-xs font-medium text-brand-dark transition-colors hover:bg-slate-50 sm:mt-0"
        >
          Open fleet
          <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5" aria-hidden="true" />
        </button>
      )}
    </div>
  );
}

function InsightFact({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-slate-100 py-2.5 last:border-b-0">
      <span className="text-sm text-slate-500">{label}</span>
      <span className="text-sm font-medium text-brand-dark text-right">{value}</span>
    </div>
  );
}

function TopHarnessList(props: {
  items: GuardReceiptAnalytics["by_harness"];
  onFilterHarness: (harness: string) => void;
}) {
  const maxTotal = props.items[0]?.total ?? 1;

  if (props.items.length === 0) {
    return <p className="text-sm text-slate-400">No app activity yet.</p>;
  }

  return (
    <div className="space-y-1">
      {props.items.slice(0, 6).map((item) => {
        const widthPct = Math.max((item.total / maxTotal) * 100, 8);
        return (
          <button
            key={item.harness}
            type="button"
            onClick={() => props.onFilterHarness(item.harness)}
            className="group flex w-full items-center gap-3 rounded-lg px-2 py-2 text-left transition-colors hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue"
          >
            <div className="min-w-0 flex-1">
              <div className="flex items-center justify-between gap-2">
                <span className="truncate text-sm font-medium text-brand-dark">
                  {harnessDisplayName(item.harness)}
                </span>
                <span className="shrink-0 text-xs tabular-nums text-slate-500">{formatCount(item.total)}</span>
              </div>
              <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-slate-100">
                <div className="h-full rounded-full bg-brand-blue/70 transition-all" style={{ width: `${widthPct}%` }} />
              </div>
            </div>
          </button>
        );
      })}
    </div>
  );
}

export function EvidenceAnalyticsPanel({
  analytics,
  runtime,
  sampleCount,
  onFilterHarness,
  onFilterDay,
  onViewActions,
  onOpenCloud,
}: EvidenceAnalyticsPanelProps) {
  const insightFacts = useMemo(() => {
    return [
      {
        label: "Most active app",
        value: analytics.by_harness[0] ? harnessDisplayName(analytics.by_harness[0].harness) : "None yet",
      },
      {
        label: "Top recurring action",
        value: analytics.top_artifacts[0]?.name ?? "None yet",
      },
      {
        label: "Reviewed actions",
        value: formatCount(analytics.reviewed),
      },
      {
        label: "Apps seen",
        value: String(analytics.by_harness.length),
      },
      {
        label: "Tracking since",
        value: analytics.first_activity_at
          ? new Date(analytics.first_activity_at).toLocaleDateString(undefined, {
              month: "short",
              day: "numeric",
              year: "numeric",
            })
          : "Not yet",
      },
    ];
  }, [analytics]);

  if (analytics.total === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-16 text-center">
        <p className="text-sm font-medium text-brand-dark">No data yet</p>
        <p className="mt-1 text-xs text-slate-500">Insights will appear once Guard records actions on this machine.</p>
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <LocalDataCard analytics={analytics} sampleCount={sampleCount} onViewActions={onViewActions} />
      <CloudInsightsCard runtime={runtime} onOpenCloud={onOpenCloud} />
      <SummaryRibbon analytics={analytics} />
      <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
        <SectionLabel>90-Day Activity</SectionLabel>
        <p className="mt-1 text-xs text-slate-500">Daily action volume across your local evidence store.</p>
        <div className="mt-4">
          <EvidenceActivityHeatmap days={analytics.daily_activity} onSelectDay={onFilterDay} />
        </div>
      </div>
      <TrendChart buckets={analytics.trend_buckets} />
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
          <SectionLabel>Activity Insights</SectionLabel>
          <div className="mt-2">
            {insightFacts.map((fact) => (
              <InsightFact key={fact.label} label={fact.label} value={fact.value} />
            ))}
          </div>
        </div>
        <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
          <SectionLabel>Most Active Apps</SectionLabel>
          <div className="mt-3">
            <TopHarnessList items={analytics.by_harness} onFilterHarness={onFilterHarness} />
          </div>
        </div>
      </div>
      {analytics.top_artifacts.length > 0 && (
        <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
          <SectionLabel>Top Recurring Actions</SectionLabel>
          <div className="mt-3 divide-y divide-slate-100">
            {analytics.top_artifacts.slice(0, 6).map((action) => (
              <div key={action.name} className="flex items-center justify-between gap-4 py-2.5">
                <span className="truncate text-sm text-brand-dark">{action.name}</span>
                <div className="flex shrink-0 items-center gap-2">
                  <Badge tone="default">{formatCount(action.total)}×</Badge>
                  {action.blocked > 0 && <Badge tone="attention">{formatCount(action.blocked)} stopped</Badge>}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
