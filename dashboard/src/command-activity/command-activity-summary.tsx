import { useMemo } from "react";

import { SectionLabel } from "../approval-center-primitives";
import type { CommandActivityLoadState } from "./command-activity-state";
import {
  commandBreakdownsAreGlobalOnly,
  commandHealthCopy,
  commandMetricSummary,
  commandProofCoveragePercent,
  commandTrendPoints,
  commandWindowLabel,
  safeEvidenceId,
} from "./command-activity-presenters";
import type { CommandActivityAnalytics, CommandCountBucket } from "./command-activity-types";

function Metric(props: { label: string; value: number | string; detail: string }) {
  return (
    <div className="border-l-2 border-slate-200 pl-3">
      <p className="text-xs font-medium text-slate-500">{props.label}</p>
      <p className="mt-1 text-xl font-semibold text-brand-dark">
        {typeof props.value === "number" ? props.value.toLocaleString() : props.value}
      </p>
      <p className="mt-0.5 text-xs text-slate-500">{props.detail}</p>
    </div>
  );
}

function Trend({ analytics }: { analytics: CommandActivityAnalytics }) {
  const recent = commandTrendPoints(analytics);
  const maximum = Math.max(1, ...recent.map((point) => point.count));
  const accessibleSummary = recent.map((point) => `${point.day}: ${point.count}`).join("; ");
  return (
    <div>
      <div className="flex items-center justify-between gap-3">
        <SectionLabel>Recent command checks</SectionLabel>
        <p className="text-xs text-slate-500">{commandWindowLabel(analytics)}</p>
      </div>
      {recent.length > 0 ? (
        <div className="mt-3 flex h-28 items-end gap-1" role="img" aria-label={`Command checks by day: ${accessibleSummary}`}>
          {recent.map((point) => (
            <div key={point.day} className="group relative flex min-w-0 flex-1 items-end self-stretch">
              <div
                className="w-full rounded-t-sm bg-brand-blue/70 motion-safe:transition-[height]"
                style={{ height: `${point.count === 0 ? 0 : Math.max(4, Math.round((point.count / maximum) * 100))}%` }}
              />
            </div>
          ))}
        </div>
      ) : (
        <p className="mt-3 text-sm text-slate-500">No trend points are available for this window.</p>
      )}
    </div>
  );
}

function safeBuckets(buckets: CommandCountBucket[]): CommandCountBucket[] {
  return buckets.filter((bucket) => safeEvidenceId(bucket.value) !== "Unavailable").slice(0, 5);
}

function FrequencyList(props: { title: string; buckets: CommandCountBucket[] }) {
  const buckets = useMemo(() => safeBuckets(props.buckets), [props.buckets]);
  return (
    <div>
      <SectionLabel>{props.title}</SectionLabel>
      {buckets.length > 0 ? (
        <ol className="mt-2 space-y-2">
          {buckets.map((bucket) => (
            <li key={bucket.value} className="flex items-center justify-between gap-3 text-sm">
              <span className="truncate text-brand-dark">{safeEvidenceId(bucket.value)}</span>
              <span className="tabular-nums text-slate-500">{bucket.count.toLocaleString()}</span>
            </li>
          ))}
        </ol>
      ) : (
        <p className="mt-2 text-sm text-slate-500">No frequency data in this window.</p>
      )}
    </div>
  );
}

export function CommandActivitySummary(props: {
  state: CommandActivityLoadState<CommandActivityAnalytics>;
  outsideTableFilters: boolean;
}) {
  if (props.state.kind === "idle" || (props.state.kind === "loading" && props.state.previous === null)) {
    return <div className="guard-skeleton h-52 w-full" aria-label="Loading command activity summary" />;
  }
  if (props.state.kind === "error" && props.state.previous === null) {
    return (
      <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
        Command activity summary is unavailable.
      </div>
    );
  }
  if (props.state.kind === "empty") return null;
  let analytics: CommandActivityAnalytics | null = null;
  if (props.state.kind === "ready") analytics = props.state.data;
  if (props.state.kind === "loading" || props.state.kind === "error") analytics = props.state.previous;
  if (!analytics) return null;
  const metrics = commandMetricSummary(analytics);
  const globalOnly = commandBreakdownsAreGlobalOnly(analytics);
  const healthCopy = commandHealthCopy(analytics);

  return (
    <section className="min-w-0 max-w-full space-y-5" aria-label="Command activity summary">
      {props.outsideTableFilters ? (
        <div className="rounded-lg border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-700" role="status">
          Summary and trend totals do not include every active filter below.
        </div>
      ) : null}
      {healthCopy ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900" role="status">
          {healthCopy}
        </div>
      ) : null}
      {props.state.kind === "error" ? (
        <div className="rounded-lg border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900" role="status">
          Refresh failed. Showing the last loaded command activity summary.
        </div>
      ) : null}
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <Metric label="Commands checked" value={metrics.commandsChecked} detail="One per recorded activity" />
        <Metric
          label="Review prompts"
          value={globalOnly ? "Global only" : metrics.prompted}
          detail={globalOnly ? "Not available for this filter" : "Guard asked for a decision"}
        />
        <Metric
          label="Post-proof coverage"
          value={globalOnly ? "Global only" : metrics.postProof}
          detail={globalOnly ? "Not available for this filter" : `${commandProofCoveragePercent(analytics)}% of checks have correlated proof`}
        />
        <Metric
          label="Allowed, unconfirmed"
          value={globalOnly ? "Global only" : metrics.unconfirmed}
          detail={globalOnly ? "Not available for this filter" : "Execution not confirmed"}
        />
      </div>
      <div className="grid gap-5 border-t border-slate-100 pt-5 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,0.8fr)_minmax(0,0.8fr)]">
        <Trend analytics={analytics} />
        <FrequencyList title="Top extensions by frequency" buckets={analytics.dimensions.extension} />
        <FrequencyList title="Top rules by frequency" buckets={analytics.dimensions.rule} />
      </div>
      <p className="text-xs text-slate-500">Breakdown rankings are global frequency counts, not danger scores.</p>
    </section>
  );
}
