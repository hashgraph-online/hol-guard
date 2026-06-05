import {
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniXCircle,
  HiMiniInformationCircle,
  HiMiniArrowPath,
  HiMiniSignal,
  HiMiniClock,
} from "react-icons/hi2";
import { SectionLabel, Badge, Tag, ActionButton } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { GuardRuntimeSnapshot } from "./guard-types";

export type FeedSourceMode = "sample" | "full" | "live";

export function resolveFeedSourceMode(
  cloudState: GuardRuntimeSnapshot["cloud_state"],
): FeedSourceMode {
  if (cloudState === "local_only") return "sample";
  if (cloudState === "paired_waiting") return "full";
  return "live";
}

export function resolveFeedStaleness(snapshot: GuardRuntimeSnapshot): {
  stale: boolean;
  ageLabel: string;
  lastActivity: string | null;
} {
  const receipts = snapshot.latest_receipts;
  if (receipts.length === 0) {
    return { stale: false, ageLabel: "No activity yet", lastActivity: null };
  }
  const latest = receipts[0].timestamp;
  const ageMs = Date.now() - new Date(latest).getTime();
  const stale = ageMs > 7 * 24 * 60 * 60 * 1000;
  return {
    stale,
    ageLabel: stale
      ? `Last activity ${formatRelativeTime(latest)} (stale)`
      : `Last activity ${formatRelativeTime(latest)}`,
    lastActivity: latest,
  };
}

type FeedSourceBadgeProps = {
  mode: FeedSourceMode;
};

function FeedSourceBadge({ mode }: FeedSourceBadgeProps) {
  if (mode === "live") {
    return <Tag tone="green">Live cloud feed</Tag>;
  }
  if (mode === "full") {
    return <Tag tone="blue">Full feed (syncing)</Tag>;
  }
  return <Tag tone="attention">Sample only (local-only mode)</Tag>;
}

type FeedHealthCardProps = {
  label: string;
  value: string;
  tone: "green" | "attention" | "slate" | "red";
  description: string;
  icon: React.ComponentType<{ className?: string; "aria-hidden"?: "true" }>;
};

function FeedHealthCard({ label, value, tone, description, icon: Icon }: FeedHealthCardProps) {
  const toneClasses = {
    green: "border-brand-green/20 bg-brand-green/[0.04]",
    attention: "border-brand-attention/20 bg-brand-attention/[0.04]",
    slate: "border-slate-200 bg-slate-50/40",
    red: "border-red-200 bg-red-50/40",
  } as const;

  const iconClasses = {
    green: "text-brand-green",
    attention: "text-brand-attention",
    slate: "text-slate-400",
    red: "text-red-500",
  } as const;

  return (
    <div className={`rounded-xl border p-4 ${toneClasses[tone]}`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className={`h-4 w-4 shrink-0 ${iconClasses[tone]}`} aria-hidden="true" />
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">{label}</p>
      </div>
      <p className="text-sm font-semibold text-brand-dark">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{description}</p>
    </div>
  );
}

type FeedHealthWorkspaceProps = {
  snapshot: GuardRuntimeSnapshot;
  onOpenSettings?: () => void;
};

export function FeedHealthWorkspace({ snapshot, onOpenSettings }: FeedHealthWorkspaceProps) {
  const sourceMode = resolveFeedSourceMode(snapshot.cloud_state);
  const staleState = resolveFeedStaleness(snapshot);
  const daemonRunning = snapshot.runtime_state !== null;
  const cloudLabel = snapshot.cloud_state_label;
  const cloudDetail = snapshot.cloud_state_detail;

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-lg font-semibold text-brand-dark">Feed Health</h1>
          <p className="mt-0.5 text-sm text-slate-500">
            Intel feed source mode, freshness, and cloud sync status.
          </p>
        </div>
        {onOpenSettings && (
          <ActionButton variant="outline" onClick={onOpenSettings}>
            Open Settings
          </ActionButton>
        )}
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm space-y-4">
        <div className="flex flex-wrap items-center gap-2">
          <SectionLabel>Source mode</SectionLabel>
          <FeedSourceBadge mode={sourceMode} />
        </div>

        {sourceMode === "sample" && (
          <div className="flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5" role="alert">
            <HiMiniExclamationTriangle
              className="mt-0.5 h-4 w-4 shrink-0 text-amber-600"
              aria-hidden="true"
            />
            <div>
              <p className="text-sm font-semibold text-amber-800">Sample intel only</p>
              <p className="text-xs text-amber-700 mt-0.5">
                Guard is running in local-only mode. Threat intel is based on bundled sample data. Connect this machine to Guard Cloud for live feed updates.
              </p>
            </div>
          </div>
        )}

        {sourceMode === "full" && (
          <div className="flex items-start gap-2 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2.5">
            <HiMiniArrowPath className="mt-0.5 h-4 w-4 shrink-0 text-brand-blue" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold text-brand-dark">Full feed syncing</p>
              <p className="text-xs text-slate-600 mt-0.5">
                Guard Cloud is connected. Local Guard is finishing the first shared proof automatically.
              </p>
            </div>
          </div>
        )}

        {sourceMode === "live" && (
          <div className="flex items-start gap-2 rounded-xl border border-brand-green/20 bg-brand-green/[0.04] px-3 py-2.5">
            <HiMiniCheckCircle className="mt-0.5 h-4 w-4 shrink-0 text-brand-green" aria-hidden="true" />
            <div>
              <p className="text-sm font-semibold text-brand-dark">Live feed active</p>
              <p className="text-xs text-slate-600 mt-0.5">
                Guard is receiving live cloud intel. Threat data is up to date.
              </p>
            </div>
          </div>
        )}
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        <FeedHealthCard
          label="Feed freshness"
          value={staleState.stale ? "Stale" : "Fresh"}
          tone={staleState.stale ? "attention" : "green"}
          description={staleState.ageLabel}
          icon={staleState.stale ? HiMiniExclamationTriangle : HiMiniCheckCircle}
        />
        <FeedHealthCard
          label="Daemon status"
          value={daemonRunning ? "Running" : "Offline"}
          tone={daemonRunning ? "green" : "red"}
          description={
            daemonRunning
              ? "Guard daemon is active and processing."
              : "Guard daemon is not running. No protection active."
          }
          icon={daemonRunning ? HiMiniSignal : HiMiniXCircle}
        />
        <FeedHealthCard
          label="Cloud sync"
          value={cloudLabel}
          tone={snapshot.cloud_state === "paired_active" ? "green" : snapshot.cloud_state === "local_only" ? "slate" : "attention"}
          description={cloudDetail}
          icon={HiMiniArrowPath}
        />
        <FeedHealthCard
          label="Last activity"
          value={staleState.lastActivity ? formatRelativeTime(staleState.lastActivity) : "None"}
          tone={staleState.lastActivity ? "green" : "slate"}
          description={
            staleState.lastActivity
              ? "Most recent action processed by Guard."
              : "No actions have been processed yet."
          }
          icon={HiMiniClock}
        />
      </div>

      <div className="rounded-2xl border border-slate-100 bg-white p-5 shadow-sm">
        <SectionLabel>Cloud sync health</SectionLabel>
        <p className="mt-1 mb-3 text-sm text-slate-500">
          {snapshot.cloud_sync_health.detail}
        </p>
        <div className="flex flex-wrap items-center gap-2">
          <Badge
            tone={
              snapshot.cloud_sync_health.state === "healthy"
                ? "success"
                : snapshot.cloud_sync_health.state === "pending"
                ? "attention"
                : snapshot.cloud_sync_health.state === "disabled"
                ? "default"
                : "destructive"
            }
          >
            {snapshot.cloud_sync_health.label}
          </Badge>
        </div>
        {onOpenSettings && snapshot.cloud_state === "local_only" && (
          <div className="mt-4">
            <ActionButton variant="secondary" onClick={onOpenSettings}>
              Connect to cloud
            </ActionButton>
          </div>
        )}
      </div>
    </div>
  );
}
