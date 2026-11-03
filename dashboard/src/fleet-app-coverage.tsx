import { useCallback, type ReactNode } from "react";
import {
  HiMiniCheckCircle,
  HiMiniChevronRight,
  HiMiniExclamationCircle,
  HiMiniEye,
  HiMiniWrenchScrewdriver,
  HiMiniXCircle,
} from "react-icons/hi2";

import { EmptyState, SectionLabel } from "./approval-center-primitives";
import { harnessDisplayName } from "./approval-center-utils";
import { APP_STATUS_LABELS, resolveAppInstallStatus } from "./apps/app-catalog";
import { useFleetAppPosture, type FleetPostureApp } from "./fleet-app-protection";
import type { DetectedAppStatus } from "./harness-detection";
import { harnessRowStatus, harnessRowTone } from "./harness-posture-ui";
import type { HarnessVersionCompatibility } from "./harness-version-compatibility";
import { HarnessVersionLabel } from "./harness-version-label";

/** One app in the coverage list, with what Guard has seen from it. */
export type FleetCoverageApp = {
  harness: string;
  status: DetectedAppStatus;
  inventoryCount: number;
  policyCount: number;
  versionCompatibility: HarnessVersionCompatibility | null;
};

type FleetAppCoverageProps = {
  apps: FleetCoverageApp[];
  /** Apps known to this machine and whether Guard manages their hooks. */
  postureApps: FleetPostureApp[];
  onOpenAppDetail?: (harness: string) => void;
  onPostureChanged?: () => Promise<void> | void;
  /** Load notes for inventory or detection, shown under the list. */
  notes?: ReactNode;
};

function formatCount(value: number): string {
  return value.toLocaleString();
}

function toInstallStatus(status: DetectedAppStatus): ReturnType<typeof resolveAppInstallStatus> {
  if (status === "protected") return "active";
  if (status === "partial") return "partial";
  if (status === "needs_repair") return "partial";
  if (status === "found_unprotected") return "observed";
  return "not_installed";
}

function StatusIcon({ status, watching }: { status: DetectedAppStatus; watching: boolean }) {
  if (watching) return <HiMiniEye className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />;
  if (status === "protected") return <HiMiniCheckCircle className="h-4 w-4 shrink-0 text-emerald-500" aria-hidden="true" />;
  if (status === "found_unprotected") return <HiMiniEye className="h-4 w-4 shrink-0 text-slate-400" aria-hidden="true" />;
  if (status === "needs_repair") return <HiMiniWrenchScrewdriver className="h-4 w-4 shrink-0 text-brand-purple" aria-hidden="true" />;
  if (status === "not_found") return <HiMiniXCircle className="h-4 w-4 shrink-0 text-slate-300" aria-hidden="true" />;
  return <HiMiniExclamationCircle className="h-4 w-4 shrink-0 text-brand-attention" aria-hidden="true" />;
}

function StatusBadge({ status }: { status: DetectedAppStatus }) {
  if (status === "partial") return <span className="text-xs font-medium text-brand-blue">Partially protected</span>;
  if (status === "needs_repair") {
    return <span className="text-xs font-medium text-brand-attention">Needs repair</span>;
  }
  const installStatus = toInstallStatus(status);
  const label = APP_STATUS_LABELS[installStatus];
  if (installStatus === "active") return <span className="text-xs font-medium text-emerald-600">{label}</span>;
  if (installStatus === "partial") return <span className="text-xs font-medium text-brand-purple">{label}</span>;
  if (installStatus === "observed") return <span className="text-xs font-medium text-slate-500">{label}</span>;
  return <span className="text-xs text-slate-400">{label}</span>;
}

type AppSummaryProps = {
  app: FleetCoverageApp;
  /** Posture line under the counts, such as "Watch · recording only". */
  postureNote: string | null;
  watching: boolean;
  /** The per-app choice already states an active app's level, so its badge is dropped. */
  showBadge: boolean;
  onOpenAppDetail?: (harness: string) => void;
};

function AppSummary({ app, postureNote, watching, showBadge, onOpenAppDetail }: AppSummaryProps) {
  const handleClick = useCallback(() => onOpenAppDetail?.(app.harness), [onOpenAppDetail, app.harness]);
  const content = (
    <>
      <span className="flex min-w-0 items-center gap-3">
        <StatusIcon status={app.status} watching={watching} />
        <span className="min-w-0">
          <span className="block truncate text-sm font-medium text-brand-dark">{harnessDisplayName(app.harness)}</span>
          <span className="block text-xs text-slate-400">
            {formatCount(app.inventoryCount)} actions · {formatCount(app.policyCount)} decisions
          </span>
          {postureNote !== null ? (
            <span className={`block text-xs ${watching ? "font-medium text-brand-attention" : "text-slate-400"}`}>
              {postureNote}
            </span>
          ) : null}
          <HarnessVersionLabel compatibility={app.versionCompatibility} />
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-2">
        {showBadge ? <StatusBadge status={app.status} /> : null}
        {onOpenAppDetail ? <HiMiniChevronRight className="h-4 w-4 text-slate-300" aria-hidden="true" /> : null}
      </span>
    </>
  );
  const layout = "flex min-w-0 flex-1 items-center justify-between gap-3 rounded-lg text-left";
  if (!onOpenAppDetail) return <div className={layout}>{content}</div>;
  return (
    <button
      type="button"
      onClick={handleClick}
      className={`${layout} -mx-2 px-2 py-1 transition-colors hover:bg-slate-50/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue`}
    >
      {content}
    </button>
  );
}

/**
 * Every app Guard can see on this machine, with the per-app Protected or Watch
 * choice on the rows whose hooks Guard manages. One list answers both "is this
 * app covered?" and "how closely?", so there is no second per-app card.
 */
export function FleetAppCoverage(props: FleetAppCoverageProps) {
  const posture = useFleetAppPosture({ apps: props.postureApps, onChanged: props.onPostureChanged });
  const isWatching = (harness: string) => {
    const row = posture.rowFor(harness);
    return row !== undefined && harnessRowTone(row) === "watch";
  };
  // Watch rows first, so a weaker posture cannot hide further down the list.
  const ordered = [...props.apps].sort((a, b) => Number(isWatching(b.harness)) - Number(isWatching(a.harness)));

  return (
    <section aria-label="App coverage" data-testid="fleet-app-coverage">
      <div className="mb-4 flex flex-wrap items-end justify-between gap-x-4 gap-y-1">
        <div>
          <SectionLabel>App coverage</SectionLabel>
          <p className="mt-1 text-sm text-slate-500">
            Which apps Guard watches on this machine, and whether it protects or only records each one.
          </p>
        </div>
        {posture.summary}
      </div>

      {ordered.length > 0 ? (
        <ul className="divide-y divide-slate-100 border-t border-slate-100">
          {ordered.map((app) => {
            const row = posture.rowFor(app.harness);
            const watching = isWatching(app.harness);
            const control = posture.control(app.harness);
            const postureNote = row !== undefined && (watching || row.hasOverride) ? harnessRowStatus(row) : null;
            return (
              <li
                key={app.harness}
                className={watching ? "-mx-2 rounded-lg bg-brand-attention/[0.05] px-2 py-3" : "py-3"}
                data-harness={app.harness}
              >
                <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between sm:gap-4">
                  <AppSummary
                    app={app}
                    postureNote={postureNote}
                    watching={watching}
                    showBadge={control === null || app.status !== "protected"}
                    onOpenAppDetail={props.onOpenAppDetail}
                  />
                  {control}
                </div>
                {posture.watchConfirm(app.harness)}
              </li>
            );
          })}
        </ul>
      ) : (
        <EmptyState
          title="No watched apps yet"
          body="Run HOL Guard once with Codex, Claude Code, OpenCode, Copilot, Cursor, Gemini, Hermes, or another supported app and this machine will show coverage here."
          tone="teach"
        />
      )}

      {posture.footer}
      {props.notes}
    </section>
  );
}
