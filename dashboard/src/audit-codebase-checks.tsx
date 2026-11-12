import { useEffect, useMemo, useRef, useState } from "react";
import { ActionButton } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import { fetchWorkspaceFindings, type WorkspaceFindingsState } from "./workspace-findings-api";
import { createLatestRefresh } from "./workspace-findings-refresh";
import { sameWorktree, worktreeStatus } from "./workspace-findings-status";

const REFRESH_MS = 15_000;
// A run that hit either cap kept fewer findings than exist, so its count is a minimum.
const FINDING_CAP_REASONS = ["finding_cap", "carried_finding_cap"];

export type CodebaseCheckSummary = {
  worktrees: number;
  notChecked: number;
  latestCheckAtMs: number | null;
  oldestCheckAtMs: number | null;
  needAttention: number;
  openFindings: number;
  /** True when an assessment kept fewer findings than it found, so the count is a minimum. */
  openFindingsLowerBound: boolean;
};

/** Totals the background workspace checks the Workspaces tab lists one row at a time. */
export function summarizeCodebaseChecks(state: WorkspaceFindingsState): CodebaseCheckSummary {
  const summary: CodebaseCheckSummary = {
    worktrees: state.worktrees.length,
    notChecked: 0,
    latestCheckAtMs: null,
    oldestCheckAtMs: null,
    needAttention: 0,
    openFindings: 0,
    openFindingsLowerBound: false,
  };
  for (const worktree of state.worktrees) {
    const newestRun = state.latestRuns.find((run) => sameWorktree(worktree, run));
    const assessment = state.assessments.find((item) => sameWorktree(worktree, item));
    const status = worktreeStatus(worktree, newestRun, assessment);
    if (status.tone === "red" || status.tone === "attention") summary.needAttention += 1;
    if (assessment === undefined) {
      summary.notChecked += 1;
      continue;
    }
    summary.openFindings += assessment.findings.length;
    if (assessment.reasons.some((reason) => FINDING_CAP_REASONS.includes(reason))) {
      summary.openFindingsLowerBound = true;
    }
    const atMs = assessment.finishedAtMs;
    if (atMs === null) continue;
    if (summary.latestCheckAtMs === null || atMs > summary.latestCheckAtMs) summary.latestCheckAtMs = atMs;
    if (summary.oldestCheckAtMs === null || atMs < summary.oldestCheckAtMs) summary.oldestCheckAtMs = atMs;
  }
  return summary;
}

function checkTime(atMs: number | null): string {
  return atMs === null ? "Not yet" : formatRelativeTime(new Date(atMs).toISOString());
}

function Fact(props: { label: string; value: string; title?: string }) {
  return (
    <div className="min-w-0 py-2">
      <dt className="text-xs text-slate-500">{props.label}</dt>
      <dd className="font-mono text-sm font-semibold tabular-nums text-brand-dark" title={props.title}>
        {props.value}
      </dd>
    </div>
  );
}

/**
 * The audit list covers what agent sessions did. Background workspace checks
 * leave no receipts, so this keeps their freshness beside the list and a quiet
 * list is not read as "nothing was checked".
 */
export function AuditCodebaseChecksView(props: { summary: CodebaseCheckSummary; onOpenWorkspaces?: () => void }) {
  const { summary } = props;
  if (summary.worktrees === 0) return null;
  const notes: string[] = [];
  if (summary.notChecked > 0) {
    notes.push(
      summary.notChecked === 1
        ? "1 workspace has no finished check yet."
        : `${summary.notChecked} workspaces have no finished check yet.`,
    );
  }
  if (summary.openFindingsLowerBound) {
    notes.push("A check found more issues than it keeps, so open findings is a minimum.");
  }
  return (
    <section aria-labelledby="audit-codebase-checks-title" data-testid="audit-codebase-checks">
      <div className="flex flex-wrap items-start justify-between gap-x-4 gap-y-2">
        <div className="min-w-0 max-w-2xl">
          <h2 id="audit-codebase-checks-title" className="text-lg font-semibold tracking-tight text-brand-dark">
            Background workspace checks
          </h2>
          <p className="text-sm text-slate-600">
            Guard re-checks tracked project folders on this device between agent sessions. Their findings are on the
            Workspaces tab, not in the audit list below.
          </p>
        </div>
        {props.onOpenWorkspaces && (
          <ActionButton variant="outline" onClick={props.onOpenWorkspaces}>
            Open Workspaces
          </ActionButton>
        )}
      </div>
      <dl className="mt-2 grid grid-cols-2 gap-x-6 border-y border-slate-200 sm:grid-cols-3 lg:grid-cols-5">
        <Fact label="Workspaces" value={String(summary.worktrees)} />
        <Fact label="Latest check" value={checkTime(summary.latestCheckAtMs)} />
        <Fact label="Oldest result" value={checkTime(summary.oldestCheckAtMs)} />
        <Fact label="Need attention" value={String(summary.needAttention)} />
        <Fact
          label="Open findings"
          value={`${summary.openFindings}${summary.openFindingsLowerBound ? "+" : ""}`}
        />
      </dl>
      {notes.length > 0 && (
        <ul className="mt-2 space-y-0.5 text-xs text-slate-500">
          {notes.map((note) => (
            <li key={note}>{note}</li>
          ))}
        </ul>
      )}
    </section>
  );
}

export function AuditCodebaseChecks(props: { onOpenWorkspaces?: () => void }) {
  const [state, setState] = useState<WorkspaceFindingsState | null>(null);
  const mounted = useRef(true);
  const refresh = useMemo(
    () =>
      createLatestRefresh(() => fetchWorkspaceFindings(), {
        onData: (next) => {
          if (mounted.current) setState(next);
        },
        // The Workspaces tab owns load errors; a failed read leaves the last summary in place.
        onError: () => {},
      }),
    [],
  );

  useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_MS);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
    };
  }, [refresh]);

  const summary = useMemo(() => (state === null ? null : summarizeCodebaseChecks(state)), [state]);
  if (summary === null) return null;
  return <AuditCodebaseChecksView summary={summary} onOpenWorkspaces={props.onOpenWorkspaces} />;
}
