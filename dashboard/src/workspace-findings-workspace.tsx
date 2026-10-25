import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { HiMiniArrowPath, HiMiniExclamationTriangle, HiMiniFolderOpen } from "react-icons/hi2";
import { ActionButton, EmptyState, Tag, type TagTone } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import {
  addWorkspaceForAssessment,
  fetchWorkspaceFindings,
  runWorkspaceAction,
  type WorkspaceAction,
  type WorkspaceAssessment,
  type WorkspaceFinding,
  type WorkspaceFindingsState,
  type WorkspaceRun,
  type WorkspaceWorktree,
} from "./workspace-findings-api";
import { createLatestRefresh } from "./workspace-findings-refresh";

const REFRESH_MS = 15_000;

const COVERAGE_REASONS: Record<string, string> = {
  snapshot_entry_cap: "The workspace has more files than one assessment reads.",
  snapshot_byte_cap: "The workspace is larger than one assessment reads.",
  snapshot_oversize_detector_input: "A dependency file was too large to read.",
  snapshot_unreadable: "Some files could not be read.",
  snapshot_unstable: "Files changed while Guard was reading them.",
  snapshot_depth_cap: "Some folders are nested deeper than one assessment reads.",
  snapshot_visit_cap: "The workspace has more entries than one assessment visits.",
  supply_chain_incomplete: "Some dependencies need registry data Guard does not have offline. Use Assess now to look them up.",
  lockfile_warnings: "A lockfile could not be fully parsed.",
  finding_cap: "There were more findings than one assessment keeps.",
};

const FAILURE_REASONS: Record<string, string> = {
  workspace_snapshot_failed: "Guard could not read this workspace.",
  workspace_snapshot_native_unavailable: "The Guard runtime needed to read files is unavailable.",
  workspace_identity_changed: "The folder now points at a different repository. Add it again.",
  supply_chain_detector_failed: "The dependency check stopped before it finished.",
  assessment_result_too_large: "The result was too large to store.",
  lease_expired: "The assessment took too long and was retried.",
  feed_context_unavailable: "Guard could not read its cached advisories.",
};

const DETECTOR_LABELS: Record<string, string> = { secrets: "Secret scanning" };

export type WorktreeStatus = { label: string; tone: TagTone; detail: string | null };

function sameWorktree(left: WorkspaceWorktree, right: { codebaseKey: string; worktreeKey: string }): boolean {
  return left.codebaseKey === right.codebaseKey && left.worktreeKey === right.worktreeKey;
}

export function worktreeStatus(
  worktree: WorkspaceWorktree,
  newestRun: WorkspaceRun | undefined,
  assessment: WorkspaceAssessment | undefined,
): WorktreeStatus {
  if (worktree.paused) return { label: "Paused", tone: "slate", detail: "Guard is not watching this workspace." };
  if (newestRun?.state === "running") return { label: "Assessing", tone: "slate", detail: null };
  if (newestRun?.state === "queued") return { label: "Queued", tone: "slate", detail: null };
  if (newestRun?.state === "failed" && newestRun.errorCode !== "lease_expired") {
    const detail = FAILURE_REASONS[newestRun.errorCode ?? ""] ?? "The last assessment did not finish.";
    return { label: "Assessment failed", tone: "red", detail };
  }
  if (assessment === undefined) return { label: "Not assessed yet", tone: "slate", detail: null };
  if (worktree.stale) return { label: "Out of date", tone: "attention", detail: "Files changed since the last assessment." };
  if (assessment.partial) return { label: "Partial coverage", tone: "attention", detail: null };
  return { label: "Up to date", tone: "green", detail: null };
}

function trimTrailingSeparators(root: string): string {
  const trimmed = root.replace(/[\\/]+$/, "");
  return trimmed === "" ? root : trimmed;
}

function folderName(root: string): string {
  const parts = root.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? root;
}

function decisionTone(decision: string): TagTone {
  if (decision === "block") return "red";
  if (decision === "ask") return "attention";
  return "slate";
}

const DECISION_LABELS: Record<string, string> = { block: "Blocked", ask: "Needs review", warn: "Warning" };

export function WorkspaceFindingsWorkspace(props: {
  suggestedRoot: string;
  onChooseFolder: () => void;
}) {
  const [state, setState] = useState<WorkspaceFindingsState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [busyKey, setBusyKey] = useState<string | null>(null);
  const mounted = useRef(true);
  const suggestedRoot = props.suggestedRoot.trim();
  const suggestedRootRef = useRef(suggestedRoot);
  suggestedRootRef.current = suggestedRoot;

  const refresh = useMemo(
    () =>
      createLatestRefresh(() => fetchWorkspaceFindings({ suggestedRoot: suggestedRootRef.current }), {
        onData: (next) => {
          if (!mounted.current) return;
          setState(next);
          setLoadError(null);
        },
        onError: (error) => {
          if (mounted.current) setLoadError(error instanceof Error ? error.message : String(error));
        },
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
  }, [refresh, suggestedRoot]);

  const perform = useCallback(
    async (key: string, operation: () => Promise<void>) => {
      setBusyKey(key);
      setActionError(null);
      try {
        await operation();
        await refresh();
      } catch (error) {
        if (mounted.current) setActionError(error instanceof Error ? error.message : String(error));
      } finally {
        if (mounted.current) setBusyKey(null);
      }
    },
    [refresh],
  );

  const handleAction = useCallback(
    (action: WorkspaceAction, worktree: WorkspaceWorktree) =>
      void perform(`${action}:${worktree.worktreeKey}`, () => runWorkspaceAction(action, worktree)),
    [perform],
  );
  const handleAdd = useCallback(
    () => void perform("add", () => addWorkspaceForAssessment(suggestedRoot)),
    [perform, suggestedRoot],
  );

  if (state === null) {
    return loadError ? (
      <ErrorNotice message={loadError} onRetry={() => void refresh()} />
    ) : (
      <div className="guard-skeleton h-32 w-full rounded-2xl" aria-label="Loading workspaces" />
    );
  }

  // The daemon resolves the suggested folder like a tracked root; the local
  // comparison only covers the moment before its answer arrives.
  const tracked = new Set(state.worktrees.map((worktree) => trimTrailingSeparators(worktree.root)));
  const canAddSuggested =
    suggestedRoot !== "" && state.suggestedRootTracked !== true && !tracked.has(trimTrailingSeparators(suggestedRoot));

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <p className="max-w-2xl text-sm text-slate-600">
          Guard re-checks these folders in the background when files or threat intel change, including files you
          have not committed. Checks run on this device and use no credits.
        </p>
        {canAddSuggested && state.worktrees.length > 0 && (
          <ActionButton variant="outline" onClick={handleAdd} disabled={busyKey !== null}>
            Add {folderName(suggestedRoot)}
          </ActionButton>
        )}
      </div>
      {loadError && <ErrorNotice message={loadError} onRetry={() => void refresh()} />}
      {actionError && <ErrorNotice message={actionError} />}
      {state.worktrees.length === 0 ? (
        <EmptyState
          title="No workspaces assessed yet"
          body={
            canAddSuggested
              ? `Add ${folderName(suggestedRoot)} and Guard will keep its dependencies checked as you work.`
              : "Choose a project folder and Guard will keep its dependencies checked as you work."
          }
          action={
            canAddSuggested ? (
              <ActionButton variant="primary" onClick={handleAdd} disabled={busyKey !== null}>
                Assess {folderName(suggestedRoot)}
              </ActionButton>
            ) : (
              <ActionButton variant="primary" onClick={props.onChooseFolder}>
                <HiMiniFolderOpen className="h-4 w-4" aria-hidden="true" />
                Choose folder
              </ActionButton>
            )
          }
        />
      ) : (
        <ul className="divide-y divide-slate-100 overflow-hidden rounded-2xl border border-slate-200 bg-white">
          {state.worktrees.map((worktree) => (
            <WorktreeRow
              key={`${worktree.codebaseKey}:${worktree.worktreeKey}`}
              worktree={worktree}
              newestRun={state.latestRuns.find((run) => sameWorktree(worktree, run))}
              assessment={state.assessments.find((item) => sameWorktree(worktree, item))}
              busyKey={busyKey}
              onAction={handleAction}
            />
          ))}
        </ul>
      )}
    </div>
  );
}

export function WorktreeRow(props: {
  worktree: WorkspaceWorktree;
  newestRun: WorkspaceRun | undefined;
  assessment: WorkspaceAssessment | undefined;
  busyKey: string | null;
  onAction: (action: WorkspaceAction, worktree: WorkspaceWorktree) => void;
}) {
  const { worktree, assessment } = props;
  const status = worktreeStatus(worktree, props.newestRun, assessment);
  const active = props.newestRun?.state === "running" || props.newestRun?.state === "queued";
  const reasons = (assessment?.reasons ?? []).map((reason) => COVERAGE_REASONS[reason] ?? "Part of the workspace was not checked.");
  const notRun = (assessment?.notRun ?? []).map((name) => `${DETECTOR_LABELS[name] ?? name} is not part of this check yet.`);
  const pauseAction: WorkspaceAction = worktree.paused ? "resume" : "pause";
  const headingId = `worktree-${worktree.worktreeKey.slice(0, 16)}`;

  return (
    <li className="space-y-4 px-4 py-4 sm:px-5" aria-labelledby={headingId}>
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 flex-1 basis-56">
          <div className="flex flex-wrap items-center gap-2">
            <h3 id={headingId} className="text-base font-semibold text-brand-dark">
              {folderName(worktree.root)}
            </h3>
            <Tag tone={status.tone}>{status.label}</Tag>
          </div>
          <p className="mt-1 truncate font-mono text-xs text-slate-500" title={worktree.root}>
            {worktree.root}
          </p>
          <p className="mt-1 text-sm text-slate-600">
            {status.detail ?? (worktree.lastScanAtMs ? `Checked ${formatRelativeTime(new Date(worktree.lastScanAtMs).toISOString())}` : "Waiting for the first check.")}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2">
          <ActionButton
            variant="outline"
            onClick={() => props.onAction("run", worktree)}
            disabled={worktree.paused || active || props.busyKey !== null}
          >
            <HiMiniArrowPath className={`h-4 w-4 ${active ? "animate-spin motion-reduce:animate-none" : ""}`} aria-hidden="true" />
            Assess now
          </ActionButton>
          <ActionButton variant="ghost" onClick={() => props.onAction(pauseAction, worktree)} disabled={props.busyKey !== null}>
            {worktree.paused ? "Resume" : "Pause"}
          </ActionButton>
        </div>
      </div>
      {(reasons.length > 0 || notRun.length > 0) && (
        <ul className="space-y-1 text-sm text-slate-600">
          {[...reasons, ...notRun].map((reason) => (
            <li key={reason} className="flex gap-2">
              <HiMiniExclamationTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600" aria-hidden="true" />
              {reason}
            </li>
          ))}
        </ul>
      )}
      {assessment && <FindingsTable findings={assessment.findings} />}
    </li>
  );
}

function FindingsTable({ findings }: { findings: WorkspaceFinding[] }) {
  if (findings.length === 0) {
    return <p className="text-sm text-slate-600">No dependency findings in the checked files.</p>;
  }
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Dependency findings</caption>
        <thead className="hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group">
          <tr>
            <th scope="col" className="px-3 py-2">Package</th>
            <th scope="col" className="px-3 py-2">Installed</th>
            <th scope="col" className="px-3 py-2">Fixed in</th>
            <th scope="col" className="px-3 py-2">Decision</th>
            <th scope="col" className="px-3 py-2">Severity</th>
            <th scope="col" className="px-3 py-2">Advisories</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100">
          {findings.map((finding) => (
            <tr key={finding.findingId} className="grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0">
              <Cell label="Package" wide>
                <span className="font-semibold text-brand-dark">{finding.packageName}</span>
                <span className="ml-2 text-xs text-slate-500">{finding.ecosystem}</span>
              </Cell>
              <Cell label="Installed"><Mono value={finding.packageVersion} /></Cell>
              <Cell label="Fixed in"><Mono value={finding.fixVersion} fallback="No fix yet" /></Cell>
              <Cell label="Decision">
                <Tag tone={decisionTone(finding.decision)}>{DECISION_LABELS[finding.decision] ?? finding.decision}</Tag>
              </Cell>
              <Cell label="Severity"><span className="capitalize text-slate-700">{finding.severity}</span></Cell>
              <Cell label="Advisories" wide>
                {finding.advisoryIds.length > 0 ? (
                  <span className="break-all font-mono text-xs text-slate-700">{finding.advisoryIds.join(", ")}</span>
                ) : (
                  <span className="text-slate-500">None listed</span>
                )}
              </Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Cell(props: { label: string; wide?: boolean; children: React.ReactNode }) {
  return (
    <td className={`min-w-0 md:px-3 md:py-2.5 ${props.wide ? "col-span-2 md:col-span-1" : ""}`}>
      <span className="block text-xs font-semibold text-slate-500 md:hidden">{props.label}</span>
      {props.children}
    </td>
  );
}

function Mono({ value, fallback = "Unknown" }: { value: string | null; fallback?: string }) {
  return value ? <span className="font-mono text-xs text-slate-700">{value}</span> : <span className="text-slate-500">{fallback}</span>;
}

function ErrorNotice(props: { message: string; onRetry?: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50/60 px-4 py-3" role="alert">
      <p className="text-sm text-red-800">{props.message}</p>
      {props.onRetry && (
        <ActionButton variant="outline" onClick={props.onRetry}>
          Retry
        </ActionButton>
      )}
    </div>
  );
}
