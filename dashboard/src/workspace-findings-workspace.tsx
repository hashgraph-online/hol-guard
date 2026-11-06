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
import { sameWorktree, worktreeStatus } from "./workspace-findings-status";
import {
  CarriedNote,
  Cell,
  EditorTaskFindingsTable,
  EvidenceNote,
  HookFindingsTable,
  InstructionFindingsTable,
  McpFindingsTable,
  PluginFindingsTable,
  RuntimeFindingsTable,
  SecretFindingsTable,
  SkillFindingsTable,
  WorkflowFindingsTable,
} from "./workspace-findings-tables";
import { ExportPreviewPanel } from "./workspace-export-preview-panel";
import { FixCell, FixHistory, FixLoadError, FixReview, useWorktreeFixes, type WorktreeFixes } from "./workspace-fix-panel";

export { worktreeStatus, type WorktreeStatus } from "./workspace-findings-status";

const REFRESH_MS = 15_000;

const COVERAGE_REASONS: Record<string, string> = {
  snapshot_entry_cap: "The workspace has more files than one assessment reads.",
  snapshot_byte_cap: "The workspace is larger than one assessment reads.",
  snapshot_oversize_detector_input: "A dependency file was too large to read.",
  snapshot_unreadable: "Some files could not be read.",
  snapshot_unstable: "Files changed while Guard was reading them.",
  snapshot_depth_cap: "Some folders are nested deeper than one assessment reads.",
  snapshot_visit_cap: "The workspace has more entries than one assessment visits.",
  snapshot_unsupported_dependency_input: "Some lockfiles use a format Guard does not check yet, so those dependencies were not checked.",
  snapshot_undiscovered_dependency_input:
    "Some dependency files are more than three folders below the workspace root, so those dependencies were not checked.",
  supply_chain_incomplete: "Some dependencies need registry data Guard does not have offline. Use Assess now to look them up.",
  advisory_data_unavailable:
    "No threat intel is cached on this device yet, so dependencies were listed but not checked for known vulnerabilities.",
  lockfile_warnings: "A lockfile could not be fully parsed.",
  finding_cap: "There were more findings than one assessment keeps.",
  secrets_incomplete: "Secret scanning did not cover every file, so some secrets may not be listed.",
  runtime_advisories_unavailable: "Runtimes this workspace's tools launch were not checked: Guard has no runtime advisories cached.",
  runtimes_incomplete: "Some runtimes this workspace's tools launch could not be identified or checked.",
  skills_incomplete: "Some agent skills could not be read in full, so their instructions may not all be checked.",
  mcp_config_incomplete: "Some MCP server settings could not be read, so not every configured server was checked.",
  hook_config_incomplete: "Some agent hook settings could not be fully checked, so not every project hook was screened.",
  plugin_manifest_incomplete: "Some agent plugin files could not be fully read, so not every plugin hook or MCP server was checked.",
  ci_workflow_incomplete: "Some GitHub Actions workflows could not be fully read, so not every workflow was checked.",
  editor_task_incomplete:
    "Some editor task or dev container files could not be fully read, so not every file was checked.",
  instruction_file_incomplete: "Some agent instruction files could not be fully read, so not every file was checked.",
};

const DETECTOR_LABELS: Record<string, string> = {
  secrets: "Secret scanning",
  runtime_identity_v1: "Runtime checking",
  skill_content_v1: "Skill checking",
  mcp_config_v1: "MCP server checking",
  hook_config_v1: "Project hook checking",
  plugin_manifest_v1: "Agent plugin checking",
  ci_workflow_v1: "CI workflow checking",
  editor_task_v1: "Editor task checking",
  instruction_file_v1: "Instruction file checking",
};

// When the newest run has not produced a result yet, or failed, the findings
// on screen still come from the last finished assessment, so say when that was.
export function checkedSummary(
  worktree: WorkspaceWorktree,
  newestRun: WorkspaceRun | undefined,
  assessment: WorkspaceAssessment | undefined,
): string {
  const pending = newestRun?.state === "running" || newestRun?.state === "queued" || newestRun?.state === "failed";
  // lastScanAtMs also moves when a run fails, so it cannot stand in for a finished check.
  if (assessment === undefined && pending) return "No check has finished yet.";
  const earlier = assessment !== undefined && pending && newestRun?.runId !== assessment.runId;
  // The two endpoints are read separately, so a finished run can arrive before its assessment.
  const runAtMs = newestRun?.state === "completed" || newestRun?.state === "partial" ? newestRun.finishedAtMs : null;
  const atMs = assessment?.finishedAtMs ?? (earlier ? null : (runAtMs ?? worktree.lastScanAtMs));
  if (atMs === null) return earlier ? "Showing results from an earlier check." : "Waiting for the first check.";
  const when = formatRelativeTime(new Date(atMs).toISOString());
  return earlier ? `Showing results from the check ${when.replace(/^Yesterday/, "yesterday")}.` : `Checked ${when}`;
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

// Package policy's verdict on this version. A finding in the worktree is not
// itself a blocked action, and a saved approval or observe mode can still
// change what happens at install.
const DECISION_LABELS: Record<string, string> = { block: "Block", ask: "Ask", warn: "Warn" };

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
      {state.deferredReason === "resource_pressure" && state.worktrees.length > 0 && (
        <p role="status" className="rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600">
          This device is busy, so background checks are waiting. Checks you start with Assess now still run.
        </p>
      )}
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
          {status.detail && <p className="mt-1 text-sm text-slate-600">{status.detail}</p>}
          <p className="mt-1 text-sm text-slate-500">{checkedSummary(worktree, props.newestRun, assessment)}</p>
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
      {assessment && <AssessmentFindings worktree={worktree} assessment={assessment} />}
    </li>
  );
}

function AssessmentFindings(props: { worktree: WorkspaceWorktree; assessment: WorkspaceAssessment }) {
  const { findings, runId, notRun, dependencyFilesFound } = props.assessment;
  const fixes = useWorktreeFixes(props.worktree, runId);
  return (
    <div className="space-y-4">
      <FixLoadError fixes={fixes} />
      <FindingsSections findings={findings} dependencyFilesFound={dependencyFilesFound} secretsChecked={!notRun.includes("secrets")} fixes={fixes} />
      <FixReview fixes={fixes} findings={findings} />
      <FixHistory fixes={fixes} findings={findings} />
      <ExportPreviewPanel worktree={props.worktree} findings={findings} />
    </div>
  );
}

function emptyFindingsCopy(dependencyFilesFound: boolean, secretsChecked: boolean): string {
  // A workspace without dependency files had nothing to audit; saying its
  // dependencies came back clean would overstate what was checked.
  const none = "No dependency files were found, so there were no dependencies to check.";
  if (!dependencyFilesFound) return secretsChecked ? `${none} No secret findings in the checked files.` : none;
  return secretsChecked ? "No dependency or secret findings in the checked files." : "No dependency findings in the checked files.";
}

type FindingsSectionsProps = { findings: WorkspaceFinding[]; dependencyFilesFound: boolean; secretsChecked: boolean; fixes: WorktreeFixes };

function FindingsSections(props: FindingsSectionsProps) {
  const dependencies = props.findings.filter((finding) => finding.kind === "supply_chain");
  const secrets = props.findings.filter((finding) => finding.kind === "secret");
  const runtimes = props.findings.filter((finding) => finding.kind === "runtime");
  const skills = props.findings.filter((finding) => finding.kind === "skill");
  const servers = props.findings.filter((finding) => finding.kind === "mcp");
  const hooks = props.findings.filter((finding) => finding.kind === "hook");
  const plugins = props.findings.filter((finding) => finding.kind === "plugin");
  const workflows = props.findings.filter((finding) => finding.kind === "workflow");
  const editorTasks = props.findings.filter((finding) => finding.kind === "editor_task");
  const instructions = props.findings.filter((finding) => finding.kind === "instruction");
  if (props.findings.length === 0) {
    return <p className="text-sm text-slate-600">{emptyFindingsCopy(props.dependencyFilesFound, props.secretsChecked)}</p>;
  }
  return (
    <div className="space-y-4">
      {dependencies.length > 0 && <FindingsTable findings={dependencies} fixes={props.fixes} />}
      {secrets.length > 0 && <SecretFindingsTable findings={secrets} />}
      {runtimes.length > 0 && <RuntimeFindingsTable findings={runtimes} />}
      {skills.length > 0 && <SkillFindingsTable findings={skills} />}
      {servers.length > 0 && <McpFindingsTable findings={servers} />}
      {hooks.length > 0 && <HookFindingsTable findings={hooks} />}
      {plugins.length > 0 && <PluginFindingsTable findings={plugins} />}
      {workflows.length > 0 && <WorkflowFindingsTable findings={workflows} />}
      {editorTasks.length > 0 && <EditorTaskFindingsTable findings={editorTasks} />}
      {instructions.length > 0 && <InstructionFindingsTable findings={instructions} />}
    </div>
  );
}

function FindingsTable({ findings, fixes }: { findings: WorkspaceFinding[]; fixes: WorktreeFixes }) {
  return (
    <div className="overflow-hidden rounded-xl border border-slate-200">
      <table className="w-full text-left text-sm">
        <caption className="sr-only">Dependency findings</caption>
        <thead className="hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group">
          <tr>
            <th scope="col" className="px-3 py-2">Package</th>
            <th scope="col" className="px-3 py-2">Installed</th>
            <th scope="col" className="px-3 py-2">Fixed in</th>
            <th scope="col" className="px-3 py-2">Policy</th>
            <th scope="col" className="px-3 py-2">Severity</th>
            <th scope="col" className="px-3 py-2">Advisories</th>
            <th scope="col" className="px-3 py-2">Fix</th>
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
              <Cell label="Policy">
                <Tag tone={decisionTone(finding.decision)}>{DECISION_LABELS[finding.decision] ?? finding.decision}</Tag>
                <EvidenceNote finding={finding} />
                <CarriedNote finding={finding} />
              </Cell>
              <Cell label="Severity"><span className="capitalize text-slate-700">{finding.severity}</span></Cell>
              <Cell label="Advisories" wide>
                {finding.advisoryIds.length > 0 ? (
                  <span className="break-all font-mono text-xs text-slate-700">{finding.advisoryIds.join(", ")}</span>
                ) : (
                  <span className="text-slate-500">None listed</span>
                )}
              </Cell>
              <Cell label="Fix" wide><FixCell finding={finding} fixes={fixes} /></Cell>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
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
