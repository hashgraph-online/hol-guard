import { fetchGuardApi } from "./guard-api";

const ASSESSMENTS_PATH = "/v1/supply-chain/workspace-assessments";
const FINDINGS_PATH = "/v1/supply-chain/workspace-findings";

export type WorktreeKeys = { codebaseKey: string; worktreeKey: string };

export type WorkspaceWorktree = WorktreeKeys & {
  root: string;
  stale: boolean;
  paused: boolean;
  lastScanAtMs: number | null;
};

export type WorkspaceRunState = "queued" | "running" | "completed" | "partial" | "superseded" | "failed" | "canceled";

export type WorkspaceRun = WorktreeKeys & {
  runId: string;
  state: WorkspaceRunState;
  triggerKind: string;
  errorCode: string | null;
  finishedAtMs: number | null;
};

export type WorkspaceFindingKind = "supply_chain" | "secret" | "runtime" | "skill" | "mcp" | "hook" | "plugin";

/** The fixed wording of the skill content rule that matched; never text from the skill. */
export type WorkspaceSkillCheck = { title: string; reason: string; confidence: string; falsePositiveHint: string | null };

/** The MCP launch rule that matched and the server it names; never the server's command or URL. */
export type WorkspaceMcpCheck = WorkspaceSkillCheck & { server: string };

/** The hook rule that matched and the event the hook runs on; never the hook's command. */
export type WorkspaceHookCheck = WorkspaceSkillCheck & { event: string };

/** An executable a configured tool would launch that matches a runtime advisory. */
export type WorkspaceRuntime = { family: string; version: string | null; title: string | null; knownExploited: boolean };

export type WorkspaceFinding = {
  findingId: string;
  kind: WorkspaceFindingKind;
  severity: string;
  decision: string;
  /** Rule or advisory codes that raised the finding. */
  ruleIds: string[];
  ecosystem: string;
  /** Null for a secret finding, which names a file location instead of a package. */
  packageName: string | null;
  packageVersion: string | null;
  fixVersion: string | null;
  advisoryIds: string[];
  /**
   * Root-relative file path of a secret or skill finding, or the executable
   * path of a runtime finding. Guard never receives the secret itself.
   */
  path: string | null;
  line: number | null;
  /** Every line the same secret appears on in that file, first to last. */
  lines: number[];
  /** Set only for a runtime finding; observation only, so it has no fix. */
  runtime: WorkspaceRuntime | null;
  /** Set only for an agent skill finding, a warning with no fix. */
  skill: WorkspaceSkillCheck | null;
  /**
   * Set only for an MCP server configuration finding, a warning with no fix,
   * or for an agent plugin finding about a server the plugin ships.
   */
  mcp: WorkspaceMcpCheck | null;
  /**
   * Set only for a project hook configuration finding, a warning with no fix,
   * or for an agent plugin finding about a hook the plugin ships.
   */
  hook: WorkspaceHookCheck | null;
};

export type WorkspaceAssessment = WorktreeKeys & {
  runId: string;
  partial: boolean;
  reasons: string[];
  notRun: string[];
  /** False when the workspace has no dependency files, so there was nothing to audit. */
  dependencyFilesFound: boolean;
  finishedAtMs: number | null;
  findings: WorkspaceFinding[];
};

export type WorkspaceFindingsState = {
  worktrees: WorkspaceWorktree[];
  runs: WorkspaceRun[];
  /** The newest run of each worktree, independent of the bounded history in `runs`. */
  latestRuns: WorkspaceRun[];
  assessments: WorkspaceAssessment[];
  /** Whether the daemon already tracks the folder asked about; null when none was asked about. */
  suggestedRootTracked: boolean | null;
  /** Set while a busy device holds automatic checks back; checks the user starts still run. */
  deferredReason: string | null;
};

const RUN_STATES = new Set<string>(["queued", "running", "completed", "partial", "superseded", "failed", "canceled"]);

function record(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function count(value: unknown): number | null {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function list(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function keys(item: Record<string, unknown>): WorktreeKeys | null {
  const codebaseKey = text(item.codebase_key);
  const worktreeKey = text(item.worktree_key);
  return codebaseKey && worktreeKey ? { codebaseKey, worktreeKey } : null;
}

function normalizeWorktree(value: unknown): WorkspaceWorktree | null {
  const item = record(value);
  const ids = keys(item);
  if (ids === null) return null;
  return {
    ...ids,
    root: text(item.root) ?? "",
    stale: item.stale === true,
    paused: item.paused === true,
    lastScanAtMs: count(item.last_scan_at_ms),
  };
}

function normalizeRun(value: unknown): WorkspaceRun | null {
  const item = record(value);
  const ids = keys(item);
  const runId = text(item.run_id);
  const state = text(item.state);
  if (ids === null || runId === null || state === null || !RUN_STATES.has(state)) return null;
  return {
    ...ids,
    runId,
    state: state as WorkspaceRunState,
    triggerKind: text(item.trigger_kind) ?? "manual",
    errorCode: text(item.error_code),
    finishedAtMs: count(item.finished_at_ms),
  };
}

function normalizeRuns(value: unknown): WorkspaceRun[] {
  return list(value)
    .map(normalizeRun)
    .filter((entry): entry is WorkspaceRun => entry !== null);
}

function strings(value: unknown): string[] {
  return list(value).filter((entry): entry is string => typeof entry === "string");
}

function normalizeFinding(value: unknown): WorkspaceFinding | null {
  const item = record(value);
  const findingId = text(item.finding_id);
  if (findingId === null) return null;
  const common = {
    findingId,
    severity: text(item.severity) ?? "unknown",
    decision: text(item.decision) ?? "warn",
    ruleIds: strings(item.rule_ids),
    advisoryIds: strings(item.advisory_ids),
  };
  if (item.source_kind === "secret") {
    const path = text(item.path);
    if (path === null || common.ruleIds.length === 0) return null;
    const line = count(item.line);
    return {
      ...common,
      kind: "secret",
      ecosystem: "unknown",
      packageName: null,
      packageVersion: null,
      fixVersion: null,
      path,
      line: line !== null && line >= 1 ? line : null,
      lines: list(item.lines).flatMap((entry) => {
        const value = count(entry);
        return value !== null && value >= 1 ? [value] : [];
      }),
      runtime: null,
      skill: null,
      mcp: null,
      hook: null,
    };
  }
  if (item.source_kind === "workspace_source" && item.detector === "skill_content_v1") {
    const path = text(item.path);
    const title = text(item.title);
    const reason = text(item.reason);
    if (path === null || title === null || reason === null || common.ruleIds.length === 0) return null;
    return {
      ...common,
      kind: "skill",
      ecosystem: "unknown",
      packageName: null,
      packageVersion: null,
      fixVersion: null,
      path,
      line: null,
      lines: [],
      runtime: null,
      skill: {
        title,
        reason,
        confidence: text(item.confidence) ?? "likely",
        falsePositiveHint: text(item.false_positive_hint),
      },
      mcp: null,
      hook: null,
    };
  }
  if (item.source_kind === "workspace_source" && item.detector === "mcp_config_v1") {
    const path = text(item.path);
    const server = text(item.server);
    const title = text(item.title);
    const reason = text(item.reason);
    if (path === null || server === null || title === null || reason === null || common.ruleIds.length === 0) return null;
    return {
      ...common,
      kind: "mcp",
      ecosystem: "unknown",
      packageName: null,
      packageVersion: null,
      fixVersion: null,
      path,
      line: null,
      lines: [],
      runtime: null,
      skill: null,
      mcp: {
        server,
        title,
        reason,
        confidence: text(item.confidence) ?? "likely",
        falsePositiveHint: text(item.false_positive_hint),
      },
      hook: null,
    };
  }
  if (item.source_kind === "workspace_source" && item.detector === "hook_config_v1") {
    const path = text(item.path);
    const event = text(item.event);
    const title = text(item.title);
    const reason = text(item.reason);
    if (path === null || event === null || title === null || reason === null || common.ruleIds.length === 0) return null;
    return {
      ...common,
      kind: "hook",
      ecosystem: "unknown",
      packageName: null,
      packageVersion: null,
      fixVersion: null,
      path,
      line: null,
      lines: [],
      runtime: null,
      skill: null,
      mcp: null,
      hook: {
        event,
        title,
        reason,
        confidence: text(item.confidence) ?? "likely",
        falsePositiveHint: text(item.false_positive_hint),
      },
    };
  }
  if (item.source_kind === "workspace_source" && item.detector === "plugin_manifest_v1") {
    const path = text(item.path);
    const title = text(item.title);
    const reason = text(item.reason);
    if (path === null || title === null || reason === null || common.ruleIds.length === 0) return null;
    const check = { title, reason, confidence: text(item.confidence) ?? "likely", falsePositiveHint: text(item.false_positive_hint) };
    const event = item.component === "hook" ? text(item.event) : null;
    const server = item.component === "mcp_server" ? text(item.server) : null;
    if (event === null && server === null) return null;
    return {
      ...common,
      kind: "plugin",
      ecosystem: "unknown",
      packageName: null,
      packageVersion: null,
      fixVersion: null,
      path,
      line: null,
      lines: [],
      runtime: null,
      skill: null,
      mcp: server === null ? null : { ...check, server },
      hook: event === null ? null : { ...check, event },
    };
  }
  if (item.source_kind === "agent_inventory" && item.detector === "runtime_identity_v1") {
    const family = text(item.runtime_family);
    const path = text(item.path);
    if (family === null || path === null || common.advisoryIds.length === 0) return null;
    return {
      ...common,
      kind: "runtime",
      ecosystem: "unknown",
      packageName: null,
      packageVersion: null,
      fixVersion: null,
      path,
      line: null,
      lines: [],
      runtime: {
        family,
        version: text(item.runtime_version),
        title: text(item.title),
        knownExploited: item.known_exploited === true,
      },
      skill: null,
      mcp: null,
      hook: null,
    };
  }
  const packageName = text(item.package_name);
  if (packageName === null) return null;
  return {
    ...common,
    kind: "supply_chain",
    ecosystem: text(item.ecosystem) ?? "unknown",
    packageName,
    packageVersion: text(item.package_version),
    fixVersion: text(item.fix_version),
    path: null,
    line: null,
    lines: [],
    runtime: null,
    skill: null,
    mcp: null,
    hook: null,
  };
}

function normalizeAssessment(value: unknown): WorkspaceAssessment | null {
  const item = record(value);
  const ids = keys(item);
  const runId = text(item.run_id);
  if (ids === null || runId === null) return null;
  const coverage = record(item.coverage);
  const detectors = record(coverage.detectors);
  const reasons = list(coverage.reasons).filter(
    (entry): entry is string => typeof entry === "string" && !entry.startsWith("detector_not_run:"),
  );
  const notRun = Object.entries(detectors)
    .filter(([, status]) => status === "not_run")
    .map(([name]) => name);
  // Detectors that did not run stay in their own list, but the daemon's partial
  // classification is kept so an incomplete result is never shown as up to date.
  const reportedPartial = item.state === "partial" || coverage.status === "partial";
  return {
    ...ids,
    runId,
    partial: reasons.length > 0 || reportedPartial || notRun.length > 0,
    reasons,
    notRun,
    dependencyFilesFound: detectors.supply_chain !== "no_inputs",
    finishedAtMs: count(item.finished_at_ms),
    findings: list(item.findings)
      .map(normalizeFinding)
      .filter((entry): entry is WorkspaceFinding => entry !== null),
  };
}

export function normalizeWorkspaceFindingsState(assessmentsPayload: unknown, findingsPayload: unknown): WorkspaceFindingsState {
  const history = record(assessmentsPayload);
  const findings = record(findingsPayload);
  return {
    worktrees: list(findings.worktrees ?? history.worktrees)
      .map(normalizeWorktree)
      .filter((entry): entry is WorkspaceWorktree => entry !== null),
    runs: normalizeRuns(history.runs),
    latestRuns: normalizeRuns(history.latest_runs),
    assessments: list(findings.assessments)
      .map(normalizeAssessment)
      .filter((entry): entry is WorkspaceAssessment => entry !== null),
    suggestedRootTracked: typeof findings.suggested_root_tracked === "boolean" ? findings.suggested_root_tracked : null,
    deferredReason: text(history.deferred_reason),
  };
}

async function readPayload(path: string, init?: RequestInit): Promise<{ status: number; body: unknown }> {
  const response = await fetchGuardApi(path, init);
  const body = (await response.json().catch(() => null)) as unknown;
  if (!response.ok && response.status !== 409) {
    throw new Error(workspaceErrorMessage(text(record(body).error)));
  }
  return { status: response.status, body };
}

export async function fetchWorkspaceFindings(options: { signal?: AbortSignal; suggestedRoot?: string } = {}): Promise<WorkspaceFindingsState> {
  const { signal, suggestedRoot } = options;
  // The daemon resolves the suggested folder the way it resolves tracked ones,
  // so a symlinked or differently written path is not offered again.
  const findingsPath = suggestedRoot ? `${FINDINGS_PATH}?root=${encodeURIComponent(suggestedRoot)}` : FINDINGS_PATH;
  const [history, findings] = await Promise.all([
    readPayload(ASSESSMENTS_PATH, { signal }),
    readPayload(findingsPath, { signal }),
  ]);
  return normalizeWorkspaceFindingsState(history.body, findings.body);
}

function post(path: string, payload: Record<string, string>) {
  return readPayload(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

export async function addWorkspaceForAssessment(root: string): Promise<void> {
  await post(ASSESSMENTS_PATH, { root });
}

export type WorkspaceAction = "run" | "pause" | "resume";

export async function runWorkspaceAction(action: WorkspaceAction, worktree: WorktreeKeys): Promise<void> {
  await post(`${ASSESSMENTS_PATH}/${action}`, {
    codebase_key: worktree.codebaseKey,
    worktree_key: worktree.worktreeKey,
  });
}

const ERROR_MESSAGES: Record<string, string> = {
  invalid_root: "Choose a folder before adding it.",
  workspace_root_not_absolute: "Guard needs the full path to the folder.",
  workspace_root_missing: "That folder no longer exists. Choose it again.",
  workspace_root_not_directory: "That path is a file. Choose its folder instead.",
  invalid_worktree: "This workspace is no longer tracked. Refresh the list.",
  workspace_snapshot_failed: "Guard could not read that folder. Check that it is a readable repository, then retry.",
  workspace_snapshot_native_unavailable: "The Guard runtime that reads workspace files is unavailable. Restart Guard, then retry.",
};

export function workspaceErrorMessage(code: string | null): string {
  return (code && ERROR_MESSAGES[code]) ?? "Guard could not update workspace assessments. Check that Guard is running, then retry.";
}
