import { dk as fetchGuardApi } from "../guard-dashboard.js";
const ASSESSMENTS_PATH = "/v1/supply-chain/workspace-assessments";
const FINDINGS_PATH = "/v1/supply-chain/workspace-findings";
const RUN_STATES = /* @__PURE__ */ new Set(["queued", "running", "completed", "partial", "superseded", "failed", "canceled"]);
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function text(value) {
  return typeof value === "string" && value.trim() ? value : null;
}
function count(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
function list(value) {
  return Array.isArray(value) ? value : [];
}
function keys(item) {
  const codebaseKey = text(item.codebase_key);
  const worktreeKey = text(item.worktree_key);
  return codebaseKey && worktreeKey ? { codebaseKey, worktreeKey } : null;
}
function normalizeWorktree(value) {
  const item = record(value);
  const ids = keys(item);
  if (ids === null) return null;
  return {
    ...ids,
    root: text(item.root) ?? "",
    stale: item.stale === true,
    paused: item.paused === true,
    lastScanAtMs: count(item.last_scan_at_ms)
  };
}
function normalizeRun(value) {
  const item = record(value);
  const ids = keys(item);
  const runId = text(item.run_id);
  const state = text(item.state);
  if (ids === null || runId === null || state === null || !RUN_STATES.has(state)) return null;
  return {
    ...ids,
    runId,
    state,
    triggerKind: text(item.trigger_kind) ?? "manual",
    errorCode: text(item.error_code),
    finishedAtMs: count(item.finished_at_ms)
  };
}
function normalizeRuns(value) {
  return list(value).map(normalizeRun).filter((entry) => entry !== null);
}
function strings(value) {
  return list(value).filter((entry) => typeof entry === "string");
}
function validationState(value) {
  return value === "confirmed" || value === "unvalidated" ? value : "unknown";
}
function normalizeFinding(value) {
  const item = record(value);
  const findingId = text(item.finding_id);
  if (findingId === null) return null;
  const common = {
    findingId,
    severity: text(item.severity) ?? "unknown",
    decision: text(item.decision) ?? "warn",
    ruleIds: strings(item.rule_ids),
    advisoryIds: strings(item.advisory_ids),
    carried: text(item.carried_from_run_id) !== null,
    validation: validationState(item.validation_state)
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
        const value2 = count(entry);
        return value2 !== null && value2 >= 1 ? [value2] : [];
      }),
      runtime: null,
      skill: null,
      mcp: null,
      hook: null,
      workflow: null,
      editorTask: null,
      instruction: null
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
        falsePositiveHint: text(item.false_positive_hint)
      },
      mcp: null,
      hook: null,
      workflow: null,
      editorTask: null,
      instruction: null
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
        falsePositiveHint: text(item.false_positive_hint)
      },
      hook: null,
      workflow: null,
      editorTask: null,
      instruction: null
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
        falsePositiveHint: text(item.false_positive_hint)
      },
      workflow: null,
      editorTask: null,
      instruction: null
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
      workflow: null,
      editorTask: null,
      instruction: null
    };
  }
  if (item.source_kind === "workspace_source" && (item.detector === "ci_workflow_v1" || item.detector === "editor_task_v1" || item.detector === "instruction_file_v1")) {
    const path = text(item.path);
    const title = text(item.title);
    const reason = text(item.reason);
    if (path === null || title === null || reason === null || common.ruleIds.length === 0) return null;
    const check = { title, reason, confidence: text(item.confidence) ?? "likely", falsePositiveHint: text(item.false_positive_hint) };
    const kind = item.detector === "ci_workflow_v1" ? "workflow" : item.detector === "editor_task_v1" ? "editor_task" : "instruction";
    return {
      ...common,
      kind,
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
      hook: null,
      workflow: kind === "workflow" ? check : null,
      editorTask: kind === "editor_task" ? check : null,
      instruction: kind === "instruction" ? check : null
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
        knownExploited: item.known_exploited === true
      },
      skill: null,
      mcp: null,
      hook: null,
      workflow: null,
      editorTask: null,
      instruction: null
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
    workflow: null,
    editorTask: null,
    instruction: null
  };
}
function normalizeAssessment(value) {
  const item = record(value);
  const ids = keys(item);
  const runId = text(item.run_id);
  if (ids === null || runId === null) return null;
  const coverage = record(item.coverage);
  const detectors = record(coverage.detectors);
  const reasons = list(coverage.reasons).filter(
    (entry) => typeof entry === "string" && !entry.startsWith("detector_not_run:")
  );
  const notRun = Object.entries(detectors).filter(([, status]) => status === "not_run").map(([name]) => name);
  const reportedPartial = item.state === "partial" || coverage.status === "partial";
  return {
    ...ids,
    runId,
    partial: reasons.length > 0 || reportedPartial || notRun.length > 0,
    reasons,
    notRun,
    dependencyFilesFound: detectors.supply_chain !== "no_inputs",
    finishedAtMs: count(item.finished_at_ms),
    findings: list(item.findings).map(normalizeFinding).filter((entry) => entry !== null)
  };
}
function normalizeWorkspaceFindingsState(assessmentsPayload, findingsPayload) {
  const history = record(assessmentsPayload);
  const findings = record(findingsPayload);
  return {
    worktrees: list(findings.worktrees ?? history.worktrees).map(normalizeWorktree).filter((entry) => entry !== null),
    runs: normalizeRuns(history.runs),
    latestRuns: normalizeRuns(history.latest_runs),
    assessments: list(findings.assessments).map(normalizeAssessment).filter((entry) => entry !== null),
    suggestedRootTracked: typeof findings.suggested_root_tracked === "boolean" ? findings.suggested_root_tracked : null,
    deferredReason: text(history.deferred_reason)
  };
}
async function readPayload(path, init) {
  let response;
  try {
    response = await fetchGuardApi(path, init);
  } catch (error) {
    if (init?.signal?.aborted) throw error;
    throw new Error(workspaceErrorMessage(null));
  }
  const body = await response.json().catch(() => null);
  if (!response.ok && response.status !== 409) {
    throw new Error(workspaceErrorMessage(text(record(body).error)));
  }
  return { status: response.status, body };
}
async function fetchWorkspaceFindings(options = {}) {
  const { signal, suggestedRoot } = options;
  const findingsPath = suggestedRoot ? `${FINDINGS_PATH}?root=${encodeURIComponent(suggestedRoot)}` : FINDINGS_PATH;
  const [history, findings] = await Promise.all([
    readPayload(ASSESSMENTS_PATH, { signal }),
    readPayload(findingsPath, { signal })
  ]);
  return normalizeWorkspaceFindingsState(history.body, findings.body);
}
function post(path, payload) {
  return readPayload(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}
async function addWorkspaceForAssessment(root) {
  await post(ASSESSMENTS_PATH, { root });
}
async function runWorkspaceAction(action, worktree) {
  await post(`${ASSESSMENTS_PATH}/${action}`, {
    codebase_key: worktree.codebaseKey,
    worktree_key: worktree.worktreeKey
  });
}
const ERROR_MESSAGES = {
  invalid_root: "Choose a folder before adding it.",
  workspace_root_not_absolute: "Guard needs the full path to the folder.",
  workspace_root_missing: "That folder no longer exists. Choose it again.",
  workspace_root_not_directory: "That path is a file. Choose its folder instead.",
  invalid_worktree: "This workspace is no longer tracked. Refresh the list.",
  workspace_snapshot_failed: "Guard could not read that folder. Check that it is a readable repository, then retry.",
  workspace_snapshot_native_unavailable: "The Guard runtime that reads workspace files is unavailable. Restart Guard, then retry."
};
function workspaceErrorMessage(code) {
  return (code && ERROR_MESSAGES[code]) ?? "Guard could not update workspace assessments. Check that Guard is running, then retry.";
}
function createLatestRefresh(load, apply) {
  let latest = 0;
  return async () => {
    latest += 1;
    const request = latest;
    try {
      const value = await load();
      if (request === latest) apply.onData(value);
    } catch (error) {
      if (request === latest) apply.onError(error);
    }
  };
}
const FAILURE_REASONS = {
  workspace_snapshot_failed: "Guard could not read this workspace.",
  workspace_snapshot_native_unavailable: "The Guard runtime needed to read files is unavailable.",
  workspace_identity_changed: "The folder now points at a different repository. Add it again.",
  supply_chain_detector_failed: "The dependency check stopped before it finished.",
  assessment_result_too_large: "The result was too large to store.",
  lease_expired: "The assessment took too long and was retried.",
  assessment_timed_out: "The assessment took too long twice and was stopped. It runs again when files change or you choose Assess now.",
  feed_context_unavailable: "Guard could not read its cached advisories."
};
function sameWorktree(left, right) {
  return left.codebaseKey === right.codebaseKey && left.worktreeKey === right.worktreeKey;
}
function worktreeStatus(worktree, newestRun, assessment) {
  if (worktree.paused) return { label: "Paused", tone: "slate", detail: "Guard is not watching this workspace." };
  if (newestRun?.state === "running") return { label: "Assessing", tone: "slate", detail: null };
  if (newestRun?.state === "queued") return { label: "Queued", tone: "slate", detail: null };
  if (newestRun?.state === "failed" && newestRun.errorCode !== "lease_expired") {
    const detail = FAILURE_REASONS[newestRun.errorCode ?? ""] ?? "The last assessment did not finish.";
    return { label: "Assessment failed", tone: "red", detail };
  }
  if (assessment === void 0) return { label: "Not assessed yet", tone: "slate", detail: null };
  if (worktree.stale) return { label: "Out of date", tone: "attention", detail: "Files changed since the last assessment." };
  if (assessment.partial) return { label: "Partial coverage", tone: "attention", detail: null };
  return { label: "Up to date", tone: "green", detail: null };
}
export {
  addWorkspaceForAssessment as a,
  createLatestRefresh as c,
  fetchWorkspaceFindings as f,
  runWorkspaceAction as r,
  sameWorktree as s,
  worktreeStatus as w
};
