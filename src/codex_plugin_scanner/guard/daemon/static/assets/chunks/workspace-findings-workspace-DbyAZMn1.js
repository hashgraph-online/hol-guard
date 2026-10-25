import { cY as fetchGuardApi, r as reactExports, j as jsxRuntimeExports, A as ActionButton, N as EmptyState, eh as HiMiniFolderOpen, T as Tag, f as formatRelativeTime, d as HiMiniArrowPath, a4 as HiMiniExclamationTriangle } from "../guard-dashboard.js";
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
function normalizeFinding(value) {
  const item = record(value);
  const findingId = text(item.finding_id);
  const packageName = text(item.package_name);
  if (findingId === null || packageName === null) return null;
  return {
    findingId,
    severity: text(item.severity) ?? "unknown",
    decision: text(item.decision) ?? "warn",
    ecosystem: text(item.ecosystem) ?? "unknown",
    packageName,
    packageVersion: text(item.package_version),
    fixVersion: text(item.fix_version),
    advisoryIds: list(item.advisory_ids).filter((entry) => typeof entry === "string")
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
    suggestedRootTracked: typeof findings.suggested_root_tracked === "boolean" ? findings.suggested_root_tracked : null
  };
}
async function readPayload(path, init) {
  const response = await fetchGuardApi(path, init);
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
  invalid_worktree: "This workspace is no longer tracked. Refresh the list."
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
const REFRESH_MS = 15e3;
const COVERAGE_REASONS = {
  snapshot_entry_cap: "The workspace has more files than one assessment reads.",
  snapshot_byte_cap: "The workspace is larger than one assessment reads.",
  snapshot_oversize_detector_input: "A dependency file was too large to read.",
  snapshot_unreadable: "Some files could not be read.",
  snapshot_unstable: "Files changed while Guard was reading them.",
  snapshot_depth_cap: "Some folders are nested deeper than one assessment reads.",
  snapshot_visit_cap: "The workspace has more entries than one assessment visits.",
  supply_chain_incomplete: "Some dependencies need registry data Guard does not have offline. Use Assess now to look them up.",
  lockfile_warnings: "A lockfile could not be fully parsed.",
  finding_cap: "There were more findings than one assessment keeps."
};
const FAILURE_REASONS = {
  workspace_snapshot_failed: "Guard could not read this workspace.",
  workspace_snapshot_native_unavailable: "The Guard runtime needed to read files is unavailable.",
  workspace_identity_changed: "The folder now points at a different repository. Add it again.",
  supply_chain_detector_failed: "The dependency check stopped before it finished.",
  assessment_result_too_large: "The result was too large to store.",
  lease_expired: "The assessment took too long and was retried.",
  feed_context_unavailable: "Guard could not read its cached advisories."
};
const DETECTOR_LABELS = { secrets: "Secret scanning" };
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
function trimTrailingSeparators(root) {
  const trimmed = root.replace(/[\\/]+$/, "");
  return trimmed === "" ? root : trimmed;
}
function folderName(root) {
  const parts = root.split(/[\\/]/).filter(Boolean);
  return parts[parts.length - 1] ?? root;
}
function decisionTone(decision) {
  if (decision === "block") return "red";
  if (decision === "ask") return "attention";
  return "slate";
}
const DECISION_LABELS = { block: "Blocked", ask: "Needs review", warn: "Warning" };
function WorkspaceFindingsWorkspace(props) {
  const [state, setState] = reactExports.useState(null);
  const [loadError, setLoadError] = reactExports.useState(null);
  const [actionError, setActionError] = reactExports.useState(null);
  const [busyKey, setBusyKey] = reactExports.useState(null);
  const mounted = reactExports.useRef(true);
  const suggestedRoot = props.suggestedRoot.trim();
  const suggestedRootRef = reactExports.useRef(suggestedRoot);
  suggestedRootRef.current = suggestedRoot;
  const refresh = reactExports.useMemo(
    () => createLatestRefresh(() => fetchWorkspaceFindings({ suggestedRoot: suggestedRootRef.current }), {
      onData: (next) => {
        if (!mounted.current) return;
        setState(next);
        setLoadError(null);
      },
      onError: (error) => {
        if (mounted.current) setLoadError(error instanceof Error ? error.message : String(error));
      }
    }),
    []
  );
  reactExports.useEffect(() => {
    mounted.current = true;
    void refresh();
    const timer = window.setInterval(() => void refresh(), REFRESH_MS);
    return () => {
      mounted.current = false;
      window.clearInterval(timer);
    };
  }, [refresh, suggestedRoot]);
  const perform = reactExports.useCallback(
    async (key, operation) => {
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
    [refresh]
  );
  const handleAction = reactExports.useCallback(
    (action, worktree) => void perform(`${action}:${worktree.worktreeKey}`, () => runWorkspaceAction(action, worktree)),
    [perform]
  );
  const handleAdd = reactExports.useCallback(
    () => void perform("add", () => addWorkspaceForAssessment(suggestedRoot)),
    [perform, suggestedRoot]
  );
  if (state === null) {
    return loadError ? /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorNotice, { message: loadError, onRetry: () => void refresh() }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-32 w-full rounded-2xl", "aria-label": "Loading workspaces" });
  }
  const tracked = new Set(state.worktrees.map((worktree) => trimTrailingSeparators(worktree.root)));
  const canAddSuggested = suggestedRoot !== "" && state.suggestedRootTracked !== true && !tracked.has(trimTrailingSeparators(suggestedRoot));
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-2xl text-sm text-slate-600", children: "Guard re-checks these folders in the background when files or threat intel change, including files you have not committed. Checks run on this device and use no credits." }),
      canAddSuggested && state.worktrees.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: handleAdd, disabled: busyKey !== null, children: [
        "Add ",
        folderName(suggestedRoot)
      ] })
    ] }),
    loadError && /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorNotice, { message: loadError, onRetry: () => void refresh() }),
    actionError && /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorNotice, { message: actionError }),
    state.worktrees.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No workspaces assessed yet",
        body: canAddSuggested ? `Add ${folderName(suggestedRoot)} and Guard will keep its dependencies checked as you work.` : "Choose a project folder and Guard will keep its dependencies checked as you work.",
        action: canAddSuggested ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: handleAdd, disabled: busyKey !== null, children: [
          "Assess ",
          folderName(suggestedRoot)
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: props.onChooseFolder, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFolderOpen, { className: "h-4 w-4", "aria-hidden": "true" }),
          "Choose folder"
        ] })
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "divide-y divide-slate-100 overflow-hidden rounded-2xl border border-slate-200 bg-white", children: state.worktrees.map((worktree) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorktreeRow,
      {
        worktree,
        newestRun: state.latestRuns.find((run) => sameWorktree(worktree, run)),
        assessment: state.assessments.find((item) => sameWorktree(worktree, item)),
        busyKey,
        onAction: handleAction
      },
      `${worktree.codebaseKey}:${worktree.worktreeKey}`
    )) })
  ] });
}
function WorktreeRow(props) {
  const { worktree, assessment } = props;
  const status = worktreeStatus(worktree, props.newestRun, assessment);
  const active = props.newestRun?.state === "running" || props.newestRun?.state === "queued";
  const reasons = (assessment?.reasons ?? []).map((reason) => COVERAGE_REASONS[reason] ?? "Part of the workspace was not checked.");
  const notRun = (assessment?.notRun ?? []).map((name) => `${DETECTOR_LABELS[name] ?? name} is not part of this check yet.`);
  const pauseAction = worktree.paused ? "resume" : "pause";
  const headingId = `worktree-${worktree.worktreeKey.slice(0, 16)}`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "space-y-4 px-4 py-4 sm:px-5", "aria-labelledby": headingId, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 basis-56", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id: headingId, className: "text-base font-semibold text-brand-dark", children: folderName(worktree.root) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: status.tone, children: status.label })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 truncate font-mono text-xs text-slate-500", title: worktree.root, children: worktree.root }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: status.detail ?? (worktree.lastScanAtMs ? `Checked ${formatRelativeTime(new Date(worktree.lastScanAtMs).toISOString())}` : "Waiting for the first check.") })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 flex-wrap gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          ActionButton,
          {
            variant: "outline",
            onClick: () => props.onAction("run", worktree),
            disabled: worktree.paused || active || props.busyKey !== null,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `h-4 w-4 ${active ? "animate-spin motion-reduce:animate-none" : ""}`, "aria-hidden": "true" }),
              "Assess now"
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: () => props.onAction(pauseAction, worktree), disabled: props.busyKey !== null, children: worktree.paused ? "Resume" : "Pause" })
      ] })
    ] }),
    (reasons.length > 0 || notRun.length > 0) && /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1 text-sm text-slate-600", children: [...reasons, ...notRun].map((reason) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600", "aria-hidden": "true" }),
      reason
    ] }, reason)) }),
    assessment && /* @__PURE__ */ jsxRuntimeExports.jsx(FindingsTable, { findings: assessment.findings })
  ] });
}
function FindingsTable({ findings }) {
  if (findings.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: "No dependency findings in the checked files." });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-xl border border-slate-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full text-left text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { className: "sr-only", children: "Dependency findings" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Package" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Installed" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Fixed in" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Decision" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Severity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Advisories" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: findings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Package", wide: true, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: finding.packageName }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 text-xs text-slate-500", children: finding.ecosystem })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Installed", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Mono, { value: finding.packageVersion }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Fixed in", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Mono, { value: finding.fixVersion, fallback: "No fix yet" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Decision", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(finding.decision), children: DECISION_LABELS[finding.decision] ?? finding.decision }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Severity", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "capitalize text-slate-700", children: finding.severity }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Advisories", wide: true, children: finding.advisoryIds.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.advisoryIds.join(", ") }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: "None listed" }) })
    ] }, finding.findingId)) })
  ] }) });
}
function Cell(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: `min-w-0 md:px-3 md:py-2.5 ${props.wide ? "col-span-2 md:col-span-1" : ""}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs font-semibold text-slate-500 md:hidden", children: props.label }),
    props.children
  ] });
}
function Mono({ value, fallback = "Unknown" }) {
  return value ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs text-slate-700", children: value }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: fallback });
}
function ErrorNotice(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 rounded-xl border border-red-200 bg-red-50/60 px-4 py-3", role: "alert", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-red-800", children: props.message }),
    props.onRetry && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onRetry, children: "Retry" })
  ] });
}
export {
  WorkspaceFindingsWorkspace,
  WorktreeRow,
  worktreeStatus
};
