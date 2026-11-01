import { j as jsxRuntimeExports, T as Tag, dQ as fetchGuardApi, r as reactExports, ad as HiMiniExclamationTriangle, A as ActionButton, b as formatRelativeTime, v as HiMiniCheckCircle, az as HiMiniWrenchScrewdriver, aJ as HiMiniEye, a7 as EmptyState, f6 as HiMiniFolderOpen, i as HiMiniArrowPath } from "../guard-dashboard.js";
import { c as createLatestRefresh, r as runWorkspaceAction, a as addWorkspaceForAssessment, s as sameWorktree, w as worktreeStatus, f as fetchWorkspaceFindings } from "./workspace-findings-status-2ROeUFpB.js";
function CarriedNote({ finding }) {
  if (!finding.carried) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block text-xs text-slate-500", children: "Not rechecked in the latest scan" });
}
function evidenceSource(finding) {
  if (finding.advisoryIds.length > 0) return "Advisory match";
  return finding.kind === "supply_chain" ? "Package policy" : "Rule match";
}
const VALIDATION_SUFFIX = { confirmed: ", confirmed", unvalidated: ", not confirmed" };
function EvidenceNote({ finding }) {
  const source = evidenceSource(finding);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-1 block text-xs text-slate-500", children: [
    source,
    source === "Package policy" ? "" : VALIDATION_SUFFIX[finding.validation] ?? ""
  ] });
}
function Cell(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: `min-w-0 md:px-3 md:py-2.5 ${props.wide ? "col-span-2 md:col-span-1" : ""}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs font-semibold text-slate-500 md:hidden", children: props.label }),
    props.children
  ] });
}
function secretLines(finding) {
  const lines = finding.lines.length > 0 ? finding.lines : finding.line !== null ? [finding.line] : [];
  return lines.length > 0 ? `:${lines.join(", ")}` : "";
}
function SecretFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-xl border border-slate-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full text-left text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { className: "sr-only", children: "Possible secrets in files" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Rule" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Location" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Severity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Status" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: findings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Rule", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.ruleIds.join(", ") }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Location", wide: true, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "break-all font-mono text-xs text-slate-700", children: [
        finding.path,
        secretLines(finding)
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Severity", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "capitalize text-slate-700", children: finding.severity }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Status", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "amber", children: "Warning" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceNote, { finding }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(CarriedNote, { finding })
      ] })
    ] }, finding.findingId)) })
  ] }) });
}
const CONFIDENCE_LABELS = { strong: "Strong signal", likely: "Likely", weak: "Weak signal" };
function RuleFindingsTable({ findings, caption, subjectLabel, subject, check }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-xl border border-slate-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full text-left text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { className: "sr-only", children: caption }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: subjectLabel }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Check" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Severity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Status" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: findings.map((finding) => {
      const matched = check(finding);
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: subjectLabel, wide: true, children: subject(finding) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Check", wide: true, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block font-semibold text-brand-dark", children: matched?.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block text-xs text-slate-600", children: matched?.reason }),
          matched?.falsePositiveHint && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block text-xs text-slate-500", children: matched.falsePositiveHint }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-1 block break-all font-mono text-xs text-slate-500", children: finding.ruleIds.join(", ") })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Severity", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "capitalize text-slate-700", children: finding.severity }),
          matched && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs text-slate-500", children: CONFIDENCE_LABELS[matched.confidence] ?? matched.confidence })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Status", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "amber", children: "Warning" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceNote, { finding }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(CarriedNote, { finding })
        ] })
      ] }, finding.findingId);
    }) })
  ] }) });
}
function SkillFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "Agent skills with risky instructions",
      subjectLabel: "Skill",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.path }),
      check: (finding) => finding.skill
    }
  );
}
function McpFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "MCP servers with risky launch settings",
      subjectLabel: "Server",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-semibold text-slate-800", children: finding.mcp?.server }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-mono text-xs text-slate-500", children: finding.path })
      ] }),
      check: (finding) => finding.mcp
    }
  );
}
function HookFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "Project hooks with risky commands",
      subjectLabel: "Hook",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-semibold text-slate-800", children: finding.hook?.event }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-mono text-xs text-slate-500", children: finding.path })
      ] }),
      check: (finding) => finding.hook
    }
  );
}
function PluginFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "Agent plugins with risky hooks or MCP servers",
      subjectLabel: "Plugin",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-semibold text-slate-800", children: finding.hook ? `${finding.hook.event} hook` : `${finding.mcp?.server} MCP server` }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block break-all font-mono text-xs text-slate-500", children: finding.path })
      ] }),
      check: (finding) => finding.hook ?? finding.mcp
    }
  );
}
function WorkflowFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "GitHub Actions workflows with risky settings",
      subjectLabel: "Workflow",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.path }),
      check: (finding) => finding.workflow
    }
  );
}
function EditorTaskFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "Editor tasks and dev containers that run commands on their own",
      subjectLabel: "File",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.path }),
      check: (finding) => finding.editorTask
    }
  );
}
function InstructionFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    RuleFindingsTable,
    {
      findings,
      caption: "Agent instruction files that tell an agent to drop its safeguards",
      subjectLabel: "File",
      subject: (finding) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.path }),
      check: (finding) => finding.instruction
    }
  );
}
const RUNTIME_VERDICTS = {
  affected: { label: "Affected version", tone: "attention" },
  restart_required: { label: "Restart needed", tone: "amber" },
  fix_unverified: { label: "Fix not verified", tone: "amber" }
};
function RuntimeFindingsTable({ findings }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-xl border border-slate-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full text-left text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { className: "sr-only", children: "Runtimes launched by this workspace's tools that match an advisory" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Runtime" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Executable" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Status" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Severity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Advisories" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: findings.map((finding) => {
      const verdict = RUNTIME_VERDICTS[finding.ruleIds[0] ?? ""] ?? { label: "Matches an advisory", tone: "amber" };
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Runtime", wide: true, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold capitalize text-brand-dark", children: finding.runtime?.family }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 font-mono text-xs text-slate-500", children: finding.runtime?.version ?? "version unknown" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Executable", wide: true, children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.path }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Status", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex flex-wrap gap-1", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: verdict.tone, children: verdict.label }),
            finding.runtime?.knownExploited && /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "red", children: "Known exploited" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceNote, { finding }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(CarriedNote, { finding })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Severity", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "capitalize text-slate-700", children: finding.severity }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Advisories", wide: true, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.advisoryIds.join(", ") }),
          finding.runtime?.title && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block text-xs text-slate-500", children: finding.runtime.title })
        ] })
      ] }, finding.findingId);
    }) })
  ] }) });
}
const EXPORT_PREVIEW_PATH = "/v1/supply-chain/workspace-export-preview";
const MAX_EXPORT_PREVIEW_PATHS = 200;
const MAX_EXPORT_PREVIEW_PATH_LENGTH = 4096;
class ExportPreviewError extends Error {
  code;
  constructor(code) {
    super(exportPreviewErrorMessage(code));
    this.name = "ExportPreviewError";
    this.code = code;
  }
}
const STATUSES = /* @__PURE__ */ new Set(["ready", "empty", "blocked"]);
function record$1(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function text$1(value) {
  return typeof value === "string" && value.trim() ? value : null;
}
function count(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}
function normalizeFile(value) {
  const item = record$1(value);
  const path = text$1(item.path);
  const bytes = count(item.bytes);
  const exportBytes = count(item.export_bytes);
  const redactions = count(item.redactions);
  return path && bytes !== null && exportBytes !== null && redactions !== null ? { path, bytes, exportBytes, redactions } : null;
}
function normalizeExportPreview(value) {
  const item = record$1(value);
  const status = text$1(item.status);
  const bundleDigest = text$1(item.bundle_digest);
  if (!status || !STATUSES.has(status) || !bundleDigest || !Array.isArray(item.files) || !Array.isArray(item.excluded)) {
    return null;
  }
  const files = item.files.map(normalizeFile).filter((entry) => entry !== null);
  const excluded = item.excluded.flatMap((entry) => {
    const exclusion = record$1(entry);
    const path = typeof exclusion.path === "string" ? exclusion.path : null;
    const reason = text$1(exclusion.reason);
    return path !== null && reason ? [{ path, reason }] : [];
  });
  const limits = record$1(item.limits);
  return {
    status,
    files,
    excluded,
    // Totals come from the files kept here, so a dropped malformed entry can
    // never leave the summary larger than the list it sits above.
    exportBytes: files.reduce((total, file) => total + file.exportBytes, 0),
    redactions: files.reduce((total, file) => total + file.redactions, 0),
    bundleDigest,
    maxFileBytes: count(limits.max_file_bytes),
    maxTotalBytes: count(limits.max_total_bytes)
  };
}
function parseExportPaths(input) {
  const seen = /* @__PURE__ */ new Set();
  for (const line of input.split(/\r?\n/)) {
    const path = line.trim();
    if (path) seen.add(path);
  }
  return [...seen];
}
async function previewWorkspaceExport(worktree, paths) {
  if (paths.length === 0) throw new ExportPreviewError("no_paths");
  if (paths.length > MAX_EXPORT_PREVIEW_PATHS) throw new ExportPreviewError("invalid_paths");
  if (paths.some((path) => path.length > MAX_EXPORT_PREVIEW_PATH_LENGTH)) throw new ExportPreviewError("path_too_long");
  const response = await fetchGuardApi(EXPORT_PREVIEW_PATH, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ codebase_key: worktree.codebaseKey, worktree_key: worktree.worktreeKey, paths })
  });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new ExportPreviewError(text$1(record$1(body).error) ?? "workspace_export_preview_failed");
  const preview = normalizeExportPreview(body);
  if (preview === null) throw new ExportPreviewError("workspace_export_preview_failed");
  return preview;
}
const EXCLUSION_REASONS = {
  invalid_path: "Not a path inside this workspace.",
  sensitive: "Credential or key file. Guard never exports these.",
  policy_directory: "Inside a folder Guard never exports, such as .git or node_modules.",
  oversize: "Larger than one file may be.",
  byte_budget: "Past the total size Guard reads for one preview. List fewer files.",
  not_text: "Not a text file.",
  not_found: "No file at this path.",
  not_a_file: "A folder or other entry, not a file.",
  symlink: "Reached through a symbolic link, which Guard does not follow.",
  special: "A device, pipe or socket, not a file.",
  unreadable: "Could not be read.",
  unstable: "Changed while Guard was reading it.",
  redaction_failed: "Guard could not confirm this file is free of secrets after redaction, so it blocks the export."
};
function exclusionMessage(reason) {
  return EXCLUSION_REASONS[reason] ?? "Left out of the export.";
}
const ERROR_MESSAGES$1 = {
  no_paths: "Add at least one file path, one per line.",
  invalid_paths: `List up to ${MAX_EXPORT_PREVIEW_PATHS} file paths, one per line.`,
  path_too_long: `Each file path must be at most ${MAX_EXPORT_PREVIEW_PATH_LENGTH} characters.`,
  worktree_not_found: "This workspace is no longer tracked. Refresh the list.",
  worktree_moved: "This folder now belongs to a different workspace. Refresh the list, then preview again.",
  workspace_export_preview_root_missing: "Guard cannot find this workspace folder. Check that it still exists.",
  workspace_export_preview_root_unreadable: "Guard cannot read this workspace folder.",
  workspace_export_preview_too_many_paths: `List up to ${MAX_EXPORT_PREVIEW_PATHS} file paths, one per line.`,
  workspace_export_preview_native_unavailable: "The Guard runtime needed to read files is unavailable. Repair Guard, then try again."
};
function exportPreviewErrorMessage(code) {
  return ERROR_MESSAGES$1[code] ?? "Guard could not build the preview. Check that Guard is running, then retry.";
}
function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}
const FIX_PROPOSALS_PATH = "/v1/supply-chain/workspace-fix-proposals";
class FixRequestError extends Error {
  code;
  reason;
  /** Files a refused prepare left unchanged, so the review can still list them. */
  skipped;
  truncated;
  constructor(code, reason, skipped = [], truncated = false) {
    super(fixErrorMessage(code, reason));
    this.name = "FixRequestError";
    this.code = code;
    this.reason = reason;
    this.skipped = skipped;
    this.truncated = truncated;
  }
}
const STATES = /* @__PURE__ */ new Set(["prepared", "applied", "verified_fixed", "still_present", "stale"]);
function record(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value : {};
}
function text(value) {
  return typeof value === "string" && value.trim() ? value : null;
}
function time(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}
function list(value) {
  return Array.isArray(value) ? value : [];
}
function normalizeEdit(value) {
  const item = record(value);
  const section = text(item.section);
  const fromSpec = text(item.from_spec);
  const toSpec = text(item.to_spec);
  return section && fromSpec && toSpec ? { section, fromSpec, toSpec } : null;
}
function normalizeFixProposal(value) {
  const item = record(value);
  const proposalId = text(item.proposal_id);
  const codebaseKey = text(item.codebase_key);
  const worktreeKey = text(item.worktree_key);
  const findingId = text(item.finding_id);
  const packageName = text(item.package_name);
  const fixVersion = text(item.fix_version);
  const manifestPath = text(item.manifest_path);
  const state = text(item.state);
  const createdAtMs = time(item.created_at_ms);
  const edits = list(item.edits).map(normalizeEdit).filter((entry) => entry !== null);
  if (!proposalId || !codebaseKey || !worktreeKey || !findingId || !packageName || !fixVersion || !manifestPath || !state || !STATES.has(state) || createdAtMs === null || edits.length === 0) {
    return null;
  }
  return {
    proposalId,
    codebaseKey,
    worktreeKey,
    findingId,
    packageName,
    fixVersion,
    advisoryIds: list(item.advisory_ids).filter((entry) => typeof entry === "string"),
    manifestPath,
    edits,
    diff: state === "prepared" ? text(item.diff) : null,
    state,
    createdAtMs,
    appliedAtMs: time(item.applied_at_ms),
    verifiedAtMs: time(item.verified_at_ms)
  };
}
function normalizeSkipped(value) {
  return list(value).flatMap((entry) => {
    const item = record(entry);
    const manifestPath = text(item.manifest_path);
    const reason = text(item.reason);
    return manifestPath && reason ? [{ manifestPath, reason }] : [];
  });
}
function normalizeProposals(value) {
  return list(value).map(normalizeFixProposal).filter((entry) => entry !== null);
}
async function request(path, init) {
  const response = await fetchGuardApi(path, init);
  const body = await response.json().catch(() => null);
  if (!response.ok) {
    const detail = record(body);
    throw new FixRequestError(
      text(detail.error) ?? "workspace_fix_failed",
      text(detail.reason),
      normalizeSkipped(detail.skipped),
      detail.truncated === true
    );
  }
  return body;
}
function postJson(path, payload) {
  return request(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
}
async function fetchFixProposals(worktree, signal) {
  const query = new URLSearchParams({ codebase_key: worktree.codebaseKey, worktree_key: worktree.worktreeKey });
  return normalizeProposals(record(await request(`${FIX_PROPOSALS_PATH}?${query}`, { signal })).proposals);
}
async function prepareFix(worktree, findingId) {
  const body = record(
    await postJson(FIX_PROPOSALS_PATH, {
      codebase_key: worktree.codebaseKey,
      worktree_key: worktree.worktreeKey,
      finding_id: findingId
    })
  );
  return {
    proposals: normalizeProposals(body.proposals),
    skipped: normalizeSkipped(body.skipped),
    truncated: body.truncated === true
  };
}
async function applyFix(proposalId) {
  const body = record(await postJson(`${FIX_PROPOSALS_PATH}/${encodeURIComponent(proposalId)}/apply`, {}));
  const proposal = normalizeFixProposal(body.proposal);
  if (proposal === null) throw new FixRequestError("workspace_fix_failed", null);
  return {
    proposal,
    lockfiles: list(body.lockfiles).filter((entry) => typeof entry === "string"),
    verificationQueued: body.verification_queued === true
  };
}
const SKIP_REASONS = {
  spec_workspace_protocol: "It points at another package in this workspace.",
  spec_npm_alias: "It installs the package under another name.",
  spec_git_or_url: "It installs from a Git repository or URL.",
  spec_local_path: "It installs from a local folder or file.",
  spec_dist_tag: "It follows a release tag rather than a version.",
  spec_not_plain_semver: "Its version range is too complex to change safely.",
  spec_not_a_string: "Its entry is not a version string.",
  declared_range_already_covers_fix: "Its range already allows the fixed version. Update the lockfile instead.",
  manifest_duplicate_section: "The file declares the same section twice.",
  manifest_duplicate_declaration: "The file declares the package twice.",
  manifest_invalid_json: "The file is not valid JSON.",
  manifest_too_large: "The file is too large to edit safely.",
  manifest_too_deep: "The file is nested too deeply to edit safely.",
  manifest_is_symlink: "The file is a symbolic link.",
  manifest_not_regular: "The path is not a regular file.",
  manifest_unreadable: "The file could not be read.",
  diff_too_large: "The change would be too large to review."
};
function skippedManifestMessage(reason) {
  return SKIP_REASONS[reason] ?? "Guard could not change this file safely.";
}
const UNSUPPORTED_REASONS = {
  unsupported_source: "Guard prepares fixes for dependency findings only.",
  unsupported_ecosystem: "Guard prepares fixes for npm dependencies only.",
  no_fix_version: "No fixed version has been published yet.",
  finding_incomplete: "This finding is missing the details a fix needs. Run Assess now, then try again.",
  transitive_dependency: "No package.json lists this package directly. It comes in through another dependency, so update that dependency instead.",
  manifest_scan_incomplete: "Guard could not read every package.json in this workspace, so it prepared no change."
};
const ERROR_MESSAGES = {
  no_assessed_run: "Guard has not finished checking this workspace yet. Wait for the check, then try again.",
  finding_not_found: "This finding changed since the last check. Refresh to see the current findings.",
  worktree_not_found: "This workspace is no longer tracked. Refresh the list.",
  worktree_paused: "Resume this workspace before applying a fix.",
  worktree_unavailable: "Guard cannot reach this workspace folder. Check that it still exists.",
  fix_proposal_not_found: "This fix is no longer available. Prepare it again.",
  fix_proposal_not_prepared: "This fix was already applied or replaced.",
  fix_proposal_stale: "The file changed after you reviewed this fix, so Guard wrote nothing. Prepare the fix again.",
  fix_apply_unsupported: "Guard cannot apply fixes on this system yet, so it wrote nothing. Make the change shown above yourself.",
  fix_native_unavailable: "The Guard runtime needed to edit files is unavailable. Repair Guard, then try again.",
  fix_apply_failed: "Guard could not write the change. The file was left as it was."
};
function fixErrorMessage(code, reason) {
  if (code === "fix_unsupported") {
    if (reason && UNSUPPORTED_REASONS[reason]) return UNSUPPORTED_REASONS[reason];
    if (reason && SKIP_REASONS[reason]) return `Guard prepared no change. ${SKIP_REASONS[reason]}`;
    return "Guard cannot prepare a fix for this finding.";
  }
  return ERROR_MESSAGES[code] ?? "Guard could not prepare or apply this fix. Check that Guard is running, then retry.";
}
function canPrepareFix(finding) {
  return finding.ecosystem === "npm" && finding.fixVersion !== null && finding.packageName !== null;
}
const STATE_TAGS = {
  applied: { label: "Waiting for re-check", tone: "attention" },
  still_present: { label: "Still found", tone: "red" },
  verified_fixed: { label: "Fixed", tone: "green" },
  stale: { label: "File changed", tone: "slate" }
};
function message(error) {
  return error instanceof Error ? error.message : String(error);
}
function useWorktreeFixes(worktree, assessmentRunId) {
  const [proposals, setProposals] = reactExports.useState([]);
  const [reviewing, setReviewing] = reactExports.useState(null);
  const [prepared, setPrepared] = reactExports.useState(null);
  const [busy, setBusy] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  const [loaded, setLoaded] = reactExports.useState(false);
  const [loadError, setLoadError] = reactExports.useState(null);
  const [applyUnsupported, setApplyUnsupported] = reactExports.useState(false);
  const [notice, setNotice] = reactExports.useState(null);
  const mounted = reactExports.useRef(true);
  const latestReload = reactExports.useRef(0);
  const { codebaseKey, worktreeKey } = worktree;
  const reload = reactExports.useCallback(async (signal) => {
    latestReload.current += 1;
    const request2 = latestReload.current;
    try {
      const next = await fetchFixProposals({ codebaseKey, worktreeKey }, signal);
      if (!mounted.current || request2 !== latestReload.current) return null;
      setProposals(next);
      setLoaded(true);
      setLoadError(null);
      return next;
    } catch (reason) {
      if (mounted.current && request2 === latestReload.current && !signal?.aborted) setLoadError(message(reason));
      throw reason;
    }
  }, [codebaseKey, worktreeKey]);
  reactExports.useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    reload(controller.signal).catch(() => void 0);
    return () => {
      mounted.current = false;
      controller.abort();
    };
  }, [reload, assessmentRunId]);
  const run = reactExports.useCallback(async (key, operation) => {
    setBusy(key);
    setError(null);
    setNotice(null);
    try {
      await operation();
    } catch (reason) {
      if (!mounted.current) return;
      setError(message(reason));
      if (reason instanceof FixRequestError && reason.code === "fix_apply_unsupported") setApplyUnsupported(true);
    } finally {
      if (mounted.current) setBusy(null);
    }
  }, []);
  const prepare = reactExports.useCallback((finding) => {
    setReviewing(finding.findingId);
    setPrepared(null);
    void run(`prepare:${finding.findingId}`, async () => {
      let result;
      try {
        result = await prepareFix({ codebaseKey, worktreeKey }, finding.findingId);
      } catch (reason) {
        if (mounted.current && reason instanceof FixRequestError && (reason.skipped.length > 0 || reason.truncated)) {
          setPrepared({ proposals: [], skipped: reason.skipped, truncated: reason.truncated });
        }
        throw reason;
      }
      if (!mounted.current) return;
      setPrepared(result);
      await reload();
    });
  }, [codebaseKey, worktreeKey, reload, run]);
  const apply = reactExports.useCallback((proposal) => {
    void run(`apply:${proposal.proposalId}`, async () => {
      let result = null;
      try {
        result = await applyFix(proposal.proposalId);
      } finally {
        const next = await reload().catch(() => null);
        if (result && mounted.current) {
          setNotice(appliedNotice(proposal, result));
          const remaining = next === null || next.some(
            (item) => item.findingId === proposal.findingId && item.state === "prepared"
          );
          if (!remaining) {
            setReviewing(null);
            setPrepared(null);
          }
        }
      }
    });
  }, [reload, run]);
  const review = reactExports.useCallback((findingId) => {
    setReviewing(findingId);
    setPrepared(null);
    setError(null);
  }, []);
  const close = reactExports.useCallback(() => {
    setReviewing(null);
    setPrepared(null);
    setError(null);
  }, []);
  const retry = reactExports.useCallback(() => {
    void reload().catch(() => void 0);
  }, [reload]);
  return {
    proposals,
    reviewing,
    prepared,
    busy,
    error,
    loaded,
    loadError,
    applyUnsupported,
    notice,
    prepare,
    review,
    close,
    apply,
    retry
  };
}
function appliedNotice(proposal, result) {
  const lockfiles = result.lockfiles.length > 0 ? result.lockfiles.join(", ") : "your lockfile";
  const changed = `Guard changed ${proposal.manifestPath}. Update ${lockfiles} with your package manager. `;
  if (!result.verificationQueued) {
    return changed + "Guard could not schedule a check, so run Assess now once the lockfile is updated. It marks this fixed only when a complete check no longer finds it.";
  }
  return changed + "Guard checks again after each change and marks this fixed only when a complete check no longer finds it.";
}
function currentFor(proposals, findingId) {
  const own = proposals.filter((proposal) => proposal.findingId === findingId);
  return own.find((proposal) => proposal.state === "prepared") ?? own[0];
}
function FixCell(props) {
  const { finding, fixes } = props;
  const proposal = currentFor(fixes.proposals, finding.findingId);
  const preparing = fixes.busy === `prepare:${finding.findingId}`;
  const blocked = fixes.busy !== null || fixes.loadError !== null || !fixes.loaded;
  if (proposal?.state === "prepared") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: () => fixes.review(finding.findingId), disabled: fixes.busy !== null, children: "Review fix" });
  }
  if (proposal && proposal.state !== "stale" && proposal.state !== "verified_fixed") {
    const tag = STATE_TAGS[proposal.state];
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex flex-col items-start gap-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: tag.tone, children: tag.label }),
      proposal.state === "still_present" && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-500", children: "Update the lockfile, then Guard checks again." })
    ] });
  }
  if (!canPrepareFix(finding)) return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: "Manual update" });
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", className: "gap-1.5", onClick: () => fixes.prepare(finding), disabled: blocked, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "h-4 w-4", "aria-hidden": "true" }),
    preparing ? "Preparing…" : proposal ? "Prepare again" : "Prepare fix"
  ] });
}
function FixReview(props) {
  const { fixes } = props;
  const heading = reactExports.useRef(null);
  reactExports.useEffect(() => {
    if (fixes.reviewing === null) return;
    heading.current?.focus({ preventScroll: true });
    const reduced = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    heading.current?.scrollIntoView({ block: "nearest", behavior: reduced ? "auto" : "smooth" });
  }, [fixes.reviewing]);
  if (fixes.reviewing === null) return null;
  const finding = props.findings.find((item) => item.findingId === fixes.reviewing);
  const pending = finding ? fixes.proposals.filter((proposal) => proposal.findingId === fixes.reviewing && proposal.state === "prepared") : [];
  const preparing = fixes.busy === `prepare:${fixes.reviewing}`;
  const headingId = `fix-review-${fixes.reviewing.slice(0, 16)}`;
  const skipped = fixes.prepared?.skipped ?? [];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": headingId, className: "space-y-4 rounded-xl border border-slate-200 bg-surface-1/60 px-4 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 basis-64", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("h4", { id: headingId, ref: heading, tabIndex: -1, className: "text-sm font-semibold text-brand-dark focus:outline-none", children: [
          "Review fix for ",
          finding?.packageName ?? pending[0]?.packageName ?? "this package"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-[68ch] text-sm text-slate-600", children: "Guard changes only the version range shown below. Nothing is written until you apply it, and an edit made to the file after this review cancels the change." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: fixes.close, disabled: fixes.busy !== null && !preparing, children: "Close" })
    ] }),
    preparing && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-24 w-full rounded-xl", "aria-label": "Preparing fix" }),
    fixes.error && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "error", text: fixes.error }),
    !finding && !preparing && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "success", text: "The latest check no longer lists this finding, so there is nothing to apply." }),
    pending.map((proposal) => /* @__PURE__ */ jsxRuntimeExports.jsx(ProposalReview, { proposal, fixes }, proposal.proposalId)),
    skipped.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Left unchanged" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1 text-sm text-slate-600", children: skipped.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs text-slate-700", children: item.manifestPath }),
        " ",
        skippedManifestMessage(item.reason)
      ] }, `${item.manifestPath}:${item.reason}`)) })
    ] }),
    fixes.prepared?.truncated && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "warning", text: "Guard stopped before reading every package.json, so other files may still list this package." })
  ] });
}
function ProposalReview(props) {
  const { proposal, fixes } = props;
  const applying = fixes.busy === `apply:${proposal.proposalId}`;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1 text-sm text-slate-700", children: proposal.edits.map((edit) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: proposal.manifestPath }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-slate-500", children: [
        " · ",
        edit.section,
        ": "
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: edit.fromSpec }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: " to " }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs font-semibold", children: edit.toSpec })
    ] }, `${edit.section}:${edit.fromSpec}`)) }),
    proposal.diff && /* @__PURE__ */ jsxRuntimeExports.jsx(DiffBlock, { diff: proposal.diff, label: `Proposed change to ${proposal.manifestPath}` }),
    !fixes.applyUnsupported && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: () => fixes.apply(proposal), disabled: fixes.busy !== null, children: applying ? "Applying…" : `Apply to ${proposal.manifestPath}` })
  ] });
}
function lineClass(line) {
  if (line.startsWith("+") && !line.startsWith("+++")) return "bg-emerald-50 text-emerald-900";
  if (line.startsWith("-") && !line.startsWith("---")) return "bg-red-50 text-red-900";
  if (line.startsWith("@@")) return "text-slate-500";
  return "text-slate-700";
}
function DiffBlock(props) {
  const lines = props.diff.replace(/\n$/, "").split("\n");
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "pre",
    {
      "aria-label": props.label,
      tabIndex: 0,
      className: "max-h-72 overflow-auto rounded-lg border border-slate-200 bg-white py-2 font-mono text-xs leading-5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40",
      children: lines.map((line, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `block whitespace-pre px-3 ${lineClass(line)}`, children: line || " " }, index))
    }
  );
}
const HISTORY_DETAIL = {
  applied: "Waiting for a complete check.",
  still_present: "A complete check still found it. Update the lockfile, then Guard checks again.",
  verified_fixed: "Confirmed by a complete check"
};
function FixHistory(props) {
  const listed = new Set(props.findings.map((finding) => finding.findingId));
  const settled = props.fixes.proposals.filter(
    (proposal) => proposal.state !== "prepared" && proposal.state !== "stale" && !listed.has(proposal.findingId)
  );
  if (settled.length === 0 && !props.fixes.notice) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
    props.fixes.notice && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "success", text: props.fixes.notice }),
    settled.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "divide-y divide-slate-100 border-y border-slate-100 text-sm", children: settled.map((proposal) => {
      const tag = STATE_TAGS[proposal.state];
      const when = proposal.state === "verified_fixed" && proposal.verifiedAtMs ? ` ${formatRelativeTime(new Date(proposal.verifiedAtMs).toISOString())}.` : "";
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-wrap items-center justify-between gap-2 py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: proposal.packageName }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-600", children: " to " }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs text-slate-700", children: proposal.fixVersion }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-600", children: " in " }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs text-slate-700", children: proposal.manifestPath }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "block text-xs text-slate-500", children: [
            HISTORY_DETAIL[proposal.state],
            when
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: tag.tone, children: tag.label })
      ] }, proposal.proposalId);
    }) })
  ] });
}
function FixLoadError(props) {
  if (props.fixes.loadError === null) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 rounded-lg border border-red-200 bg-red-50/60 px-3 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex gap-2 text-sm text-red-800", role: "alert", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-4 w-4 shrink-0", "aria-hidden": "true" }),
      "Guard could not load the fixes prepared for this workspace, so Prepare stays off until they load. Check that Guard is running, then retry."
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.fixes.retry, children: "Retry" })
  ] });
}
function FixNotice(props) {
  const styles = {
    error: "border-red-200 bg-red-50/60 text-red-800",
    warning: "border-amber-200 bg-amber-50/60 text-amber-900",
    success: "border-emerald-200 bg-emerald-50/60 text-emerald-900"
  }[props.tone];
  const Icon = props.tone === "success" ? HiMiniCheckCircle : HiMiniExclamationTriangle;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: `flex gap-2 rounded-lg border px-3 py-2 text-sm ${styles}`, role: props.tone === "error" ? "alert" : "status", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "mt-0.5 h-4 w-4 shrink-0", "aria-hidden": "true" }),
    props.text
  ] });
}
const RESULT_LABELS = {
  ready: "Ready",
  empty: "Nothing to export",
  blocked: "Blocked"
};
function suggestedExportPaths(findings) {
  const paths = /* @__PURE__ */ new Set();
  for (const finding of findings) {
    if (finding.kind !== "runtime" && finding.path) paths.add(finding.path);
  }
  return [...paths];
}
function ExportPreviewView(props) {
  const id = reactExports.useId();
  const headingId = `${id}-heading`;
  const fieldId = `${id}-paths`;
  const hintId = `${id}-hint`;
  const { preview } = props;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-labelledby": headingId, className: "space-y-4 rounded-xl border border-slate-200 bg-surface-1/60 px-4 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 basis-64", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { id: headingId, className: "text-sm font-semibold text-brand-dark", children: "Preview a source export" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-[68ch] text-sm text-slate-600", children: "See what sharing these files would carry before anything leaves this device. Guard leaves out credential files and folders such as .git, and replaces each secret it finds with [REDACTED]. A preview sends nothing and never changes your files." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: props.onClose, disabled: props.busy, children: "Close" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("label", { htmlFor: fieldId, className: "block text-sm font-semibold text-brand-dark", children: "Files to include" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { id: hintId, className: "text-xs text-slate-600", children: "One path per line, relative to the workspace folder. Starts with the files this check points at." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "textarea",
        {
          id: fieldId,
          "aria-describedby": hintId,
          value: props.input,
          onChange: (event) => props.onInput(event.target.value),
          rows: 4,
          spellCheck: false,
          autoCapitalize: "off",
          autoCorrect: "off",
          placeholder: "src/app.py\npackage.json",
          className: "w-full rounded-xl border border-slate-200 bg-white px-3 py-2.5 font-mono text-xs text-slate-800 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: props.onPreview, disabled: props.busy, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniEye, { className: "h-4 w-4", "aria-hidden": "true" }),
        props.busy ? "Reading files…" : preview ? "Preview again" : "Preview export"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "aria-live": "polite", className: "space-y-4", children: [
      props.error && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "error", text: props.error }),
      preview && /* @__PURE__ */ jsxRuntimeExports.jsx(PreviewResult, { preview, edited: props.edited })
    ] })
  ] });
}
function PreviewResult({ preview, edited }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", "data-testid": "export-preview-result", children: [
    edited && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "warning", text: "The list changed after this preview. Preview again to check it." }),
    preview.status === "blocked" && /* @__PURE__ */ jsxRuntimeExports.jsx(
      FixNotice,
      {
        tone: "error",
        text: "Guard could not confirm the file marked below is free of secrets after redaction, so this selection cannot be exported. Remove any secret from that file, or take it off the list."
      }
    ),
    preview.status === "empty" && /* @__PURE__ */ jsxRuntimeExports.jsx(FixNotice, { tone: "warning", text: "None of these files can be exported. Each one is listed below with the reason." }),
    preview.status === "ready" && preview.redactions > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
      FixNotice,
      {
        tone: "success",
        text: `Guard would replace ${preview.redactions === 1 ? "1 secret" : `${preview.redactions} secrets`} with [REDACTED]. Your files stay as they are.`
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-2 gap-x-6 border-y border-slate-200 sm:grid-cols-3 lg:grid-cols-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { label: "Result", value: RESULT_LABELS[preview.status] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { label: "Files", value: String(preview.files.length) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { label: "Export size", value: formatBytes(preview.exportBytes) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { label: "Secrets replaced", value: String(preview.redactions) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Fact, { label: "Destination", value: "None", title: "A preview stays on this device." })
    ] }),
    preview.files.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(IncludedFiles, { preview }),
    preview.excluded.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Left out" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-1 text-sm text-slate-600", children: preview.excluded.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `break-all font-mono text-xs ${item.reason === "redaction_failed" ? "font-semibold text-red-800" : "text-slate-700"}`, children: item.path || "(empty line)" }),
        " ",
        exclusionMessage(item.reason)
      ] }, `${item.path}:${item.reason}`)) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
      "Bundle fingerprint ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono", children: preview.bundleDigest }),
      ". It changes whenever an included file does."
    ] })
  ] });
}
function IncludedFiles({ preview }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-xl border border-slate-200 bg-white", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full text-left text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { className: "sr-only", children: "Files an export would include" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "File" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2 text-right", children: "On disk" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2 text-right", children: "Exported" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2 text-right", children: "Secrets replaced" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: preview.files.map((file) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "grid grid-cols-3 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "col-span-3 min-w-0 md:col-span-1 md:px-3 md:py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block text-xs font-semibold text-slate-500 md:hidden", children: "File" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-800", children: file.path })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "On disk", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Num, { value: formatBytes(file.bytes) }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Exported", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Num, { value: formatBytes(file.exportBytes) }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Secrets replaced", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Num, { value: String(file.redactions) }) })
    ] }, file.path)) })
  ] }) });
}
function Num({ value }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "block font-mono text-xs tabular-nums text-slate-700 md:text-right", children: value });
}
function Fact(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 py-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-xs text-slate-500", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-sm font-semibold tabular-nums text-brand-dark", title: props.title, children: props.value })
  ] });
}
function ExportPreviewPanel(props) {
  const [open, setOpen] = reactExports.useState(false);
  const [input, setInput] = reactExports.useState("");
  const [busy, setBusy] = reactExports.useState(false);
  const [error, setError] = reactExports.useState(null);
  const [preview, setPreview] = reactExports.useState(null);
  const mounted = reactExports.useRef(true);
  const latestInput = reactExports.useRef(input);
  latestInput.current = input;
  reactExports.useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);
  const { worktree, findings } = props;
  const show = reactExports.useCallback(() => {
    setInput(suggestedExportPaths(findings).join("\n"));
    setPreview(null);
    setError(null);
    setOpen(true);
  }, [findings]);
  const run = reactExports.useCallback(async () => {
    const submitted = input;
    setBusy(true);
    setError(null);
    try {
      const result = await previewWorkspaceExport(worktree, parseExportPaths(submitted));
      if (mounted.current) setPreview({ input: submitted, result });
    } catch (caught) {
      if (!mounted.current) return;
      setPreview(null);
      if (latestInput.current !== submitted) return;
      setError(caught instanceof ExportPreviewError ? caught.message : new ExportPreviewError("workspace_export_preview_failed").message);
    } finally {
      if (mounted.current) setBusy(false);
    }
  }, [input, worktree]);
  if (!open) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 border-t border-slate-100 pt-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-[68ch] text-sm text-slate-600", children: "Check what sharing source from this workspace would send, with secrets redacted, before anything leaves this device." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: show, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniEye, { className: "h-4 w-4", "aria-hidden": "true" }),
        "Preview a source export"
      ] })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ExportPreviewView,
    {
      input,
      busy,
      error,
      preview: preview?.result ?? null,
      edited: preview !== null && preview.input !== input,
      onInput: (value) => {
        setInput(value);
        setError(null);
      },
      onPreview: () => void run(),
      onClose: () => setOpen(false)
    }
  );
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
  snapshot_unsupported_dependency_input: "Some lockfiles use a format Guard does not check yet, so those dependencies were not checked.",
  snapshot_undiscovered_dependency_input: "Some dependency files are more than three folders below the workspace root, so those dependencies were not checked.",
  supply_chain_incomplete: "Some dependencies need registry data Guard does not have offline. Use Assess now to look them up.",
  advisory_data_unavailable: "No threat intel is cached on this device yet, so dependencies were listed but not checked for known vulnerabilities.",
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
  editor_task_incomplete: "Some editor task or dev container files could not be fully read, so not every file was checked.",
  instruction_file_incomplete: "Some agent instruction files could not be fully read, so not every file was checked."
};
const DETECTOR_LABELS = {
  secrets: "Secret scanning",
  runtime_identity_v1: "Runtime checking",
  skill_content_v1: "Skill checking",
  mcp_config_v1: "MCP server checking",
  hook_config_v1: "Project hook checking",
  plugin_manifest_v1: "Agent plugin checking",
  ci_workflow_v1: "CI workflow checking",
  editor_task_v1: "Editor task checking",
  instruction_file_v1: "Instruction file checking"
};
function checkedSummary(worktree, newestRun, assessment) {
  const pending = newestRun?.state === "running" || newestRun?.state === "queued" || newestRun?.state === "failed";
  if (assessment === void 0 && pending) return "No check has finished yet.";
  const earlier = assessment !== void 0 && pending && newestRun?.runId !== assessment.runId;
  const runAtMs = newestRun?.state === "completed" || newestRun?.state === "partial" ? newestRun.finishedAtMs : null;
  const atMs = assessment?.finishedAtMs ?? (earlier ? null : runAtMs ?? worktree.lastScanAtMs);
  if (atMs === null) return earlier ? "Showing results from an earlier check." : "Waiting for the first check.";
  const when = formatRelativeTime(new Date(atMs).toISOString());
  return earlier ? `Showing results from the check ${when.replace(/^Yesterday/, "yesterday")}.` : `Checked ${when}`;
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
const DECISION_LABELS = { block: "Block", ask: "Ask", warn: "Warn" };
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
    state.deferredReason === "resource_pressure" && state.worktrees.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "status", className: "rounded-xl border border-slate-200 bg-slate-50 px-4 py-3 text-sm text-slate-600", children: "This device is busy, so background checks are waiting. Checks you start with Assess now still run." }),
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
        status.detail && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: status.detail }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: checkedSummary(worktree, props.newestRun, assessment) })
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
    assessment && /* @__PURE__ */ jsxRuntimeExports.jsx(AssessmentFindings, { worktree, assessment })
  ] });
}
function AssessmentFindings(props) {
  const { findings, runId, notRun, dependencyFilesFound } = props.assessment;
  const fixes = useWorktreeFixes(props.worktree, runId);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(FixLoadError, { fixes }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(FindingsSections, { findings, dependencyFilesFound, secretsChecked: !notRun.includes("secrets"), fixes }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(FixReview, { fixes, findings }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(FixHistory, { fixes, findings }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ExportPreviewPanel, { worktree: props.worktree, findings })
  ] });
}
function emptyFindingsCopy(dependencyFilesFound, secretsChecked) {
  const none = "No dependency files were found, so there were no dependencies to check.";
  if (!dependencyFilesFound) return secretsChecked ? `${none} No secret findings in the checked files.` : none;
  return secretsChecked ? "No dependency or secret findings in the checked files." : "No dependency findings in the checked files.";
}
function FindingsSections(props) {
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
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-600", children: emptyFindingsCopy(props.dependencyFilesFound, props.secretsChecked) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    dependencies.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(FindingsTable, { findings: dependencies, fixes: props.fixes }),
    secrets.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(SecretFindingsTable, { findings: secrets }),
    runtimes.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(RuntimeFindingsTable, { findings: runtimes }),
    skills.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(SkillFindingsTable, { findings: skills }),
    servers.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(McpFindingsTable, { findings: servers }),
    hooks.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(HookFindingsTable, { findings: hooks }),
    plugins.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(PluginFindingsTable, { findings: plugins }),
    workflows.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(WorkflowFindingsTable, { findings: workflows }),
    editorTasks.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(EditorTaskFindingsTable, { findings: editorTasks }),
    instructions.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(InstructionFindingsTable, { findings: instructions })
  ] });
}
function FindingsTable({ findings, fixes }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-xl border border-slate-200", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full text-left text-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("caption", { className: "sr-only", children: "Dependency findings" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { className: "hidden bg-slate-50 text-xs font-semibold text-slate-600 md:table-header-group", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Package" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Installed" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Fixed in" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Policy" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Severity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Advisories" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-3 py-2", children: "Fix" })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { className: "divide-y divide-slate-100", children: findings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "grid grid-cols-2 gap-x-3 gap-y-2 px-3 py-3 md:table-row md:p-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Package", wide: true, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: finding.packageName }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 text-xs text-slate-500", children: finding.ecosystem })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Installed", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Mono, { value: finding.packageVersion }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Fixed in", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Mono, { value: finding.fixVersion, fallback: "No fix yet" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(Cell, { label: "Policy", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(finding.decision), children: DECISION_LABELS[finding.decision] ?? finding.decision }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceNote, { finding }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(CarriedNote, { finding })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Severity", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "capitalize text-slate-700", children: finding.severity }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Advisories", wide: true, children: finding.advisoryIds.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "break-all font-mono text-xs text-slate-700", children: finding.advisoryIds.join(", ") }) : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-500", children: "None listed" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Cell, { label: "Fix", wide: true, children: /* @__PURE__ */ jsxRuntimeExports.jsx(FixCell, { finding, fixes }) })
    ] }, finding.findingId)) })
  ] }) });
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
  checkedSummary,
  worktreeStatus
};
