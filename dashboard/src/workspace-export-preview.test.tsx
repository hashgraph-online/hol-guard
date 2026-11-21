import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import {
  ExportPreviewError,
  exclusionMessage,
  exportPreviewErrorMessage,
  formatBytes,
  normalizeExportPreview,
  parseExportPaths,
  previewWorkspaceExport,
} from "./workspace-export-preview-api";
import { ExportPreviewPanel, ExportPreviewView, suggestedExportPaths, type ExportPreviewViewProps } from "./workspace-export-preview-panel";
import type { WorkspaceFinding } from "./workspace-findings-api";

const CODEBASE = "c".repeat(64);
const WORKTREE = "w".repeat(64);
const DIGEST = "d".repeat(64);
const worktree = { codebaseKey: CODEBASE, worktreeKey: WORKTREE };

function rawPreview(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: "guard.workspace-export-preview.v1",
    status: "ready",
    worktree_key: WORKTREE,
    codebase_key: CODEBASE,
    bundle_digest: DIGEST,
    file_count: 1,
    export_bytes: 27,
    redactions: 1,
    files: [
      { path: "app.py", bytes: 48, source_sha256: "a".repeat(64), export_bytes: 27, export_sha256: "b".repeat(64), redactions: 1, redaction_rules: ["github-pat"] },
      { path: "broken", bytes: -1 },
    ],
    excluded: [
      { path: "config/.env", reason: "sensitive" },
      { path: "", reason: "invalid_path" },
      { reason: "not_found" },
    ],
    limits: { max_paths: 200, max_file_bytes: 262144, max_total_bytes: 2097152 },
    ...overrides,
  };
}

function finding(overrides: Partial<WorkspaceFinding>): WorkspaceFinding {
  return {
    findingId: "f".repeat(32),
    severity: "high",
    decision: "block",
    validation: "unvalidated",
    ecosystem: "",
    packageName: null,
    packageVersion: null,
    fixVersion: null,
    advisoryIds: [],
    kind: "secret",
    ruleIds: [],
    path: null,
    line: null,
    lines: [],
    runtime: null,
    skill: null,
    mcp: null,
    hook: null,
    workflow: null,
    editorTask: null,
    carried: false,
    ...overrides,
  };
}

// Normalizing keeps only well-formed entries and totals what it kept.
const preview = normalizeExportPreview(rawPreview());
assert.ok(preview);
assert.deepEqual(preview.files, [{ path: "app.py", bytes: 48, exportBytes: 27, redactions: 1 }]);
assert.deepEqual(preview.excluded, [
  { path: "config/.env", reason: "sensitive" },
  { path: "", reason: "invalid_path" },
]);
assert.equal(preview.exportBytes, 27);
assert.equal(preview.redactions, 1);
assert.equal(preview.maxFileBytes, 262144);
assert.equal(normalizeExportPreview(rawPreview({ status: "uploaded" })), null);
assert.equal(normalizeExportPreview(rawPreview({ bundle_digest: "" })), null);
assert.equal(normalizeExportPreview(rawPreview({ files: null })), null);

assert.deepEqual(parseExportPaths(" app.py \r\n\n src/a.ts\napp.py\n"), ["app.py", "src/a.ts"]);
assert.equal(formatBytes(512), "512 B");
assert.equal(formatBytes(2048), "2.0 KB");
assert.equal(formatBytes(3 * 1024 * 1024), "3.0 MB");
assert.match(exclusionMessage("redaction_failed"), /blocks the export/);
assert.match(exclusionMessage("something_new"), /Left out/);
assert.match(exportPreviewErrorMessage("worktree_moved"), /different workspace/);
assert.match(exportPreviewErrorMessage("mystery"), /retry/);

// Suggestions are the workspace files findings point at, never a runtime executable.
assert.deepEqual(
  suggestedExportPaths([
    finding({ path: "config/settings.py" }),
    finding({ path: "config/settings.py", line: 9 }),
    finding({ kind: "skill", path: ".claude/skills/x/SKILL.md" }),
    finding({ kind: "runtime", path: "/usr/local/bin/node" }),
    finding({ kind: "supply_chain", packageName: "lodash" }),
  ]),
  ["config/settings.py", ".claude/skills/x/SKILL.md"],
);

function view(overrides: Partial<ExportPreviewViewProps> = {}): string {
  const noop = () => undefined;
  return renderToStaticMarkup(
    createElement(ExportPreviewView, {
      input: "app.py\nconfig/.env",
      busy: false,
      error: null,
      preview: null,
      edited: false,
      onInput: noop,
      onPreview: noop,
      onClose: noop,
      ...overrides,
    }),
  );
}

const closed = renderToStaticMarkup(createElement(ExportPreviewPanel, { worktree, findings: [] }));
assert.match(closed, /Preview a source export/);
assert.doesNotMatch(closed, /<textarea/, "the panel never reads files until asked");

const idle = view();
assert.match(idle, /<label[^>]*for="[^"]+-paths"[^>]*>Files to include<\/label>/);
assert.match(idle, /A preview sends nothing/);
assert.match(idle, />Preview export</);
assert.doesNotMatch(idle, /export-preview-result/);

const ready = view({ preview });
assert.match(ready, /Guard would replace 1 secret with \[REDACTED\]/);
assert.match(ready, /<dt[^>]*>Destination<\/dt><dd[^>]*>None<\/dd>/);
assert.match(ready, /app\.py/);
assert.match(ready, /Credential or key file/);
assert.match(ready, /\(empty line\)/);
assert.match(ready, new RegExp(DIGEST));
assert.match(ready, />Preview again</);
assert.doesNotMatch(ready, /The list changed/);

const blocked = normalizeExportPreview(
  rawPreview({ status: "blocked", files: [], excluded: [{ path: "app.py", reason: "redaction_failed" }] }),
);
assert.ok(blocked);
const blockedView = view({ preview: blocked });
assert.match(blockedView, /role="alert"[^>]*>.*cannot be exported/s);
assert.match(blockedView, /font-semibold text-red-800[^>]*>app\.py/);
assert.doesNotMatch(blockedView, /would replace/);

const empty = normalizeExportPreview(rawPreview({ status: "empty", files: [] }));
assert.ok(empty);
assert.match(view({ preview: empty }), /None of these files can be exported/);
assert.match(view({ preview, edited: true }), /The list changed after this preview/);
assert.match(view({ busy: true }), /Reading files…/);
assert.match(view({ error: "Guard cannot find this workspace folder." }), /role="alert"/);

const storage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: { origin: "http://127.0.0.1:4174", pathname: "/", search: "", hash: "" },
    sessionStorage: storage,
    localStorage: storage,
  },
});
const previousFetch = globalThis.fetch;
try {
  const calls: Array<{ url: string; method: string; body: unknown }> = [];
  let reply: { status: number; body: unknown } = { status: 200, body: rawPreview() };
  globalThis.fetch = async (url, init) => {
    calls.push({ url: String(url), method: init?.method ?? "GET", body: init?.body ? JSON.parse(String(init.body)) : null });
    return new Response(JSON.stringify(reply.body), { status: reply.status });
  };

  const result = await previewWorkspaceExport(worktree, ["app.py"]);
  assert.equal(result.status, "ready");
  assert.equal(calls.at(-1)?.method, "POST");
  assert.match(calls.at(-1)?.url ?? "", /\/v1\/supply-chain\/workspace-export-preview$/);
  assert.deepEqual(calls.at(-1)?.body, { codebase_key: CODEBASE, worktree_key: WORKTREE, paths: ["app.py"] });

  // Requests the daemon would refuse never leave the page.
  const sent = calls.length;
  await assert.rejects(previewWorkspaceExport(worktree, []), /at least one file path/);
  await assert.rejects(
    previewWorkspaceExport(worktree, Array.from({ length: 201 }, (_, index) => `f${index}`)),
    /up to 200 file paths/,
  );
  await assert.rejects(previewWorkspaceExport(worktree, ["a".repeat(4097)]), (error: unknown) =>
    error instanceof ExportPreviewError && error.code === "path_too_long" && /at most 4096 characters/.test(error.message));
  assert.equal(calls.length, sent);

  reply = { status: 409, body: { error: "worktree_moved", detail: "private-server-marker" } };
  await assert.rejects(previewWorkspaceExport(worktree, ["app.py"]), (error: unknown) =>
    error instanceof ExportPreviewError && error.code === "worktree_moved" && !error.message.includes("private-server-marker"));
  reply = { status: 503, body: { error: "workspace_export_preview_native_unavailable" } };
  await assert.rejects(previewWorkspaceExport(worktree, ["app.py"]), /Repair Guard/);
  reply = { status: 200, body: { status: "ready" } };
  await assert.rejects(previewWorkspaceExport(worktree, ["app.py"]), (error: unknown) =>
    error instanceof ExportPreviewError && error.code === "workspace_export_preview_failed");
} finally {
  globalThis.fetch = previousFetch;
}

console.log("workspace export preview tests passed");
