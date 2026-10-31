import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { AuditCodebaseChecksView, summarizeCodebaseChecks } from "./audit-codebase-checks";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";

function keys(name: string) {
  return { codebase_key: name.repeat(64), worktree_key: name.repeat(64) };
}

const now = Date.now();
const hour = 60 * 60 * 1000;
const fresh = keys("a");
const stale = keys("b");
const failed = keys("c");
const unchecked = keys("d");
const paused = keys("e");

function finding(id: string) {
  return {
    finding_id: id.repeat(32),
    severity: "high",
    decision: "block",
    ecosystem: "npm",
    package_name: "minimist",
    package_version: "1.2.8",
    fix_version: "1.2.9",
    advisory_ids: ["GHSA-xxxx-yyyy-zzzz"],
  };
}

function assessment(ids: ReturnType<typeof keys>, runId: string, finishedAtMs: number, extra: Record<string, unknown> = {}) {
  return {
    ...ids,
    run_id: runId,
    state: "completed",
    finished_at_ms: finishedAtMs,
    coverage: { status: "complete", reasons: [], detectors: { supply_chain: "complete" } },
    findings: [],
    ...extra,
  };
}

const state = normalizeWorkspaceFindingsState(
  {
    runs: [],
    latest_runs: [
      { ...fresh, run_id: "a-1", state: "completed", trigger_kind: "file_change" },
      { ...stale, run_id: "b-1", state: "completed", trigger_kind: "file_change" },
      { ...failed, run_id: "c-2", state: "failed", trigger_kind: "file_change", error_code: "workspace_snapshot_failed" },
      { ...unchecked, run_id: "d-1", state: "running", trigger_kind: "workspace_open" },
    ],
  },
  {
    worktrees: [
      { ...fresh, root: "/Users/dev/app", stale: false, paused: false },
      { ...stale, root: "/Users/dev/api", stale: true, paused: false },
      { ...failed, root: "/Users/dev/web", stale: false, paused: false },
      { ...unchecked, root: "/Users/dev/new", stale: false, paused: false },
      { ...paused, root: "/Users/dev/old", stale: false, paused: true },
    ],
    assessments: [
      assessment(fresh, "a-1", now - 10 * 60 * 1000, { findings: [finding("1"), finding("2")] }),
      assessment(stale, "b-1", now - 3 * hour, {
        coverage: { status: "partial", reasons: ["finding_cap"], detectors: { supply_chain: "complete" } },
        findings: [finding("3")],
      }),
      assessment(failed, "c-1", now - 26 * hour),
      assessment(paused, "e-1", now - 2 * hour),
    ],
  },
);

const summary = summarizeCodebaseChecks(state);
assert.equal(summary.worktrees, 5);
assert.equal(summary.notChecked, 1, "a workspace whose first check is still running has no result yet");
assert.equal(summary.latestCheckAtMs, now - 10 * 60 * 1000);
assert.equal(
  summary.oldestCheckAtMs,
  now - 26 * hour,
  "a failed newer attempt does not refresh the result it left in place",
);
assert.equal(summary.needAttention, 2, "out of date, partial and failed workspaces need attention; paused and assessing do not");
assert.equal(summary.openFindings, 3);
assert.equal(summary.openFindingsLowerBound, true, "a capped assessment makes the count a minimum");

const markup = renderToStaticMarkup(createElement(AuditCodebaseChecksView, { summary, onOpenWorkspaces: () => {} }));
assert.match(markup, /Background workspace checks/);
assert.match(markup, /aria-labelledby="audit-codebase-checks-title"/);
assert.match(markup, /not in the audit list below/, "says these findings are not in the audit list");
assert.match(markup, /Open Workspaces/);
assert.match(markup, />3\+</, "open findings shows the lower bound");
assert.match(markup, /10m ago/);
assert.match(markup, /1 workspace has no finished check yet\./);
assert.match(markup, /open findings is a minimum/);

const withoutNav = renderToStaticMarkup(createElement(AuditCodebaseChecksView, { summary }));
assert.doesNotMatch(withoutNav, /Open Workspaces/, "no button without a way to navigate");

const empty = summarizeCodebaseChecks(normalizeWorkspaceFindingsState({ runs: [] }, { worktrees: [], assessments: [] }));
assert.equal(
  renderToStaticMarkup(createElement(AuditCodebaseChecksView, { summary: empty, onOpenWorkspaces: () => {} })),
  "",
  "nothing renders before any workspace is tracked",
);

const unrun = summarizeCodebaseChecks(
  normalizeWorkspaceFindingsState(
    { runs: [] },
    { worktrees: [{ ...fresh, root: "/Users/dev/app", stale: false, paused: false }], assessments: [] },
  ),
);
const unrunMarkup = renderToStaticMarkup(createElement(AuditCodebaseChecksView, { summary: unrun }));
assert.match(unrunMarkup, /Not yet/, "no check time is shown as not yet, never as a time");
assert.doesNotMatch(unrunMarkup, /minimum/);

const carried = summarizeCodebaseChecks(
  normalizeWorkspaceFindingsState(
    { runs: [], latest_runs: [{ ...fresh, run_id: "a-1", state: "completed", trigger_kind: "file_change" }] },
    {
      worktrees: [{ ...fresh, root: "/Users/dev/app", stale: false, paused: false }],
      assessments: [
        assessment(fresh, "a-1", now - 5 * 60 * 1000, {
          coverage: { status: "partial", reasons: ["carried_finding_cap"], detectors: { supply_chain: "complete" } },
          findings: [finding("4")],
        }),
      ],
    },
  ),
);
assert.equal(carried.openFindingsLowerBound, true, "dropped carried findings also make the count a minimum");
assert.equal(carried.needAttention, 1, "an up-to-date workspace with partial coverage still needs attention");

console.log("audit codebase checks: ok");
