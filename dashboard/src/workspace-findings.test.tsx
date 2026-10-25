import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState, workspaceErrorMessage } from "./workspace-findings-api";
import { createLatestRefresh } from "./workspace-findings-refresh";
import { WorktreeRow, worktreeStatus } from "./workspace-findings-workspace";

const CODEBASE = "c".repeat(64);
const WORKTREE = "w".repeat(64);
const ids = { codebase_key: CODEBASE, worktree_key: WORKTREE };

const state = normalizeWorkspaceFindingsState(
  {
    worktrees: [],
    runs: [
      { ...ids, run_id: "run-2", state: "failed", trigger_kind: "file_change", error_code: "workspace_snapshot_failed" },
      { ...ids, run_id: "run-1", state: "partial", trigger_kind: "workspace_open", finding_count: 1 },
      { ...ids, run_id: "bad", state: "exploded" },
    ],
    latest_runs: [{ ...ids, run_id: "run-2", state: "running", trigger_kind: "manual" }],
  },
  {
    worktrees: [
      { ...ids, root: "/Users/dev/app", stale: false, paused: false, last_scan_at_ms: 1_700_000_000_000 },
      { codebase_key: CODEBASE, root: "/missing-key" },
    ],
    assessments: [
      {
        ...ids,
        run_id: "run-1",
        state: "partial",
        coverage: {
          status: "partial",
          reasons: ["snapshot_unstable", "detector_not_run:secrets"],
          detectors: { supply_chain: "complete", secrets: "not_run" },
        },
        findings: [
          {
            finding_id: "f".repeat(32),
            severity: "high",
            decision: "block",
            ecosystem: "npm",
            package_name: "minimist",
            package_version: "1.2.8",
            fix_version: "1.2.9",
            advisory_ids: ["GHSA-xxxx-yyyy-zzzz", 7],
          },
          { finding_id: "no-package" },
        ],
      },
    ],
  },
);

assert.deepEqual(
  state.latestRuns.map((run) => [run.runId, run.state]),
  [["run-2", "running"]],
  "the newest run of each worktree is read apart from the bounded history",
);
assert.equal(state.suggestedRootTracked, null, "no answer about a suggested folder unless one was asked about");
assert.equal(
  normalizeWorkspaceFindingsState({}, { worktrees: [], suggested_root_tracked: true }).suggestedRootTracked,
  true,
);
assert.equal(state.worktrees.length, 1, "worktrees without both keys are dropped");
assert.deepEqual(
  state.runs.map((run) => run.runId),
  ["run-2", "run-1"],
  "unknown run states are dropped and order is kept",
);
const [worktree] = state.worktrees;
const [assessment] = state.assessments;
assert.deepEqual(assessment.reasons, ["snapshot_unstable"], "detector gaps are reported separately from coverage gaps");
assert.deepEqual(assessment.notRun, ["secrets"]);
assert.equal(assessment.partial, true);
assert.equal(assessment.findings.length, 1, "findings without a package are dropped");
assert.deepEqual(assessment.findings[0].advisoryIds, ["GHSA-xxxx-yyyy-zzzz"]);

const [onlyNotRun] = normalizeWorkspaceFindingsState(
  { worktrees: [], runs: [] },
  {
    worktrees: [],
    assessments: [
      {
        ...ids,
        run_id: "run-3",
        state: "partial",
        coverage: {
          status: "partial",
          reasons: ["detector_not_run:secrets"],
          detectors: { supply_chain: "complete", secrets: "not_run" },
        },
      },
    ],
  },
).assessments;
assert.equal(onlyNotRun.partial, true, "a detector that did not run keeps the daemon's partial classification");
assert.deepEqual(onlyNotRun.notRun, ["secrets"]);

const [failedRun, partialRun] = state.runs;
assert.equal(worktreeStatus(worktree, failedRun, assessment).label, "Assessment failed");
assert.equal(worktreeStatus(worktree, failedRun, assessment).detail, "Guard could not read this workspace.");
assert.equal(worktreeStatus(worktree, partialRun, assessment).label, "Partial coverage");
assert.equal(worktreeStatus({ ...worktree, stale: true }, partialRun, assessment).label, "Out of date");
assert.equal(worktreeStatus({ ...worktree, paused: true }, partialRun, assessment).label, "Paused");
assert.equal(worktreeStatus(worktree, { ...partialRun, state: "running" }, assessment).label, "Assessing");
assert.equal(worktreeStatus(worktree, undefined, undefined).label, "Not assessed yet");
assert.equal(worktreeStatus(worktree, partialRun, onlyNotRun).label, "Partial coverage", "never shown as up to date");
assert.equal(worktreeStatus(worktree, partialRun, { ...assessment, partial: false, reasons: [] }).label, "Up to date");
assert.equal(
  worktreeStatus(worktree, { ...failedRun, errorCode: "lease_expired" }, assessment).label,
  "Partial coverage",
  "an expired lease is retried, so the last assessed result still stands",
);

const markup = renderToStaticMarkup(
  createElement(WorktreeRow, { worktree, newestRun: partialRun, assessment, busyKey: null, onAction: () => {} }),
);
for (const copy of [
  "app",
  "Partial coverage",
  "Files changed while Guard was reading them.",
  "Secret scanning is not part of this check yet.",
  "minimist",
  "1.2.9",
  "Blocked",
  "GHSA-xxxx-yyyy-zzzz",
  "Assess now",
  "Pause",
]) {
  assert.ok(markup.includes(copy), `row shows ${copy}`);
}

const paused = renderToStaticMarkup(
  createElement(WorktreeRow, {
    worktree: { ...worktree, paused: true },
    newestRun: partialRun,
    assessment,
    busyKey: null,
    onAction: () => {},
  }),
);
assert.ok(paused.includes("Resume"), "paused rows offer resume");
assert.match(paused, /<button[^>]*disabled=""[^>]*>.*?Assess now/s, "paused rows cannot start an assessment");

assert.equal(workspaceErrorMessage("workspace_root_missing"), "That folder no longer exists. Choose it again.");
assert.match(workspaceErrorMessage("anything_else"), /Check that Guard is running/);
assert.match(workspaceErrorMessage(null), /Check that Guard is running/);

async function checkOverlappingRefreshes() {
  const pending: Array<{ resolve: (value: string) => void; reject: (error: Error) => void }> = [];
  const applied: string[] = [];
  const failed: string[] = [];
  const refresh = createLatestRefresh(
    () => new Promise<string>((resolve, reject) => pending.push({ resolve, reject })),
    { onData: (value) => applied.push(value), onError: (error) => failed.push((error as Error).message) },
  );
  // An interval poll starts, then an action's refresh starts. The newer one
  // finishes first and the older one finishes last.
  const poll = refresh();
  const afterAction = refresh();
  pending[1].resolve("after-action");
  await afterAction;
  pending[0].resolve("stale-poll");
  await poll;
  assert.deepEqual(applied, ["after-action"], "an older response never replaces a newer one");

  const failingPoll = refresh();
  const afterPause = refresh();
  pending[3].resolve("after-pause");
  await afterPause;
  pending[2].reject(new Error("obsolete load error"));
  await failingPoll;
  assert.deepEqual(applied, ["after-action", "after-pause"]);
  assert.deepEqual(failed, [], "an older failure does not raise a stale load error");

  const lone = refresh();
  pending[4].reject(new Error("current failure"));
  await lone;
  assert.deepEqual(failed, ["current failure"], "the latest request still reports its own failure");
}

await checkOverlappingRefreshes();

console.log("workspace findings tests passed");
