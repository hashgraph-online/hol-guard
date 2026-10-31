import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { checkedSummary, WorktreeRow } from "./workspace-findings-workspace";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };
const assessedAt = Date.now() - 2 * 60 * 60 * 1000;
const attemptedAt = Date.now() - 5 * 60 * 1000;

const state = normalizeWorkspaceFindingsState(
  {
    worktrees: [],
    runs: [
      { ...ids, run_id: "run-2", state: "failed", trigger_kind: "file_change", error_code: "workspace_snapshot_failed" },
      { ...ids, run_id: "run-1", state: "completed", trigger_kind: "workspace_open" },
    ],
  },
  {
    worktrees: [{ ...ids, root: "/Users/dev/app", stale: false, paused: false, last_scan_at_ms: attemptedAt }],
    assessments: [
      {
        ...ids,
        run_id: "run-1",
        state: "completed",
        finished_at_ms: assessedAt,
        coverage: { status: "complete", reasons: [], detectors: { supply_chain: "complete" } },
        findings: [],
      },
    ],
  },
);
const [worktree] = state.worktrees;
const [assessment] = state.assessments;
const [failedRun, completedRun] = state.runs;

function row(newestRun = completedRun, target = worktree, result: typeof assessment | undefined = assessment) {
  return renderToStaticMarkup(
    createElement(WorktreeRow, { worktree: target, newestRun, assessment: result, busyKey: null, onAction: () => {} }),
  );
}

assert.equal(checkedSummary(worktree, completedRun, assessment), "Checked 2h ago", "the time of the shown result");

const stale = row(completedRun, { ...worktree, stale: true });
assert.match(stale, /Files changed since the last assessment\./);
assert.match(stale, /Checked 2h ago/, "an out-of-date workspace still says when it was last checked");

const failed = row(failedRun);
assert.match(failed, /Guard could not read this workspace\./);
assert.match(
  failed,
  /Showing results from the check 2h ago\./,
  "after a failed run the findings come from the earlier check, not the failed attempt",
);
assert.doesNotMatch(failed, /Checked 5m ago/);

const running = row({ ...failedRun, state: "running", errorCode: null });
assert.match(running, /Showing results from the check 2h ago\./, "a run in progress has not replaced the result yet");

assert.equal(
  checkedSummary(worktree, failedRun, { ...assessment, finishedAtMs: null }),
  "Showing results from an earlier check.",
);
assert.equal(
  checkedSummary(worktree, failedRun, undefined),
  "No check has finished yet.",
  "a failed first attempt is not a finished check",
);
assert.equal(checkedSummary(worktree, completedRun, undefined), "Checked 5m ago");
assert.equal(
  checkedSummary(worktree, { ...completedRun, finishedAtMs: assessedAt }, undefined),
  "Checked 2h ago",
  "a finished run whose assessment has not loaded yet shows its own finish time, not the last attempt",
);
assert.equal(
  checkedSummary({ ...worktree, lastScanAtMs: null }, undefined, undefined),
  "Waiting for the first check.",
);

console.log("workspace findings checked time tests passed");
