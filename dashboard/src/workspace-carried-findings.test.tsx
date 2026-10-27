import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { WorktreeRow } from "./workspace-findings-workspace";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };
const NOTE = "Not rechecked in the latest scan";
const workflow = {
  source_kind: "workspace_source",
  detector: "ci_workflow_v1",
  rule_ids: ["ci.workflow.untrusted-checkout"],
  severity: "high",
  decision: "warn",
  title: "Privileged workflow runs pull request code",
  reason: "A workflow with repository secrets checks out code from the pull request.",
};

function render(findings: Record<string, unknown>[]) {
  const state = normalizeWorkspaceFindingsState(
    { worktrees: [], runs: [{ ...ids, run_id: "run-2", state: "partial", trigger_kind: "manual" }] },
    {
      worktrees: [{ ...ids, root: "/Users/dev/app", stale: false, paused: false }],
      assessments: [
        {
          ...ids,
          run_id: "run-2",
          state: "partial",
          coverage: { status: "partial", reasons: ["ci_workflow_incomplete"], detectors: { ci_workflow_v1: "incomplete" } },
          findings,
        },
      ],
    },
  );
  return {
    findings: state.assessments[0].findings,
    html: renderToStaticMarkup(
      createElement(WorktreeRow, {
        worktree: state.worktrees[0],
        newestRun: state.runs[0],
        assessment: state.assessments[0],
        busyKey: null,
        onAction: () => {},
      }),
    ),
  };
}

// A finding the latest scan could not recheck stays listed and says so.
const carried = render([{ ...workflow, finding_id: "old", path: ".github/workflows/ci.yml", carried_from_run_id: "run-1" }]);
assert.equal(carried.findings[0].carried, true);
assert.ok(carried.html.includes("Privileged workflow runs pull request code"));
assert.ok(carried.html.includes(NOTE));

// One the latest scan observed itself carries no note.
const observed = render([{ ...workflow, finding_id: "new", path: ".github/workflows/ci.yml" }]);
assert.equal(observed.findings[0].carried, false);
assert.ok(!observed.html.includes(NOTE));

// A blank run id is not a carried finding.
assert.equal(render([{ ...workflow, finding_id: "blank", path: ".github/workflows/ci.yml", carried_from_run_id: " " }]).findings[0].carried, false);

console.log("workspace carried findings tests passed");
