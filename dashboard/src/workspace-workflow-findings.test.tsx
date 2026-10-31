import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { WorktreeRow } from "./workspace-findings-workspace";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };
const workflowFinding = {
  source_kind: "workspace_source",
  detector: "ci_workflow_v1",
  rule_ids: ["ci.workflow.untrusted-checkout"],
  path: ".github/workflows/ci.yml",
  title: "t",
  reason: "r",
};

function stateWith(findings: Record<string, unknown>[], coverage: Record<string, unknown>) {
  return normalizeWorkspaceFindingsState(
    { worktrees: [], runs: [{ ...ids, run_id: "run-workflow", state: "completed", trigger_kind: "manual" }] },
    {
      worktrees: [{ ...ids, root: "/Users/dev/app", stale: false, paused: false }],
      assessments: [{ ...ids, run_id: "run-workflow", state: "completed", coverage, findings }],
    },
  );
}

function render(state: ReturnType<typeof stateWith>) {
  const [worktree] = state.worktrees;
  const [run] = state.runs;
  return renderToStaticMarkup(
    createElement(WorktreeRow, { worktree, newestRun: run, assessment: state.assessments[0], busyKey: null, onAction: () => {} }),
  );
}

const state = stateWith(
  [
    {
      ...workflowFinding,
      finding_id: "checkout",
      severity: "high",
      decision: "warn",
      confidence: "likely",
      title: "Privileged workflow runs pull request code",
      reason: "A workflow with repository secrets checks out code from the pull request.",
      false_positive_hint: "Safe when the job only reads the checked-out files.",
    },
    {
      ...workflowFinding,
      finding_id: "unpinned",
      severity: "medium",
      decision: "warn",
      rule_ids: ["ci.workflow.unpinned-action"],
      path: ".github/workflows/release.yaml",
      confidence: "strong",
      title: "Action not pinned to a commit",
      reason: "A tag or branch can move to different code.",
    },
    { ...workflowFinding, finding_id: "no-path", path: undefined },
    { ...workflowFinding, finding_id: "no-title", title: undefined },
    { ...workflowFinding, finding_id: "no-rule", rule_ids: [] },
  ],
  { status: "complete", reasons: [], detectors: { supply_chain: "complete", ci_workflow_v1: "complete" } },
);
const findings = state.assessments[0].findings;
assert.equal(findings.length, 2, "a workflow finding without its path, wording or rule is dropped");
const [checkout, unpinned] = findings;
assert.deepEqual(
  [checkout.kind, checkout.path, checkout.workflow?.confidence, checkout.workflow?.falsePositiveHint, checkout.packageName, checkout.skill],
  ["workflow", ".github/workflows/ci.yml", "likely", "Safe when the job only reads the checked-out files.", null, null],
  "a workflow finding carries its file and the workflow check",
);
assert.deepEqual([unpinned.kind, unpinned.ruleIds], ["workflow", ["ci.workflow.unpinned-action"]]);

const markup = render(state);
assert.ok(markup.includes("GitHub Actions workflows with risky settings"), "workflow findings get their own table");
assert.ok(markup.includes(".github/workflows/ci.yml") && markup.includes(".github/workflows/release.yaml"));
assert.ok(markup.includes("Privileged workflow runs pull request code") && markup.includes("Action not pinned to a commit"));
assert.ok(markup.includes("Safe when the job only reads the checked-out files."), "the false positive hint is shown");
assert.ok(!markup.includes("No dependency or secret findings"), "a run with only workflow findings is not shown as clean");
assert.ok(!markup.includes("Prepare fix"), "a workflow finding is a warning with no fix");

const gapMarkup = render(
  stateWith([], {
    status: "partial",
    reasons: ["ci_workflow_incomplete", "detector_not_run:ci_workflow_v1"],
    detectors: { supply_chain: "complete", ci_workflow_v1: "not_run" },
  }),
);
assert.ok(gapMarkup.includes("Some GitHub Actions workflows could not be fully read"), "an incomplete workflow scan is named");
assert.ok(gapMarkup.includes("CI workflow checking is not part of this check yet."), "a workflow scan that did not run is named");
