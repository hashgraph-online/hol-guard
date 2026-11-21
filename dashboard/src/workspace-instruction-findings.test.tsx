import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { WorktreeRow } from "./workspace-findings-workspace";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };
const instructionFinding = {
  source_kind: "workspace_source",
  detector: "instruction_file_v1",
  rule_ids: ["instruction.approval-bypass"],
  path: "packages/app/AGENTS.md",
  title: "t",
  reason: "r",
};

function stateWith(findings: Record<string, unknown>[], coverage: Record<string, unknown>) {
  return normalizeWorkspaceFindingsState(
    { worktrees: [], runs: [{ ...ids, run_id: "run-instructions", state: "completed", trigger_kind: "manual" }] },
    {
      worktrees: [{ ...ids, root: "/Users/dev/app", stale: false, paused: false }],
      assessments: [{ ...ids, run_id: "run-instructions", state: "completed", coverage, findings }],
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
      ...instructionFinding,
      finding_id: "bypass",
      severity: "high",
      decision: "warn",
      confidence: "likely",
      title: "Instruction file turns off approvals",
      reason: "An agent instruction file in this project tells the agent to skip approval prompts.",
      false_positive_hint: "Expected when the file only warns against the setting.",
    },
    {
      ...instructionFinding,
      finding_id: "controls",
      severity: "medium",
      decision: "warn",
      rule_ids: ["instruction.unicode-controls"],
      path: ".cursorrules",
      confidence: "likely",
      title: "Instruction file hides text",
      reason: "An agent instruction file holds control characters that can hide what it tells the agent.",
    },
    { ...instructionFinding, finding_id: "no-path", path: undefined },
    { ...instructionFinding, finding_id: "no-title", title: undefined },
    { ...instructionFinding, finding_id: "no-rule", rule_ids: [] },
  ],
  { status: "complete", reasons: [], detectors: { supply_chain: "complete", instruction_file_v1: "complete" } },
);
const findings = state.assessments[0].findings;
assert.equal(findings.length, 2, "an instruction finding without its path, wording or rule is dropped");
const [bypass, controls] = findings;
assert.deepEqual(
  [bypass.kind, bypass.path, bypass.instruction?.falsePositiveHint, bypass.editorTask, bypass.workflow, bypass.packageName],
  ["instruction", "packages/app/AGENTS.md", "Expected when the file only warns against the setting.", null, null, null],
  "an instruction finding carries its file and the instruction check",
);
assert.deepEqual([controls.kind, controls.ruleIds], ["instruction", ["instruction.unicode-controls"]]);

const markup = render(state);
assert.ok(markup.includes("Agent instruction files that tell an agent to drop its safeguards"), "instruction findings get their own table");
assert.ok(markup.includes("packages/app/AGENTS.md") && markup.includes(".cursorrules"));
assert.ok(markup.includes("Instruction file turns off approvals") && markup.includes("Instruction file hides text"));
assert.ok(markup.includes("Expected when the file only warns against the setting."), "the false positive hint is shown");
assert.ok(!markup.includes("Editor tasks and dev containers"), "instruction findings are not shown as editor tasks");
assert.ok(!markup.includes("No dependency or secret findings"), "a run with only instruction findings is not shown as clean");
assert.ok(!markup.includes("Prepare fix"), "an instruction finding is a warning with no fix");

const gapMarkup = render(
  stateWith([], {
    status: "partial",
    reasons: ["instruction_file_incomplete", "detector_not_run:instruction_file_v1"],
    detectors: { supply_chain: "complete", instruction_file_v1: "not_run" },
  }),
);
assert.ok(gapMarkup.includes("Some agent instruction files could not be fully read"), "an incomplete scan is named");
assert.ok(gapMarkup.includes("Instruction file checking is not part of this check yet."), "a scan that did not run is named");

console.log("workspace instruction findings tests passed");
