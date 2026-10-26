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
          {
            finding_id: "s".repeat(32),
            source_kind: "secret",
            detector: "secrets",
            severity: "high",
            decision: "warn",
            rule_ids: ["github-token"],
            path: "src/deploy.py",
            line: 2,
            lines: [2, 9, 0, "x", 31],
            fingerprint: "0".repeat(32),
            validation_state: "unvalidated",
            package_name: null,
          },
          { finding_id: "secret-no-path", source_kind: "secret", rule_ids: ["github-token"], path: "", line: 1 },
          { finding_id: "secret-no-rule", source_kind: "secret", rule_ids: [], path: "a.txt", line: 1 },
          {
            finding_id: "r".repeat(32),
            source_kind: "agent_inventory",
            detector: "runtime_identity_v1",
            severity: "high",
            decision: "warn",
            runtime_family: "node",
            runtime_version: "20.11.1",
            path: "/Users/dev/.nvm/versions/node/v20.11.1/bin/node",
            rule_ids: ["restart_required"],
            advisory_ids: ["GHSA-node-0001"],
            title: "Path traversal in node",
            known_exploited: true,
            package_name: null,
          },
          { finding_id: "runtime-no-advisory", source_kind: "agent_inventory", detector: "runtime_identity_v1", runtime_family: "node", path: "/bin/node" },
          { finding_id: "inventory-other", source_kind: "agent_inventory", detector: "something_else", advisory_ids: ["X"], path: "/bin/node" },
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
assert.equal(state.deferredReason, null, "no deferral unless the daemon reports one");
assert.equal(
  normalizeWorkspaceFindingsState({ deferred_reason: "resource_pressure" }, { worktrees: [] }).deferredReason,
  "resource_pressure",
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
assert.equal(assessment.findings.length, 3, "findings with neither a package, a secret location nor a matched runtime are dropped");
assert.deepEqual(assessment.findings[0].advisoryIds, ["GHSA-xxxx-yyyy-zzzz"]);
const secretFinding = assessment.findings[1];
assert.deepEqual(
  [secretFinding.kind, secretFinding.ruleIds, secretFinding.path, secretFinding.line, secretFinding.packageName],
  ["secret", ["github-token"], "src/deploy.py", 2, null],
  "a secret finding is read as a rule and a file location, with no package",
);
assert.deepEqual(secretFinding.lines, [2, 9, 31], "every line of a repeated secret is kept, malformed entries dropped");
assert.deepEqual(assessment.findings[0].lines, [], "a dependency finding has no lines");
assert.equal(assessment.findings[0].runtime, null);
const runtimeFinding = assessment.findings[2];
assert.deepEqual(
  [runtimeFinding.kind, runtimeFinding.packageName, runtimeFinding.path, runtimeFinding.ruleIds, runtimeFinding.runtime],
  [
    "runtime",
    null,
    "/Users/dev/.nvm/versions/node/v20.11.1/bin/node",
    ["restart_required"],
    { family: "node", version: "20.11.1", title: "Path traversal in node", knownExploited: true },
  ],
  "a runtime finding names the launched executable and the advisory, with no package",
);

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
const timedOut = worktreeStatus(worktree, { ...failedRun, errorCode: "assessment_timed_out" }, assessment);
assert.equal(timedOut.label, "Assessment failed", "a run stopped after its retry is not retried again");
assert.match(timedOut.detail ?? "", /took too long twice/);

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
  "github-token",
  "src/deploy.py:2",
  "Not verified",
  "Assess now",
  "Pause",
  "Prepare fix",
  "/Users/dev/.nvm/versions/node/v20.11.1/bin/node",
  "20.11.1",
  "Restart needed",
  "Known exploited",
  "GHSA-node-0001",
  "Path traversal in node",
]) {
  assert.ok(markup.includes(copy), `row shows ${copy}`);
}
assert.equal(markup.match(/Prepare fix/g)?.length, 1, "a runtime finding is observation only and offers no fix");

const secretsRan = normalizeWorkspaceFindingsState(
  { worktrees: [], runs: [] },
  {
    worktrees: [],
    assessments: [
      {
        ...ids,
        run_id: "run-4",
        state: "completed",
        coverage: { status: "complete", reasons: [], detectors: { supply_chain: "complete", secrets: "complete" } },
        findings: [],
      },
    ],
  },
).assessments[0];
assert.deepEqual(secretsRan.notRun, [], "a detector that ran is not listed as missing");
assert.equal(secretsRan.partial, false);
const cleanMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, { worktree, newestRun: partialRun, assessment: secretsRan, busyKey: null, onAction: () => {} }),
);
assert.ok(cleanMarkup.includes("No dependency or secret findings in the checked files."), "a clean run says secrets were checked");
assert.ok(!cleanMarkup.includes("not part of this check yet"));
const noDependencyFiles = normalizeWorkspaceFindingsState(
  { worktrees: [], runs: [] },
  {
    worktrees: [],
    assessments: [
      {
        ...ids,
        run_id: "run-5",
        state: "completed",
        coverage: { status: "complete", reasons: [], detectors: { supply_chain: "no_inputs", secrets: "complete" } },
        findings: [],
      },
    ],
  },
).assessments[0];
assert.equal(noDependencyFiles.dependencyFilesFound, false);
assert.equal(secretsRan.dependencyFilesFound, true);
const noDependencyMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, { worktree, newestRun: partialRun, assessment: noDependencyFiles, busyKey: null, onAction: () => {} }),
);
assert.ok(noDependencyMarkup.includes("No dependency files were found"), "a workspace with nothing to audit says so");
assert.ok(!noDependencyMarkup.includes("No dependency or secret findings"), "an empty audit is never described as clean dependencies");
const incompleteMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, {
    worktree,
    newestRun: partialRun,
    assessment: { ...secretsRan, partial: true, reasons: ["secrets_incomplete"] },
    busyKey: null,
    onAction: () => {},
  }),
);
assert.ok(incompleteMarkup.includes("Secret scanning did not cover every file"), "truncation is named to the operator");
const runtimeGapMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, {
    worktree,
    newestRun: partialRun,
    assessment: { ...secretsRan, partial: true, reasons: ["runtime_advisories_unavailable"], notRun: ["runtime_identity_v1"] },
    busyKey: null,
    onAction: () => {},
  }),
);
assert.ok(runtimeGapMarkup.includes("Guard has no runtime advisories cached"), "unchecked runtimes are never shown as clean");
assert.ok(runtimeGapMarkup.includes("Runtime checking is not part of this check yet."));

const skillState = normalizeWorkspaceFindingsState(
  { worktrees: [], runs: [] },
  {
    worktrees: [],
    assessments: [
      {
        ...ids,
        run_id: "run-skill",
        state: "completed",
        coverage: {
          status: "complete",
          reasons: [],
          detectors: { supply_chain: "complete", secrets: "complete", skill_content_v1: "complete" },
        },
        findings: [
          {
            finding_id: "skill-1",
            source_kind: "workspace_source",
            detector: "skill_content_v1",
            severity: "critical",
            decision: "warn",
            rule_ids: ["skill.remote-fetch-exec"],
            path: ".claude/skills/setup/SKILL.md",
            confidence: "strong",
            title: "Skill downloads and runs remote code",
            reason: "The skill tells the agent to pipe a download into a shell.",
            false_positive_hint: null,
          },
          { finding_id: "skill-no-path", source_kind: "workspace_source", detector: "skill_content_v1", rule_ids: ["skill.cron"], title: "t", reason: "r" },
          { finding_id: "skill-no-title", source_kind: "workspace_source", detector: "skill_content_v1", rule_ids: ["skill.cron"], path: "skills/a/SKILL.md", reason: "r" },
        ],
      },
    ],
  },
).assessments[0];
assert.equal(skillState.findings.length, 1, "a skill finding without a path or rule wording is dropped");
const [skillFinding] = skillState.findings;
assert.deepEqual(
  [skillFinding.kind, skillFinding.path, skillFinding.ruleIds, skillFinding.packageName, skillFinding.skill?.confidence],
  ["skill", ".claude/skills/setup/SKILL.md", ["skill.remote-fetch-exec"], null, "strong"],
);
const skillMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, { worktree, newestRun: partialRun, assessment: skillState, busyKey: null, onAction: () => {} }),
);
assert.ok(skillMarkup.includes("Agent skills with risky instructions"), "skill findings get their own table");
assert.ok(skillMarkup.includes("Skill downloads and runs remote code"));
assert.ok(skillMarkup.includes(".claude/skills/setup/SKILL.md"));
assert.ok(!skillMarkup.includes("No dependency or secret findings"), "a run with only skill findings is not shown as clean");
const mcpState = normalizeWorkspaceFindingsState(
  { worktrees: [], runs: [] },
  {
    worktrees: [],
    assessments: [
      {
        ...ids,
        run_id: "run-mcp",
        state: "completed",
        coverage: { status: "complete", reasons: [], detectors: { supply_chain: "complete", mcp_config_v1: "complete" } },
        findings: [
          {
            finding_id: "mcp-1",
            source_kind: "workspace_source",
            detector: "mcp_config_v1",
            severity: "high",
            decision: "warn",
            rule_ids: ["mcp.config.privileged-launch"],
            path: ".mcp.json",
            server: "admin-tools",
            confidence: "strong",
            title: "MCP server launches with elevated privileges",
            reason: "The server's launch command runs through a privilege wrapper.",
            false_positive_hint: "Expected only for a server that manages the machine itself.",
          },
          { finding_id: "mcp-no-server", source_kind: "workspace_source", detector: "mcp_config_v1", rule_ids: ["mcp.config.remote-code"], path: ".mcp.json", title: "t", reason: "r" },
          { finding_id: "mcp-no-path", source_kind: "workspace_source", detector: "mcp_config_v1", rule_ids: ["mcp.config.remote-code"], server: "s", title: "t", reason: "r" },
        ],
      },
    ],
  },
).assessments[0];
assert.equal(mcpState.findings.length, 1, "an MCP finding without its server or path is dropped");
const [mcpFinding] = mcpState.findings;
assert.deepEqual(
  [mcpFinding.kind, mcpFinding.path, mcpFinding.mcp?.server, mcpFinding.skill, mcpFinding.packageName],
  ["mcp", ".mcp.json", "admin-tools", null, null],
);
const mcpMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, { worktree, newestRun: partialRun, assessment: mcpState, busyKey: null, onAction: () => {} }),
);
assert.ok(mcpMarkup.includes("MCP servers with risky launch settings"), "MCP findings get their own table");
assert.ok(mcpMarkup.includes("admin-tools") && mcpMarkup.includes(".mcp.json"));
assert.ok(mcpMarkup.includes("MCP server launches with elevated privileges"));
assert.ok(mcpMarkup.includes("Expected only for a server that manages the machine itself."));
assert.ok(!mcpMarkup.includes("No dependency or secret findings"), "a run with only MCP findings is not shown as clean");
const hookState = normalizeWorkspaceFindingsState(
  { worktrees: [], runs: [] },
  {
    worktrees: [],
    assessments: [
      {
        ...ids,
        run_id: "run-hook",
        state: "completed",
        coverage: { status: "complete", reasons: [], detectors: { supply_chain: "complete", hook_config_v1: "complete" } },
        findings: [
          {
            finding_id: "hook-1",
            source_kind: "workspace_source",
            detector: "hook_config_v1",
            severity: "critical",
            decision: "warn",
            rule_ids: ["hook.config.remote-code"],
            path: ".claude/settings.json",
            event: "SessionStart",
            confidence: "strong",
            title: "Project hook runs downloaded code",
            reason: "A hook the project configures pipes a download into a shell.",
          },
          { finding_id: "hook-no-event", source_kind: "workspace_source", detector: "hook_config_v1", rule_ids: ["hook.config.remote-code"], path: ".cursor/hooks.json", title: "t", reason: "r" },
          { finding_id: "hook-no-path", source_kind: "workspace_source", detector: "hook_config_v1", rule_ids: ["hook.config.remote-code"], event: "stop", title: "t", reason: "r" },
        ],
      },
    ],
  },
).assessments[0];
assert.equal(hookState.findings.length, 1, "a hook finding without its event or path is dropped");
const [hookFinding] = hookState.findings;
assert.deepEqual(
  [hookFinding.kind, hookFinding.path, hookFinding.hook?.event, hookFinding.mcp, hookFinding.packageName],
  ["hook", ".claude/settings.json", "SessionStart", null, null],
);
const hookMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, { worktree, newestRun: partialRun, assessment: hookState, busyKey: null, onAction: () => {} }),
);
assert.ok(hookMarkup.includes("Project hooks with risky commands"), "hook findings get their own table");
assert.ok(hookMarkup.includes("SessionStart") && hookMarkup.includes(".claude/settings.json"));
assert.ok(hookMarkup.includes("Project hook runs downloaded code"));
assert.ok(!hookMarkup.includes("No dependency or secret findings"), "a run with only hook findings is not shown as clean");
const hookGapMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, {
    worktree,
    newestRun: partialRun,
    assessment: { ...secretsRan, partial: true, reasons: ["hook_config_incomplete"], notRun: ["hook_config_v1"] },
    busyKey: null,
    onAction: () => {},
  }),
);
assert.ok(hookGapMarkup.includes("Some agent hook settings could not be fully checked"), "an incomplete hook scan is named");
assert.ok(hookGapMarkup.includes("Project hook checking is not part of this check yet."));
const skillGapMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, {
    worktree,
    newestRun: partialRun,
    assessment: { ...secretsRan, partial: true, reasons: ["skills_incomplete"], notRun: [] },
    busyKey: null,
    onAction: () => {},
  }),
);
assert.ok(skillGapMarkup.includes("Some agent skills could not be read in full"), "an incomplete skill scan is named");
const skillNotRunMarkup = renderToStaticMarkup(
  createElement(WorktreeRow, {
    worktree,
    newestRun: partialRun,
    assessment: { ...secretsRan, partial: true, notRun: ["skill_content_v1"] },
    busyKey: null,
    onAction: () => {},
  }),
);
assert.ok(skillNotRunMarkup.includes("Skill checking is not part of this check yet."));

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
assert.match(workspaceErrorMessage("workspace_snapshot_failed"), /could not read that folder/);
assert.doesNotMatch(workspaceErrorMessage("workspace_snapshot_failed"), /Check that Guard is running/);
assert.match(workspaceErrorMessage("workspace_snapshot_native_unavailable"), /runtime that reads workspace files is unavailable/);
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
