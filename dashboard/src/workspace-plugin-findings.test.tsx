import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { normalizeWorkspaceFindingsState } from "./workspace-findings-api";
import { WorktreeRow } from "./workspace-findings-workspace";

const ids = { codebase_key: "c".repeat(64), worktree_key: "w".repeat(64) };
const pluginFinding = {
  source_kind: "workspace_source",
  detector: "plugin_manifest_v1",
  rule_ids: ["hook.config.remote-code"],
  path: "plugins/helper/hooks/hooks.json",
  title: "t",
  reason: "r",
};

function stateWith(findings: Record<string, unknown>[], coverage: Record<string, unknown>) {
  return normalizeWorkspaceFindingsState(
    { worktrees: [], runs: [{ ...ids, run_id: "run-plugin", state: "completed", trigger_kind: "manual" }] },
    {
      worktrees: [{ ...ids, root: "/Users/dev/app", stale: false, paused: false }],
      assessments: [{ ...ids, run_id: "run-plugin", state: "completed", coverage, findings }],
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
      ...pluginFinding,
      finding_id: "plugin-hook",
      severity: "critical",
      decision: "warn",
      component: "hook",
      event: "SessionStart",
      confidence: "strong",
      title: "Project hook runs downloaded code",
      reason: "A hook the project configures pipes a download into a shell.",
    },
    {
      ...pluginFinding,
      finding_id: "plugin-server",
      severity: "high",
      decision: "warn",
      rule_ids: ["mcp.config.remote-code"],
      path: "plugins/helper/.mcp.json",
      component: "mcp_server",
      server: "fetcher",
      title: "MCP server runs downloaded code",
      reason: "A server the plugin ships pipes a download into a shell.",
    },
    { ...pluginFinding, finding_id: "no-name", component: "hook" },
    { ...pluginFinding, finding_id: "wrong-name", component: "hook", server: "fetcher" },
    { ...pluginFinding, finding_id: "no-component", event: "SessionStart" },
    { ...pluginFinding, finding_id: "no-path", component: "hook", event: "SessionStart", path: undefined },
    { ...pluginFinding, finding_id: "no-rule", component: "hook", event: "SessionStart", rule_ids: [] },
  ],
  { status: "complete", reasons: [], detectors: { supply_chain: "complete", plugin_manifest_v1: "complete" } },
);
const findings = state.assessments[0].findings;
assert.equal(findings.length, 2, "a plugin finding without its path, rule, component or matching name is dropped");
const [hook, server] = findings;
assert.deepEqual(
  [hook.kind, hook.path, hook.hook?.event, hook.hook?.confidence, hook.mcp, hook.packageName],
  ["plugin", "plugins/helper/hooks/hooks.json", "SessionStart", "strong", null, null],
  "a plugin hook finding carries its event and the hook check",
);
assert.deepEqual(
  [server.kind, server.path, server.mcp?.server, server.hook],
  ["plugin", "plugins/helper/.mcp.json", "fetcher", null],
  "a plugin server finding carries its server name and the MCP check",
);

const markup = render(state);
assert.ok(markup.includes("Agent plugins with risky hooks or MCP servers"), "plugin findings get their own table");
assert.ok(markup.includes("SessionStart hook") && markup.includes("plugins/helper/hooks/hooks.json"));
assert.ok(markup.includes("fetcher MCP server") && markup.includes("plugins/helper/.mcp.json"));
assert.ok(markup.includes("Project hook runs downloaded code") && markup.includes("MCP server runs downloaded code"));
assert.ok(!markup.includes("No dependency or secret findings"), "a run with only plugin findings is not shown as clean");
assert.ok(!markup.includes("Prepare fix"), "a plugin finding is a warning with no fix");

const gapMarkup = render(
  stateWith([], {
    status: "partial",
    reasons: ["plugin_manifest_incomplete", "detector_not_run:plugin_manifest_v1"],
    detectors: { supply_chain: "complete", plugin_manifest_v1: "not_run" },
  }),
);
assert.ok(gapMarkup.includes("Some agent plugin files could not be fully read"), "an incomplete plugin scan is named");
assert.ok(gapMarkup.includes("Agent plugin checking is not part of this check yet."), "a plugin scan that did not run is named");
