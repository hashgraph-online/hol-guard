import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { readFileSync } from "node:fs";
import { McpCrossExamWorkspace, normalizeMcpCrossExamResults } from "./mcp-cross-exam-workspace";

const markup = renderToStaticMarkup(createElement(McpCrossExamWorkspace));
assert.match(markup, /Protocol audit, not a policy decision/);
assert.match(markup, /Warning/);
assert.doesNotMatch(markup, /\bBlock\b/);
assert.doesNotMatch(markup, /runAuditRemediation/);
assert.doesNotMatch(markup, /Inbox/);

const enabled = normalizeMcpCrossExamResults({
  enabled: true,
  runs: [
    {
      run_id: "run-1",
      target: "http://127.0.0.1:8765/mcp",
      transport: "http",
      status: "incomplete",
      score: 72,
      coverage: "partial",
      finding_count: 2,
      probes: ["schema.undeclared-required-arg"],
      tools: ["search"],
      artifacts: ["/tmp/mcp-cross-exam-results/report.json"],
      auditor_version: "0.1.0",
      finished_at: "2026-11-02T00:00:00+00:00",
    },
  ],
});
assert.equal(enabled.enabled, true);
assert.equal(enabled.runs[0]?.coverage, "partial");
assert.equal(enabled.runs[0]?.findingCount, 2);

const source = readFileSync(new URL("./mcp-cross-exam-workspace.tsx", import.meta.url), "utf8");
assert.match(source, /fetchGuardApi/);
assert.match(source, /\/v1\/mcp-cross-exam\/results/);
assert.doesNotMatch(source, /runAuditRemediation/);
assert.doesNotMatch(source, /\bBlock\b/);

console.log("mcp-cross-exam-workspace.test.tsx: all assertions passed");
