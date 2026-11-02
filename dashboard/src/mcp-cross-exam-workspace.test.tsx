import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { MCPCrossExamWorkspace, normalizeMCPCrossExamResults } from "./mcp-cross-exam-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const markup = renderToStaticMarkup(createElement(MCPCrossExamWorkspace));
assert(/Protocol audit, not a policy decision/.test(markup), "workspace states it is not a policy decision");
assert(/Warning/.test(markup), "workspace keeps the Warning tone");
assert(!/\bBlock\b/.test(markup), "workspace does not offer Block");
assert(!/runAuditRemediation/.test(markup), "workspace does not offer remediation");
assert(!/Inbox/.test(markup), "workspace does not route through Inbox");

const enabled = normalizeMCPCrossExamResults({
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
assert(enabled.enabled === true, "enabled payload stays enabled");
assert(enabled.runs[0]?.coverage === "partial", "partial coverage is preserved");
assert(enabled.runs[0]?.findingCount === 2, "finding count is preserved");

console.log("mcp-cross-exam-workspace.test.tsx: all assertions passed");
