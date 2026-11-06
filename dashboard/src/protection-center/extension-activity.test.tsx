import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { buildDemoRuntimeSnapshot, normalizeRuntimeSnapshot } from "../guard-api";
import type { GuardReceipt } from "../guard-types";
import { protectionModuleFixture } from "./fixtures/protection-fixtures";
import { ExtensionActivity, recentExtensionReceipts } from "./extension-activity";

const extension = protectionModuleFixture({ executables: ["git"] });
function receipt(id: string, timestamp: string, toolName: string): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: "a".repeat(64),
    policy_decision: id === "blocked" ? "block" : "allow",
    capabilities_summary: "Git command protection",
    changed_capabilities: [],
    provenance_summary: "Guard decision",
    user_override: null,
    source_scope: null,
    timestamp,
    action_envelope_json: {
      schema_version: 1,
      action_id: id,
      harness: "codex",
      event_name: "tool.execute",
      action_type: "shell_command",
      workspace: null,
      workspace_hash: null,
      tool_name: toolName,
      command: null,
      prompt_excerpt: null,
      target_paths: [],
      network_hosts: [],
      mcp_server: null,
      mcp_tool: null,
      package_manager: null,
      package_name: null,
      script_name: null,
      raw_payload_redacted: {},
    },
  };
}

const receipts = [
  receipt("allowed", "2026-08-24T12:00:00Z", "git"),
  receipt("blocked", "2026-08-25T12:00:00Z", "git"),
  receipt("unrelated", "2026-08-26T12:00:00Z", "npm"),
];
assert.deepEqual(recentExtensionReceipts(receipts, extension).map((item) => item.receipt_id), ["blocked", "allowed"]);

const markup = renderToStaticMarkup(createElement(ExtensionActivity, { extension, receipts }));
assert.match(markup, /Recent Extension decisions/);
assert.match(markup, /Blocked · codex/);
assert.match(markup, /Allowed · codex/);
assert.match(markup, /selected=blocked/);
assert.doesNotMatch(markup, /unrelated/);

const normalizedCommandReceipt = normalizeRuntimeSnapshot({
  ...buildDemoRuntimeSnapshot(),
  latest_receipts: [{
    ...receipt("normalized-command", "2026-08-27T12:00:00Z", "unrelated-tool"),
    action_envelope_json: {
      ...receipt("normalized-command", "2026-08-27T12:00:00Z", "unrelated-tool").action_envelope_json,
      command_category: "command.git",
    },
  }],
}).latest_receipts[0];
assert.equal(normalizedCommandReceipt?.action_envelope_json?.command_category, "command.git");
assert.deepEqual(
  recentExtensionReceipts(normalizedCommandReceipt ? [normalizedCommandReceipt] : [], extension)
    .map((item) => item.receipt_id),
  ["normalized-command"],
  "Activity attributes a command receipt after the production runtime normalization path",
);

const oversizedCategoryReceipt = normalizeRuntimeSnapshot({
  ...buildDemoRuntimeSnapshot(),
  latest_receipts: [{
    ...receipt("oversized-category", "2026-08-28T12:00:00Z", "unrelated-tool"),
    action_envelope_json: {
      ...receipt("oversized-category", "2026-08-28T12:00:00Z", "unrelated-tool").action_envelope_json,
      command_category: "x".repeat(161),
    },
  }],
}).latest_receipts[0];
assert.equal(oversizedCategoryReceipt?.action_envelope_json, null, "oversized command attribution is rejected");

console.log("extension-activity.test.tsx: all assertions passed");
