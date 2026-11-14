import { renderToStaticMarkup } from "react-dom/server";
import { plainEnglishRequestTitle } from "./evidence/plain-english";
import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";
import { describeQueueItem } from "./home-hero";
import { classifyMcpToolEffect, mcpToolInput, resolveMcpToolCallView, splitMcpToolName } from "./mcp-tool-call-view";
import { PrimaryActionCard } from "./review-states";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

// The payload a Grok X Ads call queued: the hook payload is nested inside the input.
const X_ADS_ENVELOPE: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-x-ads",
  harness: "grok",
  event_name: "PreToolUse",
  action_type: "mcp_tool",
  workspace: "/workspace/project",
  workspace_hash: null,
  tool_name: "x_ads__list_ads",
  command: null,
  prompt_excerpt: null,
  prompt_text: null,
  target_paths: [],
  network_hosts: [],
  mcp_server: "x_ads",
  mcp_tool: "list_ads",
  package_manager: null,
  package_name: null,
  script_name: null,
  raw_payload_redacted: {
    hook_event_name: "PreToolUse",
    input: {
      tool_input: { account_id: "18ce55s6o5v", line_item_id: "y1xml" },
      tool_name: "x_ads__list_ads",
    },
  },
};

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "request-x-ads",
  harness: "grok",
  artifact_id: "grok:project:x_ads__list_ads",
  artifact_name: "x_ads__list_ads",
  artifact_type: "tool_action_request",
  artifact_hash: "sha256-x-ads",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "./grok.json",
  launch_target: null,
  transport: "stdio",
  review_command: "hol-guard approvals approve request-x-ads",
  approval_url: "http://127.0.0.1:4781/approvals/request-x-ads",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-11-14T12:00:00Z",
  resolved_at: null,
  action_envelope_json: X_ADS_ENVELOPE,
};

function requestWith(envelope: Partial<GuardActionEnvelope>): GuardApprovalRequest {
  return { ...BASE_REQUEST, action_envelope_json: { ...X_ADS_ENVELOPE, ...envelope } };
}

// The reported call reads as a sentence with labelled details, not JSON.
{
  const view = resolveMcpToolCallView(BASE_REQUEST);
  assert(view !== null, "an MCP tool call gets a plain view");
  assert(view?.server === "X Ads", `server reads as a name, got ${view?.server}`);
  assert(view?.tool === "List ads", `tool reads as words, got ${view?.tool}`);
  assert(view?.sentence === "list ads in X Ads", `sentence, got ${view?.sentence}`);
  assert(view?.effect === "reads", "a list call looks up information");
  assert(
    JSON.stringify(view?.fields.map((field) => [field.label, field.value])) ===
      JSON.stringify([["Account ID", "18ce55s6o5v"], ["Line item ID", "y1xml"]]),
    `the nested hook payload is peeled off, got ${JSON.stringify(view?.fields)}`,
  );
  assert(view?.fields.every((field) => field.mono) === true, "IDs use a fixed-width face");

  const markup = renderToStaticMarkup(PrimaryActionCard({ item: BASE_REQUEST }));
  assert(markup.includes("wants to list ads in X Ads"), "the card says what the agent wants to do");
  assert(markup.includes("Tool from X Ads"), "the card names the server");
  assert(markup.includes("Looks up information"), "the card says it only reads");
  assert(markup.includes("<dt") && markup.includes("Account ID"), "inputs are labelled rows");
  assert(markup.includes("Technical details"), "the raw input stays one click away");
  assert(markup.includes("<details"), "the raw input is collapsed by default");
  assert(!markup.includes("MCP server / tool"), "the jargon label is gone");
  assert(markup.indexOf("Account ID") < markup.indexOf("Technical details"), "plain details come first");

  assert(plainEnglishRequestTitle(BASE_REQUEST) === "Grok wants to list ads in X Ads", plainEnglishRequestTitle(BASE_REQUEST));
  assert(describeQueueItem(BASE_REQUEST) === "wants to list ads in X Ads", describeQueueItem(BASE_REQUEST));
}

// Calls that change things are flagged; unknown verbs say Guard can't tell.
{
  const send = resolveMcpToolCallView(requestWith({ mcp_server: "slack", mcp_tool: "slack_send_message" }));
  assert(send?.tool === "Send message" && send.server === "Slack", `server prefix is dropped, got ${send?.tool}`);
  assert(send?.effect === "changes", "send is a change");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item: requestWith({ mcp_server: "slack", mcp_tool: "send_message" }) }));
  assert(markup.includes("Can make changes"), "the card flags a change");

  const report = resolveMcpToolCallView(requestWith({ mcp_server: "github", mcp_tool: "pr_report" }));
  assert(report?.effect === "unknown", "an unknown verb is not guessed");
  assert(report?.sentence === "use “PR report” from GitHub", `unknown sentence, got ${report?.sentence}`);
}

// Harness spellings of tool names all split into server and tool.
{
  assert(JSON.stringify(splitMcpToolName("mcp__github__create_issue")) === JSON.stringify({ server: "github", tool: "create_issue" }), "claude spelling");
  assert(JSON.stringify(splitMcpToolName("mcp__codex_apps__gmail__gmail_send")) === JSON.stringify({ server: "gmail", tool: "send" }), "codex apps spelling");
  assert(JSON.stringify(splitMcpToolName("x_ads__list_ads")) === JSON.stringify({ server: "x_ads", tool: "list_ads" }), "grok spelling");
  assert(JSON.stringify(splitMcpToolName("chrome-devtools:click")) === JSON.stringify({ server: "chrome-devtools", tool: "click" }), "colon spelling");
  assert(JSON.stringify(splitMcpToolName("search")) === JSON.stringify({ server: null, tool: "search" }), "bare tool");
  assert(classifyMcpToolEffect("deleteRecord") === "changes", "camelCase verbs are read");
}

// Inputs: string JSON is parsed, nested objects flatten one level, long lists are cut.
{
  const input = mcpToolInput({ arguments: "{\"query\":\"open invoices\"}" });
  assert(JSON.stringify(input) === "{\"query\":\"open invoices\"}", "a JSON string input is parsed");
  const ownArguments = mcpToolInput({ tool_input: { input: "text", name: "recipient" } });
  assert(
    JSON.stringify(ownArguments) === "{\"input\":\"text\",\"name\":\"recipient\"}",
    `a tool's own input/name arguments are not taken for a hook wrapper, got ${JSON.stringify(ownArguments)}`,
  );
  const singleArgument = mcpToolInput({ tool_input: { arguments: "--verbose" } });
  assert(JSON.stringify(singleArgument) === "{\"arguments\":\"--verbose\"}", "a lone arguments field stays a field");
  const view = resolveMcpToolCallView(requestWith({
    raw_payload_redacted: {
      tool_input: {
        filter: { status: "active", owner: { id: "u-1" } },
        tags: ["a", "b", "c", "d", "e", "f", "g"],
        dry_run: false,
        note: "",
      },
    },
  }));
  const rows = Object.fromEntries((view?.fields ?? []).map((field) => [field.label, field.value]));
  assert(rows["Filter › Status"] === "active", `nested values get a path label, got ${JSON.stringify(rows)}`);
  assert(rows["Filter › Owner"] === "1 setting", "depth is bounded");
  assert(rows["Tags"] === "a, b, c, d, e and 2 more", rows["Tags"]);
  assert(rows["Dry run"] === "No", "booleans read as Yes/No");
  assert(rows["Note"] === "Empty", "empty strings say so");

  const many = Object.fromEntries(Array.from({ length: 15 }, (_, index) => [`field_${index}`, index]));
  const capped = resolveMcpToolCallView(requestWith({ raw_payload_redacted: { tool_input: many } }));
  assert(capped?.fields.length === 12 && capped.hiddenFieldCount === 3, "long inputs are capped with a count");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item: requestWith({ raw_payload_redacted: { tool_input: many } }) }));
  assert(markup.includes("3 more details are in the"), "the card says where the rest are");
}

// Anything that is not a tool call keeps the existing panel.
{
  const shell = requestWith({ action_type: "shell_command", command: "ls", mcp_server: null, mcp_tool: null, tool_name: "Bash" });
  assert(resolveMcpToolCallView({ ...shell, artifact_type: "command" }) === null, "shell commands are not tool calls");
}

console.log("mcp-tool-call-view tests passed");
