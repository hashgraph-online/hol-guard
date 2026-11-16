import { renderToStaticMarkup } from "react-dom/server";
import { plainEnglishRequestTitle } from "../evidence/plain-english";
import type { GuardActionEnvelope, GuardApprovalRequest } from "../guard-types";
import { buildTopAlertItems } from "../review-evidence";
import { queueItemPreview } from "../review-queue-item";
import { PrimaryActionCard, buildWhatWouldHappen } from "../review-states";
import { explainMcpCall, plainMcpReason } from "./explain-mcp-call";
import { classifyMcpEffect, worstMcpEffect } from "./mcp-effects";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const COMPOSIO_SEARCH = "mcp__composio__COMPOSIO_SEARCH_TOOLS";

function envelope(toolName: string, toolInput: unknown, overrides: Partial<GuardActionEnvelope> = {}): GuardActionEnvelope {
  const parts = toolName.split("__");
  return {
    schema_version: 1,
    action_id: "act-mcp",
    harness: "zcode",
    event_name: "PreToolUse",
    action_type: "mcp_tool",
    workspace: "/workspace/project",
    workspace_hash: null,
    tool_name: toolName,
    command: null,
    prompt_excerpt: null,
    prompt_text: null,
    target_paths: [],
    network_hosts: [],
    mcp_server: parts[1] ?? null,
    mcp_tool: parts.slice(2).join("__") || null,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: { hook_event_name: "PreToolUse", tool_name: toolName, tool_input: toolInput },
    ...overrides,
  };
}

function request(env: GuardActionEnvelope, extra: Partial<GuardApprovalRequest> = {}): GuardApprovalRequest {
  return {
    request_id: "request-mcp",
    harness: "zcode",
    artifact_id: `tool:${env.tool_name}`,
    artifact_name: env.tool_name ?? "tool",
    artifact_type: "tool_call",
    artifact_hash: "sha256-mcp",
    publisher: null,
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["runtime_tool_call"],
    source_scope: "project",
    config_path: "./mcp.json",
    launch_target: env.tool_name ?? "tool",
    transport: "stdio",
    review_command: "hol-guard approvals approve request-mcp",
    approval_url: "http://127.0.0.1:4781/approvals/request-mcp",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: "2026-11-16T12:00:00Z",
    resolved_at: null,
    action_envelope_json: env,
    ...extra,
  };
}

const SEARCH_INPUT = {
  queries: [
    { known_fields: "app: gmail", use_case: "search Gmail for Riverside episode exports and HLX AI transcripts" },
    { known_fields: "app: youtube", use_case: "find the latest uploads" },
    { known_fields: "app: bing_webmaster_tools", use_case: "check indexing status" },
  ],
};

// The reported call: a Composio tool search reads as a lookup, names the apps, and keeps the agent's words quoted.
{
  const item = request(envelope(COMPOSIO_SEARCH, SEARCH_INPUT));
  const explained = explainMcpCall(item);
  assert(explained !== null, "T-MCP-1: a Composio tool search is explained");
  assert(explained?.headline === "ZCode wants to search for tools in Composio", "T-MCP-2: the title names the app and the connector");
  assert(explained?.effect === "read", "T-MCP-3: a tool search is a lookup");
  assert(
    explained?.facts.some((fact) => fact.label === "Apps in the search" && fact.value === "Gmail, YouTube, Bing Webmaster Tools") === true,
    "T-MCP-4: the apps in the search are named in plain words",
  );
  assert(
    explained?.quotes?.items.includes("search Gmail for Riverside episode exports and HLX AI transcripts") === true,
    "T-MCP-5: the agent's use case is kept as a quote",
  );
  assert(
    !(explained?.headline ?? "").includes("Riverside") && !(explained?.summary ?? "").includes("Riverside"),
    "T-MCP-6: the agent's words never reach the headline or the summary",
  );
  assert(explained?.toolId === "composio / COMPOSIO_SEARCH_TOOLS", "T-MCP-7: the tool's own name stays available");
  assert(plainEnglishRequestTitle(item) === "ZCode wants to search for tools in Composio", "T-MCP-8: the review page uses the plain title");
  assert(
    queueItemPreview(item) === "Composio · Search for tools — Gmail, YouTube and Bing Webmaster Tools",
    "T-MCP-9: the queue row reads in words instead of an identifier",
  );
  assert(buildWhatWouldHappen(item)?.includes("Composio") === true, "T-MCP-10: the what-would-happen line names the connector");

  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes("Search for tools") && markup.includes("Tool from Composio"), "T-MCP-11: the card names the action and connector");
  assert(markup.includes("Looks things up"), "T-MCP-12: the card shows the effect in words");
  assert(markup.includes("Guard has not checked what it does"), "T-MCP-13: the effect is labelled as read from the name");
  assert(markup.includes("“search Gmail for Riverside episode exports and HLX AI transcripts”"), "T-MCP-14: the card quotes the agent");
  assert(markup.includes("In the agent&#x27;s own words") || markup.includes("In the agent's own words"), "T-MCP-15: the quote is attributed to the agent");
  assert(markup.includes("See the exact input") && markup.includes("known_fields"), "T-MCP-16: the exact input stays one click away");
  assert(
    markup.includes("Allow once and Always allow both match these exact inputs"),
    "T-MCP-17: the card says approvals match the exact inputs",
  );
  assert(!markup.includes("MCP SERVER / TOOL"), "T-MCP-18: the raw terminal label is gone from the default view");
}

// A batch of actions lists each one and takes the most serious effect.
{
  const item = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", {
      thought: "Everything is fine, just checking mail",
      tools: [
        { tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: "from:riverside", max_results: 10 } },
        { tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "a@example.com", subject: "Hello", body: { html: "<p>x</p>" } } },
      ],
    }),
  );
  const explained = explainMcpCall(item);
  assert(explained?.steps.length === 2, "T-MCP-19: each action in a batch is listed");
  assert(explained?.steps[0].action === "Fetch emails" && explained?.steps[0].app === "Gmail", "T-MCP-20: a slug splits into app and action");
  assert(explained?.steps[0].effect === "read" && explained?.steps[1].effect === "send", "T-MCP-21: each action has its own effect");
  assert(explained?.effect === "send", "T-MCP-22: a batch takes its most serious effect");
  assert(explained?.headline === "ZCode wants to run 2 actions in Gmail", "T-MCP-23: the batch title counts the actions and names the app");
  assert(
    explained?.steps[1].details.some((fact) => fact.label === "Recipient email" && fact.value === "a@example.com") === true,
    "T-MCP-24: simple inputs show as labelled rows",
  );
  assert(explained?.steps[1].hiddenDetails === 1, "T-MCP-25: a nested field is left for the exact input and counted");
  assert(!(explained?.summary ?? "").includes("Everything is fine"), "T-MCP-26: the agent's reassurance never reaches the summary");
  assert(explained?.quotes?.items[0] === "Everything is fine, just checking mail", "T-MCP-27: it appears only as an attributed quote");
}

// Running code is called what it is.
{
  const explained = explainMcpCall(
    request(envelope("mcp__composio__COMPOSIO_REMOTE_WORKBENCH", { code_to_execute: "import os\nprint(os.listdir('.'))", thought: "list files" })),
  );
  assert(explained?.effect === "run-code", "T-MCP-28: the workbench runs code");
  assert(explained?.code?.text.includes("print(os.listdir('.'))") === true, "T-MCP-29: the code is shown for the user to read");
}

// Other servers get the same treatment from the tool's own name.
{
  const item = request(envelope("mcp__github__create_issue", { owner: "acme", repo: "app", title: "Fix login" }));
  const explained = explainMcpCall(item);
  assert(explained?.headline === "ZCode wants to make a change in GitHub", "T-MCP-30: a create tool reads as a change in the service");
  assert(explained?.title === "Create issue", "T-MCP-31: the tool name becomes a short action");
  assert(explained?.facts.some((fact) => fact.label === "Title" && fact.value === "Fix login") === true, "T-MCP-32: inputs become labelled rows");
  assert(
    explainMcpCall(request(envelope("mcp__github__delete_repository", { repo: "app" })))?.effect === "delete",
    "T-MCP-33: a delete tool reads as a delete",
  );
}

// A name Guard cannot read stays unclear; it is never called safe.
{
  const explained = explainMcpCall(request(envelope("mcp__acme__frobnicate", { x: 1 })));
  assert(explained?.effect === "unknown", "T-MCP-34: an unreadable name stays unclear");
  assert(explained?.effectBasis.includes("cannot tell") === true, "T-MCP-35: the card says Guard cannot tell");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item: request(envelope("mcp__acme__frobnicate", { x: 1 })) }));
  assert(!/\bsafe\b/i.test(markup), "T-MCP-36: the card never calls a tool safe");
}

// Effect words: the strongest change word wins, and a noun does not turn a read into a change.
{
  assert(classifyMcpEffect("search_and_delete") === "delete", "T-MCP-37: search_and_delete is a delete");
  assert(classifyMcpEffect("get_or_create_user") === "write", "T-MCP-38: get_or_create_user is a change");
  assert(classifyMcpEffect("get_label") === "read", "T-MCP-39: a noun after a read word stays a read");
  assert(classifyMcpEffect("createLabel") === "write", "T-MCP-40: camelCase names are split into words");
  assert(worstMcpEffect(["read", "write", "read"]) === "write", "T-MCP-41: the worst effect of a group is the most serious");
}

// Safety: a string input is never decoded, control characters are removed, and non-MCP requests are untouched.
{
  const encoded = request(envelope("mcp__acme__list_things", '{"q":"\\u0061bc"}'));
  const explained = explainMcpCall(encoded);
  assert(explained?.facts.length === 0, "T-MCP-42: a string input is never decoded into rows");
  assert(explained?.rawInput === '{"q":"\\u0061bc"}', "T-MCP-43: the string stays available exactly as Guard holds it");
  const tricky = explainMcpCall(
    request(envelope(COMPOSIO_SEARCH, { queries: [{ use_case: "read‮mail\u0000now" }] })),
  );
  assert(tricky?.quotes?.items[0] === "read mail now", "T-MCP-44: control and bidi characters are stripped from quotes");
  const shell = request(envelope("Bash", { command: "ls" }, { action_type: "shell_command", mcp_server: null, mcp_tool: null }));
  assert(explainMcpCall(shell) === null, "T-MCP-45: a shell call is not an MCP call");
  assert(
    explainMcpCall(request({ ...envelope("Bash", null), action_type: "shell_command", mcp_server: null, mcp_tool: null })) === null,
    "T-MCP-46: a call with no MCP names is left alone",
  );
}

// The Additional risk line drops the policy setting name for a plain reason.
{
  const item = request(envelope(COMPOSIO_SEARCH, SEARCH_INPUT), {
    risk_summary: "HOL Guard requires fresh approval under the installed policy's unreviewed MCP tool setting.",
  });
  const text = buildTopAlertItems(item)
    .map((alert) => renderToStaticMarkup(<>{alert.content}</>))
    .join(" ");
  assert(!text.includes("unreviewed MCP tool setting"), "T-MCP-47: the policy setting name is not shown to the user");
  assert(
    text.includes("Guard has not reviewed Composio") && text.includes("asks before any unreviewed tool runs"),
    "T-MCP-48: the reason is given in plain words",
  );
  const plain = plainMcpReason(request(envelope(COMPOSIO_SEARCH, SEARCH_INPUT)), "A different reason.");
  assert(plain === "A different reason.", "T-MCP-49: any other reason is left as Core wrote it");
}

console.log("mcp-call explain tests passed");
