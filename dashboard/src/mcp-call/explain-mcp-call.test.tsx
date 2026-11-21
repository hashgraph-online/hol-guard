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
    !(explained?.headline ?? "").includes("Riverside") &&
      !(explained?.consequence.text ?? "").includes("Riverside") &&
      !(explained?.aside ?? "").includes("Riverside"),
    "T-MCP-6: the agent's words never reach the headline, the consequence or the aside",
  );
  assert(explained?.toolId === "composio / COMPOSIO_SEARCH_TOOLS", "T-MCP-7: the tool's own name stays available");
  assert(plainEnglishRequestTitle(item) === "ZCode wants to search for tools in Composio", "T-MCP-8: the review page uses the plain title");
  assert(
    queueItemPreview(item) === "Composio · Search for tools — Gmail, YouTube and Bing Webmaster Tools",
    "T-MCP-9: the queue row reads in words instead of an identifier",
  );
  assert(buildWhatWouldHappen(item) === null, "T-MCP-10: the card says what approving does, so no what-would-happen filler is added");

  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes("Search for tools") && markup.includes("Tool from Composio"), "T-MCP-11: the card names the action and connector");
  assert(markup.includes("Looks things up"), "T-MCP-12: the card shows the effect in words");
  assert(markup.includes("Guard has not checked what it does"), "T-MCP-13: the effect is labelled as read from the name");
  assert(markup.includes("“search Gmail for Riverside episode exports and HLX AI transcripts”"), "T-MCP-14: the card quotes the agent");
  assert(markup.includes("In the agent&#x27;s own words") || markup.includes("In the agent's own words"), "T-MCP-15: the quote is attributed to the agent");
  assert(markup.includes("See the exact input") && markup.includes("known_fields"), "T-MCP-16: the exact input stays one click away");
  assert(
    markup.includes("Allow once and Always allow both cover only these exact inputs"),
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
  assert(explained?.steps[0].action === "Get emails" && explained?.steps[0].app === "Gmail", "T-MCP-20: a slug splits into app and action");
  assert(explained?.steps[0].effect === "read" && explained?.steps[1].effect === "send", "T-MCP-21: each action has its own effect");
  assert(explained?.effect === "send", "T-MCP-22: a batch takes its most serious effect");
  assert(explained?.headline === "ZCode wants to take 2 actions in Gmail", "T-MCP-23: the batch title counts the actions and names the app");
  assert(
    explained?.steps[1].details.some((fact) => fact.label === "To" && fact.value === "a@example.com" && fact.kind === "email") === true,
    "T-MCP-24: a send action puts who it goes to first, under a plain label",
  );
  assert(explained?.steps[1].hiddenDetails === 1, "T-MCP-25: a nested field is left for the exact input and counted");
  assert(
    !(explained?.consequence.text ?? "").includes("Everything is fine") && !(explained?.aside ?? "").includes("Everything is fine"),
    "T-MCP-26: the agent's reassurance never reaches the consequence or the aside",
  );
  assert(explained?.quotes?.items[0] === "Everything is fine, just checking mail", "T-MCP-27: it appears only as an attributed quote");
}

// A long batch still counts every action: only the rows are capped.
{
  const reads = Array.from({ length: 10 }, (_, index) => ({ tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: `q${index}` } }));
  const item = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", { tools: [...reads, { tool_slug: "GMAIL_DELETE_MESSAGE", arguments: { message_id: "m1" } }] }),
  );
  const explained = explainMcpCall(item);
  assert(explained?.steps.length === 10 && explained?.hiddenSteps === 1, "T-MCP-50: the card lists ten rows and counts the rest");
  assert(explained?.effect === "delete", "T-MCP-51: an action past the tenth row still sets the effect");
  assert(explained?.headline === "ZCode wants to take 11 actions in Gmail", "T-MCP-52: the title counts every action");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes("1 more action in the exact input"), "T-MCP-53: the card says an action is left in the exact input");
  const odd = explainMcpCall(
    request(envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", { tools: [{ tool_slug: "GMAIL_FETCH_EMAILS", arguments: {} }, "not an object", 7] })),
  );
  assert(odd?.effect === "unknown" && odd?.steps.length === 3, "T-MCP-54: an entry that is not an object reads as an action Guard cannot identify");
  assert(odd?.headline === "ZCode wants to take 3 actions in Gmail", "T-MCP-55: the title counts entries that are not objects");
}

// The rows and the exact input come from the same value, chosen the way Core chooses it.
{
  const raw = { tool_input: '{"first":"value"}', toolInput: { second: "other" } };
  const item = request(envelope("mcp__acme__list_things", null, { raw_payload_redacted: { tool_name: "mcp__acme__list_things", ...raw } }));
  const explained = explainMcpCall(item);
  assert(explained?.facts.length === 0, "T-MCP-56: rows never come from a later key when Core's input is a JSON string");
  assert(explained?.rawInput === '{"first":"value"}', "T-MCP-57: the exact input is the one Core uses");
  const empty = explainMcpCall(request(envelope("mcp__acme__list_things", {})));
  assert(empty?.rawInput === "{}", "T-MCP-58: an empty object Core accepts is shown as the input");
  const skipped = explainMcpCall(
    request(envelope("mcp__acme__list_things", null, { raw_payload_redacted: { tool_name: "mcp__acme__list_things", tool_input: "42", toolInput: { q: "x" } } })),
  );
  assert(skipped?.facts[0]?.value === "x" && skipped?.rawInput === JSON.stringify({ q: "x" }, null, 2), "T-MCP-59: a string Core skips does not hide the next key");
}

// Names that match object-prototype members are ordinary names.
{
  const item = request(envelope("mcp__constructor__constructor", { x: 1 }));
  const explained = explainMcpCall(item);
  assert(explained?.connector === "Constructor", "T-MCP-60: a server named constructor reads as a name");
  assert(typeof explained?.title === "string" && explained.title === "Constructor", "T-MCP-61: a tool named constructor reads as a name");
  assert(renderToStaticMarkup(PrimaryActionCard({ item })).includes("Tool from Constructor"), "T-MCP-62: the card renders for such a name");
  assert(classifyMcpEffect("toString") === "unknown" && classifyMcpEffect("hasOwnProperty") === "unknown", "T-MCP-63: prototype member names stay unclear");
}

// Codex reaches connectors through codex_apps; the connector is the service the user knows.
{
  const item = request(
    envelope("mcp__codex_apps__composio__COMPOSIO_MULTI_EXECUTE_TOOL", {
      tools: [{ tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "a@example.com" } }],
    }),
  );
  assert(item.action_envelope_json?.mcp_server === "codex_apps", "T-MCP-64: the recorded server is the Codex wrapper");
  const explained = explainMcpCall(item);
  assert(explained?.connector === "Composio" && explained?.steps.length === 1, "T-MCP-65: the connector and its actions are read through the wrapper");
  assert(explained?.headline === "ZCode wants to send email in Gmail", "T-MCP-66: the title names the connector's app");
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
  assert(explained?.consequence.text.includes("cannot tell") === true && explained?.effectBasis === "", "T-MCP-35: the card says Guard cannot tell, once");
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
  const whyAsked = explainMcpCall(item)?.whyAsked ?? "";
  assert(
    whyAsked.includes("has not reviewed this Composio tool") && !text.includes("has not reviewed"),
    "T-MCP-48: the reason is given once, in plain words on the card, not repeated above it",
  );
  const plain = plainMcpReason(request(envelope(COMPOSIO_SEARCH, SEARCH_INPUT)), "A different reason.");
  assert(plain === "A different reason.", "T-MCP-49: any other reason is left as Core wrote it");
}

// Core takes a call's input from `toolCalls` when the top-level input is empty, and the card follows.
{
  const name = "mcp__acme__list_things";
  const withCalls = (payload: Record<string, unknown>) =>
    explainMcpCall(request(envelope(name, null, { raw_payload_redacted: { tool_name: name, ...payload } })));
  const fromCalls = withCalls({ toolCalls: [{ name, args: { q: "hello" } }] });
  assert(fromCalls?.facts[0]?.value === "hello" && fromCalls?.rawInput === JSON.stringify({ q: "hello" }, null, 2), "T-MCP-67: an input held only in toolCalls fills the rows and the exact input");
  const afterEmpty = withCalls({ tool_input: {}, toolCalls: [{ name, args: { q: "again" } }] });
  assert(afterEmpty?.facts[0]?.value === "again", "T-MCP-68: an empty top-level input falls back to toolCalls");
  const kept = withCalls({ tool_input: { q: "top" }, toolCalls: [{ name, args: { q: "call" } }] });
  assert(kept?.facts[0]?.value === "top", "T-MCP-69: a non-empty top-level input is kept");
  const matched = withCalls({ toolCalls: [{ name: "other", args: { q: "no" } }, { name, args: { q: "yes" } }] });
  assert(matched?.facts[0]?.value === "yes", "T-MCP-70: the call named like the tool is the one used");
}

// A string Core cannot have cut is skipped; one at the cut length may be Core's input.
{
  const name = "mcp__acme__list_things";
  const skipped = explainMcpCall(
    request(envelope(name, null, { raw_payload_redacted: { tool_name: name, tool_input: "not JSON", toolInput: { q: "x" } } })),
  );
  assert(skipped?.rawInput === JSON.stringify({ q: "x" }, null, 2), "T-MCP-71: a short string that is not JSON does not become the exact input");
  const cut = `{"q":"${"a".repeat(233)}…`;
  const long = explainMcpCall(request(envelope(name, null, { raw_payload_redacted: { tool_name: name, tool_input: cut, toolInput: { q: "x" } } })));
  assert(cut.length === 240 && long?.rawInput === cut && long?.facts.length === 0, "T-MCP-72: a string cut at the limit is shown as recorded, with no rows");
  assert(long?.truncated === true, "T-MCP-73: a cut input string is called shortened");
}

// A long string that is not a cut object is skipped, and the first named toolCalls item stays the fallback.
{
  const name = "mcp__acme__list_things";
  const notObject = `not an object ${"a".repeat(225)}…`;
  const skipped = explainMcpCall(
    request(envelope(name, null, { raw_payload_redacted: { tool_name: name, tool_input: notObject, toolInput: { q: "x" } } })),
  );
  assert(notObject.length === 240 && skipped?.rawInput === JSON.stringify({ q: "x" }, null, 2), "T-MCP-81: a long string that does not start like an object is skipped");
  const noArgsFirst = explainMcpCall(
    request(envelope(name, null, { raw_payload_redacted: { tool_name: "c", toolCalls: [{ name: "a" }, { name: "b", args: { q: "x" } }] } })),
  );
  assert(noArgsFirst?.rawInput === null && noArgsFirst?.facts.length === 0, "T-MCP-82: the first named call stays the fallback even with no args");
}

// Bidirectional controls show as escapes in the exact input.
{
  const explained = explainMcpCall(request(envelope("mcp__acme__list_things", { file: "invoice\u202etxt.exe" })));
  assert(explained?.rawInput?.includes("invoice\\u202etxt.exe") === true && !explained.rawInput.includes("\u202e"), "T-MCP-74: a bidi control is escaped in the exact input");
}

// The recorded server can be the Codex wrapper while `mcp_tool` holds the whole name.
{
  const whole = "mcp__codex_apps__composio__COMPOSIO_SEARCH_TOOLS";
  const item = request(envelope(whole, SEARCH_INPUT, { mcp_server: "codex_apps", mcp_tool: whole }));
  const explained = explainMcpCall(item);
  assert(explained?.connector === "Composio" && explained?.title === "Search for tools", "T-MCP-75: the connector is read from a whole mcp_tool name");
}

// The agent's own text is quoted, never a row or the queue detail.
{
  const thought = explainMcpCall(request(envelope("mcp__acme__list_things", { thought: "checking things", q: "x" })));
  assert(thought?.facts.every((fact) => fact.label !== "Thought") === true && thought?.queueDetail === "x", "T-MCP-76: a thought is not a row or the queue detail");
  assert(thought?.quotes?.items[0] === "checking things", "T-MCP-77: the thought is quoted");
  const useCase = explainMcpCall(request(envelope("mcp__acme__list_things", { use_case: "find mail", q: "y" })));
  assert(useCase?.queueDetail === "y", "T-MCP-78: a use case is not the queue detail");
}

// One order for a name that both runs code and sends.
{
  assert(classifyMcpEffect("execute_and_send") === "run-code", "T-MCP-79: a name that runs code and sends reads as running code");
  assert(worstMcpEffect([classifyMcpEffect("execute_and_send")]) === classifyMcpEffect("execute_and_send"), "T-MCP-80: a group and a single tool agree");
}

console.log("mcp-call explain tests passed");
