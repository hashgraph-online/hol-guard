import { renderToStaticMarkup } from "react-dom/server";
import type { GuardActionEnvelope, GuardApprovalRequest } from "../guard-types";
import { queueItemPreview } from "../review-queue-item";
import { PrimaryActionCard } from "../review-states";
import { explainMcpCall } from "./explain-mcp-call";
import { McpAppMark } from "./mcp-app-mark";
import { mcpBrandFor } from "./mcp-brand";
import { readableDate } from "./mcp-input";
import { queueMcpMarkName } from "./mcp-queue-name";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function envelope(server: string, tool: string, toolInput: unknown): GuardActionEnvelope {
  const toolName = `mcp__${server}__${tool}`;
  return {
    schema_version: 1,
    action_id: "act-mcp",
    harness: "claude-code",
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
    mcp_server: server,
    mcp_tool: tool,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: { hook_event_name: "PreToolUse", tool_name: toolName, tool_input: toolInput },
  };
}

function request(env: GuardActionEnvelope): GuardApprovalRequest {
  return {
    request_id: "request-mcp-app",
    harness: "claude-code",
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
    review_command: "hol-guard approvals approve request-mcp-app",
    approval_url: "http://127.0.0.1:4781/approvals/request-mcp-app",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: "2026-11-17T12:00:00Z",
    resolved_at: null,
    action_envelope_json: env,
  };
}

const call = (server: string, tool: string, input: unknown) => request(envelope(server, tool, input));

// Popular apps get their own logo, found from a display name or a server key.
{
  assert(mcpBrandFor("Gmail")?.label === "Gmail", "T-APP-1: Gmail has its logo");
  assert(mcpBrandFor("Google Calendar")?.label === "Google Calendar", "T-APP-2: a display name finds its logo");
  assert(mcpBrandFor("mcp-server-github")?.label === "GitHub", "T-APP-3: wrapper words in a server key are ignored");
  assert(mcpBrandFor("slack_mcp")?.label === "Slack", "T-APP-4: a trailing mcp is ignored");
  assert(mcpBrandFor("brave-search")?.label === "Brave Search", "T-APP-5: an alias finds the service");
  assert(mcpBrandFor("claude-in-chrome")?.label === "Chrome", "T-APP-6: Claude in Chrome shows Chrome");
  assert(mcpBrandFor("Claude_Browser")?.label === "Browser", "T-APP-7: Claude's browser shows a browser, not Claude");
  assert(mcpBrandFor("playwright")?.label === "Browser", "T-APP-8: a browser automation server shows a browser");
  assert(mcpBrandFor("filesystem")?.label === "Files", "T-APP-9: a files server shows a folder");
  assert(mcpBrandFor("google_search")?.label === "Search", "T-APP-10: a maker's name alone does not pick its logo");
  assert(mcpBrandFor("Claude")?.label === "Claude", "T-APP-11: the Claude app has its logo");
  assert(mcpBrandFor("acme-internal") === null, "T-APP-12: an unknown server has no logo");
  assert(mcpBrandFor("profiles") === null && mcpBrandFor("docsfs") === null, "T-APP-13: short kind words must stand alone");
}

// The mark is drawn like an extension mark, and falls back to a letter.
{
  const gmail = renderToStaticMarkup(McpAppMark({ name: "Gmail", size: "sm" }));
  assert(gmail.includes('class="guard-extension-mark"') && gmail.includes('data-mcp-app="Gmail"'), "T-APP-14: Gmail uses the extension mark tile");
  assert(gmail.includes('aria-hidden="true"') && gmail.includes("--extension-brand:#ea4335"), "T-APP-15: the tile carries Gmail's colour and is decorative");
  const notion = renderToStaticMarkup(McpAppMark({ name: "Notion" }));
  assert(notion.includes("--extension-brand:#3f4174"), "T-APP-16: a black logo sits on the readable dark tint");
  const unknown = renderToStaticMarkup(McpAppMark({ name: "acme-internal" }));
  assert(unknown.includes('data-kind="letter"') && unknown.includes(">A</span>"), "T-APP-17: an unknown app shows its first letter");
}

// Composio rows and cards lead with the app the action lands in.
{
  const item = call("composio", "COMPOSIO_MULTI_EXECUTE_TOOL", {
    tools: [{ tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "ann@example.com", subject: "Update" } }],
  });
  const explained = explainMcpCall(item);
  assert(explained?.headline === "Claude Code wants to send email in Gmail", "T-APP-18: the headline names the action, not 'an action'");
  assert(explained?.queueTitle === "Gmail · Send email", "T-APP-19: the row leads with Gmail, not Composio");
  assert(queueItemPreview(item) === "Gmail · Send email — ann@example.com", "T-APP-20: the row says who the email goes to");
  assert(queueMcpMarkName(item) === "Gmail", "T-APP-21: the row shows Gmail's mark");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes('data-mcp-app="Gmail"'), "T-APP-22: the card shows Gmail's mark");
  assert(markup.includes("Gmail, through Composio"), "T-APP-23: the card still names the service in between");
}

// Browser tools read as plain steps, and say the agent acts as you.
{
  const open = explainMcpCall(call("Claude_Browser", "navigate", { url: "https://www.example-shop.com/checkout?cart=12", tabId: 3 }));
  assert(open?.title === "Open a web page", "T-APP-24: navigate is opening a web page");
  assert(open?.headline === "Claude Code wants to open www.example-shop.com in Claude's browser", "T-APP-25: the headline names the site and the browser");
  assert(open?.effect === "act-as-you" && open?.consequence.text.includes("as if it were you"), "T-APP-26: a browser step says it acts as you");
  assert(open?.facts[0]?.label === "Web page" && open?.facts[0]?.kind === "url", "T-APP-27: the address is the first row");
  assert(open?.facts.every((fact) => !/tab/i.test(fact.label)) === true, "T-APP-28: the tab id stays in the exact input");
  assert(open?.queueTitle === "Claude's browser · Open www.example-shop.com", "T-APP-29: the row names the site");

  const click = explainMcpCall(call("claude-in-chrome", "computer", { action: "left_click", coordinate: [420, 610], tabId: 2 }));
  assert(click?.title === "Click on the page" && click?.connector === "Chrome", "T-APP-30: a computer click is a click in Chrome");
  assert(click?.facts.length === 0, "T-APP-31: coordinates and tab ids are not rows");
  assert(click?.headline === "Claude Code wants to click on the page in Chrome", "T-APP-32: the headline says where it clicks");

  const typed = explainMcpCall(call("claude-in-chrome", "computer", { action: "type", text: "hello" }));
  assert(typed?.title === "Type on the page" && typed?.facts.some((fact) => fact.label === "What it types" && fact.value === "hello") === true, "T-APP-33: typing shows the text");

  const shot = explainMcpCall(call("Claude_Browser", "computer", { action: "screenshot" }));
  assert(shot?.effect === "read" && shot?.consequence.tone === "calm", "T-APP-34: a screenshot only looks");

  const code = explainMcpCall(call("claude-in-chrome", "javascript_tool", { action: "javascript_exec", text: "document.title" }));
  assert(code?.effect === "run-code" && code?.code?.text === "document.title", "T-APP-35: page code is shown as code");

  const odd = explainMcpCall(call("playwright", "browser_frobnicate", { x: 1 }));
  assert(odd?.effect === "unknown", "T-APP-36: an unknown browser tool stays unclear");
  const plain = explainMcpCall(call("github", "navigate", { url: "https://example.com" }));
  assert(plain?.effect !== "act-as-you", "T-APP-37: only browser servers read as acting as you");
}

// Technical pointer fields and raw dates are made readable.
{
  const issue = explainMcpCall(call("acme", "sync_records", { batch: 4, session_id: "s-1", request_id: "r-2" }));
  assert(issue?.facts.length === 1 && issue?.facts[0]?.label === "Batch", "T-APP-38: session and request ids are not rows");
  assert(readableDate("2026-11-20T09:00:00") === "Fri, Nov 20, 2026, 9:00 AM", "T-APP-39: a local time reads as written");
  assert(readableDate("2026-11-20") === "Fri, Nov 20, 2026", "T-APP-40: a date reads as a day");
  assert(readableDate("2026-02-30") === null && readableDate("next friday") === null, "T-APP-41: anything else is left alone");
  const event = explainMcpCall(
    call("composio", "COMPOSIO_MULTI_EXECUTE_TOOL", {
      tools: [{ tool_slug: "GOOGLECALENDAR_CREATE_EVENT", arguments: { summary: "Dentist", start_datetime: "2026-11-20T09:00:00" } }],
    }),
  );
  const details = event?.steps[0]?.details ?? [];
  assert(details.some((fact) => fact.value === "Fri, Nov 20, 2026, 9:00 AM"), "T-APP-42: an event start reads as a day and time");
  assert(readableDate("2026-11-20T99:00") === null && readableDate("2026-11-20T10:75") === null, "T-APP-45: an impossible time is left as written");
  assert(readableDate("2026-03-08T02:30:00") === "Sun, Mar 8, 2026, 2:30 AM", "T-APP-46: a clock change does not move a written time");
  const mail = explainMcpCall(
    call("composio", "COMPOSIO_MULTI_EXECUTE_TOOL", {
      tools: [{ tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "ann@example.com", subject: "2026-11-20", body: "2026-11-20" } }],
    }),
  );
  const mailDetails = mail?.steps[0]?.details ?? [];
  assert(mailDetails.length > 0 && mailDetails.every((fact) => !fact.value.includes("Nov 20")), "T-APP-47: a subject or message that looks like a date is shown as written");
}

// A tool's title does not repeat the service's name.
{
  const search = explainMcpCall(call("brave-search", "brave_web_search", { query: "standing desk" }));
  assert(search?.title === "Web search" && search?.queueTitle === "Brave Search · Web search", "T-APP-43: the service name is not repeated in the title");
  const lone = explainMcpCall(call("notion", "notion", { q: "x" }));
  assert(lone?.title === "Notion", "T-APP-44: a tool named only after its service keeps its name");
}

console.log("mcp-call app tests passed");
