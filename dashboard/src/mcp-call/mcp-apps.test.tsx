import { renderToStaticMarkup } from "react-dom/server";
import type { GuardActionEnvelope, GuardApprovalRequest, GuardBrowserCardV1 } from "../guard-types";
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

// Browser steps come from Core's native card, never from the tool's name.
{
  const card = (overrides: Partial<GuardBrowserCardV1>): GuardBrowserCardV1 => ({
    headline: "Claude Code wants to open www.example-shop.com",
    verb: "navigate",
    site: { origin: "https://www.example-shop.com", first_visit_in_task: false, left_granted_site: false },
    profile_line: "shared",
    detail: { element_preview: null, input_kind: null, input_length: null, input_masked: false },
    risk_chips: [],
    provider_findings: [],
    choices: ["allow_once", "always_allow", "deny"],
    steps: [],
    ...overrides,
  });
  const carded = (server: string, tool: string, input: unknown, browserCard: GuardBrowserCardV1) => ({
    ...call(server, tool, input),
    browser_card: browserCard,
  });

  const open = explainMcpCall(
    carded("playwright", "browser_navigate", { url: "https://www.example-shop.com/checkout?cart=12", tabId: 3 }, card({})),
  );
  assert(open?.title === "Open a web page", "T-APP-24: a navigate card is opening a web page");
  assert(open?.headline === "Claude Code wants to open www.example-shop.com", "T-APP-25: the headline is Core's");
  assert(open?.effect === "act-as-you" && open?.consequence.text.includes("as if it were you"), "T-APP-26: a browser step says it acts as you");
  assert(open?.facts[0]?.label === "Web page" && open?.facts[0]?.value === "https://www.example-shop.com", "T-APP-27: the site is the first row, without its path");
  assert(open?.facts.some((fact) => fact.label === "Browser" && fact.value === "Your own browser profile") === true, "T-APP-28: the browser line names the profile");
  assert(open?.queueTitle.endsWith("· Open www.example-shop.com") === true, "T-APP-29: the row names the site");

  const typed = explainMcpCall(
    carded(
      "playwright",
      "browser_type",
      { element: "Password", text: "hunter2-secret" },
      card({
        headline: "Claude Code wants to type into a form on www.example-shop.com",
        verb: "type",
        detail: { element_preview: "Password", input_kind: "text", input_length: 14, input_masked: true },
        risk_chips: ["password_field"],
      }),
    ),
  );
  assert(typed?.title === "Type on the page", "T-APP-30: a type card is typing on the page");
  assert(typed?.facts.some((fact) => fact.label === "What it types" && fact.value === "Hidden · 14 characters") === true, "T-APP-31: masked input shows only its length");
  assert(typed?.facts.every((fact) => !fact.value.includes("hunter2")) === true, "T-APP-32: typed text never becomes a row");
  assert(typed?.facts.some((fact) => fact.label === "Touches" && fact.value === "Password field") === true, "T-APP-33: risk chips are named");

  const shot = explainMcpCall(
    carded("playwright", "browser_take_screenshot", {}, card({ headline: "Claude Code wants to take a screenshot on www.example-shop.com", verb: "screenshot" })),
  );
  assert(shot?.effect === "read" && shot?.consequence.tone === "calm", "T-APP-34: a screenshot only looks");

  const code = explainMcpCall(
    carded(
      "playwright",
      "browser_evaluate",
      { function: "() => document.title" },
      card({
        headline: "Claude Code wants to run a script on www.example-shop.com",
        verb: "evaluate",
        detail: { element_preview: null, input_kind: "script", input_length: 21, input_masked: false },
        risk_chips: ["script_eval"],
      }),
    ),
  );
  assert(code?.effect === "run-code" && code?.code?.text === "() => document.title", "T-APP-35: page code is shown as code");

  const uncarded = explainMcpCall(call("playwright", "browser_navigate", { url: "https://example.com" }));
  assert(uncarded?.effect !== "act-as-you" && uncarded?.title !== "Open a web page", "T-APP-36: without a card a browser-named tool reads as an ordinary tool");
  const malformed = explainMcpCall({ ...call("playwright", "browser_click", {}), browser_card: { headline: "x", verb: "fly" } as unknown as GuardBrowserCardV1 });
  assert(malformed !== null && !malformed.effectBasis.includes("browser driver profile") && malformed.title !== "Click on the page", "T-APP-37: a malformed card falls back to the generic card");
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

// Code for Composio's workspace reads as the actions it names, with the code one click away.
{
  const code = [
    "import json",
    "",
    "# Search Gmail for episode exports",
    "result, error = run_composio_tool('GMAIL_FETCH_EMAILS', {",
    "    'query': 'riverside OR HLX',",
    "    'max_results': 15,",
    "    'verbose': False,",
    "    'include_payload': Fa…",
  ].join("\n");
  const item = call("composio", "COMPOSIO_REMOTE_WORKBENCH", { code_to_execute: code, thought: "Find episode exports" });
  const explained = explainMcpCall(item);
  assert(explained?.title === "Get emails in Gmail", `T-APP-48: the card is titled by the action in the code, got ${explained?.title}`);
  assert(explained?.headline === "Claude Code wants to get emails in Gmail, using code", `T-APP-49: the headline says code does it, got ${explained?.headline}`);
  assert(explained?.effect === "run-code", "T-APP-50: running code still reads as running code");
  assert(explained?.consequence.text.startsWith("Runs code that can use Gmail") === true, "T-APP-51: the warning names the app the code uses");
  const details = explained?.steps[0]?.details ?? [];
  assert(details.some((fact) => fact.value === "riverside OR HLX"), "T-APP-52: the search words are a row");
  assert(details.some((fact) => fact.value === "15"), "T-APP-53: the result count is a row");
  assert(details.every((fact) => fact.value !== "No"), "T-APP-54: yes/no settings stay in the code");
  assert(explained?.code?.collapsed === true && explained.code.text === code, "T-APP-55: the code is kept whole, behind a toggle");
  assert(explained?.queueTitle === "Gmail · Get emails", `T-APP-56: the row leads with Gmail, got ${explained?.queueTitle}`);
  assert(queueMcpMarkName(item) === "Gmail", "T-APP-57: the row shows Gmail's mark");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes('data-mcp-app="Gmail"') && markup.includes("What the code asks for"), "T-APP-58: the card shows Gmail and what the code asks for");
  assert(markup.includes("See the code (8 lines)"), "T-APP-59: the code is behind a toggle that says how long it is");

  const two = explainMcpCall(
    call("composio", "COMPOSIO_REMOTE_WORKBENCH", {
      code_to_execute: "x = run_composio_tool(\"GMAIL_FETCH_EMAILS\", {\"query\": \"a\"})\nlimit = 99\nrun_composio_tool('SLACK_SEND_MESSAGE', {'channel': 'C1', 'text': 'hi'})\nrun_composio_tool(name, {})",
    }),
  );
  assert(two?.steps.length === 2 && two.title === "Run 2 actions in Gmail and Slack", `T-APP-60: each named action is a step, got ${two?.title}`);
  assert(two?.steps[0]?.details.every((fact) => fact.value !== "99") === true, "T-APP-61: values after a call are not its inputs");
  assert(two?.aside?.includes("ways Guard cannot read") === true && two.code?.collapsed === false, "T-APP-62: an action named by a variable is called out, and the code stays open");

  const plain = explainMcpCall(call("composio", "COMPOSIO_REMOTE_WORKBENCH", { code_to_execute: "import os\nprint(os.listdir('.'))" }));
  assert(plain?.title === "Run code in Composio's workspace" && plain.code?.collapsed !== true, "T-APP-63: code that names no action is shown as code");
}

// The agent writes the code, so nothing it can hide sets the card's words.
{
  const workbench = (code: string) => explainMcpCall(call("composio", "COMPOSIO_REMOTE_WORKBENCH", { code_to_execute: code }));
  const commented = workbench("# run_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'a'})\nimport os\nos.remove('notes.txt')");
  assert(commented?.title === "Run code in Composio's workspace" && commented.code?.collapsed !== true, `T-APP-65: a call in a comment is not a call, got ${commented?.title}`);
  const inString = workbench("s = \"run_composio_tool('GMAIL_FETCH_EMAILS', {})\"\nexec(s)");
  assert(inString?.title === "Run code in Composio's workspace", `T-APP-66: a call in a string is not a call, got ${inString?.title}`);
  const tripleQuoted = workbench("doc = '''\nrun_composio_tool('GMAIL_FETCH_EMAILS', {})\n'''\nprint(doc)");
  assert(tripleQuoted?.title === "Run code in Composio's workspace", `T-APP-67: a call in a long string is not a call, got ${tripleQuoted?.title}`);

  const joined = workbench("run_composio_tool('GMAIL_SEND_EMAIL', {'recipient_email': 'ann@example.com' + '.evil.example', 'subject': 'Hi'})");
  const sent = joined?.steps[0];
  assert(sent?.details.every((fact) => !fact.value.includes("ann@example.com")) === true, "T-APP-68: a value built from pieces is not shown as one of them");
  assert(sent?.details.some((fact) => fact.value === "Hi") === true && (sent?.hiddenDetails ?? 0) >= 1, "T-APP-69: plain values still show, and the built one is counted");
  const fString = workbench("run_composio_tool('GMAIL_SEND_EMAIL', {'recipient_email': f'{name}@example.com'})");
  assert(fString?.steps[0]?.details.length === 0 && (fString?.steps[0]?.hiddenDetails ?? 0) === 1, "T-APP-70: an f-string value is counted, not shown");
  const builtName = workbench("run_composio_tool('GMAIL_' + verb, {})\nrun_composio_tool('SLACK_SEND_MESSAGE', {'text': 'hi'})");
  assert(builtName?.steps.length === 1 && builtName.aside?.includes("cannot read") === true, "T-APP-71: an action name built from pieces is not read as the first piece");

  const apostrophe = workbench("# don't page through\nrun_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'invoices'})");
  assert(apostrophe?.steps[0]?.details.some((fact) => fact.value === "invoices") === true, "T-APP-72: an apostrophe in a comment does not hide the inputs");
  const alias = workbench("send = run_composio_tool\nrun_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'a'})\nsend('GMAIL_SEND_EMAIL', {})");
  assert(alias?.aside?.includes("cannot read") === true && alias.code?.collapsed === false, "T-APP-73: the call function under another name is called out");
  const imported = workbench("from composio import run_composio_tool\nrun_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'a'})");
  assert(imported?.code?.collapsed === true && imported.aside?.includes("cannot read") === false, "T-APP-74: importing the call function is not passing it around");
  const named = "\nrun_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'a'})\nsend('GMAIL_SEND_EMAIL', {})";
  const renamed = workbench(`from composio import run_composio_tool as send${named}`);
  assert(renamed?.aside?.includes("cannot read") === true && renamed.code?.collapsed === false, "T-APP-78: importing the call function under another name is called out");
  const sameLine = workbench(`import os; send = run_composio_tool${named}`);
  assert(sameLine?.aside?.includes("cannot read") === true, "T-APP-79: an alias after an import on the same line is called out");

  const many = Array.from({ length: 11 }, (_, index) => `run_composio_tool('GMAIL_FETCH_EMAILS', {'query': 'q${index}'})`);
  many.push("run_composio_tool('SLACK_SEND_MESSAGE', {'text': 'done'})");
  const long = workbench(many.join("\n"));
  assert(long?.title === "Run 12 actions in Gmail and Slack", `T-APP-75: every call counts toward the title, got ${long?.title}`);
  assert(long?.steps.length === 10 && long.hiddenSteps === 2, "T-APP-76: rows past the limit are counted");
  assert(long?.consequence.text.includes("Slack") === true, "T-APP-77: an app used only by a later call is still named");
}

// When Guard cannot confirm the account, the card says the approval is once only, once.
{
  const item = {
    ...call("composio", "COMPOSIO_MULTI_EXECUTE_TOOL", { tools: [{ tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: "x" } }] }),
    scope_restrictions: ["provider_account_unverified_once_only"],
  };
  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes("You can allow this once") && !markup.includes("Always allow both"), "T-APP-64: a once-only call does not promise Always allow");
}

console.log("mcp-call app tests passed");
