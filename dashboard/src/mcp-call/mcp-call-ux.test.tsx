import { renderToStaticMarkup } from "react-dom/server";
import type { GuardActionEnvelope, GuardApprovalRequest } from "../guard-types";
import { queueItemPreview } from "../review-queue-item";
import { resolveQueueCategory } from "../queue-state";
import { whyPaused } from "../evidence/plain-english";
import { PrimaryActionCard } from "../review-states";
import { decisionButtonLabels } from "../review-decision-labels";
import { ReviewDecisionControls } from "../review-decision-controls";
import { explainMcpCall } from "./explain-mcp-call";
import { McpCallCard } from "./mcp-call-card";
import { consequenceFor } from "./mcp-consequence";
import { simpleMcpChoiceApplies } from "./mcp-decision-choice";
import { listedMcpPreview, queueRequesterName } from "./mcp-queue-name";
import { previewFieldsFor } from "./mcp-previews";
import { emailAddresses, linkParts, valueKindOf } from "./mcp-values";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function envelope(toolName: string, toolInput: unknown): GuardActionEnvelope {
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
  };
}

function request(env: GuardActionEnvelope | null, toolName: string, extra: Partial<GuardApprovalRequest> = {}): GuardApprovalRequest {
  return {
    request_id: "request-mcp",
    harness: "zcode",
    artifact_id: `tool:${toolName}`,
    artifact_name: toolName,
    artifact_type: "tool_call",
    artifact_hash: "sha256-mcp",
    publisher: null,
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["runtime_tool_call"],
    source_scope: "project",
    config_path: "./mcp.json",
    launch_target: toolName,
    transport: "stdio",
    review_command: "hol-guard approvals approve request-mcp",
    approval_url: "http://127.0.0.1:4781/approvals/request-mcp",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: "2026-11-17T12:00:00Z",
    resolved_at: null,
    action_envelope_json: env,
    exact_action_persistence_eligible: true,
    allowed_scopes: ["artifact", "workspace"],
    ...extra,
  };
}

// A value's shape comes from the text only.
{
  assert(valueKindOf("a@example.com") === "email", "T-UX-1: an address is an address");
  assert(valueKindOf("a@example.com, b@example.org") === "email", "T-UX-2: a list of addresses is a list");
  assert(emailAddresses("a@example.com, not an address") === null, "T-UX-3: one bad part means it is not a list of addresses");
  assert(valueKindOf("https://example.com/path?q=1") === "url", "T-UX-4: a web address is a web address");
  assert(linkParts("https://example.com/path?q=1")?.host === "example.com", "T-UX-5: the host is split from the path");
  assert(linkParts("javascript:alert(1)") === null && linkParts("https://a.com/x y") === null, "T-UX-6: only plain http and https addresses are links");
  assert(valueKindOf("x".repeat(121)) === "long" && valueKindOf("one\ntwo") === "long", "T-UX-7: long or multi-line text is long");
  assert(valueKindOf("Fix login") === "text", "T-UX-8: a short title is plain text");
}

// A send action shows who it goes to first, under plain labels, in the order a person reads them.
{
  assert(previewFieldsFor("GMAIL_SEND_EMAIL") === previewFieldsFor("send_email"), "T-UX-9: a service prefix does not change the preview");
  assert(previewFieldsFor("frobnicate") === null, "T-UX-10: an unknown action has no preview");
  const item = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", {
      tools: [
        {
          tool_slug: "GMAIL_SEND_EMAIL",
          arguments: { body: "Hello there", subject: "Hi", recipient_email: "ann@example.com", priority: "high" },
        },
      ],
    }),
    "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
  );
  const labels = explainMcpCall(item)?.steps[0].details.map((fact) => fact.label) ?? [];
  assert(labels.join(",") === "To,Subject,Message,Priority", "T-UX-11: recipient, subject and message come before other fields");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item }));
  assert(markup.includes("ann@example.com") && markup.includes("Sends something through Gmail"), "T-UX-12: the card names who gets it and what approving does");
  assert(markup.includes("Run actions") || markup.includes("Send email"), "T-UX-13: the action reads in words");
}

// A call with one action names it once, in the heading. Several actions are numbered.
{
  const one = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", { tools: [{ tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "a@example.com" } }] }),
    "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
  );
  const oneMarkup = renderToStaticMarkup(PrimaryActionCard({ item: one }));
  assert((oneMarkup.match(/Send email/g) ?? []).length === 1, "T-UX-44: a lone action is named once, not again in its row");
  assert(oneMarkup.includes("a@example.com"), "T-UX-45: its details still show");
  const many = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", {
      tools: [
        { tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: "x" } },
        { tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "a@example.com" } },
      ],
    }),
    "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
  );
  const manyMarkup = renderToStaticMarkup(PrimaryActionCard({ item: many }));
  assert(manyMarkup.includes("Get emails") && manyMarkup.includes("Send email"), "T-UX-46: each of several actions is listed");
  assert(whyPaused(one) === "Guard asks before a tool it has not reviewed runs.", "T-UX-47: Why paused names the reason for a tool Guard has not reviewed");
}

// What approving lets happen follows the effect, in "may" words, and unknown is never calm.
{
  assert(consequenceFor("read", "Gmail").tone === "calm", "T-UX-14: a lookup is calm");
  assert(consequenceFor("write", "GitHub").tone === "care", "T-UX-15: a change asks for care");
  assert(consequenceFor("send", "Gmail").tone === "danger" && consequenceFor("delete", "Gmail").tone === "danger", "T-UX-16: send and delete are the strongest tone");
  assert(consequenceFor("run-code", "x").tone === "danger", "T-UX-17: running code is the strongest tone");
  assert(consequenceFor("unknown", "x").tone === "care", "T-UX-18: a name Guard cannot read still asks for care");
  assert(consequenceFor("read", "Gmail").text.startsWith("By its name,") && !/not change|no change|nothing/i.test(consequenceFor("read", "Gmail").text), "T-UX-19: a lookup is read from the name, never promised");
  const all = (["read", "write", "send", "delete", "run-code", "connect", "unknown"] as const).map((effect) => consequenceFor(effect, "Gmail").text);
  assert(all.every((text) => !/\bsafe\b/i.test(text)), "T-UX-20: no consequence calls a tool safe");
  assert(consequenceFor("write", "GitHub").text.startsWith("By its name,"), "T-UX-48: a change is read from the name too");
  const connect = consequenceFor("connect", "Composio").text;
  assert(connect.includes("Checks or changes") && connect.includes("may ask you to link another"), "T-UX-49: an account check does not claim a change always happens");
}

// The card names the one app a call acts in, and the connector it goes through.
{
  const composio = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", { tools: [{ tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: "x" } }] }),
    "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
  );
  const markup = renderToStaticMarkup(PrimaryActionCard({ item: composio }));
  assert(markup.includes("Gmail, through Composio"), "T-UX-21: the subtitle names the app and the connector");
  const github = request(envelope("mcp__github__create_issue", { title: "Fix login" }), "mcp__github__create_issue");
  assert(renderToStaticMarkup(PrimaryActionCard({ item: github })).includes("Tool from GitHub"), "T-UX-22: a plain tool says whose tool it is");
}

// A list row that arrives without its envelope still reads in words, and is filed as a tool call.
{
  const listed = (name: string) => request(null, name, { artifact_id: `tool:${name}`, queue_preview: name });
  const composio = listed("mcp__composio__COMPOSIO_SEARCH_TOOLS");
  assert(listedMcpPreview(composio) === "Composio · Search for tools", "T-UX-23: a Composio row is named without the envelope");
  assert(queueItemPreview(composio) === "Composio · Search for tools", "T-UX-24: the queue row uses it");
  assert(resolveQueueCategory(composio).id === "mcp_tool", "T-UX-25: the row is filed as an MCP tool call, not an other review");
  assert(listedMcpPreview(listed("mcp__codex_apps__github__create_issue")) === "GitHub · Create issue", "T-UX-26: a Codex connector row names the connector");
  assert(listedMcpPreview(listed("mcp__github__list_issues")) === "GitHub · List issues", "T-UX-27: a plain tool row reads as a short action");
  const shell = request(null, "ls", { artifact_id: "command:ls", queue_preview: "ls -la", launch_target: "ls", artifact_name: "ls", artifact_type: "command" });
  assert(listedMcpPreview(shell) === null && queueItemPreview(shell) === "ls -la", "T-UX-28: a row that is not an MCP tool is left alone");
  const withEnvelope = request(envelope("mcp__github__list_issues", {}), "mcp__github__list_issues");
  assert(listedMcpPreview(withEnvelope) === null, "T-UX-29: a row with its envelope uses the full explanation");
}

// The two-card choice applies only when both choices can really be offered.
{
  const base = request(envelope("mcp__github__create_issue", { title: "Fix login" }), "mcp__github__create_issue");
  assert(simpleMcpChoiceApplies(base), "T-UX-30: a plain MCP review gets the two-card choice");
  assert(!simpleMcpChoiceApplies({ ...base, exact_action_persistence_eligible: false }), "T-UX-31: no Always allow means the full controls stay");
  assert(!simpleMcpChoiceApplies({ ...base, scope_restrictions: ["retry_cannot_reuse_approval"] }), "T-UX-32: a request that cannot take Allow once keeps the full controls");
  assert(!simpleMcpChoiceApplies({ ...base, allowed_scopes: ["workspace"] }), "T-UX-33: a request without the exact scope keeps the full controls");
  const shell = request(envelope("Bash", { command: "ls" }), "Bash");
  assert(!simpleMcpChoiceApplies({ ...shell, action_envelope_json: { ...envelope("Bash", { command: "ls" }), action_type: "shell_command", mcp_server: null, mcp_tool: null } }), "T-UX-34: a shell review keeps the full controls");

  const props = {
    commonScopeOptions: [],
    broaderScopeOptions: [],
    advancedScopeOptions: [],
    blockScopeOptions: [],
    hasAllowScope: true,
    taskCapabilityCopy: null,
    exactActionPersistenceEligible: true,
    rememberExactAction: false,
    allowScope: "artifact" as const,
    blockScope: "artifact" as const,
    onAllowScopeChange: () => undefined,
    onBlockScopeChange: () => undefined,
    onRememberExactActionChange: () => undefined,
  };
  const simple = renderToStaticMarkup(<ReviewDecisionControls {...props} simpleMcp />);
  assert(simple.includes("Just this once") && simple.includes("Always allow this call"), "T-UX-35: both choices are offered in plain words");
  assert(simple.includes("More choices") && !simple.includes("Approval scope"), "T-UX-36: wider choices are one click away and the old heading is gone");
  assert(simple.includes('aria-checked="true"'), "T-UX-37: the current choice is marked");
  const full = renderToStaticMarkup(<ReviewDecisionControls {...props} simpleMcp={false} />);
  assert(full.includes("Approval scope") && !full.includes("Just this once"), "T-UX-38: every other review keeps the full controls");
}

// The Allow button says what it will do, and Always allow is never dropped.
{
  const item = request(envelope("mcp__github__create_issue", { title: "Fix login" }), "mcp__github__create_issue");
  const labels = (rememberExactAction: boolean, simpleMcp: boolean, watchOnlyObservation = false) =>
    decisionButtonLabels({ item, allowScope: "artifact", blockScope: "artifact", rememberExactAction, watchOnlyObservation, simpleMcp });
  assert(labels(false, true).allowLabel === "Allow once", "T-UX-39: once reads as Allow once");
  assert(labels(true, true).allowLabel === "Always allow this call", "T-UX-40: always reads as Always allow");
  assert(labels(true, true).persistExactAllow && !labels(false, true).persistExactAllow, "T-UX-41: only Always allow saves the call");
  assert(labels(true, false).allowLabel === "Approve and remember", "T-UX-42: other reviews keep their wording");
  assert(labels(false, true, true).allowLabel === "Keep allowing", "T-UX-43: a watch-only observation keeps its wording");
}

// A web address keeps its port, so a reviewer sees which service answers.
{
  assert(linkParts("http://localhost:8080/admin")?.host === "localhost:8080", "T-UX-50: a non-default port stays in the host");
  assert(linkParts("https://example.com:443/a")?.host === "example.com", "T-UX-51: the default port is not shown");
  assert(linkParts("https://example.com:8443/admin")?.rest === "/admin", "T-UX-52: the path stays separate");
  assert(linkParts("https://trusted.com@evil.example/x")?.host === "evil.example", "T-UX-53: the host after the at-sign is the one shown");
}

// The service in the consequence comes from every action, listed or not, and only the actions that carry the effect.
{
  const fetches = Array.from({ length: 11 }, () => ({ tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: "x" } }));
  const call = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", { tools: [...fetches, { tool_slug: "SLACK_DELETE_MESSAGE", arguments: { channel: "c1" } }] }),
    "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
  );
  const text = explainMcpCall(call)?.consequence.text ?? "";
  assert(text.includes("Slack") && !text.includes("Gmail"), "T-UX-54: a hidden delete is named in Slack, not in the Gmail rows shown");
  const mixed = request(
    envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", {
      tools: [{ tool_slug: "GMAIL_FETCH_EMAILS", arguments: { query: "x" } }, { tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: "a@example.com" } }],
    }),
    "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL",
  );
  assert((explainMcpCall(mixed)?.consequence.text ?? "").includes("through Gmail"), "T-UX-55: one app that sends is still named");
}

// A Codex connector row reads as the connector, from the shared name parser.
{
  const row = request(null, "mcp__codex_apps__github__create_issue");
  assert(listedMcpPreview(row) === "GitHub · Create issue", "T-UX-56: a codex_apps row is named for its connector");
}

// Why paused keeps a specific reason, and names the unreviewed tool only where the reason would be generic.
{
  const secret = request(envelope("mcp__files__read_id_rsa", { path: "x" }), "mcp__files__read_id_rsa");
  assert(explainMcpCall(secret) !== null, "T-UX-57: the secret-named tool is still an MCP call");
  assert(whyPaused(secret) === "This file may contain passwords or keys. Guard stops this by default.", "T-UX-58: a specific reason is never hidden by the generic one");
}

// What Guard's own hook stamped when the Claude desktop app ran it.
function fromClaudeDesktop(env: GuardActionEnvelope): GuardActionEnvelope {
  return {
    ...env,
    raw_payload_redacted: {
      ...(env.raw_payload_redacted as Record<string, unknown>),
      guard_execution_environment: { environment_names: ["CLAUDECODE", "CLAUDE_CODE_DESKTOP_APP_VERSION", "HOME"] },
    },
  };
}

// A tool built into the Claude app reads as Claude's own, in plain words, once the call is shown to come from that app.
{
  const input = {
    recap: "The card now names the app that asked.",
    ask: "Merge it?",
    actions: [{ label: "Yes, merge" }, { label: "Not now" }],
  };
  const call = request(fromClaudeDesktop(envelope("mcp__ccd_turn__wrap_up", input)), "mcp__ccd_turn__wrap_up", { harness: "cursor" });
  const explained = explainMcpCall(call);
  assert(explained !== null, "T-UX-59: a built-in tool is still explained");
  assert(explained?.headline === "Claude wants to show you a summary and next-step buttons", "T-UX-60: the headline says what the tool does");
  assert(explained?.requester === "Claude", "T-UX-61: Guard's stamp of the Claude desktop app outweighs the hook's harness label");
  assert(explained?.effect === "in-app", "T-UX-62: a summary card only changes the app");
  assert(explained?.builtIn === true, "T-UX-63: the card knows the tool is built in");
  const labels = (explained?.facts ?? []).map((item) => `${item.label}=${item.value}`);
  assert(labels.includes("Summary=The card now names the app that asked."), "T-UX-64: the summary is shown");
  assert(labels.includes("Question=Merge it?"), "T-UX-65: the question is shown");
  assert(labels.includes("Buttons=Yes, merge · Not now"), "T-UX-66: the button labels are shown");
  const shown = [explained?.headline, explained?.title, explained?.queueTitle, explained?.connector, explained?.requester].join(" ");
  assert(!/ccd|wrap_up|Wrap up|Cursor/i.test(shown), "T-UX-67: no server id, raw tool name or wrong app reaches the headline");
  assert(queueItemPreview(call) === "Claude · Show a summary and next steps", "T-UX-68: the queue row names Claude and the job");
  assert(!(explained?.consequence?.text ?? "").includes("does not reach"), "T-UX-76: the in-app note promises nothing Guard has not checked");
}

// A server merely named like the Claude app's gets no Claude treatment: the real harness asks, and its names stay.
{
  const call = request(envelope("mcp__ccd_turn__wrap_up", { recap: "x" }), "mcp__ccd_turn__wrap_up", { harness: "codex" });
  const explained = explainMcpCall(call);
  assert(explained?.builtIn !== true, "T-UX-77: a look-alike server is not called built in");
  assert(explained?.requester === "Codex", "T-UX-78: the look-alike call keeps the real harness as requester");
  assert(explained?.effect !== "in-app", "T-UX-79: the look-alike call is not called in-app");
}

// The task list tool shows each task with its state. The claude-code hook route is evidence on its own.
{
  const claude = { harness: "claude-code" };
  const call = request(
    envelope("mcp__ccd_turn__update_plan", { items: [{ content: "Write tests", status: "completed" }, { content: "Build", status: "in_progress" }, { content: "Push", status: "pending" }] }),
    "mcp__ccd_turn__update_plan",
    claude,
  );
  const facts = explainMcpCall(call)?.facts ?? [];
  assert(facts[0]?.value === "Done: Write tests · Now: Build · Next: Push", "T-UX-69: tasks read Done / Now / Next");
  const advance = request(envelope("mcp__ccd_turn__update_plan", { advance: true }), "mcp__ccd_turn__update_plan", claude);
  assert((explainMcpCall(advance)?.facts[0]?.label ?? "") === "Change", "T-UX-70: an advance says what changes");
}

// An unlisted Claude app tool is still Claude's, and its effect still comes from its name.
{
  const call = request(envelope("mcp__ccd_session__delete_session", { id: "s1" }), "mcp__ccd_session__delete_session", { harness: "claude-code" });
  const explained = explainMcpCall(call);
  assert(explained?.requester === "Claude", "T-UX-71: an unlisted built-in tool is Claude's");
  assert(explained?.effect === "delete", "T-UX-72: an unlisted built-in delete is not called in-app");
}

// A list row without its envelope names Claude only when the hook route says Claude.
{
  const row = request(null, "mcp__ccd_turn__wrap_up", { harness: "claude-code" });
  assert(listedMcpPreview(row) === "Claude · Show a summary and next steps", "T-UX-73: a listed built-in row is named for Claude");
  assert(queueRequesterName(row) === "Claude", "T-UX-74: a listed built-in row's requester is Claude");
  const other = request(null, "mcp__github__create_issue", { harness: "cursor" });
  assert(queueRequesterName(other) === "Cursor", "T-UX-75: any other tool keeps the hook's harness");
  const lookalike = request(null, "mcp__ccd_turn__wrap_up", { harness: "cursor" });
  assert(queueRequesterName(lookalike) === "Cursor", "T-UX-80: a listed look-alike row keeps the hook's harness");
  assert(whyPaused(lookalike) === "Guard asks before a tool it has not reviewed runs.", "T-UX-81: a listed MCP row without an envelope gets the MCP reason");
}

// A query keeps its lines, with control characters gone, inside the row limit.
{
  const sql = "SELECT id\nFROM users\u0007\nWHERE active = 1";
  const call = request(envelope("mcp__postgres__run_query", { sql }), "mcp__postgres__run_query");
  const query = (explainMcpCall(call)?.facts ?? []).find((item) => item.label === "Query");
  assert(query?.value === "SELECT id\nFROM users \nWHERE active = 1", "T-UX-82: a query keeps its line breaks and drops controls");
  const long = request(envelope("mcp__postgres__run_query", { sql: "SELECT 1;\n".repeat(60) }), "mcp__postgres__run_query");
  const cut = (explainMcpCall(long)?.facts ?? []).find((item) => item.label === "Query");
  assert(Array.from(cut?.value ?? "").length <= 240 && (cut?.value ?? "").endsWith("…"), "T-UX-83: a long query stays within the row limit");
}

// A card whose extra actions are left out names the connector, not the one app it showed.
{
  const tools = [
    ...Array.from({ length: 10 }, (_, index) => ({ tool_slug: "GMAIL_SEND_EMAIL", arguments: { recipient_email: `p${index}@example.com` } })),
    { tool_slug: "SLACK_SEND_MESSAGE", arguments: { channel: "general" } },
  ];
  const call = request(envelope("mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL", { tools }), "mcp__composio__COMPOSIO_MULTI_EXECUTE_TOOL");
  const explained = explainMcpCall(call);
  assert((explained?.hiddenSteps ?? 0) > 0, "T-UX-84: the eleventh action is left out of the rows");
  const html = renderToStaticMarkup(<McpCallCard item={call} explanation={explained!} />);
  assert(html.includes("Tool from Composio") && !html.includes("Gmail, through Composio"), "T-UX-85: the subtitle names the connector when actions are hidden");
}

console.log("mcp-call ux tests passed");
