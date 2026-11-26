import { renderToStaticMarkup } from "react-dom/server";
import type { GuardActionEnvelope, GuardApprovalRequest, GuardBrowserCardV1 } from "../guard-types";
import { PrimaryActionCard } from "../review-states";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function envelope(tool: string, toolInput: unknown): GuardActionEnvelope {
  const toolName = `mcp__example-pilot__${tool}`;
  return {
    schema_version: 1,
    action_id: "act-browser",
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
    mcp_server: "example-pilot",
    mcp_tool: tool,
    package_manager: null,
    package_name: null,
    script_name: null,
    raw_payload_redacted: { hook_event_name: "PreToolUse", tool_name: toolName, tool_input: toolInput },
  };
}

function card(overrides: Partial<GuardBrowserCardV1>): GuardBrowserCardV1 {
  return {
    headline: "Claude Code wants to open shop.example.test",
    verb: "navigate",
    site: { origin: "https://shop.example.test", first_visit_in_task: false, left_granted_site: false },
    profile_line: "isolated",
    detail: { element_preview: null, input_kind: null, input_length: null, input_masked: false },
    risk_chips: [],
    provider_findings: [],
    choices: ["allow_once", "always_allow", "deny"],
    steps: [],
    ...overrides,
  };
}

function item(tool: string, input: unknown, browserCard: GuardBrowserCardV1 | null): GuardApprovalRequest {
  const env = envelope(tool, input);
  return {
    request_id: "request-browser-card",
    harness: "claude-code",
    artifact_id: `tool:${env.tool_name}`,
    artifact_name: env.tool_name ?? "tool",
    artifact_type: "tool_call",
    artifact_hash: "sha256-browser",
    publisher: null,
    policy_action: "require-reapproval",
    recommended_scope: "artifact",
    changed_fields: ["runtime_tool_call"],
    source_scope: "project",
    config_path: "./mcp.json",
    launch_target: env.tool_name ?? "tool",
    transport: "stdio",
    review_command: "hol-guard approvals approve request-browser-card",
    approval_url: "http://127.0.0.1:4781/approvals/request-browser-card",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: "2026-11-26T12:00:00Z",
    resolved_at: null,
    action_envelope_json: env,
    browser_card: browserCard,
  };
}

const render = (request: GuardApprovalRequest) => renderToStaticMarkup(PrimaryActionCard({ item: request }));

// The card names the step, the site and the browser.
{
  const markup = render(item("page_open", { url: "https://shop.example.test/cart" }, card({})));
  assert(markup.includes('data-browser-card="navigate"'), "T-BCC-1: a browser card renders the browser layout");
  // The page heading says Core's headline; the card names the step instead of repeating it.
  assert(!markup.includes("Claude Code wants to open shop.example.test"), "T-BCC-2: the card does not repeat the headline");
  assert(/<h3[^>]*>[^<]+<\/h3>/.test(markup), "T-BCC-2b: the card names the step");
  assert(markup.includes(">Site<") && markup.includes(">shop.example.test<"), "T-BCC-3: the site line names the host");
  assert(markup.includes("A throwaway browser"), "T-BCC-4: the browser line names the profile");
  assert(!markup.includes("signed-in sites"), "T-BCC-5: a throwaway browser is not flagged");
  assert(!markup.includes("Can reach"), "T-BCC-6: no chips, no chip list");
  assert(markup.includes("See the exact input"), "T-BCC-7: the exact input stays one click away");
}

// Site history and a shared profile are flagged in words.
{
  const markup = render(
    item(
      "page_open",
      { url: "https://docs.example.test/" },
      card({
        headline: "Claude Code wants to open docs.example.test",
        site: { origin: "https://docs.example.test", first_visit_in_task: true, left_granted_site: true },
        profile_line: "shared",
      }),
    ),
  );
  assert(markup.includes("First visit in this task"), "T-BCC-8: a first visit is said");
  assert(markup.includes("Outside the site you allowed"), "T-BCC-9: leaving the granted site is said");
  assert(markup.includes("Your own browser profile") && markup.includes("signed-in sites"), "T-BCC-10: a shared profile says what it can reach");
}

// Typed text never appears; masked input shows only its length; chips are named list items.
{
  const markup = render(
    item(
      "page_fill",
      { element: "Password", text: "typed-sample-value" },
      card({
        headline: "Claude Code wants to type into a form on shop.example.test",
        verb: "type",
        detail: { element_preview: "Password", input_kind: "text", input_length: 18, input_masked: true },
        risk_chips: ["password_field", "cookies", "password_field"],
      }),
    ),
  );
  const visible = markup.split("See the exact input")[0] ?? "";
  assert(!visible.includes("typed-sample-value"), "T-BCC-11: typed text is not on the card face");
  assert(visible.includes(">On<") && visible.includes(">Password<"), "T-BCC-12: the element is named");
  assert(visible.includes("Hidden · 18 characters"), "T-BCC-13: masked input shows only its length");
  assert(visible.includes("Guard does not show what it types here."), "T-BCC-14: masking is explained");
  const chips = visible.match(/data-browser-surface="[a-z_]+"/g) ?? [];
  assert(chips.length === 2, `T-BCC-15: duplicate chips collapse (${chips.length})`);
  assert(/<ul aria-labelledby="[^"]+"/.test(visible) && visible.includes(">Password field</li>"), "T-BCC-16: each chip is a labelled list item with its own text");
}

// Script steps show their code; a missing site is said, not guessed.
{
  const markup = render(
    item(
      "page_eval",
      { script: "() => document.title" },
      card({
        headline: "Claude Code wants to run a script in the browser",
        verb: "evaluate",
        site: { origin: null, first_visit_in_task: false, left_granted_site: false },
        profile_line: "unknown",
        detail: { element_preview: null, input_kind: "script", input_length: 20, input_masked: false },
        risk_chips: ["script_eval"],
      }),
    ),
  );
  assert(markup.includes("Guard could not tell which site"), "T-BCC-17: an unknown site is said plainly");
  assert(markup.includes("document.title"), "T-BCC-18: page code is shown");
  assert(markup.includes("Guard treats it as your own profile."), "T-BCC-19: an unknown browser is treated as shared");
}

// Without a card, the ordinary MCP card renders.
{
  const markup = render(item("page_open", { url: "https://shop.example.test/" }, null));
  assert(!markup.includes("data-browser-card"), "T-BCC-20: no card, no browser layout");
}
