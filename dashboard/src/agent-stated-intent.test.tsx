import { renderToStaticMarkup } from "react-dom/server";
import { resolveAgentStatedIntent } from "./agent-stated-intent";
import type { GuardActionEnvelope, GuardApprovalRequest } from "./guard-types";
import { PrimaryActionCard } from "./review-states";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const LABEL = "What the agent said it is doing";

const SHELL_ENVELOPE: GuardActionEnvelope = {
  schema_version: 1,
  action_id: "act-agent-intent",
  harness: "claude-code",
  event_name: "PreToolUse",
  action_type: "shell_command",
  workspace: "/workspace/project",
  workspace_hash: null,
  tool_name: "Bash",
  command: "git push --force origin main",
  prompt_excerpt: null,
  prompt_text: null,
  target_paths: [],
  network_hosts: [],
  mcp_server: null,
  mcp_tool: null,
  package_manager: null,
  package_name: null,
  script_name: null,
  raw_payload_redacted: {
    hook_event_name: "PreToolUse",
    tool_name: "Bash",
    tool_input: {
      command: "git push --force origin main",
      description: "Force-push the rebased branch to origin",
    },
  },
};

const BASE_REQUEST: GuardApprovalRequest = {
  request_id: "request-agent-intent",
  harness: "claude-code",
  artifact_id: "claude-code:project:bash",
  artifact_name: "bash",
  artifact_type: "command",
  artifact_hash: "sha256-agent-intent",
  publisher: null,
  policy_action: "require-reapproval",
  recommended_scope: "artifact",
  changed_fields: ["first_seen"],
  source_scope: "project",
  config_path: "./claude.json",
  launch_target: "git push --force origin main",
  transport: "stdio",
  review_command: "hol-guard approvals approve request-agent-intent",
  approval_url: "http://127.0.0.1:4781/approvals/request-agent-intent",
  status: "pending",
  resolution_action: null,
  resolution_scope: null,
  reason: null,
  created_at: "2026-11-05T12:00:00Z",
  resolved_at: null,
  action_envelope_json: SHELL_ENVELOPE,
};

function requestWith(
  envelope: Partial<GuardActionEnvelope>,
  toolInput?: Record<string, unknown>,
): GuardApprovalRequest {
  const raw = toolInput === undefined
    ? SHELL_ENVELOPE.raw_payload_redacted
    : { ...SHELL_ENVELOPE.raw_payload_redacted, tool_input: toolInput };
  return {
    ...BASE_REQUEST,
    action_envelope_json: { ...SHELL_ENVELOPE, raw_payload_redacted: raw, ...envelope },
  };
}

// A Claude Code Bash description is shown, quoted and attributed to the agent.
{
  const intent = resolveAgentStatedIntent(BASE_REQUEST);
  assert(intent?.text === "Force-push the rebased branch to origin", "reads the Bash description");
  assert(intent?.field === "description", "reports the description field");
  const markup = renderToStaticMarkup(PrimaryActionCard({ item: BASE_REQUEST }));
  assert(markup.includes(LABEL), "the card labels the agent's line");
  assert(markup.includes("“Force-push the rebased branch to origin”"), "the card quotes the line verbatim");
  assert(markup.includes("Guard has not checked this"), "the card says Guard did not check it");
}

// Codex escalation calls carry `justification` instead.
{
  const intent = resolveAgentStatedIntent(
    requestWith(
      { harness: "codex", tool_name: "shell" },
      { command: ["rm", "-rf", "build"], justification: "Clean the build output" },
    ),
  );
  assert(intent?.text === "Clean the build output", "falls back to justification");
  assert(intent?.field === "justification", "reports the justification field");
}

// Package scripts run through the shell tool keep the line too.
assert(
  resolveAgentStatedIntent(requestWith({ action_type: "package_script" }))?.text ===
    "Force-push the rebased branch to origin",
  "package scripts show the agent's line",
);

// Another tool's `description` can be content, so it is never shown as intent.
assert(
  resolveAgentStatedIntent(requestWith({ action_type: "mcp_tool", mcp_server: "github" }, { description: "Issue body" })) ===
    null,
  "an MCP tool's description input is not the agent's intent",
);
assert(
  resolveAgentStatedIntent(requestWith({ mcp_server: "shell-server" })) === null,
  "a shell-like MCP tool is not read either",
);
assert(
  resolveAgentStatedIntent(requestWith({ action_type: "file_write" }, { description: "Notes" })) === null,
  "file writes are not read",
);
// Core classes a non-shell tool as shell_command when its input has a
// command-like key; the tool name keeps its `description` off the card.
assert(
  resolveAgentStatedIntent(
    requestWith({ tool_name: "Search" }, { query: "deploy keys", description: "Saved search notes" }),
  ) === null,
  "a non-shell tool with a command-like input is not read",
);

// The input is read from the same keys Core accepts, under the raw tool name
// when the envelope has none.
{
  const request = requestWith({
    harness: "gemini",
    tool_name: null,
    raw_payload_redacted: {
      tool_name: "run_shell_command",
      toolInput: { command: "npm test", description: "Run the unit tests" },
    },
  });
  assert(resolveAgentStatedIntent(request)?.text === "Run the unit tests", "reads toolInput under run_shell_command");
}

// Missing or unusable input renders nothing.
assert(resolveAgentStatedIntent({ ...BASE_REQUEST, action_envelope_json: null }) === null, "no envelope");
assert(resolveAgentStatedIntent(requestWith({ raw_payload_redacted: {} })) === null, "no tool_input");
assert(resolveAgentStatedIntent(requestWith({}, { command: "ls", description: 42 })) === null, "non-string description");
assert(resolveAgentStatedIntent(requestWith({}, { command: "ls", description: "  \n\t " })) === null, "blank description");
{
  const markup = renderToStaticMarkup(PrimaryActionCard({ item: requestWith({}, { command: "ls" }) }));
  assert(!markup.includes(LABEL), "no label without a line");
}

// Control characters and bidi overrides cannot hide or reorder the quote.
{
  const intent = resolveAgentStatedIntent(
    requestWith({}, { command: "ls", description: "List\nfiles‮  gnihton\u0007 here" }),
  );
  assert(intent?.text === "List files gnihton here", `unsafe characters are removed: ${JSON.stringify(intent?.text)}`);
}

// A long line is cut, and markup in the line stays text.
{
  const intent = resolveAgentStatedIntent(requestWith({}, { command: "ls", description: "x".repeat(400) }));
  assert(intent?.text.length === 301 && intent.text.endsWith("…"), "long lines are cut to 300 characters");
  const markup = renderToStaticMarkup(
    PrimaryActionCard({ item: requestWith({}, { command: "ls", description: "<img src=x onerror=alert(1)>" }) }),
  );
  assert(markup.includes("&lt;img src=x onerror=alert(1)&gt;"), "markup in the line is escaped");
  assert(!markup.includes("<img src=x"), "markup in the line is not rendered");
}

console.log("agent-stated-intent tests passed");
