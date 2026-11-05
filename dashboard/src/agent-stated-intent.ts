import type { GuardApprovalRequest } from "./guard-types";

/**
 * The agent's own one-line account of a command, exactly as its harness sent it.
 *
 * Claude Code's Bash tool and Gemini's run_shell_command carry `description`,
 * and Codex shell calls can carry `justification`. Core keeps the hook payload
 * redacted, with each string cut to 240 characters, in
 * `action_envelope_json.raw_payload_redacted`, so nothing new is stored or
 * sent to show it.
 *
 * This is a claim by the agent, not Guard's judgment. A prompt-injected agent
 * can write a reassuring line, so callers show it quoted and attributed, and
 * never feed it into a decision, a risk label, "Why paused" or any summary.
 */
export type AgentStatedIntent = {
  text: string;
  field: (typeof INTENT_FIELDS)[number];
};

const INTENT_FIELDS = ["description", "justification"] as const;
const MAX_INTENT_CHARS = 300;
// Control characters and bidirectional overrides could hide or reorder the
// quoted text on screen; whitespace runs are collapsed so the line stays one line.
// Built from escaped text so the bundled file carries no literal bidi characters.
const UNSAFE_CHARACTERS = new RegExp(
  "[\\u0000-\\u001f\\u007f-\\u009f\\u200e\\u200f\\u202a-\\u202e\\u2066-\\u2069]",
  "g",
);

export function resolveAgentStatedIntent(item: GuardApprovalRequest): AgentStatedIntent | null {
  const envelope = item.action_envelope_json;
  if (!envelope) {
    return null;
  }
  // Only the harness's own shell tool documents these fields as the agent's
  // account of the command. Another tool's `description` input can be content,
  // such as an issue body or a commit message.
  if (envelope.action_type !== "shell_command" && envelope.action_type !== "package_script") {
    return null;
  }
  if (envelope.mcp_server) {
    return null;
  }
  const toolInput = recordValue(recordValue(envelope.raw_payload_redacted)?.tool_input);
  if (toolInput === null) {
    return null;
  }
  for (const field of INTENT_FIELDS) {
    const value = toolInput[field];
    if (typeof value !== "string") {
      continue;
    }
    const text = value.replace(UNSAFE_CHARACTERS, " ").replace(/\s+/g, " ").trim();
    if (text.length === 0) {
      continue;
    }
    return {
      text: text.length > MAX_INTENT_CHARS ? `${text.slice(0, MAX_INTENT_CHARS)}…` : text,
      field,
    };
  }
  return null;
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}
