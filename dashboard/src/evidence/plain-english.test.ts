import {
  plainEnglishRequestTitle,
  resolveActionSubtitle,
  resolveActionTitle,
  resolveActionTitleTooltip,
  whyPaused,
  humanFileName,
} from "./plain-english";
import type { GuardApprovalRequest, GuardActionEnvelope, GuardReceipt } from "../guard-types";
import assert from "node:assert/strict";

function buildShellRequest(overrides: Partial<GuardApprovalRequest> = {}): GuardApprovalRequest {
  return {
    request_id: "req-1",
    harness: "codex",
    artifact_id: "art-1",
    artifact_name: "compound unmodeled compound shell command",
    artifact_type: "shell_command",
    artifact_hash: "",
    publisher: null,
    policy_action: "ask",
    recommended_scope: "artifact",
    changed_fields: [],
    source_scope: "user",
    config_path: "",
    review_command: "",
    approval_url: "",
    status: "pending",
    resolution_action: null,
    resolution_scope: null,
    reason: null,
    created_at: new Date().toISOString(),
    resolved_at: null,
    ...overrides,
  } as unknown as GuardApprovalRequest;
}

function buildShellReceipt(overrides: Partial<GuardReceipt> = {}): GuardReceipt {
  return {
    receipt_id: "receipt-1",
    harness: "codex",
    artifact_id: "artifact-1",
    artifact_hash: "hash-1",
    policy_decision: "review",
    capabilities_summary: "",
    changed_capabilities: [],
    provenance_summary: "",
    user_override: null,
    artifact_name: "bun",
    source_scope: null,
    timestamp: new Date().toISOString(),
    action_envelope_json: {
      action_type: "package_script",
      package_name: "bun",
    } as unknown as GuardActionEnvelope,
    ...overrides,
  };
}

// T12: a command-like receipt with no typed command uses the retained raw command.
{
  const receipt = buildShellReceipt({
    capabilities_summary: "bun custom",
    raw_command_text: "bun custom",
  });
  assert(resolveActionTitle(receipt) === "bun custom", "T12: raw command should replace the executable-only title");
  assert(resolveActionSubtitle(receipt) === null, "T12: duplicate command metadata should not become the subtitle");
  assert(resolveActionTitleTooltip(receipt) === "bun custom", "T12: short raw command remains available to assistive text");

  const longCommand = `bun custom ${"--flag ".repeat(20)}`.trim();
  const longReceipt = buildShellReceipt({ raw_command_text: longCommand });
  assert(resolveActionTitle(longReceipt).endsWith("…"), "T12: long raw command remains compact in the visible title");
  assert(resolveActionTitleTooltip(longReceipt) === longCommand, "T12: hover and assistive text retain the full command");
}

// T13: an envelope command still wins, and risk signal titles stay authoritative.
{
  const receipt = buildShellReceipt({
    raw_command_text: "bun custom",
    action_envelope_json: {
      action_type: "shell_command",
      command: "bun run check",
    } as unknown as GuardActionEnvelope,
  });
  assert(resolveActionTitle(receipt) === "bun run check", "T13: typed envelope command should remain preferred");
  assert(resolveActionTitleTooltip(receipt) === "bun run check", "T13: typed command remains available to assistive text");

  const differentCommands = buildShellReceipt({
    raw_command_text: `bun custom ${"--raw ".repeat(20)}`,
    action_envelope_json: {
      action_type: "package_script",
      command: "bun run check",
      package_name: "bun",
    } as unknown as GuardActionEnvelope,
  });
  assert(resolveActionTitleTooltip(differentCommands) === differentCommands.raw_command_text?.trim(),
    "T13: package tooltip follows the raw command used by its title");

  const longTypedCommand = `bun run check ${"--typed ".repeat(20)}`.trim();
  const longTypedReceipt = buildShellReceipt({
    capabilities_summary: longTypedCommand,
    raw_command_text: "bun custom",
    action_envelope_json: {
      action_type: "shell_command",
      command: longTypedCommand,
    } as unknown as GuardActionEnvelope,
  });
  assert(resolveActionTitleTooltip(longTypedReceipt) === longTypedCommand,
    "T13: shell tooltip retains the full typed command");
  assert(resolveActionSubtitle(longTypedReceipt) === null,
    "T13: full typed command is not repeated in the subtitle");

  const riskyReceipt = buildShellReceipt({
    raw_command_text: "bun custom",
    scanner_evidence: [{
      signal_id: "signal-1",
      category: "execution",
      severity: "high",
      confidence: "strong",
      detector: "test",
      title: "Runs an untrusted custom command",
      plain_reason: "This command is not trusted.",
      technical_detail: null,
      evidence_ref: null,
      redaction_level: "none",
      false_positive_hint: null,
      advisory_id: null,
    }],
  });
  assert(resolveActionTitle(riskyReceipt) === "Runs an untrusted custom command", "T13: scanner title should remain preferred");
}

// T14: absent or blank raw command falls back to the normal artifact title.
{
  assert(resolveActionTitle(buildShellReceipt()) === "bun", "T14: missing raw command should preserve artifact fallback");
  assert(resolveActionTitle(buildShellReceipt({ raw_command_text: "  " })) === "bun", "T14: blank raw command should preserve artifact fallback");
}

// T1: shell command title should not include raw artifact name
{
  const request = buildShellRequest({
    artifact_name: "compound unmodeled compound shell command",
    artifact_type: "shell_command",
  });
  const title = plainEnglishRequestTitle(request);
  assert(title === "Codex wants to run a shell command", `T1: expected shell command title, got "${title}"`);
  assert(!title.includes("compound unmodeled"), "T1: title must not include raw artifact name");
}

// T2: action_envelope action_type shell_command should also trigger clear title
{
  const request = buildShellRequest({
    artifact_name: "some weird artifact name",
    artifact_type: "other_type",
    action_envelope_json: { action_type: "shell_command" } as unknown as GuardActionEnvelope | null,
  });
  const title = plainEnglishRequestTitle(request);
  assert(title === "Codex wants to run a shell command", `T2: expected shell command title, got "${title}"`);
}

// T3: non-shell unknown artifacts should fall back to generic title
{
  const request = buildShellRequest({
    artifact_name: "mystery-artifact",
    artifact_type: "unknown_type",
  });
  const title = plainEnglishRequestTitle(request);
  assert(title === "Codex wants to do something with mystery-artifact", `T3: expected generic title, got "${title}"`);
}

// T4: secret category title is preserved
{
  const request = buildShellRequest({
    artifact_name: ".env",
    artifact_type: "file_read",
  });
  const title = plainEnglishRequestTitle(request);
  assert(title === "Codex wants to read your secrets file", `T4: expected secret title, got "${title}"`);
}

// T5: whyPaused for shell commands should be clear and not contain jargon
{
  const request = buildShellRequest({
    artifact_type: "shell_command",
  });
  const reason = whyPaused(request);
  assert(reason.includes("shell command"), `T5: pause reason should mention shell command, got "${reason}"`);
  assert(reason.includes("could not fully inspect"), `T5: pause reason should explain inspection, got "${reason}"`);
  assert(!reason.includes("compound"), `T5: pause reason must not contain 'compound', got "${reason}"`);
}

// T6: package installs should explain the dependency mutation risk
{
  const request = buildShellRequest({
    action_envelope_json: {
      action_type: "shell_command",
      command: "bun install --frozen-lockfile",
      package_manager: "bun",
      package_intent_kind: "install",
    } as unknown as GuardActionEnvelope | null,
  });
  const reason = whyPaused(request);
  assert(reason.includes("mutates project dependencies"), `T6: package reason should explain dependency mutation, got "${reason}"`);
  assert(reason.includes("installed packages"), `T6: package reason should mention installed packages, got "${reason}"`);
  assert(!reason.includes("could not fully inspect"), `T6: package reason must not claim incomplete inspection, got "${reason}"`);
}

// T7: command text still identifies a package install when envelope metadata is incomplete
{
  const request = buildShellRequest({
    action_envelope_json: {
      action_type: "shell_command",
      command: "bun install --frozen-lockfile",
    } as unknown as GuardActionEnvelope | null,
  });
  const reason = whyPaused(request);
  assert(reason.includes("mutates project dependencies"), `T7: command fallback should explain dependency mutation, got "${reason}"`);
}

// T8: compound commands retain the incomplete-inspection explanation
{
  const request = buildShellRequest({
    action_envelope_json: {
      action_type: "shell_command",
      command: "cd project && bun install --frozen-lockfile",
      package_manager: "bun",
      package_intent_kind: "install",
    } as unknown as GuardActionEnvelope | null,
  });
  const reason = whyPaused(request);
  assert(reason.includes("could not fully inspect"), `T8: compound reason should explain incomplete inspection, got "${reason}"`);
  assert(!reason.includes("mutates project dependencies"), `T8: compound reason must not hide incomplete inspection, got "${reason}"`);
}

// T9: whyPaused for non-shell unknowns should use generic reason
{
  const request = buildShellRequest({
    artifact_type: "unknown_type",
  });
  const reason = whyPaused(request);
  assert(reason === "Guard paused this so you can review it first.", `T9: expected generic pause reason, got "${reason}"`);
}

// T10: humanFileName returns human-friendly names for known file types
{
  assert(humanFileName(".env") === "your secrets file", "T10: .env should be 'your secrets file'");
  assert(humanFileName("config.json") === "a settings file", "T10: config.json should be 'a settings file'");
  assert(humanFileName("script.sh") === "a shell script", "T10: script.sh should be 'a shell script'");
}

// T11: humanFileName returns a file for empty input
{
  assert(humanFileName(null) === "a file", "T11: null should be 'a file'");
  assert(humanFileName(undefined) === "a file", "T11: undefined should be 'a file'");
  assert(humanFileName("") === "a file", "T11: empty string should be 'a file'");
}

console.log("plain-english.test.ts: all tests passed");
