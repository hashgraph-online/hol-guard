import { plainEnglishRequestTitle, whyPaused, humanFileName } from "./plain-english";
import type { GuardApprovalRequest, GuardActionEnvelope } from "../guard-types";
import { assert } from "node:console";

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

// T6: whyPaused for non-shell unknowns should use generic reason
{
  const request = buildShellRequest({
    artifact_type: "unknown_type",
  });
  const reason = whyPaused(request);
  assert(reason === "Guard paused this so you can review it first.", `T6: expected generic pause reason, got "${reason}"`);
}

// T7: humanFileName returns human-friendly names for known file types
{
  assert(humanFileName(".env") === "your secrets file", "T7: .env should be 'your secrets file'");
  assert(humanFileName("config.json") === "a settings file", "T7: config.json should be 'a settings file'");
  assert(humanFileName("script.sh") === "a shell script", "T7: script.sh should be 'a shell script'");
}

// T8: humanFileName returns a file for empty input
{
  assert(humanFileName(null) === "a file", "T8: null should be 'a file'");
  assert(humanFileName(undefined) === "a file", "T8: undefined should be 'a file'");
  assert(humanFileName("") === "a file", "T8: empty string should be 'a file'");
}

console.log("plain-english.test.ts: all tests passed");
