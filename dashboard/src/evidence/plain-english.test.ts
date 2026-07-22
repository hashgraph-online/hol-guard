import { describe, it, expect } from "bun:test";
import { plainEnglishRequestTitle, whyPaused, humanFileName } from "./plain-english";
import type { GuardApprovalRequest, GuardActionEnvelope } from "../guard-types";

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

describe("plainEnglishRequestTitle", () => {
  it("uses clear title for shell commands instead of raw artifact name", () => {
    const request = buildShellRequest({
      artifact_name: "compound unmodeled compound shell command",
      artifact_type: "shell_command",
    });
    const title = plainEnglishRequestTitle(request);
    expect(title).toBe("Codex wants to run a shell command");
    expect(title).not.toContain("compound unmodeled");
  });

  it("uses clear title when action envelope indicates shell command", () => {
    const request = buildShellRequest({
      artifact_name: "some weird artifact name",
      artifact_type: "other_type",
      action_envelope_json: { action_type: "shell_command" } as unknown as GuardActionEnvelope | null,
    });
    const title = plainEnglishRequestTitle(request);
    expect(title).toBe("Codex wants to run a shell command");
  });

  it("falls back to generic title for non-shell unknown artifacts", () => {
    const request = buildShellRequest({
      artifact_name: "mystery-artifact",
      artifact_type: "unknown_type",
    });
    const title = plainEnglishRequestTitle(request);
    expect(title).toBe("Codex wants to do something with mystery-artifact");
  });

  it("preserves secret category title", () => {
    const request = buildShellRequest({
      artifact_name: ".env",
      artifact_type: "file_read",
    });
    const title = plainEnglishRequestTitle(request);
    expect(title).toBe("Codex wants to read your secrets file");
  });
});

describe("whyPaused", () => {
  it("explains shell command pause reason clearly", () => {
    const request = buildShellRequest({
      artifact_type: "shell_command",
    });
    const reason = whyPaused(request);
    expect(reason).toContain("shell command");
    expect(reason).toContain("could not fully inspect");
    expect(reason).not.toContain("compound");
  });

  it("uses generic pause reason for non-shell unknowns", () => {
    const request = buildShellRequest({
      artifact_type: "unknown_type",
    });
    const reason = whyPaused(request);
    expect(reason).toBe("Guard paused this so you can review it first.");
  });
});

describe("humanFileName", () => {
  it("returns human-friendly names for known file types", () => {
    expect(humanFileName(".env")).toBe("your secrets file");
    expect(humanFileName("config.json")).toBe("a settings file");
    expect(humanFileName("script.sh")).toBe("a shell script");
  });

  it("returns a file for empty input", () => {
    expect(humanFileName(null)).toBe("a file");
    expect(humanFileName(undefined)).toBe("a file");
    expect(humanFileName("")).toBe("a file");
  });
});
