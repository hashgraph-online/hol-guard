"""Active OMP-only input replacement for native-required test containment."""

from __future__ import annotations

CONTAINED_TEST_HELPERS_SOURCE = r"""
  const containedTestRequests = new Map<string, string>();
  const containedTestPresentations = new Map<string, { input: Record<string, unknown>; command: string }>();

  pi.on("tool_result", (event) => {
    const key = toolCallIdKey(event.toolCallId);
    const presentation = key ? containedTestPresentations.get(key) : undefined;
    if (!key || !presentation) return undefined;
    const details = event.details && typeof event.details === "object" && !Array.isArray(event.details)
      ? event.details : {};
    return { details: { ...details, holGuardContainedTest: {
      schema: "guard-contained-test-presentation.v1", toolCallId: key, ...presentation,
    } } };
  });

  pi.on("context", (event) => {
    // Only provider projection changes. The stored execution input remains an
    // audit record of the protected sink; every new call still passes Guard.
    const presentations = new Map(containedTestPresentations);
    for (const message of event.messages) {
      if (message.role !== "toolResult") continue;
      const proof = message.details?.holGuardContainedTest;
      if (proof?.schema !== "guard-contained-test-presentation.v1" ||
          proof.toolCallId !== message.toolCallId || typeof proof.command !== "string" ||
          !proof.input || typeof proof.input.command !== "string") continue;
      try {
        const serialized = JSON.stringify(proof);
        if (serialized.length > 32_768) continue;
        const clean = JSON.parse(serialized);
        presentations.set(clean.toolCallId, { input: clean.input, command: clean.command });
      } catch { continue; }
    }
    let changed = false;
    const messages = event.messages.map((message) => {
      if (message.role !== "assistant" || !Array.isArray(message.content)) return message;
      const content = message.content.map((block) => {
        if (block.type !== "toolCall" || block.name !== "bash") return block;
        const presentation = presentations.get(block.id);
        if (!presentation || block.arguments?.command !== presentation.command) return block;
        changed = true;
        return { ...block, arguments: { ...presentation.input } };
      });
      return { ...message, content };
    });
    return changed ? { messages } : undefined;
  });

  pi.on("session_shutdown", () => containedTestPresentations.clear());

  function cleanupContainedTestRequest(toolCallId: unknown): void {
    const key = toolCallIdKey(toolCallId);
    const directory = key ? containedTestRequests.get(key) : undefined;
    if (!key || !directory) return;
    containedTestRequests.delete(key);
    try { rmSync(directory, { recursive: true, force: true }); } catch {}
  }

  pi.on("session_stop", () => {
    for (const key of containedTestRequests.keys()) cleanupContainedTestRequest(key);
  });

  function prepareContainedTestInput(
    response: GuardResponse,
    snapshot: ToolCallSnapshot,
  ): Record<string, unknown> | null {
    const profile = Reflect.get(response, "required_execution_profile");
    const input = snapshot.payload.tool_input;
    const key = toolCallIdKey(snapshot.payload.tool_call_id);
    const profileMatches = (
      (profile === "package-test-readonly-v1" && response.reason_code === "native_package_test_readonly_containment_required") ||
      (profile === "node-build-output-v1" && response.reason_code === "native_node_build_output_containment_required") ||
      (profile === "node-tool-readonly-v1" && response.reason_code === "native_node_tool_readonly_containment_required") ||
      (profile === "git-readonly-v1" && response.reason_code === "native_git_readonly_containment_required") ||
      (profile === "pytest-readonly-v2" && response.reason_code === "native_pytest_readonly_containment_required") ||
      (profile === "vitest-readonly-v1" && response.reason_code === "native_vitest_readonly_containment_required") ||
      (profile === "node-test-readonly-v1" && response.reason_code === "native_node_test_readonly_containment_required")
    );
    if (
      response.decision !== "deny" || response.policy_action !== "sandbox-required" ||
      !profileMatches || response.observe_mode === true ||
      process.platform !== "darwin" || GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS ||
      !GUARD_CLI_WRAPPER_COMMAND.startsWith("/") ||
      snapshot.payload.tool_name !== "bash" || !key || containedTestRequests.has(key) ||
      !input || typeof input !== "object" || Array.isArray(input) ||
      typeof (input as Record<string, unknown>).command !== "string"
    ) return null;
    const serialized = JSON.stringify({
      schema: "guard-contained-test-request.v1", workspace: snapshot.cwd, payload: snapshot.payload,
    });
    if (Buffer.byteLength(serialized, "utf8") > 1_048_576) return null;
    const directory = mkdtempSync(join(tmpdir(), "hol-guard-contained-test-"));
    try {
      chmodSync(directory, 0o700);
      const requestPath = join(directory, "request.json");
      writeFileSync(requestPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
      const digest = createHash("sha256").update(serialized, "utf8").digest("hex");
      const args = [
        "execute-contained-test", "--guard-home", GUARD_HOME, "--workspace", snapshot.cwd,
        "--request-file", requestPath, "--request-sha256", digest,
      ];
      if (!GUARD_HOME_DIR_IS_DEFAULT) args.push("--home", GUARD_HOME_DIR);
      const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
      const command = [GUARD_CLI_WRAPPER_COMMAND, ...args].map(quote).join(" ");
      containedTestRequests.set(key, directory);
      containedTestPresentations.set(key, { input: { ...(input as Record<string, unknown>) }, command });
      while (containedTestPresentations.size > 256) {
        const oldest = containedTestPresentations.keys().next().value;
        if (oldest === undefined) break;
        containedTestPresentations.delete(oldest);
      }
      return { ...(input as Record<string, unknown>), command };
    } catch {
      try { rmSync(directory, { recursive: true, force: true }); } catch {}
      return null;
    }
  }
"""

CONTAINED_TEST_BRANCH_SOURCE = r"""
    const requiredProfile = Reflect.get(response, "required_execution_profile");
    if (requiredProfile !== undefined) {
      const input = prepareContainedTestInput(response, snapshot);
      if (!input) {
        const reason = "HOL Guard could not enforce the required protected test runner. Execution was not started.";
        ctx.ui.notify(reason, "warning");
        return { block: true, reason };
      }
      return { input };
    }
"""


def with_contained_test_routing(shared_source: str) -> str:
    """Extend only the active OMP variant, keeping the previous v1 text frozen."""
    branch = '    if (response.decision === "deny") {\n      const reason = ompInteractiveContext(ctx)'
    cleanup = '  pi.on("tool_result", async (event, ctx) => {\n'
    if shared_source.count(branch) != 1 or shared_source.count(cleanup) != 1:
        raise ValueError("OMP containment insertion point changed")
    return CONTAINED_TEST_HELPERS_SOURCE + shared_source.replace(
        branch,
        CONTAINED_TEST_BRANCH_SOURCE + branch,
        1,
    ).replace(cleanup, cleanup + "    cleanupContainedTestRequest(event.toolCallId);\n", 1)
