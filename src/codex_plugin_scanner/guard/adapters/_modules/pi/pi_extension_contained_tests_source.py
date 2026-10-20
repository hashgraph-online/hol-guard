"""Active Pi and OMP input replacement for native-required test containment."""

from __future__ import annotations

from .pi_extension_bound_bash_intent_source import BOUND_BASH_INTENT_SOURCE
from .pi_extension_bound_bash_result_source import BOUND_BASH_RESULT_SOURCE

CONTAINED_TEST_HELPERS_SOURCE = (
    BOUND_BASH_INTENT_SOURCE
    + BOUND_BASH_RESULT_SOURCE
    + r"""
  const boundBashHarness = "omp";
  const containedTestRequests = new Map<string, string>();
  const boundBashInvocations = new Map<string, { operationId: string; cwd: string }>();
  const containedTestPresentations = new Map<string, { input: Record<string, unknown>; command: string }>();

  function boundBashObservedExit(
    event: { details?: unknown; isError?: boolean; content?: unknown },
  ): number | undefined {
    const details = event.details && typeof event.details === "object"
      ? event.details as Record<string, unknown> : {};
    if (typeof details.exitCode === "number") return details.exitCode;
    if (event.isError === false) return 0;
    // Pi's Bash tool throws this terminal diagnostic for a normal nonzero
    // exit. It is only an observation: native signed completion must agree.
    if ((boundBashHarness as string) !== "pi" || event.isError !== true ||
        !Array.isArray(event.content)) return undefined;
    const last = event.content[event.content.length - 1];
    if (!last || last.type !== "text" || typeof last.text !== "string" ||
        last.text.length > 1_048_576) return undefined;
    const match = /(?:^|\n\n)Command exited with code ([1-9][0-9]{0,2})(?![\s\S])/.exec(last.text);
    return match ? Number(match[1]) : undefined;
  }

  pi.on("tool_result", async (event) => {
    const key = toolCallIdKey(event.toolCallId);
    const presentation = key ? containedTestPresentations.get(key) : undefined;
    if (!key || !presentation) return undefined;
    const details = event.details && typeof event.details === "object" && !Array.isArray(event.details)
      ? event.details : {};
    return { details: { ...details, holGuardContainedTest: {
      schema: "guard-contained-test-presentation.v1", toolCallId: key, ...presentation,
    } } };
  });

  pi.on("context", async (event) => {
    await acknowledgeBoundBashContext(event.messages);
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

  // A backgrounded call returns before its job reads the request, so the
  // sink owns that file and removes it once read. Shutdown releases any that
  // a job never reached.
  const backgroundContainedTestRequests = new Set<string>();
  function releaseBackgroundContainedTestRequests(): void {
    for (const directory of backgroundContainedTestRequests) {
      try { rmSync(directory, { recursive: true, force: true }); } catch {}
    }
    backgroundContainedTestRequests.clear();
  }

  pi.on("session_shutdown", () => {
    acknowledgedBoundBashResults.clear();
    boundBashInvocations.clear();
    containedTestPresentations.clear();
    releaseBackgroundContainedTestRequests();
  });

  function cleanupContainedTestRequest(toolCallId: unknown, details?: unknown): void {
    const key = toolCallIdKey(toolCallId);
    const directory = key ? containedTestRequests.get(key) : undefined;
    if (!key || !directory) return;
    containedTestRequests.delete(key);
    const job = details && typeof details === "object" ? Reflect.get(details, "async") : undefined;
    if (job && typeof job === "object" && Reflect.get(job, "state") === "running") {
      backgroundContainedTestRequests.add(directory);
      return;
    }
    try { rmSync(directory, { recursive: true, force: true }); } catch {}
  }

  pi.on("session_stop", () => {
    for (const key of containedTestRequests.keys()) cleanupContainedTestRequest(key);
  });

  function prepareContainedTestInput(
    response: GuardResponse,
    snapshot: ToolCallSnapshot,
    ctx?: unknown,
  ): Record<string, unknown> | null {
    const profile = Reflect.get(response, "required_execution_profile");
    const input = snapshot.payload.tool_input;
    const key = toolCallIdKey(snapshot.payload.tool_call_id);
    const boundBash = profile === "native-bash-owner-v1" && response.reason_code === "native_bash_owner_required";
    const boundBashIntent = boundBash && typeof snapshot.payload.session_id === "string"
      ? boundBashIntentFor(ctx, snapshot.payload.session_id) : null;
    const profileMatches = (
      boundBash ||
      (profile === "python-eval-readonly-v1" &&
        response.reason_code === "native_python_eval_readonly_containment_required") ||
      (profile === "node-eval-readonly-v1" &&
        response.reason_code === "native_node_eval_readonly_containment_required") ||
      (profile === "node-eval-readonly-v1" &&
        response.reason_code === "native_bun_eval_readonly_containment_required") ||
      (profile === "package-test-readonly-v1" &&
        response.reason_code === "native_package_test_readonly_containment_required") ||
      (profile === "node-build-output-v1" &&
        response.reason_code === "native_node_build_output_containment_required") ||
      (profile === "node-tool-readonly-v1" &&
        response.reason_code === "native_node_tool_readonly_containment_required") ||
      (profile === "git-readonly-v1" && response.reason_code === "native_git_readonly_containment_required") ||
      (profile === "pytest-readonly-v2" && response.reason_code === "native_pytest_readonly_containment_required") ||
      (profile === "vitest-readonly-v1" && response.reason_code === "native_vitest_readonly_containment_required") ||
      (profile === "node-test-readonly-v1" &&
        response.reason_code === "native_node_test_readonly_containment_required") ||
      (profile === "workspace-contained-v1" && response.reason_code === "native_workspace_containment_required")
    );
    // Windows runs installed Python and Node scripts, Vite builds, and local lint,
    // typecheck and format checks, in an AppContainer. Its sink starts from a fixed
    // argv and reads requests from the profile's Temp directory, which does not
    // follow the TEMP this process or the shell was given.
    const windowsSink = process.platform === "win32" &&
      (profile === "python-eval-readonly-v1" || profile === "node-eval-readonly-v1" ||
        profile === "node-build-output-v1" || profile === "node-tool-readonly-v1") &&
      GUARD_CONTAINED_SINK_COMMAND.length > 0 && GUARD_CONTAINED_REQUEST_ROOT !== "";
    if (
      response.decision !== "deny" || response.policy_action !== "sandbox-required" ||
      !profileMatches || response.observe_mode === true ||
      (process.platform !== "darwin" && !(process.platform === "linux" && profile === "workspace-contained-v1") &&
        !windowsSink) ||
      (!windowsSink && (GUARD_CLI_WRAPPER_ACCEPTS_JSON_ARGS || !GUARD_CLI_WRAPPER_COMMAND.startsWith("/"))) ||
      snapshot.payload.tool_name !== "bash" || !key || containedTestRequests.has(key) ||
      (boundBash && (!boundBashIntent || process.platform !== "darwin" ||
        !Number.isSafeInteger(process.pid) || process.pid <= 1 ||
        typeof snapshot.payload.session_id !== "string" ||
        snapshot.payload.session_id.length === 0)) ||
      !input || typeof input !== "object" || Array.isArray(input) ||
      typeof (input as Record<string, unknown>).command !== "string"
    ) return null;
    const serialized = JSON.stringify({
      schema: "guard-contained-test-request.v1", workspace: snapshot.cwd, payload: snapshot.payload,
    });
    if (Buffer.byteLength(serialized, "utf8") > 1_048_576) return null;
    // A request root that has since gone away denies the route like any other failure.
    let directory: string | undefined;
    try {
      directory = mkdtempSync(
        join(windowsSink ? GUARD_CONTAINED_REQUEST_ROOT : tmpdir(), "hol-guard-contained-test-"),
      );
      chmodSync(directory, 0o700);
      const requestPath = join(directory, "request.json");
      writeFileSync(requestPath, serialized, { encoding: "utf8", mode: 0o600, flag: "wx" });
      const digest = createHash("sha256").update(serialized, "utf8").digest("hex");
      const operationId = "bash-operation:" + createHash("sha256").update(JSON.stringify({
        schema: "guard-bash-tool-operation.v1", harness: boundBashHarness,
        session: snapshot.payload.session_id, intent: boundBashIntent, cwd: snapshot.cwd,
        toolCwd: (input as Record<string, unknown>).cwd ?? null,
        command: (input as Record<string, unknown>).command,
      }), "utf8").digest("hex");
      const timeoutSeconds = boundBash && typeof (input as Record<string, unknown>).timeout === "number"
        ? Math.max(1, Math.min(120, Math.ceil((input as Record<string, unknown>).timeout as number))) : 120;
      const args = boundBash ? [
        "execute-bound-bash", "--harness", boundBashHarness, "--operation-id", operationId,
        "--host-owner-pid", String(process.pid),
        "--tool-call-id", key,
        "--guard-home", GUARD_HOME, "--workspace", snapshot.cwd,
        "--request-file", requestPath, "--request-sha256", digest,
        "--timeout-seconds", String(timeoutSeconds),
      ] : [
        "execute-contained-test", "--guard-home", GUARD_HOME, "--workspace", snapshot.cwd,
        "--request-file", requestPath, "--request-sha256", digest,
      ];
      if (!GUARD_HOME_DIR_IS_DEFAULT) args.push("--home", GUARD_HOME_DIR);
      const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";
      const prefix = windowsSink ? GUARD_CONTAINED_SINK_COMMAND : [GUARD_CLI_WRAPPER_COMMAND];
      const command = [...prefix, ...args].map(quote).join(" ");
      containedTestRequests.set(key, directory);
      if (boundBash) boundBashInvocations.set(key, { operationId, cwd: snapshot.cwd });
      containedTestPresentations.set(key, { input: { ...(input as Record<string, unknown>) }, command });
      while (containedTestPresentations.size > 256) {
        const oldest = containedTestPresentations.keys().next().value;
        if (oldest === undefined) break;
        containedTestPresentations.delete(oldest);
        boundBashInvocations.delete(oldest);
      }
      return { ...(input as Record<string, unknown>), command };
    } catch {
      if (directory !== undefined) {
        try { rmSync(directory, { recursive: true, force: true }); } catch {}
      }
      return null;
    }
  }
"""
)

CONTAINED_TEST_BRANCH_SOURCE = r"""
    const requiredProfile = Reflect.get(response, "required_execution_profile");
    if (requiredProfile !== undefined) {
      const input = prepareContainedTestInput(response, snapshot, ctx);
      if (!input) {
        const reason = "HOL Guard could not enforce the required protected test runner. Execution was not started.";
        ctx.ui.notify(reason, "warning");
        return { block: true, reason };
      }
      return { input };
    }
"""


# Pi ignores a returned `input`; its extension API changes arguments only when
# the handler mutates `event.input` in place. The reviewed snapshot is a frozen
# deep copy, so the mutation cannot alter what Guard reviewed or the request file.
_PI_INPUT_RETURN = "      Object.assign(event.input, input);\n      return undefined;\n"
# The sink re-checks native authority under the harness it names; Pi must not
# be re-checked under OMP's harness-scoped policy.
_SINK_ARGS = '"execute-contained-test", "--guard-home"'
_PI_SINK_ARGS = '"execute-contained-test", "--harness", "pi", "--guard-home"'
# Pi has no `session_stop`; release unconsumed request files on shutdown instead.
_SHUTDOWN = "    releaseBackgroundContainedTestRequests();\n  });\n"
_PI_SHUTDOWN = (
    "    releaseBackgroundContainedTestRequests();\n"
    "    for (const key of containedTestRequests.keys()) cleanupContainedTestRequest(key);\n"
    "  });\n"
)


def with_contained_test_routing(shared_source: str, *, harness: str = "omp") -> str:
    """Extend the active Pi or OMP variant, keeping the previous v1 text frozen."""
    if harness == "omp":
        branch = '    if (response.decision === "deny") {\n      const reason = ompInteractiveContext(ctx)'
        helpers, branch_source = CONTAINED_TEST_HELPERS_SOURCE, CONTAINED_TEST_BRANCH_SOURCE
    elif harness == "pi":
        branch = (
            '    if (response.decision === "deny") {\n'
            '      const reason = approvalBlockedReason(response, response.reason ?? "Blocked by HOL Guard.");\n'
        )
        helpers = _replace_once(
            _replace_once(CONTAINED_TEST_HELPERS_SOURCE, _SINK_ARGS, _PI_SINK_ARGS), _SHUTDOWN, _PI_SHUTDOWN
        )
        helpers = _replace_once(helpers, 'const boundBashHarness = "omp";', 'const boundBashHarness = "pi";')
        branch_source = _replace_once(CONTAINED_TEST_BRANCH_SOURCE, "      return { input };\n", _PI_INPUT_RETURN)
    else:
        raise ValueError(f"no contained routing for harness {harness!r}")
    cleanup = '  pi.on("tool_result", async (event, ctx) => {\n'
    if shared_source.count(branch) != 1 or shared_source.count(cleanup) != 1:
        raise ValueError("Pi-family containment insertion point changed")
    return helpers + shared_source.replace(
        branch,
        branch_source + branch,
        1,
    ).replace(cleanup, cleanup + "    cleanupContainedTestRequest(event.toolCallId, event.details);\n", 1)


def _replace_once(source: str, old: str, new: str) -> str:
    if source.count(old) != 1:
        raise ValueError("Pi-family containment source changed")
    return source.replace(old, new, 1)
