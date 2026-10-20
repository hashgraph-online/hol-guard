"""Bash result observations and acknowledgement after final host-context delivery."""

BOUND_BASH_RESULT_SOURCE = r"""
  const acknowledgedBoundBashResults = new Set<string>();
  type BoundBashResultEvent = {
    toolCallId?: unknown; toolName?: unknown; details?: unknown; isError?: boolean; content?: unknown;
  };
  function boundBashPostObservation(
    event: BoundBashResultEvent, input: Record<string, unknown>,
  ): Record<string, unknown> | undefined {
    const key = toolCallIdKey(event.toolCallId);
    const invocation = key ? boundBashInvocations.get(key) : undefined;
    const presentation = key ? containedTestPresentations.get(key) : undefined;
    const exit = boundBashObservedExit(event);
    const job = event.details && typeof event.details === "object" ? Reflect.get(event.details, "async") : undefined;
    if (!key || !invocation || !presentation || event.toolName !== "bash" ||
        input.command !== presentation.command || !Number.isInteger(exit) || exit! < 0 || exit! > 255 ||
        (job && typeof job === "object" && Reflect.get(job, "state") === "running")) return undefined;
    // An observation, not authority: the resident checks its authenticated journal.
    return { schema: "guard-native-bash-post-observation.v1", operation_id: invocation.operationId,
      tool_call_id: key, exit_code: exit };
  }
  function markBoundBashResultDelivery(
    event: BoundBashResultEvent, outputSha256: string,
  ): Record<string, unknown> | undefined {
    const key = toolCallIdKey(event.toolCallId);
    const invocation = key ? boundBashInvocations.get(key) : undefined;
    const exit = boundBashObservedExit(event);
    const job = event.details && typeof event.details === "object" ? Reflect.get(event.details, "async") : undefined;
    if (!key || !invocation || event.toolName !== "bash" || !/^[0-9a-f]{64}$/.test(outputSha256) ||
        !Number.isInteger(exit) || exit! < 0 || exit! > 255 ||
        (job && typeof job === "object" && Reflect.get(job, "state") === "running")) return undefined;
    const details = event.details && typeof event.details === "object" && !Array.isArray(event.details)
      ? event.details : {};
    return { ...details, holGuardBashResultDelivery: {
      schema: "guard-native-bash-result-delivery.v1", harness: boundBashHarness,
      operation_id: invocation.operationId, tool_call_id: key, workspace: invocation.cwd,
      exit_code: exit, output_sha256: outputSha256, is_error: event.isError === true,
    } };
  }
  function boundBashContextDigest(content: unknown): string | null {
    if (!Array.isArray(content) || content.length > 1024) return null;
    const parts: string[] = [];
    let length = 0;
    for (const part of content) {
      if (!part || part.type !== "text" || typeof part.text !== "string") return null;
      length += part.text.length;
      if (length > 1_048_576) return null;
      if (part.text.length > 0) parts.push(part.text);
    }
    return createHash("sha256").update(parts.join("\n"), "utf8").digest("hex");
  }
  async function acknowledgeBoundBashContext(messages: unknown[]): Promise<void> {
    // Final tool results are now stored in host context, after every result hook.
    // After restart, earlier calls from one intent are superseded by its latest
    // stored result. Native still verifies that call's current signed generation.
    const latest = new Map<string, Record<string, any>>();
    for (const value of messages.slice(-4096)) {
      if (!value || typeof value !== "object") continue;
      const message = value as Record<string, any>;
      if (message.role !== "toolResult" || message.toolName !== "bash") continue;
      const operation = message.details?.holGuardBashResultDelivery?.operation_id;
      if (typeof operation === "string" && /^bash-operation:[0-9a-f]{64}$/.test(operation)) {
        latest.set(operation, message);
      }
    }
    for (const message of latest.values()) {
      const proof = message.details?.holGuardBashResultDelivery;
      if (!proof || proof.schema !== "guard-native-bash-result-delivery.v1" ||
          proof.harness !== boundBashHarness || proof.tool_call_id !== message.toolCallId ||
          typeof proof.tool_call_id !== "string" || !proof.tool_call_id || proof.tool_call_id.length > 256 ||
          typeof proof.operation_id !== "string" || !/^bash-operation:[0-9a-f]{64}$/.test(proof.operation_id) ||
          typeof proof.workspace !== "string" || !proof.workspace.startsWith("/") || proof.workspace.length > 8192 ||
          !Number.isInteger(proof.exit_code) || proof.exit_code < 0 || proof.exit_code > 255 ||
          proof.exit_code !== boundBashObservedExit(message) ||
          message.details?.async?.state === "running" ||
          typeof proof.is_error !== "boolean" || proof.is_error !== (message.isError === true) ||
          typeof proof.output_sha256 !== "string" || !/^[0-9a-f]{64}$/.test(proof.output_sha256) ||
          proof.output_sha256 !== boundBashContextDigest(message.content)) continue;
      const identity = createHash("sha256").update(JSON.stringify(
        [proof.operation_id, proof.tool_call_id]), "utf8").digest("hex");
      if (acknowledgedBoundBashResults.has(identity)) continue;
      const args = ["ack-bound-bash", "--harness", boundBashHarness,
        "--operation-id", proof.operation_id, "--tool-call-id", proof.tool_call_id,
        "--exit-code", String(proof.exit_code), "--guard-home", GUARD_HOME, "--workspace", proof.workspace];
      if (!GUARD_HOME_DIR_IS_DEFAULT) args.push("--home", GUARD_HOME_DIR);
      try {
        const result = await pi.exec(GUARD_CLI_WRAPPER_COMMAND, args, { cwd: proof.workspace, timeout: 10_000 });
        if (result.code !== 0) continue;
        acknowledgedBoundBashResults.add(identity);
        boundBashInvocations.delete(proof.tool_call_id);
        while (acknowledgedBoundBashResults.size > 4096) {
          const oldest = acknowledgedBoundBashResults.values().next().value;
          if (oldest === undefined) break;
          acknowledgedBoundBashResults.delete(oldest);
        }
      } catch { /* A lost acknowledgement retains the original native operation. */ }
    }
  }
"""
