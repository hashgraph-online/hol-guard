// Telemetry only. Probe metadata is diagnostic-only; Guard decisions and responses are unchanged.
import { appendFileSync, closeSync, constants, fstatSync, openSync, readFileSync } from "node:fs";
import { basename, dirname } from "node:path";
import { createHash, randomUUID } from "node:crypto";
import { createRequire } from "node:module";

const logPath = process.env.GUARD_GAUNTLET_OBSERVER_LOG;
const guardPort = process.env.GUARD_GAUNTLET_DAEMON_PORT;
const hostLogPath = process.env.GUARD_GAUNTLET_HOST_OBSERVER_LOG;
const actualFetch = globalThis.fetch.bind(globalThis);

type JsonRecord = Record<string, unknown>;

function transitionProbe(): { operation_id: string; request_id: string } {
  return {
    operation_id: randomUUID(),
    request_id: `transition-hook-${randomUUID().replaceAll("-", "")}`,
  };
}

function publicNativeObservation(body: unknown): JsonRecord | undefined {
  if (!body || typeof body !== "object") return undefined;
  const response = body as JsonRecord;
  const observation = response.guard_transition_observation;
  if (!observation || typeof observation !== "object") return undefined;
  const native = (observation as JsonRecord).native_receipt;
  if (!native || typeof native !== "object") return undefined;
  const receipt = native as JsonRecord;
  return {
    schema: (observation as JsonRecord).schema,
    operation_id: (observation as JsonRecord).operation_id,
    request_id: (observation as JsonRecord).request_id,
    ...(typeof response.required_execution_profile === "string"
      ? { required_execution_profile: response.required_execution_profile }
      : {}),
    native_receipt: {
      schema: receipt.schema,
      version: receipt.version,
      authority: receipt.authority,
      decision_id: receipt.decision_id,
      request_id: receipt.request_id,
      request_digest: receipt.request_digest,
      harness: receipt.harness,
      event_name: receipt.event_name,
      payload_kind: receipt.payload_kind,
      policy_generation: receipt.policy_generation,
      policy_digest: receipt.policy_digest,
      runtime_identity: receipt.runtime_identity,
      decision: receipt.decision,
      observe_mode: receipt.observe_mode,
      policy_action: receipt.policy_action,
      observed_policy_action: receipt.observed_policy_action,
      reason_code: receipt.reason_code,
      command_extensions: receipt.command_extensions,
    },
  };
}

const TEXT_KEYS = ["systemMessage", "message", "stopReason", "additionalContext", "permissionDecisionReason"];

// Names of response fields that carry text the harness would render; mirrors interruptions.py.
// Only names are recorded, never the text. Text counts from either level, so an empty top-level
// string never shadows a non-empty hookSpecificOutput one; other keys prefer the nested value.
function renderedFields(body: unknown): string[] {
  if (!body || typeof body !== "object") return [];
  const response = body as JsonRecord;
  const nested = response.hookSpecificOutput;
  const specific: JsonRecord = nested && typeof nested === "object" ? (nested as JsonRecord) : {};
  const hasText = (key: string): boolean =>
    [response, specific].some(source => typeof source[key] === "string" && (source[key] as string).trim() !== "");
  const present = (value: unknown): boolean => value != null && !(typeof value === "string" && value.trim() === "");
  const flat: JsonRecord = { ...response };
  for (const [key, value] of Object.entries(specific)) if (present(value) || !(key in flat)) flat[key] = value;
  const fields = TEXT_KEYS.filter(hasText);
  const loud = flat.notice === "warning" || flat.notice === "excerpt";
  if (loud) fields.push("notice");
  if (hasText("reason") && (loud || flat.policy_action === "warn")) fields.push("reason");
  return fields.sort();
}

type Probe = { operation_id: string; request_id: string };

// The hook payload with this observation's probe added, for whichever lane
// carries it. The probe only asks Guard to echo the native receipt it already
// produced; the reviewed hook is unchanged.
//
// The probe carries a request identity only the daemon assigns, so a resident
// defers every probed payload (`HookDirectDefer::TransitionProbe`) and the
// answer comes from the daemon behind the same bridge. That is what makes the
// receipt correlatable, and it is why `resident_direct_answers` reads zero on
// this lane: the bridge transport is covered, the resident's in-process answer
// is not. Covering that one needs a probe the resident can echo.
function probedPayload(payload: string): { text: string; request: JsonRecord; probe: Probe } {
  const request = JSON.parse(payload) as JsonRecord;
  if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("invalid hook request");
  const probe = transitionProbe();
  request.guard_transition_probe = { schema: "hol-guard.transition-hook-probe.v1", ...probe };
  return { text: JSON.stringify(request), request, probe };
}

function record(value: Record<string, unknown>): void {
  if (!logPath) throw new Error("Gauntlet observer log is not configured");
  appendFileSync(logPath, JSON.stringify(value) + "\n", { mode: 0o600 });
}

function isGuard(input: RequestInfo | URL): boolean {
  try {
    let target: string;
    if (typeof input === "string") target = input;
    else if (input instanceof URL) target = input.href;
    else target = input.url;
    const url = new URL(target);
    return url.protocol === "http:" && url.hostname === "127.0.0.1"
      && url.port === guardPort && url.pathname === "/v1/hooks/omp";
  } catch { return false; }
}

// One observed hook exchange, on either lane.
function recordExchange(exchange: {
  event: unknown;
  request: JsonRecord;
  probe?: Probe;
  body: JsonRecord;
  status: number;
  elapsedMs: number;
  transport?: string;
}): void {
  const { request, probe, body } = exchange;
  const nativeObservation = publicNativeObservation(body);
  const input = JSON.stringify(request.tool_input ?? null);
  record({
    ...(exchange.transport ? { transport: exchange.transport } : {}),
    event: exchange.event,
    tool: request.tool_name,
    tool_call_id: request.tool_call_id,
    input_json: input,
    input_sha256: createHash("sha256").update(input).digest("hex"),
    http_status: exchange.status,
    decision: body.decision,
    policy_action: body.policy_action,
    reason_code: body.reason_code,
    rendered_fields: renderedFields(body),
    model_output_action: body.model_output_action,
    reviewed_output_sha256: body.reviewed_output_sha256,
    response_sha256: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
    elapsed_ms: exchange.elapsedMs,
    ...(probe ? { probe_operation_id: probe.operation_id, probe_request_id: probe.request_id } : {}),
    ...(nativeObservation ? { native_observation: nativeObservation } : {}),
  });
}

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  if (!isGuard(input)) return actualFetch(input, init);
  let forwardedInit = init;
  let request: JsonRecord = {};
  let probe: Probe | undefined;
  try {
    const rawBody = init?.body;
    const probed = probedPayload(typeof rawBody === "string" ? rawBody : "");
    request = probed.request;
    probe = probed.probe;
    forwardedInit = { ...init, body: probed.text };
  } catch {
    record({ observer_error: true, observer_error_code: "probe_injection_failed" });
  }
  const started = performance.now();
  // Capture the event before transport so timeouts retain their event group.
  const event = request?.hook_event_name;
  const elapsed = () => Number((performance.now() - started).toFixed(3));
  let response: Response;
  try {
    response = await actualFetch(input, forwardedInit);
  } catch (error) {
    record({ transport_error: true, event, elapsed_ms: elapsed() });
    throw error;
  }
  try {
    const body = await response.clone().json();
    recordExchange({ event, request, probe, body, status: response.status, elapsedMs: elapsed() });
  } catch {
    record({ observer_error: true, event, elapsed_ms: elapsed() });
  }
  return response;
}) as typeof fetch;

// An installed extension answers each hook through the native runtime's
// `pi-hook-bridge` instead of the loopback `fetch` above: it spawns the runtime
// with the daemon payload on the child's stdin and reads one `{status, body}`
// JSON line from its stdout. Observe that lane at the same two points, so the
// Gauntlet exercises the transport users actually run.
const childProcess = createRequire(import.meta.url)("node:child_process");

type BridgeChild = {
  stdin?: { end(chunk?: unknown, ...rest: unknown[]): unknown } | null;
  stdout?: { on(event: string, handler: (chunk: unknown) => void): unknown } | null;
  once(event: string, handler: (code: unknown) => void): unknown;
};

function observeBridge(child: BridgeChild): void {
  const started = performance.now();
  const elapsed = () => Number((performance.now() - started).toFixed(3));
  let request: JsonRecord = {};
  let probe: Probe | undefined;
  const stdin = child.stdin;
  if (stdin) {
    const actualEnd = stdin.end.bind(stdin);
    stdin.end = (chunk?: unknown, ...rest: unknown[]): unknown => {
      if (typeof chunk !== "string") return actualEnd(chunk, ...rest);
      try {
        const probed = probedPayload(chunk.trim());
        request = probed.request;
        probe = probed.probe;
        return actualEnd(`${probed.text}\n`, ...rest);
      } catch {
        record({ observer_error: true, observer_error_code: "probe_injection_failed" });
        return actualEnd(chunk, ...rest);
      }
    };
  }
  let stdout = "";
  child.stdout?.on("data", chunk => {
    if (stdout.length <= 8_388_608) stdout += String(chunk);
  });
  const dropBridge = (code: unknown) => {
    // The extension discards this child and retries. public_observations
    // drops bridge_no_reply before the row can become a Guard observation.
    record({
      observer_error: true,
      transport: "pi-hook-bridge",
      observer_error_code: "bridge_no_reply",
      exit_code: code,
      elapsed_ms: elapsed(),
    });
  };
  child.once("close", (code: unknown) => {
    // Take a reply only when the extension would: the child exited 0 and the
    // envelope status is an HTTP code. A timeout kill or any other status is
    // discarded there, and recording it as a call would double-count the retry.
    try {
      if (code !== 0) {
        dropBridge(code);
        return;
      }
      const envelope = JSON.parse(stdout.trim());
      const status = envelope?.status;
      if (!Number.isInteger(status) || status < 100 || status > 599 || typeof envelope.body !== "string") {
        dropBridge(code);
        return;
      }
      const body = JSON.parse(envelope.body);
      if (!body || typeof body !== "object" || Array.isArray(body)) {
        dropBridge(code);
        return;
      }
      recordExchange({
        event: request.hook_event_name,
        request,
        probe,
        body,
        status,
        elapsedMs: elapsed(),
        transport: "pi-hook-bridge",
      });
    } catch {
      dropBridge(code);
    }
  });
}

// Hook the instance method every `spawn` export calls, not the export itself:
// Bun binds a module's `import { spawn }` once, when node:child_process is
// first imported anywhere, so a module that imported it before this observer
// loaded never sees a replaced export. `options.args` is the full argv,
// starting with the program, and the child's pipes exist once it returns.
const childPrototype = childProcess.ChildProcess.prototype;
const actualChildSpawn = childPrototype.spawn;
childPrototype.spawn = function (this: BridgeChild, options: { args?: unknown }): unknown {
  const result = actualChildSpawn.call(this, options);
  if (Array.isArray(options?.args) && options.args[1] === "pi-hook-bridge") observeBridge(this);
  return result;
};

// Each argument is single-quoted with embedded apostrophes written as '\'' (canonical shell argv).
const QUOTED = String.raw`'(?:[^']|'\\'')+'`;
// On Windows the sink is Guard's isolated Python running a fixed bootstrap: `python.exe -I -c <bootstrap> guard`.
const CONTAINED_WRAPPER = new RegExp(
  `^${QUOTED}(?: '-I' '-c' ${QUOTED} 'guard')? 'execute-contained-test' '--guard-home' ${QUOTED} '--workspace' ${QUOTED} ` +
    `'--request-file' (${QUOTED}) '--request-sha256' '[0-9a-f]{64}'(?: '--home' ${QUOTED})?$`,
);
const BASH_OWNER_WRAPPER = new RegExp(
  `^${QUOTED} 'execute-bound-bash' '--harness' 'omp' '--operation-id' 'bash-operation:[0-9a-f]{64}' ` +
    `'--host-owner-pid' '[0-9]+' '--tool-call-id' ${QUOTED} '--guard-home' ${QUOTED} '--workspace' ${QUOTED} ` +
    `'--request-file' (${QUOTED}) '--request-sha256' '[0-9a-f]{64}' '--timeout-seconds' '[0-9]+' '--home' ${QUOTED}$`,
);

// Guard's adapter deletes its contained-test request once the wrapper runs. Read only the exact
// owner-only file the executing wrapper names, before it runs; the judge binds the bytes by digest.
function containedRequest(event: JsonRecord): JsonRecord | undefined {
  const command = (event.args as JsonRecord | undefined)?.command;
  if (event.toolName !== "bash" || typeof command !== "string") return undefined;
  const match = CONTAINED_WRAPPER.exec(command) ?? BASH_OWNER_WRAPPER.exec(command);
  const path = match?.[1]?.slice(1, -1).replaceAll("'\\''", "'");
  if (!path || basename(path) !== "request.json" || !basename(dirname(path)).startsWith("hol-guard-contained-test-")) {
    return undefined;
  }
  let descriptor: number | undefined;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const info = fstatSync(descriptor);
    // Windows reports no owner and fixed mode bits; the request directory's ACL is what keeps it private there.
    const foreign = process.platform !== "win32" && (info.uid !== process.getuid?.() || (info.mode & 0o777) !== 0o600);
    if (!info.isFile() || foreign || info.size > 1_048_576) {
      return undefined;
    }
    const request = readFileSync(descriptor);
    if (request.length > 1_048_576) return undefined;
    return { type: "contained_request_capture", toolCallId: event.toolCallId, request: request.toString("base64") };
  } catch {
    return undefined;
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

export default function (api: {
  on(event: string, handler: (event: JsonRecord) => void): void;
}): void {
  const observe = (event: JsonRecord): void => {
    if (!hostLogPath) throw new Error("Gauntlet host observer log is not configured");
    appendFileSync(hostLogPath, JSON.stringify(event) + "\n", { mode: 0o600 });
  };
  // SDK extension events include delegated sessions; print mode's stdout only
  // carries the primary session. Observe actual events without rewriting them.
  api.on("message_end", event => {
    if ((event.message as JsonRecord | undefined)?.role === "assistant") observe(event);
  });
  const evals = new Set<string>();
  const bridges = new Map<string, string[]>();
  api.on("tool_execution_start", event => {
    if (event.toolName === "eval" && typeof event.toolCallId === "string") evals.add(event.toolCallId);
    const request = containedRequest(event);
    observe(event);
    if (request) observe(request);
  });
  api.on("tool_execution_end", event => {
    observe(event);
    if (typeof event.toolCallId === "string") evals.delete(event.toolCallId);
  });
  // The pinned SDK invokes eval bridge tools directly: they emit extension
  // tool_call/tool_result hooks, but no agent-core execution events.
  api.on("tool_call", event => {
    if (typeof event.toolCallId !== "string" || !event.toolCallId.startsWith("js-")) return;
    // These SDK hooks expose no parent identity. Record the actual candidates
    // without guessing or interrupting overlapping executions.
    const parents = [...evals];
    bridges.set(event.toolCallId, parents);
    observe({ type: "eval_bridge_start", parentToolCallId: parents.length === 1 ? parents[0] : null,
      parentToolCallIds: parents, event });
  });
  api.on("tool_result", event => {
    if (typeof event.toolCallId !== "string" || !event.toolCallId.startsWith("js-")) return;
    const parents = bridges.get(event.toolCallId) ?? [];
    observe({ type: "eval_bridge_end", parentToolCallId: parents.length === 1 ? parents[0] : null,
      parentToolCallIds: parents, event });
    bridges.delete(event.toolCallId);
  });
}
