// Telemetry only. Probe metadata is diagnostic-only; Guard decisions and responses are unchanged.
import { appendFileSync } from "node:fs";
import { createHash, randomUUID } from "node:crypto";

const logPath = process.env.GUARD_GAUNTLET_OBSERVER_LOG;
const guardPort = process.env.GUARD_GAUNTLET_DAEMON_PORT;
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
      harness: receipt.harness,
      event_name: receipt.event_name,
      payload_kind: receipt.payload_kind,
      decision: receipt.decision,
      policy_action: receipt.policy_action,
      observed_policy_action: receipt.observed_policy_action,
      reason_code: receipt.reason_code,
      command_extensions: receipt.command_extensions,
    },
  };
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

globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
  if (!isGuard(input)) return actualFetch(input, init);
  let forwardedInit = init;
  let request: JsonRecord = {};
  let probe: { operation_id: string; request_id: string } | undefined;
  try {
    const rawBody = init?.body;
    request = JSON.parse(typeof rawBody === "string" ? rawBody : "") as JsonRecord;
    if (!request || typeof request !== "object" || Array.isArray(request)) throw new Error("invalid hook request");
    probe = transitionProbe();
    request.guard_transition_probe = {
      schema: "hol-guard.transition-hook-probe.v1",
      ...probe,
    };
    forwardedInit = { ...init, body: JSON.stringify(request) };
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
    const nativeObservation = publicNativeObservation(body);
    record({
      event,
      tool: request.tool_name,
      tool_call_id: request.tool_call_id,
      input_json: JSON.stringify(request.tool_input ?? null),
      input_sha256: createHash("sha256").update(JSON.stringify(request.tool_input ?? null)).digest("hex"),
      http_status: response.status,
      decision: body.decision,
      policy_action: body.policy_action,
      reason_code: body.reason_code,
      model_output_action: body.model_output_action,
      reviewed_output_sha256: body.reviewed_output_sha256,
      response_sha256: createHash("sha256").update(JSON.stringify(body)).digest("hex"),
      elapsed_ms: elapsed(),
      ...(probe ? { probe_operation_id: probe.operation_id, probe_request_id: probe.request_id } : {}),
      ...(nativeObservation ? { native_observation: nativeObservation } : {}),
    });
  } catch {
    record({ observer_error: true, event, elapsed_ms: elapsed() });
  }
  return response;
}) as typeof fetch;

export default function (): void {}
