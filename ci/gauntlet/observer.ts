// Telemetry only. The installed Guard extension and its responses are unchanged.
import { appendFileSync } from "node:fs";
import { createHash } from "node:crypto";

const logPath = process.env.GUARD_GAUNTLET_OBSERVER_LOG;
const guardPort = process.env.GUARD_GAUNTLET_DAEMON_PORT;
const actualFetch = globalThis.fetch.bind(globalThis);

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
  const started = performance.now();
  const response = await actualFetch(input, init);
  try {
    const request = JSON.parse(typeof init?.body === "string" ? init.body : "{}");
    const body = await response.clone().json();
    record({
      event: request.hook_event_name,
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
      elapsed_ms: Math.round((performance.now() - started) * 1000) / 1000,
    });
  } catch {
    record({ observer_error: true });
  }
  return response;
}) as typeof fetch;

export default function (): void {}
