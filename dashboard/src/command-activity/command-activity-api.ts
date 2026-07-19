import {
  normalizeCommandActivityAnalytics,
  normalizeCommandActivityDeletion,
  normalizeCommandActivityDiagnostics,
  normalizeCommandActivityInvalidation,
  normalizeCommandActivityPage,
  normalizeCommandExtensionsPage,
  normalizeCommandFeedbackResult,
} from "./command-activity-normalizers";
import {
  buildCommandActivityAnalyticsQuery,
  buildCommandActivityQuery,
  type CommandActivityAnalyticsQuery,
  type CommandActivityFilters,
} from "./command-activity-state";
import type {
  CommandActivityAnalytics,
  CommandActivityDeletionResult,
  CommandActivityDiagnostics,
  CommandActivityInvalidation,
  CommandActivityPage,
  CommandExtensionsPage,
  CommandFeedbackLabel,
  CommandFeedbackResult,
} from "./command-activity-types";

type ErrorPayload = { error?: unknown; message?: unknown };
export type CommandActivityTransport = (input: RequestInfo, init?: RequestInit) => Promise<Response>;
const MAX_ERROR_RESPONSE_BYTES = 16_384;
const MAX_JSON_RESPONSE_BYTES = 2_097_152;
const API_ERROR_CODES = new Set([
  "activity_not_found",
  "approval_gate_grant_expired",
  "approval_gate_invalid_cooldown",
  "approval_gate_invalid_password",
  "approval_gate_locked",
  "approval_gate_password_mismatch",
  "approval_gate_password_required",
  "approval_gate_recovery_required",
  "approval_gate_required",
  "approval_gate_totp_enabled",
  "approval_gate_totp_invalid",
  "approval_gate_totp_pending_required",
  "approval_gate_totp_required",
  "approval_gate_weak_password",
  "confirmation_required",
  "date_range_out_of_range",
  "days_out_of_range",
  "forbidden_origin",
  "incomplete_dimension_filter",
  "invalid_activity_id",
  "invalid_approval_reuse_status",
  "invalid_cursor",
  "invalid_date_range",
  "invalid_dimension",
  "invalid_dimension_value",
  "invalid_execution_status",
  "invalid_extension_id",
  "invalid_feedback_label",
  "invalid_feedback_payload",
  "invalid_harness",
  "invalid_integer",
  "invalid_occurred_from",
  "invalid_occurred_through",
  "invalid_prompted",
  "invalid_proof_level",
  "invalid_query_parameter",
  "invalid_request",
  "invalid_rule_id",
  "limit_out_of_range",
  "query_too_long",
  "top_limit_out_of_range",
  "too_many_streams",
  "unauthorized",
  "unknown_query_parameter",
]);

export class CommandActivityApiError extends Error {
  readonly status: number;
  readonly code: string | null;

  constructor(status: number, code: string | null) {
    super(code ? `Command activity request failed: ${code} (${status})` : `Command activity request failed (${status})`);
    this.name = "CommandActivityApiError";
    this.status = status;
    this.code = code;
  }
}

async function readBoundedJson(response: Response, maxBytes: number): Promise<unknown> {
  const contentLength = response.headers.get("Content-Length");
  if (contentLength && /^\d+$/.test(contentLength) && Number(contentLength) > maxBytes) {
    throw new Error("Command activity response too large");
  }
  if (!response.body) throw new Error("Command activity response unavailable");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.value) {
        total += chunk.value.byteLength;
        if (total > maxBytes) throw new Error("Command activity response too large");
        chunks.push(chunk.value);
      }
      if (chunk.done) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) as unknown;
}

async function responseError(response: Response): Promise<CommandActivityApiError> {
  let code: string | null = null;
  try {
    const payload = (await readBoundedJson(response, MAX_ERROR_RESPONSE_BYTES)) as ErrorPayload;
    if (payload && typeof payload === "object") {
      if (typeof payload.error === "string" && API_ERROR_CODES.has(payload.error)) code = payload.error;
      else if (typeof payload.message === "string" && API_ERROR_CODES.has(payload.message)) code = payload.message;
    }
  } catch {
    code = null;
  }
  return new CommandActivityApiError(response.status, code);
}

async function requestJson(path: string, init: RequestInit | undefined, transport: CommandActivityTransport): Promise<unknown> {
  const response = await transport(path, init);
  if (!response.ok) throw await responseError(response);
  try {
    return await readBoundedJson(response, MAX_JSON_RESPONSE_BYTES);
  } catch {
    throw new Error("Invalid command activity JSON payload");
  }
}

export async function fetchCommandActivityPage(
  filters: CommandActivityFilters,
  cursor: string | null,
  signal: AbortSignal | undefined,
  transport: CommandActivityTransport,
): Promise<CommandActivityPage> {
  const query = buildCommandActivityQuery(filters, cursor);
  return normalizeCommandActivityPage(await requestJson(`/v1/command-activity?${query}`, { signal }, transport));
}

export async function fetchCommandActivityAnalytics(
  query: CommandActivityAnalyticsQuery,
  signal: AbortSignal | undefined,
  transport: CommandActivityTransport,
): Promise<CommandActivityAnalytics> {
  const encoded = buildCommandActivityAnalyticsQuery(query);
  return normalizeCommandActivityAnalytics(
    await requestJson(`/v1/command-activity/analytics?${encoded}`, { signal }, transport),
  );
}

export async function fetchCommandExtensionsPage(
  input: { limit?: number; cursor?: string | null },
  signal: AbortSignal | undefined,
  transport: CommandActivityTransport,
): Promise<CommandExtensionsPage> {
  const limit = input.limit ?? 50;
  if (!Number.isInteger(limit) || limit < 1 || limit > 100) throw new Error("Invalid command extensions query");
  const params = new URLSearchParams({ limit: String(limit) });
  if (input.cursor) {
    if (input.cursor.length > 2_048) throw new Error("Invalid command extensions cursor");
    params.set("cursor", input.cursor);
  }
  return normalizeCommandExtensionsPage(
    await requestJson(`/v1/command-extensions?${params.toString()}`, { signal }, transport),
  );
}

export async function recordCommandActivityFeedback(
  input: { activity_id: string; label: CommandFeedbackLabel },
  signal: AbortSignal | undefined,
  transport: CommandActivityTransport,
): Promise<CommandFeedbackResult> {
  if (
    !input.activity_id ||
    input.activity_id.length > 256 ||
    !["should_not_have_interrupted", "expected_guard_to_stop_this"].includes(input.label)
  ) {
    throw new Error("Invalid command feedback request");
  }
  return normalizeCommandFeedbackResult(
    await requestJson(
      "/v1/command-activity/feedback",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ activity_id: input.activity_id, label: input.label }),
        signal,
      },
      transport,
    ),
  );
}

export async function fetchCommandActivityDiagnostics(
  signal: AbortSignal | undefined,
  transport: CommandActivityTransport,
): Promise<CommandActivityDiagnostics> {
  return normalizeCommandActivityDiagnostics(
    await requestJson("/v1/command-activity/diagnostics", { signal }, transport),
  );
}

export interface ClearCommandActivityProof {
  approval_password?: string;
  approval_totp_code?: string;
  approval_gate_use_cooldown?: boolean;
}

export async function clearCommandActivityEvidence(
  proof: ClearCommandActivityProof,
  signal: AbortSignal | undefined,
  transport: CommandActivityTransport,
): Promise<CommandActivityDeletionResult> {
  if (
    (proof.approval_password !== undefined && typeof proof.approval_password !== "string") ||
    (proof.approval_totp_code !== undefined && typeof proof.approval_totp_code !== "string") ||
    (proof.approval_gate_use_cooldown !== undefined && typeof proof.approval_gate_use_cooldown !== "boolean")
  ) {
    throw new Error("Invalid command activity deletion proof");
  }
  const body = {
    confirm: "clear-command-activity",
    ...(proof.approval_password !== undefined ? { approval_password: proof.approval_password } : {}),
    ...(proof.approval_totp_code !== undefined ? { approval_totp_code: proof.approval_totp_code } : {}),
    ...(proof.approval_gate_use_cooldown !== undefined
      ? { approval_gate_use_cooldown: proof.approval_gate_use_cooldown }
      : {}),
  };
  return normalizeCommandActivityDeletion(
    await requestJson(
      "/v1/command-activity",
      {
        method: "DELETE",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
        signal,
      },
      transport,
    ),
  );
}

export function parseCommandActivitySseFrame(frame: string): CommandActivityInvalidation | null {
  let id: string | null = null;
  const data: string[] = [];
  for (const rawLine of frame.split(/\r?\n/)) {
    if (!rawLine || rawLine.startsWith(":")) continue;
    const separator = rawLine.indexOf(":");
    const field = separator === -1 ? rawLine : rawLine.slice(0, separator);
    const value = separator === -1 ? "" : rawLine.slice(separator + 1).replace(/^ /, "");
    if (field === "id") id = value;
    else if (field === "data") data.push(value);
  }
  if (id === null || !/^\d+$/.test(id) || data.length === 0) return null;
  const sequence = Number(id);
  if (!Number.isSafeInteger(sequence)) return null;
  try {
    return normalizeCommandActivityInvalidation(sequence, JSON.parse(data.join("\n")) as unknown);
  } catch {
    return null;
  }
}

export async function* streamCommandActivityInvalidations(
  cursor: number,
  signal: AbortSignal,
  transport: CommandActivityTransport,
): AsyncGenerator<CommandActivityInvalidation, void, undefined> {
  if (!Number.isSafeInteger(cursor) || cursor < 0) throw new Error("Invalid command activity event cursor");
  const response = await transport(`/v1/command-activity/events?cursor=${cursor}`, {
    headers: { Accept: "text/event-stream", "Last-Event-ID": String(cursor) },
    signal,
  });
  if (!response.ok) throw await responseError(response);
  if (!response.body) throw new Error("Command activity event stream unavailable");
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (!signal.aborted) {
      const chunk = await reader.read();
      buffer += decoder.decode(chunk.value ?? new Uint8Array(), { stream: !chunk.done });
      let boundary = buffer.search(/\r?\n\r?\n/);
      while (boundary >= 0) {
        const separator = buffer.slice(boundary).match(/^\r?\n\r?\n/)?.[0] ?? "\n\n";
        const frame = buffer.slice(0, boundary);
        buffer = buffer.slice(boundary + separator.length);
        if (frame.length > 65_536) throw new Error("Command activity event frame too large");
        const event = parseCommandActivitySseFrame(frame);
        if (event) yield event;
        boundary = buffer.search(/\r?\n\r?\n/);
      }
      if (buffer.length > 65_536) throw new Error("Command activity event frame too large");
      if (chunk.done) break;
    }
  } finally {
    await reader.cancel().catch(() => undefined);
  }
}

export function createCommandActivityClient(transport: CommandActivityTransport) {
  return {
    fetchPage: (filters: CommandActivityFilters, cursor: string | null = null, signal?: AbortSignal) =>
      fetchCommandActivityPage(filters, cursor, signal, transport),
    fetchAnalytics: (query: CommandActivityAnalyticsQuery, signal?: AbortSignal) =>
      fetchCommandActivityAnalytics(query, signal, transport),
    fetchExtensions: (input: { limit?: number; cursor?: string | null } = {}, signal?: AbortSignal) =>
      fetchCommandExtensionsPage(input, signal, transport),
    recordFeedback: (input: { activity_id: string; label: CommandFeedbackLabel }, signal?: AbortSignal) =>
      recordCommandActivityFeedback(input, signal, transport),
    fetchDiagnostics: (signal?: AbortSignal) => fetchCommandActivityDiagnostics(signal, transport),
    clearEvidence: (proof: ClearCommandActivityProof, signal?: AbortSignal) =>
      clearCommandActivityEvidence(proof, signal, transport),
    streamInvalidations: (cursor: number, signal: AbortSignal) =>
      streamCommandActivityInvalidations(cursor, signal, transport),
  };
}
