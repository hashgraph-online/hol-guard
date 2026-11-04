import { fetchWithGuardAuth } from "../guard-api";
import { ContextAssistanceApiError } from "./api";
import type { ContextProof } from "./workspaces-api";

/** Whether Guard's compaction limit is in the Codex config, a limit the user set, or none. */
export type CodexLeanState = { state: "on" | "off" | "yours"; limit: number | null };

const PATH = "/v1/context-assistance/codex-lean";
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function parsed(body: unknown): CodexLeanState {
  const state = object(body) ? body.state : null;
  const limit = object(body) ? body.limit : null;
  if ((state !== "on" && state !== "off" && state !== "yours") || (limit !== null && typeof limit !== "number")) {
    throw new ContextAssistanceApiError("codex_lean_payload_invalid", "Guard returned a Codex setting this page does not understand.");
  }
  return { state, limit };
}

function failure(status: number, body: unknown, reading: boolean): ContextAssistanceApiError {
  let code = "codex_lean_unavailable";
  if (object(body) && typeof body.code === "string") code = body.code;
  else if (object(body) && typeof body.error === "string") code = body.error;
  if (status === 403) return new ContextAssistanceApiError(code, "Guard needs your approval before this change.");
  if (code === "codex_config_unreadable") return new ContextAssistanceApiError(code, "Guard could not read your Codex config, so it left it as it is. Fix the file, then try again.");
  if (code === "codex_hooks_need_recovery") return new ContextAssistanceApiError(code, "Guard's Codex setup needs a repair first. Open Apps, repair Codex, then try again.");
  if (code === "codex_config_busy") return new ContextAssistanceApiError(code, "Another change to your Codex config is in progress. Try again in a moment.");
  if (reading) return new ContextAssistanceApiError(code, "Guard could not check your Codex config. Try again in a moment.");
  return new ContextAssistanceApiError(code, "Guard could not change your Codex config. Nothing was changed.");
}

async function call(init: RequestInit, signal?: AbortSignal): Promise<CodexLeanState> {
  const timeout = AbortSignal.timeout(12_000);
  const response = await fetchWithGuardAuth(PATH, { ...init, cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) throw failure(response.status, body, init.method === "GET");
  return parsed(body);
}

export function readCodexLean(signal?: AbortSignal): Promise<CodexLeanState> {
  return call({ method: "GET" }, signal);
}

export function saveCodexLean(enabled: boolean, proof?: ContextProof, signal?: AbortSignal): Promise<CodexLeanState> {
  return call({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled,
    ...(proof?.currentPassword ? { approval_password: proof.currentPassword } : {}),
    ...(proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}) }) }, signal);
}
