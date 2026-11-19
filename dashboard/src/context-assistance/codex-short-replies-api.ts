import { fetchWithGuardAuth } from "../guard-api";
import { ContextAssistanceApiError } from "./api";
import type { ContextProof } from "./workspaces-api";

/**
 * on: Guard's short-reply instruction is in the Codex config. off: the user turned it off.
 * not_set: not written yet. yours: the config has instructions the user wrote, which Guard leaves alone.
 */
export type CodexShortRepliesState = { state: "on" | "off" | "not_set" | "yours" };

const PATH = "/v1/context-assistance/codex-short-replies";
const STATES = new Set(["on", "off", "not_set", "yours"]);
const object = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

function parsed(body: unknown): CodexShortRepliesState {
  const state = object(body) ? body.state : null;
  if (typeof state !== "string" || !STATES.has(state)) {
    throw new ContextAssistanceApiError("codex_short_replies_payload_invalid", "Guard returned a Codex setting this page does not understand.");
  }
  return { state: state as CodexShortRepliesState["state"] };
}

function failure(status: number, body: unknown, reading: boolean): ContextAssistanceApiError {
  let code = "codex_short_replies_unavailable";
  if (object(body) && typeof body.code === "string") code = body.code;
  else if (object(body) && typeof body.error === "string") code = body.error;
  if (status === 403) return new ContextAssistanceApiError(code, "Guard needs your approval before this change.");
  if (code === "codex_config_unreadable") return new ContextAssistanceApiError(code, "Guard could not read your Codex config, so it left it as it is. Fix the file, then try again.");
  if (code === "codex_hooks_need_recovery") return new ContextAssistanceApiError(code, "Guard's Codex setup needs a repair first. Open Apps, repair Codex, then try again.");
  if (code === "codex_config_busy") return new ContextAssistanceApiError(code, "Another change to your Codex config is in progress. Try again in a moment.");
  if (reading) return new ContextAssistanceApiError(code, "Guard could not check your Codex config. Try again in a moment.");
  return new ContextAssistanceApiError(code, "Guard could not change your Codex config. Nothing was changed.");
}

async function call(init: RequestInit, signal?: AbortSignal): Promise<CodexShortRepliesState> {
  const timeout = AbortSignal.timeout(12_000);
  const response = await fetchWithGuardAuth(PATH, { ...init, cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) throw failure(response.status, body, init.method === "GET");
  return parsed(body);
}

export function readCodexShortReplies(signal?: AbortSignal): Promise<CodexShortRepliesState> {
  return call({ method: "GET" }, signal);
}

/** Turn Guard's short-reply instruction on or off. Instructions the user wrote stay. */
export function setCodexShortReplies(enabled: boolean, proof?: ContextProof, signal?: AbortSignal): Promise<CodexShortRepliesState> {
  return call({ method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ enabled,
    ...(proof?.currentPassword ? { approval_password: proof.currentPassword } : {}),
    ...(proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}) }) }, signal);
}
