import { fetchWithGuardAuth } from "../guard-api";
import { ContextAssistanceApiError } from "./api";
import type { ContextProof } from "./workspaces-api";

export const isObject = (v: unknown): v is Record<string, unknown> => v !== null && typeof v === "object" && !Array.isArray(v);

/** A read should answer quickly. A change can wait on the Codex config lock, so it gets longer. */
const READ_TIMEOUT_MS = 12_000;
const WRITE_TIMEOUT_MS = 60_000;

function failure(fallback: string, status: number, body: unknown, reading: boolean): ContextAssistanceApiError {
  let code = fallback;
  if (isObject(body) && typeof body.code === "string") code = body.code;
  else if (isObject(body) && typeof body.error === "string") code = body.error;
  if (status === 403) return new ContextAssistanceApiError(code, "Guard needs your approval before this change.");
  if (code === "codex_config_unreadable") return new ContextAssistanceApiError(code, "Guard could not read your Codex config, so it left it as it is. Fix the file, then try again.");
  if (code === "codex_hooks_need_recovery") return new ContextAssistanceApiError(code, "Guard's Codex setup needs a repair first. Open Apps, repair Codex, then try again.");
  if (code === "codex_config_busy") return new ContextAssistanceApiError(code, "Another change to your Codex config is in progress. Try again in a moment.");
  if (reading) return new ContextAssistanceApiError(code, "Guard could not check your Codex config. Try again in a moment.");
  return new ContextAssistanceApiError(code, "Guard could not change your Codex config. Nothing was changed.");
}

/** One call to a Guard route that reads or changes the Codex config. */
export async function callCodexConfig<T>(path: string, fallback: string, parse: (body: unknown) => T,
  init: RequestInit, signal?: AbortSignal): Promise<T> {
  const reading = init.method === "GET";
  const timeout = AbortSignal.timeout(reading ? READ_TIMEOUT_MS : WRITE_TIMEOUT_MS);
  const response = await fetchWithGuardAuth(path, { ...init, cache: "no-store", signal: signal ? AbortSignal.any([signal, timeout]) : timeout });
  const body: unknown = await response.json().catch(() => null);
  if (!response.ok) throw failure(fallback, response.status, body, reading);
  return parse(body);
}

/** A POST body that changes a Codex setting, with the approval proof when there is one. */
export function codexConfigChange(fields: Record<string, unknown>, proof?: ContextProof): RequestInit {
  return { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ ...fields,
    ...(proof?.currentPassword ? { approval_password: proof.currentPassword } : {}),
    ...(proof?.totpCode ? { approval_totp_code: proof.totpCode } : {}) }) };
}
