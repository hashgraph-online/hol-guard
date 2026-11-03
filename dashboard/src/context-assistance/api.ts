import { fetchWithGuardAuth } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";
import { parseContextAssistanceStatus } from "./status";
import type { ContextAssistanceStatus, ContextControlAction } from "./types";

export class ContextAssistanceApiError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "ContextAssistanceApiError";
  }
}

async function request(path: string, action?: ContextControlAction, signal?: AbortSignal): Promise<ContextAssistanceStatus> {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Context assistance setup requires a local Guard installation.");
  const timeout = AbortSignal.timeout(10_000);
  const response = await fetchWithGuardAuth(path, {
    cache: "no-store",
    signal: signal ? AbortSignal.any([signal, timeout]) : timeout,
    ...(action ? {
      method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
    } : {}),
  });
  if (!response.ok) {
    const body: unknown = await response.json().catch(() => null);
    const code = body !== null && typeof body === "object" && "code" in body
      && typeof body.code === "string" && /^[a-z0-9_]{1,160}$/.test(body.code) ? body.code : "context_assistance_unavailable";
    throw new ContextAssistanceApiError(code,
      response.status === 404
        ? "This Guard installation needs a native core with context assistance support. Update Guard to continue."
        : "Context assistance is unavailable. Refresh its status before trying again.");
  }
  return parseContextAssistanceStatus(await response.json());
}

export const fetchContextAssistance = (signal?: AbortSignal) => request("/v1/context-assistance", undefined, signal);
export const fetchContextInstallations = (signal?: AbortSignal) => request("/v1/context-assistance/installations", undefined, signal);
export function controlContextAssistance(action: ContextControlAction, signal?: AbortSignal): Promise<ContextAssistanceStatus> {
  if (!["recheck", "activate", "stop"].includes(action)) {
    return Promise.reject(new ContextAssistanceApiError("action_invalid", "Invalid context assistance action."));
  }
  return request(`/v1/context-assistance/${action}`, action, signal);
}
