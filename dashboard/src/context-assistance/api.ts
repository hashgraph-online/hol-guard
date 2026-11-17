import { fetchWithGuardAuth } from "../guard-api";
import { isGuardDemoMode } from "../guard-demo";
import { forgetTurnOn } from "./setup-resume";
import { parseContextAssistanceStatus } from "./status";
import type { ContextAssistanceStatus, ContextControlAction } from "./types";

export class ContextAssistanceApiError extends Error {
  constructor(public readonly code: string, message: string) {
    super(message);
    this.name = "ContextAssistanceApiError";
  }
}

function waitForStatusRetry(signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) { reject(signal.reason); return; }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, 1_000);
    function onAbort(): void {
      clearTimeout(timer);
      reject(signal.reason);
    }
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function request(path: string, action?: ContextControlAction, signal?: AbortSignal): Promise<ContextAssistanceStatus> {
  if (isGuardDemoMode()) throw new ContextAssistanceApiError("demo_unavailable", "Context assistance setup requires a local Guard installation.");
  const timeout = AbortSignal.timeout(10_000);
  const requestSignal = signal ? AbortSignal.any([signal, timeout]) : timeout;
  for (let retry = 0; ; retry += 1) {
    requestSignal.throwIfAborted();
    const response = await fetchWithGuardAuth(path, {
      cache: "no-store",
      signal: requestSignal,
      ...(action ? {
        method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
      } : {}),
    });
    if (response.ok) return parseContextAssistanceStatus(await response.json());
    const body: unknown = await response.json().catch(() => null);
    const code = body !== null && typeof body === "object" && "code" in body
      && typeof body.code === "string" && /^[a-z0-9_]{1,160}$/.test(body.code) ? body.code : "context_assistance_unavailable";
    // Startup may briefly occupy the native actor. Retry only status reads,
    // within the original deadline; never replay a control or access grant.
    if (!action && response.status === 409 && code === "native_context_assistance_busy" && retry < 8) {
      await waitForStatusRetry(requestSignal);
      continue;
    }
    throw new ContextAssistanceApiError(code,
      response.status === 404
        ? "This Guard installation needs a native core with context assistance support. Update Guard to continue."
        : "Context assistance is unavailable. Refresh its status before trying again.");
  }
}

export const fetchContextAssistance = (signal?: AbortSignal) => request("/v1/context-assistance", undefined, signal);
export const fetchContextInstallations = (signal?: AbortSignal) => request("/v1/context-assistance/installations", undefined, signal);
export function controlContextAssistance(action: ContextControlAction, signal?: AbortSignal): Promise<ContextAssistanceStatus> {
  if (!["recheck", "activate", "stop"].includes(action)) {
    return Promise.reject(new ContextAssistanceApiError("action_invalid", "Invalid context assistance action."));
  }
  // Turning CIGAR off from any page cancels an unfinished Turn on click.
  if (action === "stop") forgetTurnOn();
  return request(`/v1/context-assistance/${action}`, action, signal);
}
