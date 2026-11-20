import type { ContextAssistanceStatus } from "../../src/context-assistance/types";
import type { IntegrationState } from "./fixtures";

/** Retry bounded queue/generation races on this read-only endpoint. */
export async function contextStatus(state: IntegrationState): Promise<ContextAssistanceStatus> {
  for (let attempt = 0; attempt < 12; attempt += 1) {
    const response = await fetch(new URL("/v1/context-assistance", state.origin), {
      headers: { "x-guard-token": state.daemonToken },
    });
    if (response.status === 409) {
      const body = await response.json() as { code?: unknown };
      if (body.code !== "native_context_assistance_busy" && body.code !== "native_context_assistance_context_busy"
        && body.code !== "native_context_assistance_context_stale") {
        const code = typeof body.code === "string" && /^native_context_assistance_[a-z_]{1,100}$/.test(body.code)
          ? body.code : "unrecognized";
        throw new Error(`Context status returned a non-retryable conflict (${code})`);
      }
      await new Promise((done) => setTimeout(done, Math.min(attempt + 1, 4) * 25));
      continue;
    }
    if (!response.ok) throw new Error(`Context status returned HTTP ${response.status}`);
    return await response.json() as ContextAssistanceStatus;
  }
  throw new Error("Context status remained busy or stale after bounded read-only retries");
}
