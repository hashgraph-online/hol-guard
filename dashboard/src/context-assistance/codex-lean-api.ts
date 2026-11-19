import { ContextAssistanceApiError } from "./api";
import { callCodexConfig, codexConfigChange, isObject } from "./codex-config-api";
import type { ContextProof } from "./workspaces-api";

/** Whether a summary size Guard wrote is in the Codex config, a size the user set, or none. */
export type CodexLeanState = { state: "on" | "off" | "yours"; limit: number | null };

const PATH = "/v1/context-assistance/codex-lean";

function parsed(body: unknown): CodexLeanState {
  const state = isObject(body) ? body.state : null;
  const limit = isObject(body) ? body.limit : null;
  if ((state !== "on" && state !== "off" && state !== "yours") || (limit !== null && typeof limit !== "number")) {
    throw new ContextAssistanceApiError("codex_lean_payload_invalid", "Guard returned a Codex setting this page does not understand.");
  }
  return { state, limit };
}

export function readCodexLean(signal?: AbortSignal): Promise<CodexLeanState> {
  return callCodexConfig(PATH, "codex_lean_unavailable", parsed, { method: "GET" }, signal);
}

/** Remove the summary size Guard wrote to the Codex config. A size the user set stays. */
export function removeCodexLean(proof?: ContextProof, signal?: AbortSignal): Promise<CodexLeanState> {
  return callCodexConfig(PATH, "codex_lean_unavailable", parsed, codexConfigChange({ enabled: false }, proof), signal);
}
