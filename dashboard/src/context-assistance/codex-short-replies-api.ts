import { ContextAssistanceApiError } from "./api";
import { callCodexConfig, codexConfigChange, isObject } from "./codex-config-api";
import type { ContextProof } from "./workspaces-api";

/**
 * on: Guard's short-reply instruction is in the Codex config. off: the user turned it off.
 * not_set: not written yet. yours: the config has instructions the user wrote, which Guard leaves alone.
 */
export type CodexShortRepliesState = { state: "on" | "off" | "not_set" | "yours" };

const PATH = "/v1/context-assistance/codex-short-replies";
const STATES = new Set(["on", "off", "not_set", "yours"]);

function parsed(body: unknown): CodexShortRepliesState {
  const state = isObject(body) ? body.state : null;
  if (typeof state !== "string" || !STATES.has(state)) {
    throw new ContextAssistanceApiError("codex_short_replies_payload_invalid", "Guard returned a Codex setting this page does not understand.");
  }
  return { state: state as CodexShortRepliesState["state"] };
}

export function readCodexShortReplies(signal?: AbortSignal): Promise<CodexShortRepliesState> {
  return callCodexConfig(PATH, "codex_short_replies_unavailable", parsed, { method: "GET" }, signal);
}

/** Turn Guard's short-reply instruction on or off. Instructions the user wrote stay. */
export function setCodexShortReplies(enabled: boolean, proof?: ContextProof, signal?: AbortSignal): Promise<CodexShortRepliesState> {
  return callCodexConfig(PATH, "codex_short_replies_unavailable", parsed, codexConfigChange({ enabled }, proof), signal);
}
