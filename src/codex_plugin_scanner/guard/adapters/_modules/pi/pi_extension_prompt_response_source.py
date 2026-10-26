"""Validate the native prompt approval envelope for Pi-family hooks."""

PROMPT_RESPONSE_HELPER_SOURCE = r"""
function normalizePromptGuardResponse(value: unknown, event: unknown): GuardResponse | null {
  const normalized = normalizeGuardResponse(value);
  if (normalized !== null) return normalized;
  if (event !== "UserPromptSubmit" || !value || typeof value !== "object" || Array.isArray(value)) {
    return null;
  }
  const parsed = value as Record<string, unknown>;
  // Protocol-2 native prompt approvals carry policy_action and the event envelope.
  if (Object.keys(parsed).some((key) =>
    !["policy_action", "reason_code", "hookSpecificOutput", "risk_signals"].includes(key))) return null;
  if (parsed.policy_action !== "allow" && parsed.policy_action !== "warn") return null;
  if (typeof parsed.reason_code !== "string" || !parsed.reason_code) return null;
  const hook = parsed.hookSpecificOutput;
  if (!hook || typeof hook !== "object" || Array.isArray(hook)) return null;
  if (Object.keys(hook).some((key) => key !== "hookEventName")) return null;
  if ((hook as Record<string, unknown>).hookEventName !== "UserPromptSubmit") return null;
  if (parsed.risk_signals !== undefined &&
      (!Array.isArray(parsed.risk_signals) || parsed.risk_signals.some((item) => typeof item !== "string"))) {
    return null;
  }
  return { ...parsed, decision: "allow" } as GuardResponse;
}

"""
