import type { GuardReceipt } from "./guard-types";

/**
 * R-SELF: the first sentence of the reason the native runtime records when it blocks a browser
 * action on Guard's own approval center (`GUARD_ORIGIN_SUMMARY` in `mcp_tool_signals.rs`).
 */
export const GUARD_ORIGIN_REASON_PREFIX =
  "Guard blocked this browser action because it reaches Guard's own approval center.";

export const GUARD_ORIGIN_COPY = {
  title: "Blocked: an agent's browser reached Guard's approval center",
  detail:
    "An agent tried to open, click or read Guard's approval center from its browser tool. Guard always stops this, so an agent can never answer its own requests.",
  remediation:
    "Nothing to change. No approval, grant or setting allows this. Review pending requests yourself in your own browser.",
  breakdownLabel: "Guard's approval center",
} as const;

export function isGuardOriginBlock(receipt: Pick<GuardReceipt, "capabilities_summary">): boolean {
  return (
    typeof receipt.capabilities_summary === "string" &&
    receipt.capabilities_summary.startsWith(GUARD_ORIGIN_REASON_PREFIX)
  );
}
