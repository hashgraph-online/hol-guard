import type { GuardReceipt } from "./guard-types";

/**
 * R-SELF: the signal the native runtime records on a receipt when it blocks a browser action on
 * Guard's own approval center (`GUARD_ORIGIN_SIGNAL` in `mcp_tool_signals.rs`). Receipts carry
 * their signals in `changed_capabilities`.
 */
export const GUARD_ORIGIN_SIGNAL = "browser action on Guard's own approval center";

export const GUARD_ORIGIN_COPY = {
  title: "Blocked: an agent's browser reached Guard's approval center",
  detail:
    "An agent tried to open, click or read Guard's approval center from its browser tool. Guard always stops this, so an agent can never answer its own requests.",
  remediation:
    "Nothing to change. No approval, grant or setting allows this. Review pending requests yourself in your own browser.",
  breakdownLabel: "Guard's approval center",
} as const;

export function isGuardOriginBlock(
  receipt: Pick<GuardReceipt, "policy_decision" | "changed_capabilities">,
): boolean {
  return (
    receipt.policy_decision === "block" &&
    Array.isArray(receipt.changed_capabilities) &&
    receipt.changed_capabilities.includes(GUARD_ORIGIN_SIGNAL)
  );
}
