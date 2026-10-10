// State helpers that keep a review decision tied to the request it was made on.
import { useCallback, useLayoutEffect, useRef } from "react";
import { GuardRequestResolutionError } from "./guard-api";
import type { GuardApprovalRequest } from "./guard-types";

/** A decision only describes the request it was made on, never the request shown after it. */
export function resolvedStateForItem<T extends { requestId: string }>(
  state: T | null,
  item: Pick<GuardApprovalRequest, "request_id"> | null,
): T | null {
  return item !== null && state?.requestId === item.request_id ? state : null;
}

/** Lock and missing-code errors mean the gate snapshot is stale; refresh it before retrying. */
export function approvalGateRefreshNeeded(err: unknown): boolean {
  if (!(err instanceof GuardRequestResolutionError)) return false;
  const code = err.payload?.["error"];
  return (err.status === 423 && code === "approval_gate_locked") || code === "approval_gate_totp_required";
}

/**
 * Track the request currently on screen. The parent can show the next request before a
 * decision settles, so post-decision state updates must check it is still the same one.
 */
export function useShownRequestCheck(requestId: string | null): (expected: string) => boolean {
  const shown = useRef(requestId);
  useLayoutEffect(() => {
    shown.current = requestId;
  }, [requestId]);
  return useCallback((expected: string) => shown.current === expected, []);
}
