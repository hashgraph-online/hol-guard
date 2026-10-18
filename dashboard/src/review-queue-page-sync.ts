import type { GuardApprovalRequest } from "./guard-types";

/**
 * The request to select when the active one is not on the visible queue page,
 * or `null` to keep the current selection. A request opened from a setup card
 * is pinned and stays active even though the queue page or filters exclude it.
 */
export function queuePageSyncTarget(input: {
  pagedRequests: readonly GuardApprovalRequest[];
  activeRequestId: string | null;
  detailRequestId: string | null;
  pinnedRequestId: string | null;
}): string | null {
  const { pagedRequests, activeRequestId, detailRequestId, pinnedRequestId } = input;
  if (pagedRequests.length === 0) return null;
  if (activeRequestId !== null && activeRequestId === pinnedRequestId) return null;
  const activeOnPage =
    activeRequestId !== null &&
    (pagedRequests.some((item) => item.request_id === activeRequestId) || detailRequestId === activeRequestId);
  return activeOnPage ? null : pagedRequests[0].request_id;
}
