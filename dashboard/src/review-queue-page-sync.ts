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

/**
 * The pin after the active request changes. A request the workspace selected
 * itself (a queue row, a page change, a fallback) clears nothing and pins
 * nothing. A request opened from outside the queue (a review link, Desktop,
 * back navigation) is pinned, so it stays open while it sits beyond the
 * visible page and while its detail loads.
 */
export function pinAfterActiveChange(input: {
  activeRequestId: string | null;
  selfSelectedRequestId: string | null;
  pinnedRequestId: string | null;
}): string | null {
  const { activeRequestId, selfSelectedRequestId, pinnedRequestId } = input;
  if (activeRequestId === null || activeRequestId === selfSelectedRequestId) {
    return pinnedRequestId;
  }
  return activeRequestId;
}

/**
 * The request to select when the active one is missing from the loaded queue,
 * or `null` to keep it. A pinned request is kept until its detail is gone,
 * because its row may simply not be in the loaded queue yet.
 */
export function missingActiveFallback(input: {
  filteredRequests: readonly GuardApprovalRequest[];
  requests: readonly GuardApprovalRequest[];
  activeRequestId: string | null;
  detailRequestId: string | null;
  pinnedRequestId: string | null;
  detailGone: boolean;
}): string | null {
  const { filteredRequests, requests, activeRequestId, detailRequestId, pinnedRequestId, detailGone } = input;
  if (filteredRequests.length === 0) return null;
  if (activeRequestId !== null) {
    const loaded = requests.some((item) => item.request_id === activeRequestId) || detailRequestId === activeRequestId;
    if (loaded) return null;
    if (activeRequestId === pinnedRequestId && !detailGone) return null;
  }
  return filteredRequests[0].request_id;
}
