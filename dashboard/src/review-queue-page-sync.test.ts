import { readFileSync } from "node:fs";
import type { GuardApprovalRequest } from "./guard-types";
import { missingActiveFallback, pinAfterActiveChange, queuePageSyncTarget } from "./review-queue-page-sync";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

function row(id: string): GuardApprovalRequest {
  return { request_id: id } as GuardApprovalRequest;
}

// A review link names a request beyond the first queue page.
const firstPage = Array.from({ length: 10 }, (_, index) => row(`queued-${index + 1}`));
const linked = "linked-request";

// The link opens from outside the workspace, so the request is pinned.
const pinned = pinAfterActiveChange({ activeRequestId: linked, selfSelectedRequestId: null, pinnedRequestId: null });
assert(pinned === linked, "a request opened from a review link is pinned");
assert(
  pinAfterActiveChange({ activeRequestId: "queued-2", selfSelectedRequestId: "queued-2", pinnedRequestId: linked }) === linked,
  "a request the workspace selected itself does not replace the pin",
);
assert(
  pinAfterActiveChange({ activeRequestId: null, selfSelectedRequestId: null, pinnedRequestId: linked }) === linked,
  "clearing the active request does not pin anything",
);

// Before its detail loads, the linked request is neither in the loaded queue nor the detail.
const loading = {
  filteredRequests: firstPage,
  requests: firstPage,
  activeRequestId: linked,
  detailRequestId: null,
  pinnedRequestId: pinned,
  detailGone: false,
};
assert(missingActiveFallback(loading) === null, "a linked request stays open while its detail loads");
assert(
  queuePageSyncTarget({ pagedRequests: firstPage, activeRequestId: linked, detailRequestId: null, pinnedRequestId: pinned }) === null,
  "a linked request beyond the first page is not replaced by the first queue row",
);

// Once its detail is gone, the inbox falls back to the first queue row.
assert(
  missingActiveFallback({ ...loading, detailGone: true }) === "queued-1",
  "a linked request whose detail is gone falls back to the first queue row",
);
// An unpinned missing request still falls back, as before.
assert(
  missingActiveFallback({ ...loading, pinnedRequestId: null }) === "queued-1",
  "an unpinned missing request falls back to the first queue row",
);
assert(missingActiveFallback({ ...loading, detailRequestId: linked }) === null, "a request with loaded detail is kept");
assert(missingActiveFallback({ ...loading, filteredRequests: [] }) === null, "an empty queue selects nothing");
assert(
  missingActiveFallback({ ...loading, activeRequestId: null, pinnedRequestId: null }) === "queued-1",
  "with nothing active, the first queue row opens",
);

// The workspace wires the pin for requests opened from outside, and a mount does not clear it.
const workspace = readFileSync(new URL("./review-workspace.tsx", import.meta.url), "utf8");
assert(/useState<string \| null>\(activeRequestId\)/.test(workspace), "the request open at mount starts pinned");
assert(/pinAfterActiveChange\(/.test(workspace), "an externally changed active request is pinned");
assert(/missingActiveFallback\(/.test(workspace), "the missing-request fallback honors the pin");
assert(/selfSelectedRef\.current = id/.test(workspace), "the workspace's own selections are told apart from outside opens");
assert(/appliedFilterSignatureRef\.current === filterSignature\) return/.test(workspace), "mounting does not count as a filter change");
const layout = readFileSync(new URL("./approval-center-layout.tsx", import.meta.url), "utf8");
assert(/detailGone=\{props\.detail\.kind === "stale"\}/.test(layout), "the layout reports when the active request is gone");

console.log("review-queue-page-sync tests passed");
