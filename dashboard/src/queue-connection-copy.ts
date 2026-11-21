export const QUEUE_CONNECTION_ERROR_HEADLINE =
  "Guard daemon not reachable: approval links work when Guard is running on this device.";
export const QUEUE_CONNECTION_ERROR_INSTRUCTION =
  "Start Guard on this machine, then reload to continue approving or blocking.";
export const QUEUE_SESSION_ERROR_HEADLINE = "This approval link needs a signed local session";
export const QUEUE_SESSION_ERROR_DETAIL =
  "Guard is still running on this device. This browser is not signed in to the local dashboard.";
export const QUEUE_SESSION_ERROR_INSTRUCTION =
  "Use the signed link from the paused tool, or open Inbox from Guard on this device.";
export const QUEUE_DESKTOP_HANDOFF_HEADLINE = "Opened this request in HOL Guard Desktop";
export const QUEUE_DESKTOP_HANDOFF_DETAIL =
  "Approve it or keep it blocked in HOL Guard Desktop. This browser tab is not signed in to the local dashboard, so it cannot decide the request.";
export const QUEUE_DESKTOP_HANDOFF_INSTRUCTION = "If HOL Guard Desktop did not open, open the request again below.";
export const QUEUE_SESSION_COMMAND_INSTRUCTION =
  "Or run this in your own terminal. It opens the request signed in, in HOL Guard Desktop when you use it.";

const REQUEST_ID = /^[0-9a-f]{32}$/;

/** `hol-guard-desktop://requests/<id>` for a queue-shaped request id. */
export function desktopRequestUrl(requestId: string | null): string | null {
  return requestId !== null && REQUEST_ID.test(requestId) ? `hol-guard-desktop://requests/${requestId}` : null;
}

/** The terminal command that opens `requestId` with a signed local session. */
export function approvalsOpenCommand(requestId: string | null): string | null {
  return requestId !== null && REQUEST_ID.test(requestId) ? `hol-guard approvals open ${requestId}` : null;
}

export function queueErrorIsUnauthorizedSession(message: string): boolean {
  const lower = message.trim().toLowerCase();
  if (!lower) {
    return false;
  }
  if (lower.includes("unauthorized")) {
    return true;
  }
  return /request failed with 401(?:\D|$)/.test(lower);
}
