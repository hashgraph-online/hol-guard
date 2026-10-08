export const QUEUE_CONNECTION_ERROR_HEADLINE =
  "Guard daemon not reachable: approval links work when Guard is running on this device.";
export const QUEUE_CONNECTION_ERROR_INSTRUCTION =
  "Start Guard on this machine, then reload to continue approving or blocking.";
export const QUEUE_SESSION_ERROR_HEADLINE = "This approval link needs a signed local session";
export const QUEUE_SESSION_ERROR_DETAIL =
  "Guard is still running on this device. This browser is not signed in to the local dashboard.";
export const QUEUE_SESSION_ERROR_INSTRUCTION =
  "Use the signed link from the paused tool, or open Inbox from Guard on this device.";

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
