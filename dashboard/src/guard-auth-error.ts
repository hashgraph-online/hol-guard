export const GUARD_AUTH_REQUIRED = "This browser needs a fresh local Guard session.";

const DASHBOARD_REQUEST_PATH = /^\/(?:requests|approvals)\/([^/?#]+)\/?$/;
const DASHBOARD_REQUEST_ID = /^[a-z0-9][a-z0-9._-]{0,255}$/;

export function isGuardAuthenticationError(message: string): boolean {
  return message === GUARD_AUTH_REQUIRED || /\bunauthorized\s*\(401\)|\bfailed with 401\b/i.test(message);
}

export function guardSessionRecoveryCommand(pathname: string): string {
  const requestId = DASHBOARD_REQUEST_PATH.exec(pathname)?.[1] ?? null;
  return requestId !== null && DASHBOARD_REQUEST_ID.test(requestId)
    ? `hol-guard approvals open ${requestId}`
    : "hol-guard dashboard";
}
