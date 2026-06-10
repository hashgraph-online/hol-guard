export function insightsSharePublishErrorMessage(raw: string): string {
  const message = raw.trim();
  const lower = message.toLowerCase();

  if (lower.includes("insights") && lower.includes("not enabled")) {
    return "Guard insights sharing is not live on Guard Cloud yet. If you just updated, wait a few minutes and try again.";
  }

  if (
    lower.includes("guard:insights.share") ||
    lower.includes("insufficient scope") ||
    lower.includes("missing scope")
  ) {
    return "Reconnect Guard Cloud to grant insights sharing permission, then try again.";
  }

  if (
    lower.includes("invalid_grant") ||
    lower.includes("already consumed") ||
    lower.includes("no longer valid") ||
    lower.includes("hol-guard disconnect")
  ) {
    return "Guard Cloud sign-in on this device expired. Run hol-guard disconnect, then hol-guard connect, and try again.";
  }

  if (lower.includes("unauthorized") || lower.includes("401")) {
    return "Guard Cloud session expired. Reconnect from Settings, then try again.";
  }

  return message || "Unable to publish share link.";
}

export function isInsightsShareScopeError(raw: string): boolean {
  const lower = raw.toLowerCase();
  return (
    lower.includes("guard:insights.share") ||
    lower.includes("insufficient_scope") ||
    lower.includes("insufficient scope") ||
    lower.includes("missing_scope") ||
    lower.includes("missing scope") ||
    lower.includes("unauthorized")
  );
}
