export const PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE =
  "Your browser blocked the Guard Cloud sign-in window. Use Open sign-in page below.";

export function openPackageFirewallAuthorizeWindow(
  authorizeUrl: string | null | undefined,
): boolean {
  if (!authorizeUrl || typeof window === "undefined") {
    return false;
  }
  const popup = window.open(authorizeUrl, "_blank", "noopener,noreferrer");
  return popup !== null;
}
