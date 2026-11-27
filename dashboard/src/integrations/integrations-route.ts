import { pushExtensionHistory } from "../protection-center/extension-navigation";
import { isProviderId } from "./provider-integrations-api";

export const INTEGRATIONS_HREF = "/extensions/integrations";

export type IntegrationsRoute = { kind: "integrations" } | { kind: "provider"; providerId: string };

/** The Integrations routes under `/extensions`, or `null` for every other Extensions page. */
export function parseIntegrationsRoute(pathname: string): IntegrationsRoute | null {
  const path = pathname.endsWith("/") ? pathname.slice(0, -1) : pathname;
  if (path === INTEGRATIONS_HREF) return { kind: "integrations" };
  if (!path.startsWith("/extensions/provider.")) return null;
  let providerId: string;
  try {
    providerId = decodeURIComponent(path.slice("/extensions/".length)).trim().toLowerCase();
  } catch {
    return null;
  }
  return isProviderId(providerId) ? { kind: "provider", providerId } : null;
}

export function providerHref(providerId: string): string {
  return `/extensions/${providerId}`;
}

/** Push an Extensions URL and tell every Extensions view to reread it. */
export function navigateExtensions(href: string): void {
  pushExtensionHistory(href);
  window.dispatchEvent(new PopStateEvent("popstate"));
}
