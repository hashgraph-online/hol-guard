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

/**
 * Follow an Extensions link in place, unless the person asked the browser for something else:
 * a modified or non-primary click keeps its default (new tab, new window, download).
 */
export function followExtensionsLink(
  event: { button: number; metaKey: boolean; ctrlKey: boolean; shiftKey: boolean; altKey: boolean; preventDefault: () => void },
  href: string,
): void {
  if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault();
  navigateExtensions(href);
}
