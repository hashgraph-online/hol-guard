/**
 * Hands a request page to HOL Guard Desktop when Desktop opens request links.
 *
 * Agents relay approval links to the user, and some drop the signed code on
 * the way, which leaves the user on a tab with no local session. When the
 * daemon serves the page with the `guard-desktop-requests` marker, Desktop has
 * said it opens `hol-guard-desktop://requests/<id>`, so a browser tab that lands
 * on `/requests/<id>` opens that request in Desktop once. The tab stays usable:
 * a signed tab can still decide the request, and an unsigned one says where
 * the request went.
 *
 * The handoff only opens Desktop; it carries no session and grants nothing.
 * Desktop's own window carries the `desktop_embed` hint and never hands off to
 * itself.
 */
import { dashboardEmbedsInDesktop } from "./desktop-embed";
import { desktopRequestUrl } from "./queue-connection-copy";

export const DESKTOP_REQUESTS_META = "guard-desktop-requests";
const HANDOFF_KEY_PREFIX = "guard-desktop-handoff:";
const EMBEDDED_KEY = "guard-desktop-embedded";
const REQUEST_PATH = /^\/requests\/([0-9a-f]{32})\/?$/;

export type DesktopHandoffPage = {
  pathname: string;
  desktopOpensRequests: boolean;
  embedded: boolean;
  alreadyHandedOff: (requestId: string) => boolean;
};

/** The request id a page at `pathname` shows, when it is a single request page. */
export function requestPageId(pathname: string): string | null {
  return REQUEST_PATH.exec(pathname)?.[1] ?? null;
}

/** The Desktop link this page should open, or null when it should stay put. */
export function desktopHandoffTarget(page: DesktopHandoffPage): string | null {
  if (!page.desktopOpensRequests || page.embedded) {
    return null;
  }
  const requestId = requestPageId(page.pathname);
  if (requestId === null || page.alreadyHandedOff(requestId)) {
    return null;
  }
  return desktopRequestUrl(requestId);
}

/** Whether the daemon marked this page as served to a Desktop user. */
export function pageDesktopOpensRequests(): boolean {
  try {
    const meta = document.querySelector(`meta[name="${DESKTOP_REQUESTS_META}"]`);
    return meta?.getAttribute("content") === "1";
  } catch {
    return false;
  }
}

function storage(): Storage | null {
  try {
    return window.sessionStorage;
  } catch {
    return null;
  }
}

/**
 * Whether this tab is Desktop's own window. The `desktop_embed` hint only
 * rides the first URL, so the answer is kept for the tab's lifetime and a
 * reload inside Desktop never hands the page back to Desktop.
 */
function tabIsEmbedded(): boolean {
  const store = storage();
  let embedded = false;
  try {
    embedded = dashboardEmbedsInDesktop();
  } catch {
    embedded = false;
  }
  if (embedded) {
    store?.setItem(EMBEDDED_KEY, "1");
    return true;
  }
  return store?.getItem(EMBEDDED_KEY) === "1";
}

/** Whether this tab already opened `requestId` in Desktop. */
export function requestHandedOffToDesktop(requestId: string | null | undefined): boolean {
  if (!requestId) {
    return false;
  }
  return storage()?.getItem(HANDOFF_KEY_PREFIX + requestId) === "1";
}

/** Open this request page in Desktop once per tab, when Desktop opens requests. */
export function handOffRequestPageToDesktop(): void {
  let pathname: string;
  try {
    pathname = window.location.pathname;
  } catch {
    return;
  }
  const target = desktopHandoffTarget({
    pathname,
    desktopOpensRequests: pageDesktopOpensRequests(),
    embedded: tabIsEmbedded(),
    alreadyHandedOff: requestHandedOffToDesktop,
  });
  const requestId = requestPageId(pathname);
  const store = storage();
  if (target === null || requestId === null || store === null) {
    return;
  }
  store.setItem(HANDOFF_KEY_PREFIX + requestId, "1");
  try {
    window.location.assign(target);
  } catch {
    store.removeItem(HANDOFF_KEY_PREFIX + requestId);
  }
}
