export const GUARD_OVERLAY_ROOT_ID = "guard-overlay-root";

/**
 * Dedicated sibling of the React dashboard root. Overlays must not portal
 * into document.body, where password managers and browser chrome can move
 * nodes out from under React's commit.
 */
export function ensureGuardOverlayRoot(): HTMLElement | null {
  if (typeof document === "undefined") {
    return null;
  }
  const existing = document.getElementById(GUARD_OVERLAY_ROOT_ID);
  if (existing instanceof HTMLElement) {
    return existing;
  }
  const host = document.createElement("div");
  host.id = GUARD_OVERLAY_ROOT_ID;
  const dashboardRoot = document.getElementById("guard-dashboard-root");
  const parent = dashboardRoot?.parentElement ?? document.body;
  if (dashboardRoot?.parentElement === parent && dashboardRoot.nextSibling) {
    parent.insertBefore(host, dashboardRoot.nextSibling);
  } else if (dashboardRoot?.parentElement === parent) {
    parent.appendChild(host);
  } else {
    parent.appendChild(host);
  }
  return host;
}
