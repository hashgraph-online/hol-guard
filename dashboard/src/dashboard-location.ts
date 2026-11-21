import { useEffect, useState } from "react";

import { loadCurrentDashboardBuild } from "./dashboard-build";

export const DASHBOARD_LOCATION_EVENT = "guard-dashboard-location";

export function commitDashboardLocation(href: string): void {
  // After a Guard update, move to the next screen with a full load of the
  // current bundle rather than rendering it with this tab's stale one.
  if (loadCurrentDashboardBuild(href)) return;
  window.history.pushState({}, "", href);
  // WebKitGTK does not reliably deliver synthetic PopStateEvent to listeners.
  // Same-document dashboard navigation therefore uses a dedicated event.
  window.dispatchEvent(new Event(DASHBOARD_LOCATION_EVENT));
}

export function subscribeDashboardLocation(listener: () => void): () => void {
  window.addEventListener("popstate", listener);
  window.addEventListener(DASHBOARD_LOCATION_EVENT, listener);
  return () => {
    window.removeEventListener("popstate", listener);
    window.removeEventListener(DASHBOARD_LOCATION_EVENT, listener);
  };
}

export function useDashboardPathname(): string {
  const [pathname, setPathname] = useState(window.location.pathname);
  useEffect(() => subscribeDashboardLocation(() => setPathname(window.location.pathname)), []);
  return pathname;
}
