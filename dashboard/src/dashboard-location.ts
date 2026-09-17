import { useEffect, useState } from "react";

export const DASHBOARD_LOCATION_EVENT = "guard-dashboard-location";

export function commitDashboardLocation(href: string): void {
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
