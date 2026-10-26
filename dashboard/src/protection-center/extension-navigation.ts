import { loadCurrentDashboardBuild } from "../dashboard-build";
import { guardAwareHref } from "../guard-api";

/** Keep the dashboard session fragment on in-page Extensions navigation. */
export function pushExtensionHistory(href: string): void {
  const target = guardAwareHref(href);
  if (loadCurrentDashboardBuild(target)) return;
  window.history.pushState({}, "", target);
}

/** Canonicalize an Extensions URL without dropping the dashboard session fragment. */
export function replaceExtensionHistory(href: string): void {
  window.history.replaceState({}, "", guardAwareHref(href));
}
