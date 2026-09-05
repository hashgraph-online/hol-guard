/**
 * True when this dashboard runs inside the HOL Guard Desktop window. Desktop
 * owns the managed Core runtime and its updater (menu-bar "Check for
 * Updates"), so the embedded dashboard must not offer a second, competing
 * update action against the same runtime.
 */
export function dashboardEmbedsInDesktop(): boolean {
  try {
    const params = new URLSearchParams(window.location.search);
    const fragment = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    for (const [key, value] of new URLSearchParams(fragment)) {
      params.set(key, value);
    }
    return params.get("desktop_embed") === "1";
  } catch {
    return false;
  }
}
