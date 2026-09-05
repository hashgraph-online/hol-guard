/**
 * True when this dashboard runs inside the HOL Guard Desktop window. Desktop
 * owns the managed Core runtime and its updater (menu-bar "Check for
 * Updates"), so the embedded dashboard must not offer a second, competing
 * update action against the same runtime.
 */
let memoForHref: string | null = null;
let memoResult = false;

export function dashboardEmbedsInDesktop(): boolean {
  let href: string;
  try {
    href = window.location.href;
  } catch {
    // No usable location yet (for example a server-side render): report
    // not-embedded without latching the memo.
    return false;
  }
  if (memoForHref === href) {
    return memoResult;
  }
  const params = new URLSearchParams(window.location.search);
  const fragment = window.location.hash.startsWith("#")
    ? window.location.hash.slice(1)
    : window.location.hash;
  for (const [key, value] of new URLSearchParams(fragment)) {
    params.set(key, value);
  }
  memoForHref = href;
  memoResult = params.get("desktop_embed") === "1";
  return memoResult;
}
