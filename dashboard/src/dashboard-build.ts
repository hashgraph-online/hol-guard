// A tab opened before Guard restarted on a new version keeps running the old
// bundle against the new daemon. The old screens then read API shapes they were
// never built for, throw while rendering, and stay broken until a full reload.
// The daemon stamps its bundle fingerprint on the shell (a meta tag) and on
// every response (a header), so the page can tell when it is stale and load
// the matching bundle instead of rendering a broken screen.

import { browserSessionStorage } from "./lazy-workspace";

export const DASHBOARD_BUILD_HEADER = "X-Guard-Dashboard-Build";
export const DASHBOARD_BUILD_META_NAME = "guard-dashboard-build";
export const DASHBOARD_BUILD_RELOAD_STORAGE_KEY = "hol-guard-dashboard-build-reload";

type BuildStorage = Pick<Storage, "getItem" | "setItem"> & Partial<Pick<Storage, "removeItem">>;

export type DashboardBuildState = {
  loadedBuild: string | null;
  serverBuild: string | null;
};

export function readLoadedDashboardBuild(doc: Pick<Document, "querySelector"> | undefined): string | null {
  const content = doc
    ?.querySelector<HTMLMetaElement>(`meta[name="${DASHBOARD_BUILD_META_NAME}"]`)
    ?.getAttribute("content")
    ?.trim();
  return content ? content : null;
}

export function isDashboardBuildStale(state: DashboardBuildState): boolean {
  return state.loadedBuild !== null && state.serverBuild !== null && state.loadedBuild !== state.serverBuild;
}

/**
 * The server build a response reports, or `null` when the response did not come
 * from the daemon that serves this page. A daemon on another origin (port
 * discovery, update reconnect) cannot serve this document, so it never marks the
 * page stale.
 */
export function responseDashboardBuild(
  response: Pick<Response, "headers" | "url">,
  pageOrigin: string,
): string | null {
  const build = response.headers?.get?.(DASHBOARD_BUILD_HEADER)?.trim();
  if (!build || !response.url) {
    return null;
  }
  try {
    return new URL(response.url).origin === pageOrigin ? build : null;
  } catch {
    return null;
  }
}

/**
 * Whether to leave this document for a fresh load of the matching bundle. Each
 * server build gets one attempt per tab, so a page that still reads stale after
 * reloading falls back to its normal error handling instead of looping.
 */
export function claimStaleBuildReload(state: DashboardBuildState, storage: BuildStorage | undefined): boolean {
  if (!isDashboardBuildStale(state) || !storage || state.serverBuild === null) {
    return false;
  }
  try {
    if (storage.getItem(DASHBOARD_BUILD_RELOAD_STORAGE_KEY) === state.serverBuild) {
      return false;
    }
    storage.setItem(DASHBOARD_BUILD_RELOAD_STORAGE_KEY, state.serverBuild);
    return true;
  } catch {
    return false;
  }
}

/**
 * Forget the reload recorded for this tab. A document restored from the
 * back/forward cache is the old bundle again and shares that record, so it is
 * allowed one more recovery. Only a user's Back or Forward restores a page, so
 * this cannot loop.
 */
export function releaseStaleBuildClaim(storage: BuildStorage | undefined): void {
  try {
    storage?.removeItem?.(DASHBOARD_BUILD_RELOAD_STORAGE_KEY);
  } catch {
    // Storage is unavailable; the tab falls back to normal error handling.
  }
}

let serverBuild: string | null = null;

function currentBuildState(): DashboardBuildState {
  return {
    loadedBuild: typeof document === "undefined" ? null : readLoadedDashboardBuild(document),
    serverBuild,
  };
}

/** Forget the server build seen so far (tests). */
export function resetObservedDashboardBuild(): void {
  serverBuild = null;
}

export function observeDashboardBuild(response: Pick<Response, "headers" | "url">): void {
  const pageOrigin = typeof window === "undefined" ? undefined : window.location?.origin;
  if (!pageOrigin || !response) {
    return;
  }
  const build = responseDashboardBuild(response, pageOrigin);
  if (build === null) {
    return;
  }
  serverBuild = build;
  // Nobody is looking at a hidden tab, so swap its bundle without interrupting anyone.
  if (typeof document !== "undefined" && document.visibilityState === "hidden") {
    reloadWhenIdle();
  }
}

/**
 * Whether any screen has work a reload would lose. Screens with drafts already
 * cancel `beforeunload`, so asking them the same question needs no registry.
 */
function hasUnsavedWork(): boolean {
  if (typeof window === "undefined" || typeof window.dispatchEvent !== "function") {
    return false;
  }
  return !window.dispatchEvent(new Event("beforeunload", { cancelable: true }));
}

/** A reload nobody asked for: it never discards unsaved work and never spends the claim then. */
function reloadWhenIdle(): boolean {
  if (!dashboardBuildIsStale() || hasUnsavedWork()) {
    return false;
  }
  return loadCurrentDashboardBuild();
}

/** Ask the daemon that served this page which bundle it serves now. */
export async function probeServerBuild(): Promise<void> {
  try {
    observeDashboardBuild(await fetch("/healthz", { cache: "no-store" }));
  } catch {
    // The daemon may be restarting; the last build seen still decides.
  }
}

/**
 * Reload a stale tab when its user comes back to it. Leaving a screen open
 * across a Guard update is the common way to end up on the old bundle, and
 * returning to it is the moment a reload costs least. A tab that heard nothing
 * from the daemon while it was away asks first, and unsaved work is kept.
 */
export function installStaleBuildGuard(probe: () => Promise<void> = probeServerBuild): () => void {
  if (typeof window === "undefined" || typeof document === "undefined") {
    return () => undefined;
  }
  let checking = false;
  const check = () => {
    if (document.visibilityState === "hidden" || checking) {
      return;
    }
    checking = true;
    void probe()
      .catch(() => undefined)
      .finally(() => {
        checking = false;
        reloadWhenIdle();
      });
  };
  const restored = (event: Event) => {
    if ((event as PageTransitionEvent).persisted) {
      releaseStaleBuildClaim(browserSessionStorage());
      check();
    }
  };
  document.addEventListener("visibilitychange", check);
  window.addEventListener("focus", check);
  window.addEventListener("pageshow", restored);
  return () => {
    document.removeEventListener("visibilitychange", check);
    window.removeEventListener("focus", check);
    window.removeEventListener("pageshow", restored);
  };
}

/**
 * Whether sending the page to `target` would only change its fragment. The
 * dashboard carries its session in the fragment, so a link to the screen
 * already open differs from it in nothing else, and browsers never load a new
 * document for that.
 */
export function isFragmentOnlyChange(
  current: Pick<Location, "origin" | "pathname" | "search">,
  target: Pick<URL, "origin" | "pathname" | "search">,
): boolean {
  return (
    current.origin === target.origin && current.pathname === target.pathname && current.search === target.search
  );
}

export function dashboardBuildIsStale(): boolean {
  return isDashboardBuildStale(currentBuildState());
}

/**
 * Load `href` (or reload this page) with the bundle the daemon now serves when
 * this tab runs an older one. Returns `true` when the document is leaving.
 */
export function loadCurrentDashboardBuild(href?: string): boolean {
  if (typeof window === "undefined" || !claimStaleBuildReload(currentBuildState(), browserSessionStorage())) {
    return false;
  }
  const target = href ? new URL(href, window.location.href) : null;
  if (target === null) {
    window.location.reload();
  } else if (isFragmentOnlyChange(window.location, target)) {
    // `assign` would only change the fragment, which never loads a document.
    window.history.replaceState(window.history.state, "", target.href);
    window.location.reload();
  } else {
    window.location.assign(target.href);
  }
  return true;
}
