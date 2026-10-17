import {
  DASHBOARD_BUILD_HEADER,
  DASHBOARD_BUILD_META_NAME,
  DASHBOARD_BUILD_RELOAD_STORAGE_KEY,
  claimStaleBuildReload,
  installStaleBuildGuard,
  isFragmentOnlyChange,
  isDashboardBuildStale,
  loadCurrentDashboardBuild,
  observeDashboardBuild,
  resetObservedDashboardBuild,
  readLoadedDashboardBuild,
  responseDashboardBuild,
} from "./dashboard-build";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function memoryStorage(): Pick<Storage, "getItem" | "setItem"> & { values: Map<string, string> } {
  const values = new Map<string, string>();
  return {
    values,
    getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => {
      values.set(key, value);
    },
  };
}

function response(url: string, build: string | null): Pick<Response, "headers" | "url"> {
  const headers = new Headers();
  if (build !== null) headers.set(DASHBOARD_BUILD_HEADER, build);
  return { url, headers };
}

const origin = "http://127.0.0.1:5474";

const doc = {
  querySelector: (selector: string) =>
    selector === `meta[name="${DASHBOARD_BUILD_META_NAME}"]` ? { getAttribute: () => " build-old " } : null,
} as unknown as Pick<Document, "querySelector">;
assert(readLoadedDashboardBuild(doc) === "build-old", "the page reads the build the daemon stamped on its shell");
assert(
  readLoadedDashboardBuild({ querySelector: () => null } as unknown as Pick<Document, "querySelector">) === null,
  "a shell without a stamp (dev server) has no loaded build",
);
assert(readLoadedDashboardBuild(undefined) === null, "no document means no loaded build");

assert(responseDashboardBuild(response(`${origin}/v1/runtime`, "build-new"), origin) === "build-new", "same-origin responses report the server build");
assert(
  responseDashboardBuild(response("http://127.0.0.1:6000/v1/runtime", "build-new"), origin) === null,
  "a daemon on another origin cannot serve this page, so it never marks it stale",
);
assert(responseDashboardBuild(response(`${origin}/v1/runtime`, null), origin) === null, "an older daemon without the header reports nothing");
assert(responseDashboardBuild(response("", "build-new"), origin) === null, "responses without a URL are ignored");

assert(!isDashboardBuildStale({ loadedBuild: "a", serverBuild: null }), "no server build seen yet is not stale");
assert(!isDashboardBuildStale({ loadedBuild: null, serverBuild: "b" }), "an unstamped page is never stale");
assert(!isDashboardBuildStale({ loadedBuild: "a", serverBuild: "a" }), "matching builds are current");
assert(isDashboardBuildStale({ loadedBuild: "a", serverBuild: "b" }), "a different server build marks the tab stale");

const storage = memoryStorage();
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "a" }, storage), "a current tab never reloads");
assert(claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, storage), "a stale tab claims one reload");
assert(storage.values.get(DASHBOARD_BUILD_RELOAD_STORAGE_KEY) === "b", "the claim records the server build it reloaded for");
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, storage), "a tab still stale after reloading does not loop");
assert(claimStaleBuildReload({ loadedBuild: "b", serverBuild: "c" }, storage), "a later update gets its own reload");
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, undefined), "without session storage the tab never auto-reloads");
const throwingStorage = {
  getItem: () => {
    throw new Error("blocked");
  },
  setItem: () => undefined,
};
assert(!claimStaleBuildReload({ loadedBuild: "a", serverBuild: "b" }, throwingStorage), "blocked storage falls back to normal handling");

// Tab behavior: a stale tab loads the current bundle when its user returns or
// when it is hidden, and never twice for the same server build.
const originalWindow = (globalThis as { window?: unknown }).window;
const originalDocument = (globalThis as { document?: unknown }).document;
const originalSessionStorage = (globalThis as { sessionStorage?: unknown }).sessionStorage;
const baseStorage = memoryStorage();
const tabStorage = Object.assign(baseStorage, {
  removeItem: (key: string) => {
    baseStorage.values.delete(key);
  },
});
const documentListeners = new Map<string, Set<(event?: unknown) => void>>();
const windowListeners = new Map<string, Set<(event?: unknown) => void>>();
let unsavedWork = false;
let beforeUnloadProbes = 0;
let reloads = 0;
const assigned: string[] = [];
const replaced: string[] = [];
const fakeDocument = {
  visibilityState: "visible",
  querySelector: () => ({ getAttribute: () => "build-old" }),
  addEventListener: (type: string, listener: (event?: unknown) => void) => {
    documentListeners.set(type, (documentListeners.get(type) ?? new Set()).add(listener));
  },
  removeEventListener: (type: string, listener: (event?: unknown) => void) => {
    documentListeners.get(type)?.delete(listener);
  },
};
(globalThis as { document: unknown }).document = fakeDocument;
(globalThis as { sessionStorage: unknown }).sessionStorage = tabStorage;
(globalThis as { window: unknown }).window = {
  location: {
    origin,
    pathname: "/inbox",
    search: "?desktop_embed=1",
    href: `${origin}/inbox?desktop_embed=1#guard-token=a`,
    reload: () => {
      reloads += 1;
    },
    assign: (href: string) => {
      assigned.push(href);
      reloads += 1;
    },
  },
  dispatchEvent: (event: Event) => {
    if (event.type === "beforeunload") {
      beforeUnloadProbes += 1;
      if (unsavedWork) event.preventDefault();
    }
    return !event.defaultPrevented;
  },
  history: {
    state: null,
    replaceState: (_state: unknown, _title: string, href: string) => {
      replaced.push(href);
    },
  },
  addEventListener: (type: string, listener: (event?: unknown) => void) => {
    windowListeners.set(type, (windowListeners.get(type) ?? new Set()).add(listener));
  },
  removeEventListener: (type: string, listener: (event?: unknown) => void) => {
    windowListeners.get(type)?.delete(listener);
  },
};

const loadedBuild: { value: string | null } = { value: null };
fakeDocument.querySelector = () => (loadedBuild.value === null ? (null as never) : ({ getAttribute: () => loadedBuild.value } as never));

// An unstamped page (dev server) never reloads, however many builds the server reports.
resetObservedDashboardBuild();
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(!loadCurrentDashboardBuild(), "an unstamped page never reloads");
assert(reloads === 0, "no reload was issued for an unstamped page");

// A stamped tab that matches the server stays put.
loadedBuild.value = "build-new";
assert(!loadCurrentDashboardBuild(), "a current tab never reloads");

// A stale tab on screen keeps working until its user acts.
loadedBuild.value = "build-old";
fakeDocument.visibilityState = "visible";
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(reloads === 0, "a visible stale tab is not reloaded under its user");

// Returning to it asks the daemon first, then loads the current bundle once.
const tick = () => new Promise<void>((resolve) => setTimeout(resolve, 0));
let probes = 0;
const stop = installStaleBuildGuard(async () => {
  probes += 1;
});
for (const listener of windowListeners.get("focus") ?? []) listener();
await tick();
assert(probes === 1, "returning to a tab asks the daemon which bundle it serves");
assert(reloads === 1, "focusing a stale tab loads the current bundle");
for (const listener of documentListeners.get("visibilitychange") ?? []) listener();
await tick();
assert(reloads === 1, "the same server build is never reloaded for twice");

// A tab that heard nothing while away learns the new build from the probe.
tabStorage.values.clear();
resetObservedDashboardBuild();
for (const listener of windowListeners.get("focus") ?? []) listener();
await tick();
assert(reloads === 1, "without any build seen yet the tab cannot know it is stale");
stop();
const stopProbing = installStaleBuildGuard(async () => {
  observeDashboardBuild(response(`${origin}/healthz`, "build-new"));
});
for (const listener of windowListeners.get("focus") ?? []) listener();
await tick();
assert(reloads === 2, "the probe response reveals the update and the tab reloads");

// Events that arrive together share one probe.
tabStorage.values.clear();
let inFlight = 0;
const stopShared = installStaleBuildGuard(async () => {
  inFlight += 1;
  await tick();
});
for (const listener of windowListeners.get("focus") ?? []) listener();
for (const listener of documentListeners.get("visibilitychange") ?? []) listener();
await tick();
await tick();
assert(inFlight === 1, "focus and visibility changes together probe once");
assert(reloads === 3, "and reload once");

// Unsaved work is never thrown away by a reload nobody asked for.
tabStorage.values.clear();
unsavedWork = true;
beforeUnloadProbes = 0;
for (const listener of windowListeners.get("focus") ?? []) listener();
await tick();
await tick();
assert(beforeUnloadProbes > 0, "screens are asked through beforeunload whether they hold unsaved work");
assert(reloads === 3, "a draft blocks the reload on return");
assert(tabStorage.values.size === 0, "a blocked reload does not spend the claim for the build");
fakeDocument.visibilityState = "hidden";
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(reloads === 3, "a draft also blocks the hidden-tab reload");
fakeDocument.visibilityState = "visible";
unsavedWork = false;
for (const listener of windowListeners.get("focus") ?? []) listener();
await tick();
await tick();
assert(reloads === 4, "the reload goes through once the draft is saved");

// A tab restored from the back/forward cache is the old bundle again.
assert(tabStorage.values.size === 1, "the earlier reload left its claim behind");
for (const listener of windowListeners.get("pageshow") ?? []) listener({ persisted: false });
await tick();
assert(reloads === 4 && tabStorage.values.size === 1, "an ordinary page show changes nothing");
for (const listener of windowListeners.get("pageshow") ?? []) listener({ persisted: true });
await tick();
await tick();
assert(reloads === 5, "a stale document restored from the cache gets one more recovery");

stopProbing();
stopShared();
assert((documentListeners.get("visibilitychange")?.size ?? 0) === 0, "the guard removes its visibility listener");
assert((windowListeners.get("focus")?.size ?? 0) === 0, "the guard removes its focus listener");
assert((windowListeners.get("pageshow")?.size ?? 0) === 0, "the guard removes its pageshow listener");

// A hidden stale tab swaps its bundle as soon as it learns it is stale.
tabStorage.values.clear();
fakeDocument.visibilityState = "hidden";
observeDashboardBuild(response(`${origin}/v1/runtime`, "build-new"));
assert(reloads === 6, "a hidden stale tab reloads without waiting");

// Navigating away from a stale tab is a full load of the target.
tabStorage.values.clear();
fakeDocument.visibilityState = "visible";
assert(loadCurrentDashboardBuild("/protect?desktop_embed=1#guard-token=a"), "navigation from a stale tab becomes a full load");
assert(reloads === 7, "the full load is issued");
assert(assigned.length === 1 && assigned[0]?.endsWith("/protect?desktop_embed=1#guard-token=a"), "another screen is loaded with assign");
assert(replaced.length === 0, "another screen needs no history rewrite");

// The screen already open differs only in its fragment, which assign would
// never load: the claim must end in a real reload, not be spent on a no-op.
tabStorage.values.clear();
assert(
  loadCurrentDashboardBuild(`${origin}/inbox?desktop_embed=1#guard-token=b`),
  "a link to the open screen from a stale tab still loads the current bundle",
);
assert(reloads === 8, "the same-screen link reloads the document");
assert(assigned.length === 1, "the same-screen link does not use assign");
assert(replaced.length === 1 && replaced[0]?.endsWith("#guard-token=b"), "the new fragment is kept for the reload");

assert(
  isFragmentOnlyChange({ origin, pathname: "/inbox", search: "?x=1" }, new URL(`${origin}/inbox?x=1#f`)),
  "same path and query is a fragment-only change",
);
assert(
  !isFragmentOnlyChange({ origin, pathname: "/inbox", search: "?x=1" }, new URL(`${origin}/inbox?x=2#f`)),
  "a different query is a real navigation",
);
assert(
  !isFragmentOnlyChange({ origin, pathname: "/inbox", search: "" }, new URL(`${origin}/protect`)),
  "a different path is a real navigation",
);
assert(
  !isFragmentOnlyChange({ origin, pathname: "/inbox", search: "" }, new URL("http://127.0.0.1:6000/inbox")),
  "a different origin is a real navigation",
);

(globalThis as { window?: unknown }).window = originalWindow;
(globalThis as { document?: unknown }).document = originalDocument;
(globalThis as { sessionStorage?: unknown }).sessionStorage = originalSessionStorage;

console.log("dashboard-build tests passed");
