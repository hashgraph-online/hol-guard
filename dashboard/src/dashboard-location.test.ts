import { commitDashboardLocation, DASHBOARD_LOCATION_EVENT, subscribeDashboardLocation } from "./dashboard-location";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const originalWindow = (globalThis as { window?: unknown }).window;
const historyHrefs: string[] = [];
const location = { pathname: "/", href: "http://127.0.0.1:5474/" };
const listeners = new Map<string, Set<() => void>>();

(globalThis as { window: unknown }).window = {
  location,
  history: {
    pushState(_state: unknown, _title: string, href: string) {
      historyHrefs.push(href);
      const url = new URL(href, "http://127.0.0.1:5474");
      location.pathname = url.pathname;
      location.href = url.toString();
    },
  },
  addEventListener(type: string, listener: () => void) {
    const bucket = listeners.get(type) ?? new Set();
    bucket.add(listener);
    listeners.set(type, bucket);
  },
  removeEventListener(type: string, listener: () => void) {
    listeners.get(type)?.delete(listener);
  },
  dispatchEvent(event: Event) {
    for (const listener of listeners.get(event.type) ?? []) {
      listener();
    }
    return true;
  },
};

let seen = "";
const unsubscribe = subscribeDashboardLocation(() => {
  seen = location.pathname;
});
commitDashboardLocation("/settings#guard-token=gld1.test");
assert(seen === "/settings", `dashboard location event must update the route without popstate — got "${seen}"`);
assert(historyHrefs[0] === "/settings#guard-token=gld1.test", "navigation must keep the signed session fragment");
assert(
  (listeners.get("popstate")?.size ?? 0) === 1,
  "browser back/forward still listens for native popstate",
);
assert(
  (listeners.get(DASHBOARD_LOCATION_EVENT)?.size ?? 0) === 1,
  "same-document navigation uses the dedicated location event",
);
unsubscribe();
assert((listeners.get(DASHBOARD_LOCATION_EVENT)?.size ?? 0) === 0, "location subscription must clean up");

if (originalWindow === undefined) {
  delete (globalThis as { window?: unknown }).window;
} else {
  (globalThis as { window: unknown }).window = originalWindow;
}
