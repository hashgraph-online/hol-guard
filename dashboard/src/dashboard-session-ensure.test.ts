import { ensureGuardDashboardSession, readGuardToken } from "./guard-api";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const originalWindow = (globalThis as { window?: unknown }).window;
const originalFetch = globalThis.fetch;
const storage = new Map<string, string>();
const memoryStorage = {
  getItem(name: string) {
    return storage.get(name) ?? null;
  },
  setItem(name: string, value: string) {
    storage.set(name, value);
  },
  removeItem(name: string) {
    storage.delete(name);
  },
  clear() {
    storage.clear();
  },
  key() {
    return null;
  },
  get length() {
    return storage.size;
  },
};

(globalThis as { window: unknown }).window = {
  location: {
    origin: "http://127.0.0.1:4781",
    pathname: "/",
    search: "",
    hash: "",
    href: "http://127.0.0.1:4781/",
  },
  sessionStorage: memoryStorage,
  localStorage: memoryStorage,
  setTimeout(_handler: () => void) {
    return 1;
  },
  clearTimeout() {},
};

const initializeCalls: Array<{ url: string; hasSessionHeader: boolean }> = [];
globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
  const url = String(input);
  const headers = new Headers(init?.headers);
  initializeCalls.push({
    url,
    hasSessionHeader: headers.has("X-Guard-Dashboard-Session"),
  });
  if (url === "http://127.0.0.1:4781/v1/initialize") {
    return new Response(JSON.stringify({ dashboard_session_token: "minted-dashboard-session" }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ error: "not_found" }), { status: 404 });
}) as typeof fetch;

const reminted = await ensureGuardDashboardSession();
assert(reminted, "unsigned windows must mint a dashboard session from the local daemon");
assert(readGuardToken() === "minted-dashboard-session", "minted session must be stored for later API calls");
assert(
  initializeCalls.some((call) => call.url.endsWith("/v1/initialize") && !call.hasSessionHeader),
  "session recovery must call initialize even when no token is stored",
);

globalThis.fetch = originalFetch;
if (originalWindow === undefined) {
  delete (globalThis as { window?: unknown }).window;
} else {
  (globalThis as { window: unknown }).window = originalWindow;
}

console.log("dashboard-session-ensure.test.ts: all assertions passed");
