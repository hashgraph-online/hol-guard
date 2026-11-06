import { strict as assert } from "node:assert";
import { standardGuardDaemonOrigin } from "./guard-daemon-origin";
import { fetchApprovalPage } from "./guard-api";

assert.equal(
  standardGuardDaemonOrigin("http://127.0.0.1:5474", 4781, 1000),
  "http://127.0.0.1:5474",
  "a daemon origin inside the reserved range is authoritative",
);
assert.equal(
  standardGuardDaemonOrigin("http://127.0.0.1:4174", 4781, 1000),
  null,
  "a loopback development server is not treated as the daemon",
);
assert.equal(
  standardGuardDaemonOrigin("https://example.test:5474", 4781, 1000),
  null,
  "a non-loopback origin cannot become the local daemon",
);

function storage(values: Map<string, string>): Storage {
  return {
    get length() { return values.size; },
    clear: () => values.clear(),
    getItem: (key) => values.get(key) ?? null,
    key: (index) => [...values.keys()][index] ?? null,
    removeItem: (key) => { values.delete(key); },
    setItem: (key, value) => { values.set(key, value); },
  };
}

const saved = new Map<string, string>([["guardDaemon", "http://127.0.0.1:5473"]]);
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: {
      origin: "http://127.0.0.1:5474",
      pathname: "/requests/request-one",
      search: "",
      hash: "#guard-token=current-token",
    },
    localStorage: storage(saved),
    sessionStorage: storage(new Map()),
  },
});
let requestedUrl = "";
globalThis.fetch = async (input): Promise<Response> => {
  requestedUrl = String(input);
  return new Response(JSON.stringify({
    items: [],
    next_cursor: null,
    total_pending_count: 0,
    total_count: 0,
    status: "pending",
  }), { status: 200, headers: { "Content-Type": "application/json" } });
};
await fetchApprovalPage();
assert.equal(new URL(requestedUrl).origin, "http://127.0.0.1:5474");
assert.equal(saved.get("guardDaemon"), "http://127.0.0.1:5474");

console.log("guard-daemon-origin.test.ts: all tests passed");
