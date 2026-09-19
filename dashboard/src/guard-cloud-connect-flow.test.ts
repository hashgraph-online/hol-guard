import {
  CloudRequestTimeoutError,
  parseGuardCloudConnectHttp,
  startOrRecoverCloudConnect,
  waitForAuthorizeUrl,
} from "./guard-cloud-connect-flow";
import { fetchGuardCloudConnectStatus, startGuardCloudConnect } from "./guard-api";
import { runGuardCloudConnectFlow, type GuardCloudConnectUiState } from "./connect-guard-cloud-button";
import { createRequire } from "node:module";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const malformedConnectionStatuses: unknown[] = [
  null, {}, [], { connect_required: "false" }, { connect_required: 0 },
  { capability_enabled: true, enabled: false },
];
for (const payload of malformedConnectionStatuses) {
  const states: GuardCloudConnectUiState[] = [];
  await runGuardCloudConnectFlow(new AbortController().signal, (state) => states.push(state), {
    start: async () => parseGuardCloudConnectHttp(200, payload),
    waitAuthorize: async (status) => status,
    waitConnection: async () => { throw new Error("Unexpected polling after malformed start"); },
    openAuthorize: () => { throw new Error("Unexpected browser opening after malformed start"); },
  });
  assert(states.length === 2 && states[1]?.status === "error",
    "Malformed successful connection responses must produce an error, never connected");
}

const originalFetch = globalThis.fetch;
const originalWindow = Object.getOwnPropertyDescriptor(globalThis, "window");
const { JSDOM } = createRequire(import.meta.url)("jsdom");
const dom = new JSDOM("<!doctype html>", { url: "http://127.0.0.1:4781/?guard-token=synthetic-local-token" });
Object.defineProperty(globalThis, "window", { configurable: true, value: dom.window });
try {
  for (const body of [...malformedConnectionStatuses.map((payload) => JSON.stringify(payload)), "not-json"]) {
    globalThis.fetch = async () => new Response(body, {
      status: 200, headers: { "content-type": "application/json" },
    });
    const states: GuardCloudConnectUiState[] = [];
    await runGuardCloudConnectFlow(new AbortController().signal, (state) => states.push(state));
    assert(states.length === 2 && states[1]?.status === "error",
      "The actual start transport and flow must reject malformed JSON without reporting connected");
  }
  for (const payload of malformedConnectionStatuses) {
    globalThis.fetch = async () => new Response(JSON.stringify(payload), {
      status: 200, headers: { "content-type": "application/json" },
    });
    for (const readStatus of [fetchGuardCloudConnectStatus, startGuardCloudConnect]) {
      let rejected = false;
      try { await readStatus(); } catch (error: unknown) {
        rejected = error instanceof Error && error.message === "Guard returned an invalid connection status. Try again.";
      }
      assert(rejected, "The real status transport must reject malformed successful connection responses");
    }
  }
  for (const connectRequired of [false, true]) {
    globalThis.fetch = async () => new Response(JSON.stringify({ connect_required: connectRequired, connect_flow: null }), {
      status: 200, headers: { "content-type": "application/json" },
    });
    assert((await fetchGuardCloudConnectStatus()).connect_required === connectRequired,
      "The real status transport must preserve the explicit authoritative boolean");
  }
} finally {
  globalThis.fetch = originalFetch;
  dom.window.close();
  if (originalWindow) Object.defineProperty(globalThis, "window", originalWindow);
  else Reflect.deleteProperty(globalThis, "window");
}

const alreadyConnected = parseGuardCloudConnectHttp(409, {
  error: "guard_cloud_connect_not_required",
  connect_required: false,
  connect_flow: null,
  dashboard_url: "https://hol.org/guard",
});
assert(alreadyConnected.connect_required === false, "409 means Guard Cloud is already connected");
assert(
  alreadyConnected.dashboard_url === "https://hol.org/guard",
  "409 payload must keep dashboard_url",
);

let unauthorizedConnectFailed = false;
try {
  parseGuardCloudConnectHttp(401, { error: "unauthorized" });
} catch (error: unknown) {
  unauthorizedConnectFailed = error instanceof Error
    && error.message.includes("signed local session")
    && !error.message.includes("unauthorized");
}
assert(unauthorizedConnectFailed, "401 must use a signed-session message, not raw unauthorized");

assert(
  parseGuardCloudConnectHttp(409, {
    error: "guard_cloud_connect_not_required",
    dashboard_url: "https://evil.example/phish",
  }).dashboard_url === null,
  "untrusted dashboard hosts must be dropped",
);

const methods: Array<"GET" | "POST"> = [];
const recovered = await startOrRecoverCloudConnect(new AbortController().signal, async (method) => {
  methods.push(method);
  if (methods.length === 1) {
    throw new CloudRequestTimeoutError();
  }
  if (method === "GET") {
    throw new Error("status unavailable");
  }
  return parseGuardCloudConnectHttp(409, {
    error: "guard_cloud_connect_not_required",
    dashboard_url: "https://hol.org/guard",
  });
});

assert(methods.join(",") === "POST,GET,POST", "timeout recovery retries GET then POST");
assert(recovered.connect_required === false, "fallback POST 409 must succeed as already-connected");
assert(
  recovered.dashboard_url === "https://hol.org/guard",
  "fallback POST 409 must keep dashboard_url",
);

const polledDashboard = await waitForAuthorizeUrl(
  {
    connect_required: true,
    connect_flow: {
      state: "running",
      title: "Finish Guard Cloud sign-in in your browser",
      detail: "HOL Guard opened the secure sign-in flow in your browser.",
      action_label: "Connect Guard Cloud",
      authorize_url: null,
      connect_url: "https://hol.org/guard/connect",
      browser_opened: false,
      request_id: "guard-connect-poll",
      poll_after_ms: 100,
    },
  },
  new AbortController().signal,
  async () => parseGuardCloudConnectHttp(200, {
    connect_required: false,
    connect_flow: null,
    dashboard_url: "https://hol.org/guard",
  }),
);
assert(
  polledDashboard.dashboard_url === "https://hol.org/guard",
  "authorize poll must keep a dashboard_url returned by GET",
);

const rejectedPoll = await waitForAuthorizeUrl(
  {
    connect_required: true,
    connect_flow: {
      state: "running",
      title: "Finish Guard Cloud sign-in in your browser",
      detail: "HOL Guard opened the secure sign-in flow in your browser.",
      action_label: "Connect Guard Cloud",
      authorize_url: null,
      connect_url: "https://hol.org/guard/connect",
      browser_opened: false,
      request_id: "guard-connect-poll-reject",
      poll_after_ms: 100,
    },
  },
  new AbortController().signal,
  async () => parseGuardCloudConnectHttp(200, {
    connect_required: false,
    connect_flow: null,
    dashboard_url: "https://evil.example/phish",
  }),
);
assert(rejectedPoll.dashboard_url === null, "authorize poll must drop untrusted dashboard hosts");

console.log("guard-cloud-connect-flow.test.ts passed");
