import {
  CloudRequestTimeoutError,
  parseGuardCloudConnectHttp,
  startOrRecoverCloudConnect,
  waitForAuthorizeUrl,
} from "./guard-cloud-connect-flow";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
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
