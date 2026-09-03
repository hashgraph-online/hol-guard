import {
  CloudRequestTimeoutError,
  parseGuardCloudConnectHttp,
  startOrRecoverCloudConnect,
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
  dashboard_url: "https://example.com/cloud/dashboard",
});
assert(alreadyConnected.connect_required === false, "409 means Guard Cloud is already connected");
assert(
  alreadyConnected.dashboard_url === "https://example.com/cloud/dashboard",
  "409 payload must keep dashboard_url",
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
    dashboard_url: "https://example.com/cloud/dashboard",
  });
});

assert(methods.join(",") === "POST,GET,POST", "timeout recovery retries GET then POST");
assert(recovered.connect_required === false, "fallback POST 409 must succeed as already-connected");
assert(
  recovered.dashboard_url === "https://example.com/cloud/dashboard",
  "fallback POST 409 must keep dashboard_url",
);

console.log("guard-cloud-connect-flow.test.ts passed");
