import { renderToStaticMarkup } from "react-dom/server";

import type { GuardCloudOpenStatus } from "./guard-cloud-connect-flow";
import {
  ConnectGuardCloudButton,
  runGuardCloudConnectFlow,
  type GuardCloudConnectFlowDeps,
  type GuardCloudConnectUiState,
} from "./connect-guard-cloud-button";
import { PolicyExceptionsToolbar } from "./policy-page-chrome";
import { PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE } from "./package-firewall-connect-browser";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const AUTHORIZE_URL = "https://hol.org/api/guard/oauth/authorize?request_id=test-1";
const CONNECT_URL = "https://hol.org/guard/connect";

function connectStatus(overrides: {
  connectRequired?: boolean;
  authorizeUrl?: string | null;
  connectUrl?: string | null;
  browserOpened?: boolean | null;
}): GuardCloudOpenStatus {
  return {
    connect_required: overrides.connectRequired ?? true,
    connect_flow: {
      state: "running",
      title: "Finish Guard Cloud sign-in in your browser",
      detail: "HOL Guard opened the secure sign-in flow in your browser.",
      action_label: "Connect Guard Cloud",
      connect_url: (overrides.connectUrl === undefined ? CONNECT_URL : overrides.connectUrl) as string,
      authorize_url: overrides.authorizeUrl ?? null,
      browser_opened: overrides.browserOpened ?? null,
      request_id: "guard-connect-test",
      poll_after_ms: 100,
    },
    dashboard_url: null,
  };
}

async function runFlow(
  startStatus: GuardCloudOpenStatus,
  connectedStatus: GuardCloudOpenStatus = startStatus,
  options: { openAuthorize?: () => boolean } = {},
): Promise<GuardCloudConnectUiState[]> {
  const states: GuardCloudConnectUiState[] = [];
  await runGuardCloudConnectFlow(
    new AbortController().signal,
    (state) => states.push(state),
    {
      start: async () => startStatus,
      waitAuthorize: async (status) => status,
      waitConnection: async () => connectedStatus,
      openAuthorize: options.openAuthorize ?? (() => true),
    } satisfies GuardCloudConnectFlowDeps,
  );
  return states;
}

const connectedStatus: GuardCloudOpenStatus = {
  connect_required: false,
  connect_flow: null,
  dashboard_url: "https://hol.org/guard",
};

let states = await runFlow(connectedStatus);
assert(
  states.length === 2 && states[0]?.status === "working" && states[1]?.status === "connected",
  "already-connected machines should move from working straight to connected",
);

states = await runFlow(
  connectStatus({ authorizeUrl: AUTHORIZE_URL }),
  connectedStatus,
);
assert(states[0]?.status === "working", "connect starts in the working state");
const authorizePending = states.find((state) => state.status === "pending");
assert(
  authorizePending?.status === "pending" &&
    authorizePending.message.includes("Complete sign-in in the opened window") &&
    authorizePending.manualUrl === AUTHORIZE_URL,
  "opened authorize URL should surface a pending state with the manual sign-in link",
);
assert(
  states[states.length - 1]?.status === "connected",
  "a finished browser sign-in should end connected",
);

states = await runFlow(
  connectStatus({ authorizeUrl: AUTHORIZE_URL }),
  connectedStatus,
  { openAuthorize: () => false },
);
assert(
  states.some(
    (state) =>
      state.status === "pending" &&
      state.message === PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE &&
      state.manualUrl === AUTHORIZE_URL,
  ),
  "a blocked sign-in window must keep the manual authorize URL reachable",
);

states = await runFlow(
  connectStatus({ authorizeUrl: AUTHORIZE_URL }),
  connectStatus({ authorizeUrl: AUTHORIZE_URL }),
);
const lastPending = [...states].reverse().find((state) => state.status === "pending");
assert(
  lastPending?.status === "pending" &&
    lastPending.message.includes("Sign-in is still pending") &&
    lastPending.manualUrl === AUTHORIZE_URL,
  "an unfinished sign-in should stay pending with a retryable manual link",
);

states = await runFlow(
  connectStatus({ authorizeUrl: AUTHORIZE_URL }),
  {
    connect_required: true,
    connect_flow: {
      state: "failed",
      title: "Guard Cloud sign-in failed",
      detail: "Sign-in was denied in the browser.",
      action_label: "Connect Guard Cloud",
      connect_url: CONNECT_URL,
      authorize_url: null,
      browser_opened: null,
      request_id: "guard-connect-test",
      poll_after_ms: 100,
    },
    dashboard_url: null,
  },
);
const failedState = states[states.length - 1];
assert(
  failedState?.status === "error" && failedState.message === "Sign-in was denied in the browser.",
  "a failed daemon flow should surface the daemon detail as an error",
);

states = await runFlow(connectStatus({ connectUrl: CONNECT_URL }), connectedStatus);
const connectOnlyPending = states.find((state) => state.status === "pending");
assert(
  connectOnlyPending?.status === "pending" &&
    connectOnlyPending.manualUrl === CONNECT_URL &&
    connectOnlyPending.message.includes("Open sign-in to continue"),
  "connect_url-only flows should offer the daemon link instead of opening a dead-end page",
);
assert(
  states[states.length - 1]?.status === "connected",
  "connect_url-only flows should still reach connected after the daemon confirms",
);

states = await runFlow(
  connectStatus({ connectUrl: null }),
  connectStatus({ connectUrl: null }),
);
const noLinkState = states[states.length - 1];
assert(
  noLinkState?.status === "error" &&
    noLinkState.message === "HOL Guard opened the secure sign-in flow in your browser." &&
    noLinkState.manualUrl === null,
  "a flow with no authorize or connect URL must fail honestly with the daemon detail and no link",
);

let startErrorStates: GuardCloudConnectUiState[] = [];
let startFailureSeen = false;
try {
  await runGuardCloudConnectFlow(
    new AbortController().signal,
    (state) => startErrorStates.push(state),
    {
      start: async () => {
        throw new Error("daemon offline");
      },
      waitAuthorize: async (status) => status,
      waitConnection: async () => connectedStatus,
      openAuthorize: () => true,
    } satisfies GuardCloudConnectFlowDeps,
  );
} catch {
  startFailureSeen = true;
}
assert(!startFailureSeen, "runGuardCloudConnectFlow must not reject; errors arrive as states");
const startErrorState = startErrorStates[startErrorStates.length - 1];
assert(
  startErrorState?.status === "error" && startErrorState.message === "daemon offline",
  "a failed start should surface the daemon error message",
);

const abortController = new AbortController();
const abortedStates: GuardCloudConnectUiState[] = [];
abortController.abort();
await runGuardCloudConnectFlow(
  abortController.signal,
  (state) => abortedStates.push(state),
  {
    start: async () => connectedStatus,
    waitAuthorize: async (status) => status,
    waitConnection: async () => connectedStatus,
    openAuthorize: () => true,
  } satisfies GuardCloudConnectFlowDeps,
);
assert(
  abortedStates.length === 0,
  "an aborted flow must not emit any UI state",
);

const buttonMarkup = renderToStaticMarkup(<ConnectGuardCloudButton />);
assert(
  buttonMarkup.includes('type="button"') && buttonMarkup.includes("Connect Guard Cloud"),
  "Connect Guard Cloud renders as a button with its action label",
);
assert(
  !buttonMarkup.includes("href="),
  "Connect Guard Cloud must not render a static connect-page href",
);

const toolbarMarkup = renderToStaticMarkup(
  <PolicyExceptionsToolbar
    cloudConnected={false}
    cloudControlsUrl="https://hol.org/guard/connect"
    onRequestException={() => undefined}
  />,
);
assert(
  toolbarMarkup.includes("Connect Guard Cloud") && toolbarMarkup.includes('type="button"'),
  "disconnected exceptions toolbar should offer a connect button",
);
assert(
  !toolbarMarkup.includes('href="https://hol.org/guard/connect"'),
  "exceptions toolbar must not blind-link to the static connect page while disconnected",
);
assert(
  !toolbarMarkup.includes("Open Guard Cloud"),
  "exceptions toolbar should not offer a cloud dashboard link while disconnected",
);

console.log("connect-guard-cloud-button.test.tsx passed");
