import { renderToStaticMarkup } from "react-dom/server";

import { parseGuardCloudConnectHttp } from "./guard-cloud-connect-flow";
import { PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE } from "./package-firewall-connect-browser";
import type { GuardCloudOpenStatus } from "./guard-cloud-connect-flow";
import {
  GuardCloudPopupBlockedError,
  OpenGuardCloudAction,
  runOpenGuardCloudConnect,
} from "./open-guard-cloud-action";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

let openedUrls: string[] = [];
let authorizeCalls: Array<{ url: string; browserOpened: boolean | null | undefined }> = [];

function resetBrowserMocks(): void {
  openedUrls = [];
  authorizeCalls = [];
}

function mockOpenUrl(url: string): boolean {
  openedUrls.push(url);
  return true;
}

function mockOpenAuthorize(
  authorizeUrl: string | null | undefined,
  browserOpened: boolean | null | undefined,
): boolean {
  if (authorizeUrl) {
    authorizeCalls.push({ url: authorizeUrl, browserOpened });
    openedUrls.push(authorizeUrl);
  }
  return true;
}

async function runWithStatus(
  status: GuardCloudOpenStatus,
  openAuthorize: typeof mockOpenAuthorize = mockOpenAuthorize,
  openUrl: (url: string) => boolean = mockOpenUrl,
): Promise<void> {
  resetBrowserMocks();
  const controller = new AbortController();
  await runOpenGuardCloudConnect(
    controller.signal,
    openAuthorize,
    openUrl,
    {
      start: async () => status,
      wait: async (initialStatus) => initialStatus,
    },
  );
}

const alreadyConnected = parseGuardCloudConnectHttp(409, {
  error: "guard_cloud_connect_not_required",
  connect_required: false,
  connect_flow: null,
  dashboard_url: "https://hol.org/guard",
});
assert(alreadyConnected.connect_required === false, "409 must mean Guard Cloud is already connected");
assert(
  alreadyConnected.dashboard_url === "https://hol.org/guard",
  "409 payload must keep dashboard_url for already-connected users",
);

let missingDashboardFailed = false;
try {
  parseGuardCloudConnectHttp(500, { error: "boom" });
} catch (error: unknown) {
  missingDashboardFailed = error instanceof Error && error.message.includes("boom");
}
assert(missingDashboardFailed, "non-409 failures must still throw");

await runWithStatus({
  connect_required: true,
  connect_flow: {
    state: "running",
    title: "Finish Guard Cloud sign-in in your browser",
    detail: "HOL Guard opened the secure sign-in flow in your browser.",
    action_label: "Connect Guard Cloud",
    authorize_url: "https://hol.org/api/guard/oauth/authorize?request_id=test-1",
    connect_url: "https://hol.org/guard/connect",
    browser_opened: false,
    request_id: "guard-connect-1",
    poll_after_ms: 1500,
  },
});

assert(
  authorizeCalls.length === 1 &&
    authorizeCalls[0]?.url === "https://hol.org/api/guard/oauth/authorize?request_id=test-1",
  "Open Guard Cloud should start OAuth and open authorize_url",
);
assert(
  openedUrls[0] === "https://hol.org/api/guard/oauth/authorize?request_id=test-1",
  "authorize_url should be opened for OAuth-required connect",
);

await runWithStatus({
  connect_required: false,
  connect_flow: null,
  dashboard_url: "https://hol.org/guard",
});

assert(
  openedUrls[0] === "https://hol.org/guard",
  "already-connected users should open dashboard_url",
);

const markup = renderToStaticMarkup(<OpenGuardCloudAction variant="sidebar" />);
assert(
  markup.includes('type="button"') && markup.includes("Open Guard Cloud"),
  "Open Guard Cloud renders as a button, not a static hol.org/guard link",
);
assert(
  !markup.includes("href="),
  "Open Guard Cloud must not use a static first-hop href",
);

resetBrowserMocks();
let connectOnlyFailed = false;
try {
  await runWithStatus({
    connect_required: true,
    connect_flow: {
      state: "running",
      title: "Finish Guard Cloud sign-in in your browser",
      detail: "HOL Guard opened the secure sign-in flow in your browser.",
      action_label: "Connect Guard Cloud",
      authorize_url: null,
      connect_url: "https://hol.org/guard/connect",
      browser_opened: false,
      request_id: "guard-connect-2",
      poll_after_ms: 1500,
    },
  });
} catch {
  connectOnlyFailed = true;
}
assert(connectOnlyFailed, "connect_url without authorize_url must not be opened as a dead-end page");
assert(openedUrls.length === 0, "dead-end connect page must not open");

resetBrowserMocks();
let authorizePopupBlocked = false;
try {
  await runWithStatus(
    {
      connect_required: true,
      connect_flow: {
        state: "running",
        title: "Finish Guard Cloud sign-in in your browser",
        detail: "HOL Guard opened the secure sign-in flow in your browser.",
        action_label: "Connect Guard Cloud",
        authorize_url: "https://hol.org/api/guard/oauth/authorize?request_id=blocked",
        connect_url: "https://hol.org/guard/connect",
        browser_opened: false,
        request_id: "guard-connect-3",
        poll_after_ms: 1500,
      },
    },
    () => false,
    mockOpenUrl,
  );
} catch (error: unknown) {
  authorizePopupBlocked = error instanceof GuardCloudPopupBlockedError
    && error.message === PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE
    && error.manualUrl === "https://hol.org/api/guard/oauth/authorize?request_id=blocked";
}
assert(authorizePopupBlocked, "blocked OAuth popup must throw a recoverable sign-in error");

resetBrowserMocks();
let dashboardPopupBlocked = false;
try {
  await runWithStatus(
    {
      connect_required: false,
      connect_flow: null,
      dashboard_url: "https://hol.org/guard",
    },
    mockOpenAuthorize,
    () => false,
  );
} catch (error: unknown) {
  dashboardPopupBlocked = error instanceof GuardCloudPopupBlockedError
    && error.manualUrl === "https://hol.org/guard";
}
assert(dashboardPopupBlocked, "blocked dashboard popup must not look like success");

resetBrowserMocks();
let untrustedDashboardFailed = false;
try {
  await runWithStatus({
    connect_required: false,
    connect_flow: null,
    dashboard_url: "https://evil.example/phish",
  });
} catch {
  untrustedDashboardFailed = true;
}
assert(untrustedDashboardFailed, "untrusted dashboard hosts must not be opened");
assert(openedUrls.length === 0, "untrusted dashboard hosts must not open a browser");

console.log("open-guard-cloud-action.test.tsx passed");
