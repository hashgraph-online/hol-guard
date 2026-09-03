import { renderToStaticMarkup } from "react-dom/server";

import type { GuardCloudConnectStatusResponse } from "./guard-types";
import { OpenGuardCloudAction, runOpenGuardCloudConnect } from "./open-guard-cloud-action";

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

function mockOpenUrl(url: string): void {
  openedUrls.push(url);
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

async function runWithStatus(status: GuardCloudConnectStatusResponse): Promise<void> {
  resetBrowserMocks();
  const controller = new AbortController();
  await runOpenGuardCloudConnect(
    controller.signal,
    mockOpenAuthorize,
    mockOpenUrl,
    {
      start: async () => status,
      wait: async (initialStatus) => initialStatus,
    },
  );
}

await runWithStatus({
  connect_required: true,
  connect_flow: {
    state: "running",
    title: "Finish Guard Cloud sign-in in your browser",
    detail: "HOL Guard opened the secure sign-in flow in your browser.",
    action_label: "Connect Guard Cloud",
    authorize_url: "https://example.com/oauth/authorize?request_id=test-1",
    connect_url: "https://example.com/guard/connect",
    browser_opened: false,
    request_id: "guard-connect-1",
    poll_after_ms: 1500,
  },
});

assert(
  authorizeCalls.length === 1 &&
    authorizeCalls[0]?.url === "https://example.com/oauth/authorize?request_id=test-1",
  "Open Guard Cloud should start OAuth and open authorize_url",
);
assert(
  openedUrls[0] === "https://example.com/oauth/authorize?request_id=test-1",
  "authorize_url should be opened for OAuth-required connect",
);

await runWithStatus({
  connect_required: false,
  connect_flow: null,
  dashboard_url: "https://example.com/cloud/dashboard",
});

assert(
  openedUrls[0] === "https://example.com/cloud/dashboard",
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
      connect_url: "https://example.com/guard/connect",
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

console.log("open-guard-cloud-action.test.tsx passed");
