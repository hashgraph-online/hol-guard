import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ServiceRecoveryPanel } from "./service-recovery-panel";
import { getRecoveryCapabilities } from "./service-recovery";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const BROWSER_STEP = "Open HOL Guard Desktop from the installed application.";
const BROWSER_MESSAGE = "This browser tab cannot control the local service.";
const ICON_TITLE = "Restart Guard from the HOL Guard icon";
const ICON_MESSAGE = "The HOL Guard recovery screen is not reachable from this page.";

function render(): string {
  return renderToStaticMarkup(createElement(ServiceRecoveryPanel, {
    bridge: null,
    installMode: "desktop-bundled",
    onRetryConnection: () => undefined,
  }));
}

// A browser tab keeps the steps that send the user to Guard Desktop.
const browser = render();
assert(browser.includes(BROWSER_STEP), "#7485: a browser tab still points to Guard Desktop");
assert(browser.includes(BROWSER_MESSAGE), "#7485: a browser tab keeps the browser-tab message");
assert(!browser.includes(ICON_TITLE), "#7485: a browser tab does not get the Desktop-window steps");

// Inside Guard Desktop without its recovery bridge, the steps must not send
// the user to the window they are already in.
Object.defineProperty(globalThis, "window", {
  configurable: true,
  value: {
    location: {
      href: "http://127.0.0.1:43123/?desktop_embed=1",
      search: "?desktop_embed=1",
      hash: "",
    },
  },
});
const desktop = render();
assert(desktop.includes(ICON_TITLE), "#7485: the Desktop window gets the HOL Guard icon steps");
assert(desktop.includes(ICON_MESSAGE), "#7485: the Desktop window says its recovery screen is unreachable");
assert(desktop.includes("choose Troubleshoot Guard"), "#7485: the Desktop window names Troubleshoot Guard");
assert(!desktop.includes(BROWSER_STEP), "#7485: the Desktop window is not told to open Guard Desktop");
assert(!desktop.includes(BROWSER_MESSAGE), "#7485: the Desktop window is not called a browser tab");
assert(desktop.includes("Retry connection"), "#7485: the Desktop window keeps the retry action");

// desktop_embed is only a URL parameter, so a browser tab can carry it too.
// The same steps must still hold there: they never claim to be in the
// Desktop window, and they cover a Desktop that is not running.
assert(!desktop.includes("This HOL Guard window"), "#7485: the copy does not claim to be the Desktop window");
assert(!desktop.includes("return to this window"), "#7485: the steps do not assume a Desktop window");
assert(
  desktop.includes("If there is no HOL Guard icon, HOL Guard is not running. Open it from your applications menu."),
  "#7485: a page without a running Desktop is told how to start it",
);

// The embed hint still never grants the native recovery handoff.
const capability = getRecoveryCapabilities({ bridge: null, installMode: "desktop-bundled" });
assert(capability.kind === "fallback", "#7485: desktop_embed does not create a recovery bridge");
assert(!desktop.includes("Open recovery"), "#7485: no native handoff button without a bridge");

// A CLI install keeps its command even inside the Desktop window.
const cli = renderToStaticMarkup(createElement(ServiceRecoveryPanel, {
  bridge: null,
  installMode: "cli",
  onRetryConnection: () => undefined,
}));
assert(cli.includes("hol-guard daemon recovery restart"), "#7485: a CLI install keeps its recovery command");

console.log("service-recovery-desktop-window.test.ts: all assertions passed");
