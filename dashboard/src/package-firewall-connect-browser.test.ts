import {
  openPackageFirewallAuthorizeWindow,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
} from "./package-firewall-connect-browser";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const openedUrls: string[] = [];

Object.assign(globalThis, {
  window: {
    open: (url: string) => {
      openedUrls.push(url);
      return {};
    },
  },
});

assert(
  openPackageFirewallAuthorizeWindow("https://hol.org/api/guard/oauth/authorize?client_id=test"),
  "expected authorize window to open",
);
assert(openedUrls.length === 1, "expected one window.open call");
assert(
  openedUrls[0] === "https://hol.org/api/guard/oauth/authorize?client_id=test",
  "expected authorize URL to be passed to window.open",
);

openedUrls.length = 0;
assert(!openPackageFirewallAuthorizeWindow(null), "null authorize URL should not open");
assert(openedUrls.length === 0, "null authorize URL should not call window.open");

Object.assign(globalThis, {
  window: {
    open: () => null,
  },
});
assert(
  !openPackageFirewallAuthorizeWindow("https://hol.org/api/guard/oauth/authorize?client_id=test"),
  "popup blocked should return false",
);
assert(
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE.includes("Open sign-in page"),
  "popup blocked message should mention manual link",
);

console.log("package-firewall-connect-browser.test.ts: all assertions passed");
