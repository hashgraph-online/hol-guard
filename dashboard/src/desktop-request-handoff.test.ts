import { desktopHandoffTarget, requestPageId } from "./desktop-request-handoff";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const requestId = "2c79d707370b453886adf5b2e7e622ec";
const page = {
  pathname: `/requests/${requestId}`,
  desktopOpensRequests: true,
  embedded: false,
  alreadyHandedOff: () => false,
};

assert(
  desktopHandoffTarget(page) === `hol-guard-desktop://requests/${requestId}`,
  "A browser tab on a request page opens that request in Desktop",
);
assert(
  desktopHandoffTarget({ ...page, pathname: `/requests/${requestId}/` }) ===
    `hol-guard-desktop://requests/${requestId}`,
  "A trailing slash is the same request page",
);
assert(
  desktopHandoffTarget({ ...page, desktopOpensRequests: false }) === null,
  "No Desktop marker: the tab stays in the browser",
);
assert(desktopHandoffTarget({ ...page, embedded: true }) === null, "Desktop's own window never hands off to itself");
assert(
  desktopHandoffTarget({ ...page, alreadyHandedOff: (id) => id === requestId }) === null,
  "A tab hands a request to Desktop once",
);
for (const pathname of [
  "/",
  "/inbox",
  "/requests",
  `/requests/${requestId.toUpperCase()}`,
  `/requests/${requestId}/1-${"0".repeat(32)}`,
  "/requests/../x",
  `/approvals/${requestId}`,
]) {
  assert(desktopHandoffTarget({ ...page, pathname }) === null, `Only a single request page hands off: ${pathname}`);
}
assert(requestPageId(`/requests/${requestId}`) === requestId, "The request page names its request");
assert(requestPageId("/requests/abc") === null, "Only a queue-shaped id is a request page");

console.log("desktop-request-handoff.test.ts: all tests passed");
