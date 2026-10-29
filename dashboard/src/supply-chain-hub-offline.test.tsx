import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { RuntimeGate } from "./runtime-error-state";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const actions = {
  onReconnectSession: () => {},
  onRefreshRuntime: () => {},
  onOpenInbox: () => {},
  onOpenSettings: () => {},
};

function render(runtime: Parameters<typeof RuntimeGate>[0]["runtime"]): string {
  return renderToStaticMarkup(
    <RuntimeGate runtime={runtime} loading={<p>loading-marker</p>} {...actions}>
      {() => <p>hub-marker</p>}
    </RuntimeGate>,
  );
}

const offline = render({ kind: "error", message: "Failed to fetch" });
assert(offline.includes("Guard is not responding"), "an unreachable daemon names the problem instead of a blank page");
assert(offline.includes("Retry"), "an unreachable daemon offers Retry");
assert(!offline.includes("hub-marker"), "the hub is not rendered without a snapshot");

const signedOut = render({ kind: "error", message: "unauthorized (401)" });
assert(signedOut.includes("needs a signed session"), "a lost session says so instead of claiming Guard is down");
assert(signedOut.includes("Reconnect"), "a lost session offers Reconnect");

assert(render({ kind: "loading" }).includes("loading-marker"), "the first load shows the loading state");
assert(
  render({ kind: "ready", snapshot: {} as GuardRuntimeSnapshot }).includes("hub-marker"),
  "a ready runtime renders the hub",
);

// Supply chain, Audit, Feed health and Workspaces share this slot. Before the
// gate, losing the daemon rendered nothing at all in any of them.
const app = readFileSync(new URL("./app.tsx", import.meta.url), "utf8");
const slot = app.slice(app.indexOf("supplyChainHubContent={"), app.indexOf("policyContent={policyContent}"));
assert(slot.includes("<RuntimeGate"), "the supply-chain hub renders through RuntimeGate");
assert(!/:\s*null\s*}/.test(slot), "the supply-chain hub never falls back to an empty slot");
// Retry reloads the snapshot alone, with receipts, so neither a failing approval
// queue nor a receipt-less snapshot follows Guard coming back.
assert(slot.includes("onRefreshRuntime={refreshHubRuntime}"), "hub Retry reloads only the runtime snapshot");
const hubRefresh = app.slice(app.indexOf("const refreshHubRuntime"), app.indexOf("const handleRepair"));
assert(
  hubRefresh.includes("fetchRuntimeSnapshot({ includeItems: false, includeReceipts: true })"),
  "hub Retry keeps the receipts Feed health shows",
);
assert(!hubRefresh.includes("fetchInboxState"), "hub Retry does not depend on the approval queue");

console.log("supply-chain-hub-offline.test.tsx: all assertions passed");
