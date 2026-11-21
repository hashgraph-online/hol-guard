import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { renderToStaticMarkup } from "react-dom/server";

import { closeOnEscape } from "./dialog-escape";
import { InterceptProofModal } from "./supply-chain-intercept-proof-modal";
import { SupplyChainManagerDrawer } from "./supply-chain-manager-drawer";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function fakeKey(key: string, defaultPrevented = false) {
  const calls = { prevented: 0, stopped: 0 };
  return {
    calls,
    event: {
      key,
      defaultPrevented,
      preventDefault: () => {
        calls.prevented += 1;
      },
      stopPropagation: () => {
        calls.stopped += 1;
      },
    },
  };
}

let closed = 0;
const handler = closeOnEscape(() => {
  closed += 1;
});

const escape = fakeKey("Escape");
handler(escape.event);
assert(closed === 1, "Escape closes the dialog");
assert(escape.calls.prevented === 1, "Escape is consumed so nothing else reacts to it");
assert(escape.calls.stopped === 1, "Escape does not bubble to a dialog underneath");

handler(fakeKey("Enter").event);
handler(fakeKey("Tab").event);
handler(fakeKey("a").event);
assert(closed === 1, "keys other than Escape leave the dialog open");

const claimed = fakeKey("Escape", true);
handler(claimed.event);
assert(closed === 1, "an Escape another control already handled does not close the dialog");
assert(claimed.calls.stopped === 0, "a handled Escape is left alone");

const noop = () => undefined;
const drawerMarkup = renderToStaticMarkup(
  <SupplyChainManagerDrawer
    manager="npm"
    shim={undefined}
    actions={{ install: "available", repair: "available", test: "available", remove: "available" }}
    anyPending={false}
    repairAwaitingRefresh={false}
    isMine={false}
    actionHandlers={{}}
    onClose={noop}
  />,
);
assert(drawerMarkup.includes('data-testid="supply-chain-manager-drawer"'), "drawer renders");
assert(drawerMarkup.includes('tabindex="-1"'), "drawer is focusable so a click inside it keeps keyboard focus there");

const proofMarkup = renderToStaticMarkup(
  <InterceptProofModal
    proof={{
      interceptProved: true,
      testedManagers: [],
      pathRepairRequired: [],
      managerResults: [],
      receiptId: null,
      timestamp: null,
      summary: "Proof recorded.",
      tone: "success",
    }}
    onClose={noop}
  />,
);
assert(proofMarkup.includes('data-testid="intercept-proof-modal"'), "intercept proof modal renders");
assert(proofMarkup.includes('tabindex="-1"'), "intercept proof modal is focusable");

const here = fileURLToPath(new URL(".", import.meta.url));
for (const file of [
  "supply-chain-manager-drawer.tsx",
  "supply-chain-intercept-proof-modal.tsx",
  "approval-proof-modal.tsx",
]) {
  const source = readFileSync(`${here}${file}`, "utf8");
  assert(source.includes("closeOnEscape("), `${file} closes on Escape`);
  assert(source.includes("useFocusTrap("), `${file} traps focus and restores it on close`);
}
console.log("dialog-escape tests passed");
