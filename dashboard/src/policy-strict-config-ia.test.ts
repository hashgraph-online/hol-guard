import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const workspaceSource = readFileSync(join(here, "policy-workspace.tsx"), "utf8");
const tabSource = readFileSync(join(here, "policy-strict-config-tab.tsx"), "utf8");

assert(workspaceSource.includes("PolicyStrictConfigTab"), "policy workspace mounts strict config tab");
assert(!workspaceSource.includes("StrictModeView"), "legacy strict mode view removed");
assert(tabSource.includes("fetchSettings"), "strict config tab loads settings");
assert(tabSource.includes("Evaluation order"), "strict config tab shows evaluation order");
assert(tabSource.includes("Policy simulator"), "strict config tab includes simulator");
assert(tabSource.includes("Local enforcement preview"), "strict config tab shows enforcement preview");
assert(tabSource.includes("Run simulation"), "strict config tab exposes run simulation");

console.log("policy-strict-config-ia.test.ts: all assertions passed");
