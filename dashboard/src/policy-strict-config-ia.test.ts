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
const enforcementSource = readFileSync(join(here, "policy-strict-config-enforcement-preview.tsx"), "utf8");
const rightRailSource = readFileSync(join(here, "policy-strict-config-right-rail.tsx"), "utf8");

assert(workspaceSource.includes("PolicyStrictConfigTab"), "policy workspace mounts strict config tab");
assert(!workspaceSource.includes("StrictModeView"), "legacy strict mode view removed");
assert(tabSource.includes("fetchSettings"), "strict config tab loads settings");
assert(enforcementSource.includes("Evaluation order"), "strict config shows evaluation order");
assert(rightRailSource.includes("Policy simulator outcome"), "strict config includes simulator");
assert(enforcementSource.includes("Local enforcement preview"), "strict config shows enforcement preview");
assert(rightRailSource.includes("Run simulation"), "strict config exposes run simulation");
assert(tabSource.includes("PolicyStrictModeCard"), "strict config tab uses extracted cards");
assert(enforcementSource.includes("min-w-[52rem]"), "strict config uses horizontal enforcement flow");
assert(rightRailSource.includes("Learn more"), "strict config links to cloud docs");
assert(workspaceSource.includes("cloudControlsUrl={resolveCloudPolicyControlsUrl(snapshot)}"), "strict config receives cloud controls url");

console.log("policy-strict-config-ia.test.ts: all assertions passed");
