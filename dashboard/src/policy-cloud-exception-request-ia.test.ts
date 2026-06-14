import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const tabSource = readFileSync(join(here, "policy-cloud-exceptions-tab.tsx"), "utf8");
const panelSource = readFileSync(join(here, "policy-cloud-exception-request-panel.tsx"), "utf8");
const guardApiSource = readFileSync(join(here, "guard-api.ts"), "utf8");

assert(tabSource.includes("PolicyCloudExceptionRequestPanel"), "cloud exceptions tab mounts request panel");
assert(panelSource.includes("createCloudExceptionRequest"), "request panel submits through Guard Cloud proxy");
assert(panelSource.includes("sourceReceiptId"), "request panel anchors to source receipt");
assert(!panelSource.includes("savePolicyDecision"), "request panel must not save local policy decisions");
assert(guardApiSource.includes("createCloudExceptionRequest"), "guard-api exposes cloud exception request create");
assert(guardApiSource.includes("/v1/policy/cloud-exception-requests"), "guard-api calls daemon proxy endpoint");

console.log("policy-cloud-exception-request-ia.test.ts: all assertions passed");
