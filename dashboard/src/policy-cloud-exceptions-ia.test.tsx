import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { resolvePolicyViewLabel } from "./policy-workspace";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));

assert(resolvePolicyViewLabel("exceptions") === "Cloud exceptions", "exceptions view label is Cloud exceptions");
assert(resolvePolicyViewLabel("rules") === "Remembered rules", "rules view label unchanged");

const workspaceSource = readFileSync(join(here, "policy-workspace.tsx"), "utf8");
const tabSource = readFileSync(join(here, "policy-cloud-exceptions-tab.tsx"), "utf8");
const pageSource = readFileSync(join(here, "policy-workspace-page.tsx"), "utf8");
const chromeSource = readFileSync(join(here, "policy-page-chrome.tsx"), "utf8");

assert(!workspaceSource.includes("PolicyExceptionForm"), "policy workspace no longer mounts PolicyExceptionForm");
assert(!workspaceSource.includes("New exception"), "policy workspace removes local New exception copy");
assert(chromeSource.includes("+ Request cloud exception"), "policy header exposes request CTA on exceptions tab");
assert(chromeSource.includes("PolicyExceptionsToolbar"), "policy page chrome exports exceptions toolbar");
assert(tabSource.includes("PolicyCloudExceptionRequestPanel"), "cloud exceptions tab opens in-dashboard request panel");
assert(tabSource.includes("fetchCloudExceptions"), "cloud exceptions tab loads synced exceptions");
assert(tabSource.includes("PolicyCloudExceptionsSummary"), "cloud exceptions tab renders summary cards");
assert(tabSource.includes("PolicyCloudExceptionDetailPanel"), "cloud exceptions tab renders detail panel");
assert(tabSource.includes("PolicyCloudExceptionsList"), "cloud exceptions tab renders grouped lists");
assert(chromeSource.includes("Open Guard Cloud"), "policy header exposes Open Guard Cloud on exceptions tab");
assert(tabSource.includes("Guard Cloud is not connected"), "disconnected Cloud copy present");
assert(pageSource.includes("add custom exceptions here"), "page header uses mockup description");
assert(!workspaceSource.includes("bypass"), "policy workspace removes bypass copy");
const sidebarSource = readFileSync(join(here, "approval-center-primitives.tsx"), "utf8");
assert(sidebarSource.includes('label: "Policy"'), "sidebar Policy label unchanged");

console.log("policy-cloud-exceptions-ia.test.ts: all assertions passed");
