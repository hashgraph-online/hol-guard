import { readFileSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const appDetailSource = readFileSync(join(__dirname, "apps/app-detail-workspace.tsx"), "utf8");
const appSource = readFileSync(join(__dirname, "app.tsx"), "utf8");
const navSource = readFileSync(join(__dirname, "approval-center-primitives.tsx"), "utf8");

assert(appDetailSource.includes("EvidenceActionList"), "app activity tab uses EvidenceActionList");
assert(appDetailSource.includes("EvidenceActionDetail"), "app activity tab uses EvidenceActionDetail");
assert(appDetailSource.includes("EvidenceFilterBar"), "app activity tab uses EvidenceFilterBar");
assert(!appDetailSource.includes("ExpandableReceiptRow"), "legacy expandable receipt rows removed");
assert(appSource.includes('export const PROTECT_ROUTE = "/protect"'), "protect route constant exported");
assert(navSource.includes('href: "/protect"'), "sidebar nav links to /protect");

console.log("app-activity-evidence.test.ts: all tests passed");
