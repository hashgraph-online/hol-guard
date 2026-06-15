import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));

const POLICY_RELEASE_FILES = [
  "policy-workspace.tsx",
  "policy-workspace-page.tsx",
  "policy-cloud-exceptions-tab.tsx",
  "policy-cloud-exceptions-list.tsx",
  "policy-cloud-exceptions-summary.tsx",
  "policy-cloud-exception-detail-panel.tsx",
  "policy-cloud-exception-request-panel.tsx",
  "policy-strict-config-tab.tsx",
  "policy-workspace-helpers.ts",
];

for (const fileName of POLICY_RELEASE_FILES) {
  const filePath = join(here, fileName);
  assert(existsSync(filePath), `missing policy release file: ${fileName}`);
  const source = readFileSync(filePath, "utf8");
  assert(!/\bbypass\b/i.test(source), `${fileName} must not use bypass copy`);
}

const listSource = readFileSync(join(here, "policy-cloud-exceptions-list.tsx"), "utf8");
const detailSource = readFileSync(join(here, "policy-cloud-exception-detail-panel.tsx"), "utf8");
const tabSource = readFileSync(join(here, "policy-cloud-exceptions-tab.tsx"), "utf8");

assert(listSource.includes("min-w-0"), "exception list cards constrain width in grid layouts");
assert(detailSource.includes("break-words"), "exception detail panel guards long copy overflow");
assert(
  /(?:lg|xl):grid-cols-\[minmax\(0,1fr\)_/.test(tabSource),
  "cloud exceptions tab keeps responsive split layout",
);

console.log("policy-final-release-guard.test.ts: all assertions passed");
