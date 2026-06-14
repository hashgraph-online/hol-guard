import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));

function readSource(relativePath: string): string {
  return readFileSync(join(here, relativePath), "utf8");
}

const POLICY_UI_FILES = [
  "policy-workspace.tsx",
  "policy-cloud-exceptions-tab.tsx",
  "policy-cloud-exceptions-list.tsx",
  "policy-cloud-exceptions-summary.tsx",
  "policy-cloud-exception-detail-panel.tsx",
  "policy-cloud-exception-request-panel.tsx",
  "policy-strict-config-tab.tsx",
];

const MOCKUP_FIXTURE_PATTERNS = [
  /\bLorem ipsum\b/i,
  /\bMock Exception\b/i,
  /\bSample Exception\b/i,
  /\bPlaceholder Owner\b/i,
  /\bDemo User\b/i,
  /\bfixture-row\b/i,
  /\bhardcodedCount\s*=\s*\d+/,
];

const HARDCODED_EXCEPTION_ROW_PATTERNS = [
  /\[\s*\{\s*id:\s*["']artifact:/,
  /const\s+(MOCK|FAKE|SAMPLE)_EXCEPTIONS\s*=/,
  /defaultExceptions\s*=\s*\[/,
];

const HARDCODED_METRIC_PATTERNS = [
  /activeCount=\{\d+\}/,
  /pendingCount=\{\d+\}/,
  /value=\{\d+\}.*(?:Active|Pending|Expiring)/,
  /sha256:[a-f0-9]{32,}/i,
  /2026-0[1-9]-[0-3]\dT[0-2]\d:/,
];

for (const file of POLICY_UI_FILES) {
  const source = readSource(file);
  for (const pattern of MOCKUP_FIXTURE_PATTERNS) {
    assert(!pattern.test(source), `${file} must not contain mockup fixture pattern ${pattern}`);
  }
  for (const pattern of HARDCODED_EXCEPTION_ROW_PATTERNS) {
    assert(!pattern.test(source), `${file} must not hardcode exception rows ${pattern}`);
  }
  for (const pattern of HARDCODED_METRIC_PATTERNS) {
    assert(!pattern.test(source), `${file} must not hardcode counts/dates/hashes ${pattern}`);
  }
}

const pageSource = readSource("policy-workspace-page.tsx");
const chromeSource = readSource("policy-page-chrome.tsx");
assert(chromeSource.includes('role="tablist"'), "policy tablist exposes tablist role");
assert(chromeSource.includes('role="tab"'), "policy tabs expose tab role");
assert(chromeSource.includes("tabIndex={selected ? 0 : -1}"), "policy tabs use roving tabindex");
assert(chromeSource.includes(".focus()"), "policy tablist moves focus on arrow keys");
assert(pageSource.includes("PolicyUnderlineTabBar"), "policy page mounts underline tab bar");

const listSource = readSource("policy-cloud-exceptions-list.tsx");
assert(listSource.includes('aria-label="Cloud exception groups"'), "grouped list exposes list label");
assert(listSource.includes("aria-pressed"), "exception cards expose selection state");

const detailSource = readSource("policy-cloud-exception-detail-panel.tsx");
assert(detailSource.includes('aria-label="Cloud exception details"'), "detail panel exposes label");

const requestSource = readSource("policy-cloud-exception-request-panel.tsx");
assert(requestSource.includes("Request cloud exception"), "request panel contains section title");
assert(requestSource.includes("aria-labelledby=\"cloud-exception-request-title\""), "request panel exposes labelled heading");

const tabSource = readSource("policy-cloud-exceptions-tab.tsx");
assert(tabSource.includes("PolicyCloudExceptionsListSkeleton"), "cloud exceptions tab preserves loading layout");
assert(
  tabSource.includes("Local remembered rules and strict config still apply"),
  "API error state preserves local protection message",
);

const summarySource = readSource("policy-cloud-exceptions-summary.tsx");
assert(summarySource.includes("SummarySkeleton"), "summary cards preserve skeleton layout while loading");

const strictSource = readSource("policy-strict-config-tab.tsx");
assert(strictSource.includes("aria-busy"), "strict config tab exposes loading busy state");

console.log("policy-ui-hardening.test.ts: all assertions passed");
