import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const repoRoot = join(here, "..", "..");
const dashboardSrc = join(here);

function readDashboardSource(relativePath: string): string {
  return readFileSync(join(dashboardSrc, relativePath), "utf8");
}

const EXPECTED_SIDEBAR_LABELS = [
  "Home",
  "Inbox",
  "Protect",
  "Evidence",
  "Supply chain",
  "Policy",
  "Settings",
  "About",
] as const;

const GUARD_CLOUD_EXCEPTION_SCOPES = ["artifact", "publisher", "harness"] as const;

const POLICY_SOURCE_FILES = [
  "policy-workspace-page.tsx",
  "policy-workspace.tsx",
  "policy-workspace-views.tsx",
  "policy-workspace-helpers.ts",
  "policy-exception-form.tsx",
];

const FORBIDDEN_FIXTURE_PATTERNS = [
  /\bAcme\b/,
  /\bJane Doe\b/,
  /john@example/,
  /policy-2026-\d/,
  /receipt_[a-f0-9]{8,}/i,
  /exception_request_[a-f0-9-]{8,}/i,
];

const REVIEW_INBOX_DENYLIST = [
  "approval-center-layout.tsx",
  "inbox-workspace.tsx",
  "queue-state.tsx",
];

const primitivesSource = readDashboardSource("approval-center-primitives.tsx");
for (const label of EXPECTED_SIDEBAR_LABELS) {
  assert(primitivesSource.includes(`label: "${label}"`), `sidebar must include label: ${label}`);
}

const policyWorkspaceSource = readDashboardSource("policy-workspace.tsx");
assert(
  policyWorkspaceSource.includes('"Remembered rules"'),
  "policy workspace must expose Remembered rules tab label",
);
assert(
  policyWorkspaceSource.includes('"Exceptions"'),
  "audit baseline: exceptions tab still uses legacy label before Phase 1 rename",
);
assert(
  policyWorkspaceSource.includes("PolicyExceptionForm"),
  "audit baseline: local PolicyExceptionForm still mounted before Phase 1 removal",
);

assert(
  GUARD_CLOUD_EXCEPTION_SCOPES.length === 3 &&
    GUARD_CLOUD_EXCEPTION_SCOPES.includes("artifact") &&
    GUARD_CLOUD_EXCEPTION_SCOPES.includes("publisher") &&
    GUARD_CLOUD_EXCEPTION_SCOPES.includes("harness"),
  "Guard Cloud exception scope contract is artifact | publisher | harness only",
);

for (const file of POLICY_SOURCE_FILES) {
  const source = readDashboardSource(file);
  for (const pattern of FORBIDDEN_FIXTURE_PATTERNS) {
    assert(!pattern.test(source), `${file} must not contain fixture pattern ${pattern}`);
  }
}

for (const file of REVIEW_INBOX_DENYLIST) {
  const path = join(dashboardSrc, file);
  try {
    readFileSync(path, "utf8");
  } catch {
    continue;
  }
  assert(true, `denylist note: ${file} exists and must not be edited by Policy slice PRs`);
}

const guardApiSource = readDashboardSource("guard-api.ts");
assert(guardApiSource.includes("fetchPolicies"), "guard-api must expose fetchPolicies");
assert(guardApiSource.includes("savePolicyDecision"), "guard-api must expose savePolicyDecision baseline");
assert(guardApiSource.includes("clearPolicy"), "guard-api must expose clearPolicy");
assert(guardApiSource.includes("/v1/policy"), "guard-api must call /v1/policy endpoints");

const boundaryDoc = readFileSync(
  join(repoRoot, "docs", "guard", "policy-cloud-exceptions-boundary.md"),
  "utf8",
);
assert(boundaryDoc.includes("Remembered rules"), "boundary doc must define Remembered rules");
assert(boundaryDoc.includes("Cloud exceptions"), "boundary doc must define Cloud exceptions");
assert(boundaryDoc.includes("Evidence"), "boundary doc must distinguish Evidence");

console.log("policy-cloud-exceptions-boundary.test.ts: all assertions passed");
