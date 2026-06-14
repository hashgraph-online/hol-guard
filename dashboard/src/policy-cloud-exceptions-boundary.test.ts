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
const dashboardSrc = here;

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

const POLICY_SOURCE_FILES = [
  "policy-workspace-page.tsx",
  "policy-workspace.tsx",
  "policy-workspace-views.tsx",
  "policy-workspace-helpers.ts",
  "policy-exception-form.tsx",
  "policy-remembered-local-rules.tsx",
  "policy-remembered-cloud-rules.tsx",
  "policy-remembered-rules-tab.tsx",
  "policy-remembered-rules-right-rail.tsx",
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
  "queue-state.ts",
];

const POLICY_SLICE_MARKERS = [
  "policy-cloud-exception",
  "PolicyCloudException",
  "policy-workspace",
];

// Phase 1 removes local exception authoring. Flip this flag in that PR.
const PHASE0_EXPECT_LOCAL_EXCEPTION_AUTHORING = false;

const primitivesSource = readDashboardSource("approval-center-primitives.tsx");
for (const label of EXPECTED_SIDEBAR_LABELS) {
  assert(primitivesSource.includes(`label: "${label}"`), `sidebar must include label: ${label}`);
}

const policyWorkspaceSource = readDashboardSource("policy-workspace.tsx");
if (PHASE0_EXPECT_LOCAL_EXCEPTION_AUTHORING) {
  assert(
    policyWorkspaceSource.includes('"Exceptions"'),
    "phase 0 baseline: exceptions tab still uses legacy label until Phase 1 rename",
  );
  assert(
    policyWorkspaceSource.includes("PolicyExceptionForm"),
    "phase 0 baseline: local PolicyExceptionForm still mounted until Phase 1 removal",
  );
} else {
  assert(
    policyWorkspaceSource.includes('"Cloud exceptions"'),
    "policy workspace must expose Cloud exceptions tab label after Phase 1",
  );
  assert(
    !policyWorkspaceSource.includes("PolicyExceptionForm"),
    "policy workspace must not mount local PolicyExceptionForm after Phase 1",
  );
}

const boundaryDoc = readFileSync(
  join(repoRoot, "docs", "guard", "policy-cloud-exceptions-boundary.md"),
  "utf8",
);
assert(
  boundaryDoc.includes("GuardExceptionScope") && boundaryDoc.includes("artifact"),
  "boundary doc must record Guard Cloud exception scope contract",
);

for (const file of POLICY_SOURCE_FILES) {
  const source = readDashboardSource(file);
  for (const pattern of FORBIDDEN_FIXTURE_PATTERNS) {
    assert(!pattern.test(source), `${file} must not contain fixture pattern ${pattern}`);
  }
}

for (const file of REVIEW_INBOX_DENYLIST) {
  const source = readDashboardSource(file);
  for (const marker of POLICY_SLICE_MARKERS) {
    assert(
      !source.includes(marker),
      `${file} must not import Policy slice modules (${marker})`,
    );
  }
}

const guardApiSource = readDashboardSource("guard-api.ts");
assert(guardApiSource.includes("fetchPolicies"), "guard-api must expose fetchPolicies");
assert(guardApiSource.includes("savePolicyDecision"), "guard-api must expose savePolicyDecision baseline");
assert(guardApiSource.includes("clearPolicy"), "guard-api must expose clearPolicy");
assert(guardApiSource.includes("/v1/policy"), "guard-api must call /v1/policy endpoints");
assert(guardApiSource.includes("fetchCloudExceptions"), "guard-api must expose fetchCloudExceptions");

assert(boundaryDoc.includes("Remembered rules"), "boundary doc must define Remembered rules");
assert(boundaryDoc.includes("Cloud exceptions"), "boundary doc must define Cloud exceptions");
assert(boundaryDoc.includes("Evidence"), "boundary doc must distinguish Evidence");

console.log("policy-cloud-exceptions-boundary.test.ts: all assertions passed");
