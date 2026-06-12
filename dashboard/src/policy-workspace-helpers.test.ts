import type { GuardPolicyDecision } from "./guard-types";
import {
  resolvePolicyDisplay,
  resolvePolicyEvidenceHref,
  resolvePolicyMatcherFamily,
  resolveWorkspaceLabel,
} from "./policy-workspace-helpers";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const basePolicy = (overrides: Partial<GuardPolicyDecision>): GuardPolicyDecision => ({
  harness: "opencode",
  scope: "workspace",
  artifact_id: "opencode:project:package-request:62de981049ed20f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
  workspace: "workspace:c188b6362f81cac126242642b9d7baaa7026c681d5c5ea9e4cc92df615049faf",
  publisher: null,
  action: "allow",
  reason: "approved in review",
  source: "local",
  updated_at: "2026-06-11T12:00:00.000Z",
  ...overrides,
});

const workspacePackageRule = basePolicy({});
const display = resolvePolicyDisplay(workspacePackageRule);

assert(
  !display.headline.includes("62de9810"),
  "POL-H1: headline must not expose artifact hash ids",
);
assert(
  !display.headline.includes("workspace:c188"),
  "POL-H2: headline must not expose workspace hash ids",
);
assert(
  display.headline.toLowerCase().includes("package install"),
  "POL-H3: workspace package rule headline names the action family",
);
assert(
  display.subtitle.includes("this project"),
  "POL-H4: workspace scope subtitle uses plain project language",
);

const familyHarnessRule = resolvePolicyDisplay(
  basePolicy({
    scope: "harness",
    artifact_id: "family:package-request",
    workspace: null,
    harness: "opencode",
  }),
);
assert(
  familyHarnessRule.headline.toLowerCase().includes("all package install"),
  "POL-H5: harness family rule explains breadth in plain language",
);

const meaningfulReason = resolvePolicyDisplay(
  basePolicy({
    reason: "Install locked portal dependencies in isolated worktree for Guard connect-flow validation.",
    scope: "artifact",
  }),
);
assert(
  meaningfulReason.headline.includes("Install locked portal dependencies"),
  "POL-H6: meaningful approval reason becomes the headline",
);

const runtimeRule = resolvePolicyDisplay(
  basePolicy({
    scope: "artifact",
    artifact_id: "opencode:runtime:global:chrome-devtools:navigate_page",
    reason: "approved in review",
  }),
);
assert(
  runtimeRule.headline.toLowerCase().includes("chrome devtools"),
  "POL-H7: runtime actions get readable tool labels",
);

assert(
  resolveWorkspaceLabel("workspace:c188b6362f81cac126242642b9d7baaa7026c681d5c5ea9e4cc92df615049faf") ===
    "this project",
  "POL-H8: workspace hash labels collapse to this project",
);

assert(
  resolvePolicyMatcherFamily(basePolicy({ artifact_id: "family:tool-action" })) === "tool-action",
  "POL-H9: family matcher ids parse correctly",
);

const evidenceHref = resolvePolicyEvidenceHref(
  basePolicy({
    artifact_hash: "sha256:62de981049ed20f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
  }),
);
assert(
  evidenceHref.includes("search=62de981049ed"),
  "POL-H10: evidence link uses short hash prefix search",
);
assert(!evidenceHref.includes("harness="), "POL-H11: evidence link does not over-filter by harness");

console.log("policy-workspace-helpers.test.ts: all assertions passed");
