import type { GuardPolicyDecision } from "./guard-types";
import {
  resolvePolicyApprovalRecordLabel,
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

const enrichedPackageRule = basePolicy({
  remembered_command: "pnpm install",
  remembered_context: "Package install via pnpm",
  workspace_label: "hol-points-portal",
  source_receipt_id: "receipt-abc123",
  artifact_hash: "sha256:62de981049ed20f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
});

const enrichedDisplay = resolvePolicyDisplay(enrichedPackageRule);

assert(enrichedDisplay.headline === "pnpm install", "POL-H1: enriched command becomes headline");
assert(
  enrichedDisplay.subtitle.includes("Package install via pnpm"),
  "POL-H2: enriched context appears in subtitle",
);
assert(
  enrichedDisplay.rememberSentence.includes("hol-points-portal"),
  "POL-H3: remember sentence names project folder",
);
assert(
  enrichedDisplay.rememberSentence.includes("pnpm install"),
  "POL-H4: remember sentence repeats exact command",
);

const workspacePackageRule = basePolicy({});
const display = resolvePolicyDisplay(workspacePackageRule);

assert(!display.headline.includes("62de9810"), "POL-H5: headline must not expose artifact hash ids");
assert(display.headline.toLowerCase().includes("package install"), "POL-H6: fallback names action family");

const evidenceHref = resolvePolicyEvidenceHref(enrichedPackageRule);
assert(evidenceHref.includes("selected=receipt-abc123"), "POL-H7: evidence link selects source receipt");
assert(evidenceHref.includes("search=receipt-abc123"), "POL-H8: evidence link searches receipt id");

const hashOnlyHref = resolvePolicyEvidenceHref(
  basePolicy({
    artifact_hash: "sha256:62de981049ed20f850ae2bb52a9aaa2820c6d9be809592ec0c4b3d207b83f9b6",
  }),
);
assert(hashOnlyHref.includes("search=62de981049ed"), "POL-H9: hash fallback strips sha256 prefix");

assert(
  resolvePolicyApprovalRecordLabel(enrichedPackageRule) === "receipt-abc123.json",
  "POL-H10: approval record label uses receipt filename",
);

assert(
  resolveWorkspaceLabel("workspace:c188b6362f81cac126242642b9d7baaa7026c681d5c5ea9e4cc92df615049faf") ===
    "this project",
  "POL-H11: workspace hash labels collapse to this project",
);

assert(
  resolvePolicyMatcherFamily(basePolicy({ artifact_id: "family:tool-action" })) === "tool-action",
  "POL-H12: family matcher ids parse correctly",
);

console.log("policy-workspace-helpers.test.ts: all assertions passed");
