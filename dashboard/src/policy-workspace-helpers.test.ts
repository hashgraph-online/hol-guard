import {
  isCloudManagedPolicy,
  resolvePolicyEvidenceHref,
  resolvePolicyEvidenceSearchTerm,
  resolvePolicyRuleSummary,
} from "./policy-workspace-helpers";
import type { GuardPolicyDecision } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const packagePolicy: GuardPolicyDecision = {
  harness: "kimi",
  scope: "artifact",
  artifact_id: "kimi:project:package-request:c5b1cf6bd0f60a3ce1f594dca9dd0cb627680046782128fb8ad0544795adc235",
  artifact_hash: "sha256:c5b1cf6bd0f6",
  workspace: "/workspace/project",
  publisher: null,
  action: "allow",
  reason: "Approved once for package install review",
  source: "manual",
  updated_at: new Date().toISOString(),
};

assert(
  resolvePolicyEvidenceSearchTerm(packagePolicy) === "c5b1cf6bd0f6",
  "POL001: evidence search prefers artifact hash prefix over full artifact id",
);

const evidenceHref = resolvePolicyEvidenceHref(packagePolicy);
assert(
  evidenceHref === "/evidence?search=c5b1cf6bd0f6",
  "POL002: evidence link avoids harness filter that hides matching receipts",
);
assert(
  !evidenceHref.includes("harness="),
  "POL003: artifact-specific evidence links do not set harness filter",
);

const familyPolicy: GuardPolicyDecision = {
  ...packagePolicy,
  artifact_id: "family:global_tools",
  artifact_hash: null,
};
assert(
  resolvePolicyEvidenceSearchTerm(familyPolicy) === "global_tools",
  "POL004: family-scoped policies search by family key",
);

assert(isCloudManagedPolicy("cloud-sync"), "POL005: cloud-sync policies are cloud managed");
assert(isCloudManagedPolicy("team-policy"), "POL006: team-policy policies are cloud managed");
assert(!isCloudManagedPolicy("manual"), "POL007: manual policies stay local");

const summary = resolvePolicyRuleSummary(packagePolicy, {
  appName: "Kimi",
  scopeLabel: "This retry only",
  actionLabel: "Allowed",
});
assert(summary.includes("Allowed"), "POL008: rule summary includes action label");
assert(summary.includes("Kimi"), "POL009: rule summary includes app name");
assert(summary.includes("Approved once for package install review"), "POL010: rule summary includes reason");

const globalPolicy: GuardPolicyDecision = {
  ...packagePolicy,
  scope: "global",
  artifact_id: null,
  reason: "Always allow npm installs",
};
const globalSummary = resolvePolicyRuleSummary(globalPolicy, {
  appName: "Kimi",
  scopeLabel: "Everywhere",
  actionLabel: "Allowed",
});
assert(globalSummary.includes("Reason: Always allow npm installs"), "POL011: global scope summary includes reason");

console.log("policy-workspace-helpers.test.ts: all assertions passed");
