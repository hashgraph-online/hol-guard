import { shouldShowFirstRunGuide } from "./apps/app-detail-workspace";
import { buildClearPayload, clearLabelForScope } from "./clear-policy-payload";
import type { GuardPolicyDecision } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  shouldShowFirstRunGuide({ status: "unknown", totalActions: 0, inventoryCount: 0, pendingCount: 0 }),
  "inactive app with no data should show first-run guide"
);

assert(
  shouldShowFirstRunGuide({ status: "needs_setup", totalActions: 0, inventoryCount: 0, pendingCount: 0 }),
  "known inactive app with no data should show first-run guide"
);

assert(
  !shouldShowFirstRunGuide({ status: "active", totalActions: 0, inventoryCount: 0, pendingCount: 0 }),
  "active app should not show first-run guide"
);

assert(
  !shouldShowFirstRunGuide({ status: "observed", totalActions: 1, inventoryCount: 0, pendingCount: 0 }),
  "app with history should show activity overview instead of first-run guide"
);

assert(
  !shouldShowFirstRunGuide({ status: "unknown", totalActions: 0, inventoryCount: 0, pendingCount: 1 }),
  "app with pending review should prioritize review queue"
);

const grArtifactPolicy: GuardPolicyDecision = {
  harness: "codex",
  scope: "artifact",
  artifact_id: "npmjs:lodash",
  artifact_hash: "sha256-lodash",
  workspace: null,
  publisher: null,
  action: "allow",
  reason: "trusted dependency",
  updated_at: "2024-01-01T00:00:00Z",
};

const grWorkspacePolicy: GuardPolicyDecision = {
  harness: "codex",
  scope: "workspace",
  artifact_id: null,
  workspace: "/home/user/project",
  publisher: null,
  action: "allow",
  reason: null,
  updated_at: "2024-01-01T00:00:00Z",
};

const grHarnessPolicy: GuardPolicyDecision = {
  harness: "cursor",
  scope: "harness",
  artifact_id: null,
  workspace: null,
  publisher: null,
  action: "block",
  reason: "untrusted",
  updated_at: "2024-01-01T00:00:00Z",
};

const grGlobalPolicy: GuardPolicyDecision = {
  harness: "codex",
  scope: "global",
  artifact_id: null,
  workspace: null,
  publisher: null,
  action: "allow",
  reason: null,
  updated_at: "2024-01-01T00:00:00Z",
};

assert(
  buildClearPayload(grArtifactPolicy).scope === "artifact",
  "T-ADW-GR119-00: artifact policy payload includes artifact scope"
);
assert(
  buildClearPayload(grArtifactPolicy).artifact_id === "npmjs:lodash",
  "T-ADW-GR119-01: artifact policy payload includes artifact_id"
);
assert(
  buildClearPayload(grArtifactPolicy).artifact_hash === "sha256-lodash",
  "T-ADW-GR119-02: artifact policy payload includes artifact_hash"
);
assert(
  buildClearPayload(grArtifactPolicy).harness === "codex",
  "T-ADW-GR119-02b: artifact policy payload includes harness"
);
assert(
  buildClearPayload(grWorkspacePolicy).scope === "workspace",
  "T-ADW-GR119-02a: workspace policy payload includes workspace scope"
);
assert(
  buildClearPayload(grWorkspacePolicy).workspace === "/home/user/project",
  "T-ADW-GR119-03: workspace policy payload includes workspace path"
);
assert(
  buildClearPayload(grWorkspacePolicy).harness === "codex",
  "T-ADW-GR119-03b: workspace policy payload includes harness"
);
assert(
  buildClearPayload(grHarnessPolicy).scope === "harness",
  "T-ADW-GR119-03a: harness policy payload includes harness scope"
);
assert(
  buildClearPayload(grHarnessPolicy).harness === "cursor",
  "T-ADW-GR119-04: harness policy payload includes harness name"
);
assert(
  buildClearPayload(grGlobalPolicy).scope === "global",
  "T-ADW-GR119-04a: global policy payload includes global scope"
);
assert(
  buildClearPayload(grGlobalPolicy).all === true,
  "T-ADW-GR119-05: global policy payload sets all=true"
);
assert(
  clearLabelForScope("artifact") === "Clear exact decision",
  "T-ADW-GR119-06: artifact scope label is 'Clear exact decision'"
);
assert(
  clearLabelForScope("workspace") === "Clear project decision",
  "T-ADW-GR119-07: workspace scope label is 'Clear project decision'"
);
assert(
  clearLabelForScope("harness") === "Clear app decision",
  "T-ADW-GR119-08: harness scope label is 'Clear app decision'"
);
assert(
  clearLabelForScope("global") === "Clear global decision",
  "T-ADW-GR119-09: global scope label is 'Clear global decision'"
);
