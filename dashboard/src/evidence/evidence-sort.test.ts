import type { GuardReceipt } from "../guard-types";
import { sortEvidence } from "./evidence-sort";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function makeReceipt(
  id: string,
  overrides: Partial<GuardReceipt> = {}
): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}`,
    policy_decision: "allow",
    capabilities_summary: "",
    changed_capabilities: [],
    provenance_summary: "",
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date(Date.now()).toISOString(),
    ...overrides,
  };
}

const r1 = makeReceipt("r1", {
  harness: "cursor",
  policy_decision: "allow",
  artifact_name: "Zebra Tool",
  timestamp: "2024-06-15T10:00:00.000Z",
});
const r2 = makeReceipt("r2", {
  harness: "claude",
  policy_decision: "block",
  artifact_name: "Alpha Tool",
  timestamp: "2024-06-14T08:00:00.000Z",
});
const r3 = makeReceipt("r3", {
  harness: "codex",
  policy_decision: "review",
  artifact_name: "beta-tool",
  timestamp: "2024-06-16T06:00:00.000Z",
});
const r4 = makeReceipt("r4", {
  harness: "codex",
  policy_decision: "allow",
  artifact_name: "beta-tool",
  timestamp: "2024-06-15T11:00:00.000Z",
  artifact_id: "artifact-r4-aaa",
  capabilities_summary: "reads .env",
});

const receipts = [r1, r2, r3, r4];

// newest
const newest = sortEvidence(receipts, "newest");
assert(newest[0].receipt_id === "r3", "newest: r3 is first (2024-06-16)");
assert(newest[1].receipt_id === "r4", "newest: r4 is second (2024-06-15T11)");
assert(newest[2].receipt_id === "r1", "newest: r1 is third (2024-06-15T10)");
assert(newest[3].receipt_id === "r2", "newest: r2 is last (2024-06-14)");

// oldest
const oldest = sortEvidence(receipts, "oldest");
assert(oldest[0].receipt_id === "r2", "oldest: r2 is first (2024-06-14)");
assert(oldest[3].receipt_id === "r3", "oldest: r3 is last (2024-06-16)");

// app (harness display name order: claude < codex < cursor)
const byApp = sortEvidence(receipts, "app");
assert(byApp[0].harness === "claude", "app: claude first");
assert(byApp[byApp.length - 1].harness === "cursor", "app: cursor last");

// decision (allow < review < block)
const byDecision = sortEvidence(receipts, "decision");
assert(byDecision[0].policy_decision === "allow", "decision: allow before block");
const decisions = byDecision.map((r) => r.policy_decision);
const firstBlock = decisions.indexOf("block");
const lastAllow = decisions.lastIndexOf("allow");
assert(lastAllow < firstBlock, "decision: all allows before blocks");

// artifact
const byArtifact = sortEvidence(receipts, "artifact");
assert(byArtifact[0].artifact_name?.toLowerCase() === "alpha tool", "artifact: alpha first");
assert(byArtifact[byArtifact.length - 1].artifact_name?.toLowerCase() === "zebra tool", "artifact: zebra last");

// stable tie-break by receipt_id
const tied1 = makeReceipt("a-receipt", { harness: "codex", timestamp: "2024-01-01T00:00:00.000Z" });
const tied2 = makeReceipt("b-receipt", { harness: "codex", timestamp: "2024-01-01T00:00:00.000Z" });
const tied3 = makeReceipt("c-receipt", { harness: "codex", timestamp: "2024-01-01T00:00:00.000Z" });
const tiedSorted = sortEvidence([tied3, tied1, tied2], "newest");
assert(tiedSorted[0].receipt_id === "a-receipt", "tie-break: a before b");
assert(tiedSorted[1].receipt_id === "b-receipt", "tie-break: b before c");
assert(tiedSorted[2].receipt_id === "c-receipt", "tie-break: c last");

// category sort
const byCategory = sortEvidence(receipts, "category");
assert(byCategory.length === receipts.length, "category: all items preserved");

// empty input
const empty = sortEvidence([], "newest");
assert(empty.length === 0, "empty: returns empty array");

// does not mutate original
const original = [r1, r2, r3];
const sorted = sortEvidence(original, "newest");
assert(sorted !== original, "immutability: returns new array");
assert(original[0].receipt_id === "r1", "immutability: original unchanged");

console.log("evidence-sort.test.ts: all tests passed");
