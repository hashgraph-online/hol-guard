import type { GuardReceipt } from "../guard-types";
import { sortEvidence } from "./evidence-sort";
import { exportEvidenceCsv, exportEvidenceJson } from "./evidence-export";
import { filterEvidence } from "./evidence-filters";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function makeReceipt(id: string, overrides: Partial<GuardReceipt> = {}): GuardReceipt {
  return {
    receipt_id: id,
    harness: "cursor",
    artifact_id: `artifact-${id}`,
    artifact_hash: `hash-${id}`,
    policy_decision: "allow",
    capabilities_summary: "Summary",
    changed_capabilities: [],
    provenance_summary: "Provenance",
    user_override: null,
    artifact_name: `Tool ${id}`,
    source_scope: null,
    timestamp: new Date("2024-06-15T10:00:00.000Z").toISOString(),
    ...overrides,
  };
}

const appReceipts = [
  makeReceipt("r1", { artifact_name: "alpha", timestamp: "2024-06-15T12:00:00.000Z" }),
  makeReceipt("r2", { artifact_name: "beta", timestamp: "2024-06-15T08:00:00.000Z", policy_decision: "block" }),
  makeReceipt("r3", {
    harness: "codex",
    artifact_name: "other-app",
    timestamp: "2024-06-15T14:00:00.000Z",
  }),
];

const scoped = filterEvidence(appReceipts, {
  search: "",
  time: "all",
  decision: "all",
  harness: "cursor",
  category: "",
  sourceScope: "",
  day: "",
  sort: "newest",
  view: "apps",
  selectedId: "",
});

assert(scoped.length === 2, "app scope: only cursor receipts");

const byNewest = sortEvidence(scoped, "newest");
assert(byNewest[0]?.receipt_id === "r1", "app scope sort newest: r1 first");

const byOldest = sortEvidence(scoped, "oldest");
assert(byOldest[0]?.receipt_id === "r2", "app scope sort oldest: r2 first");

const blockedOnly = filterEvidence(appReceipts, {
  search: "",
  time: "all",
  decision: "block",
  harness: "cursor",
  category: "",
  sourceScope: "",
  day: "",
  sort: "newest",
  view: "apps",
  selectedId: "",
});

assert(blockedOnly.length === 1, "app scope decision filter: one blocked cursor receipt");

const csv = exportEvidenceCsv(blockedOnly, {
  harness: "cursor",
  decision: "block",
  category: "",
});
assert(csv.filename.includes("cursor"), "app export csv: harness in filename");
assert(csv.filename.includes("block"), "app export csv: decision in filename");

const csvText = await csv.blob.text();
assert(csvText.includes("beta"), "app export csv: includes filtered artifact");

const json = exportEvidenceJson(scoped, {
  harness: "cursor",
  decision: "all",
  category: "",
});
const parsed = JSON.parse(await json.blob.text()) as { total_rows: number; items: GuardReceipt[] };
assert(parsed.total_rows === 2, "app export json: exports scoped rows only");

console.log("scoped-evidence-table.test.ts: all passed");
