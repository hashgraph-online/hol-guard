import type { GuardReceipt } from "../guard-types";
import { exportEvidenceCsv, exportEvidenceJson } from "./evidence-export";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(`FAIL: ${message}`);
}

function makeReceipt(id: string, overrides: Partial<GuardReceipt> = {}): GuardReceipt {
  return {
    receipt_id: id,
    harness: "codex",
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

const receipts = [
  makeReceipt("r1", { policy_decision: "allow", artifact_name: "normal-tool" }),
  makeReceipt("r2", { policy_decision: "block", artifact_name: 'Special "quoted" tool' }),
  makeReceipt("r3", { policy_decision: "ask", artifact_name: "tool,with,commas" }),
];

// CSV tests
const csv = exportEvidenceCsv(receipts);
assert(csv.blob instanceof Blob, "csv: returns Blob");
assert(csv.blob.type.includes("csv"), "csv: blob type is CSV");
assert(csv.filename.startsWith("hol-guard-evidence"), "csv: filename prefix");
assert(csv.filename.endsWith(".csv"), "csv: filename extension");

const csvText = await csv.blob.text();
const csvLines = csvText.split("\n").filter((l) => l.trim().length > 0);
assert(csvLines.length >= 4, "csv: header + 3 data rows");
assert(csvLines[0].includes("timestamp"), "csv: header has timestamp");
assert(csvLines[0].includes("artifact_name"), "csv: header has artifact_name");
assert(csvLines[0].includes("policy_decision"), "csv: header has policy_decision");
assert(csvText.includes("allow"), "csv: contains allow decision");
assert(csvText.includes("block"), "csv: contains block decision");

const quotedLine = csvLines.find((l) => l.includes("quoted"));
assert(quotedLine !== undefined, "csv: quoted name is present");
assert(quotedLine!.includes('""'), "csv: double-quote escaping applied");

// CSV with filter suffix
const filteredCsv = exportEvidenceCsv(receipts, { decision: "block", harness: "codex" });
assert(filteredCsv.filename.includes("block"), "csv filtered: decision in filename");
assert(filteredCsv.filename.includes("codex"), "csv filtered: harness in filename");

// JSON tests
const json = exportEvidenceJson(receipts);
assert(json.blob instanceof Blob, "json: returns Blob");
assert(json.blob.type.includes("json"), "json: blob type is JSON");
assert(json.filename.startsWith("hol-guard-evidence"), "json: filename prefix");
assert(json.filename.endsWith(".json"), "json: filename extension");

const jsonText = await json.blob.text();
const parsed = JSON.parse(jsonText) as {
  exported_at: string;
  total_rows: number;
  items: GuardReceipt[];
};
assert(typeof parsed.exported_at === "string", "json: has exported_at");
assert(parsed.total_rows === 3, "json: total_rows is 3");
assert(Array.isArray(parsed.items), "json: has items array");
assert(parsed.items.length === 3, "json: 3 items in export");

// Empty export
const emptyCsv = exportEvidenceCsv([]);
const emptyCsvText = await emptyCsv.blob.text();
const emptyLines = emptyCsvText.split("\n").filter((l) => l.trim().length > 0);
assert(emptyLines.length === 1, "csv empty: only header row");

const emptyJson = exportEvidenceJson([]);
const emptyJsonText = await emptyJson.blob.text();
const emptyParsed = JSON.parse(emptyJsonText) as { total_rows: number };
assert(emptyParsed.total_rows === 0, "json empty: total_rows is 0");

// Special characters in CSV
const specialReceipts = [
  makeReceipt("sp1", { artifact_name: "tool\nwith\nnewlines" }),
];
const specialCsv = exportEvidenceCsv(specialReceipts);
const specialText = await specialCsv.blob.text();
assert(specialText.includes('"'), "csv special: newline escaped with quotes");

console.log("evidence-export.test.ts: all tests passed");
