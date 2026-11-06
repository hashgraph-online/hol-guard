import { filterReceiptItems } from "./receipts-workspace";
import type { GuardAction, GuardReceipt } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function makeReceipt(index: number, harness = "codex", decision: GuardAction = "allow"): GuardReceipt {
  return {
    receipt_id: `receipt-${index}`,
    harness,
    artifact_id: `artifact-${index}`,
    artifact_hash: `hash-${index}`,
    policy_decision: decision,
    capabilities_summary: `Summary for artifact ${index}`,
    changed_capabilities: [],
    provenance_summary: `Provenance ${index}`,
    user_override: null,
    artifact_name: `Tool ${index}`,
    source_scope: null,
    timestamp: new Date(Date.now() - index * 60000).toISOString()
  };
}

const receipts500: GuardReceipt[] = Array.from({ length: 500 }, (_, i) => {
  const harnesses = ["codex", "claude", "cursor", "copilot", "gemini"];
  const decisions: GuardAction[] = ["allow", "block", "review"];
  return makeReceipt(i, harnesses[i % harnesses.length], decisions[i % decisions.length]);
});

const all500 = filterReceiptItems(receipts500, "", "all", "all", "all");
assert(all500.length === 500, "T520: all 500 receipts should render without filter");

const codexOnly = filterReceiptItems(receipts500, "", "codex", "all", "all");
assert(codexOnly.length > 0, "T520: filtering by codex should return results");
assert(codexOnly.every((r) => r.harness === "codex"), "T520: codex filter should only return codex receipts");

const wildcardHarnessFilter = filterReceiptItems(receipts500, "", "*", "all", "all");
assert(wildcardHarnessFilter.length === 500, "T521: wildcard pseudo-harness filter is ignored instead of creating a star app");

const blockedOnly = filterReceiptItems(receipts500, "", "all", "block", "all");
assert(blockedOnly.length > 0, "T520: filtering by block decision should return results");
assert(blockedOnly.every((r) => r.policy_decision === "block"), "T520: decision filter should only return matching receipts");

const warningReceipt = makeReceipt(501, "codex", "warn");
const allowedWithWarnings = filterReceiptItems([...receipts500, warningReceipt], "", "all", "allow", "all");
assert(
  allowedWithWarnings.some((receipt) => receipt.policy_decision === "warn"),
  "P45: legacy receipt filter treats warning launches as allowed",
);

const searchResult = filterReceiptItems(receipts500, "Tool 42", "all", "all", "all");
assert(searchResult.length > 0, "T520: search by name should return results");

const noResults = filterReceiptItems(receipts500, "this-will-not-match-anything-xyz", "all", "all", "all");
assert(noResults.length === 0, "T520: unmatched search should return empty array");

const todayFilter = filterReceiptItems(receipts500, "", "all", "all", "today");
assert(todayFilter.length > 0, "T520: today filter on recent receipts should return results");

const last7Filter = filterReceiptItems(receipts500, "", "all", "all", "last7");
assert(last7Filter.length > 0, "T520: last7 filter on recent receipts should return results");

const emptyInput: GuardReceipt[] = [];
const emptyResult = filterReceiptItems(emptyInput, "", "all", "all", "all");
assert(emptyResult.length === 0, "T520: empty input should return empty array");
