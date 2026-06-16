import {
  isSupplyChainAuditIncomplete,
  resolveSupplyChainAuditFailure,
} from "./supply-chain-audit-result";
import { normalizeSupplyChainAuditSnapshot } from "./supply-chain-audit-normalize";

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

const incompletePayload = {
  generated_at: "2026-06-13T18:22:54.785483+00:00",
  mode: "audit",
  manifest_paths: [],
  lockfile_paths: ["package-lock.json"],
  audit_outcome: "sync_required",
  audit_status: "incomplete",
  message: "Sync Guard supply-chain intel on this device before auditing workspace packages.",
  supply_chain: {
    status: "sync_required",
    detail: "Run `hol-guard supply-chain sync` to fetch the latest signed bundle.",
  },
};

assert(
  isSupplyChainAuditIncomplete(incompletePayload),
  "incomplete audit payload is detected",
);
assert(
  resolveSupplyChainAuditFailure(incompletePayload)?.includes("Sync Guard supply-chain intel"),
  "sync_required audit returns actionable failure copy",
);
assert(
  normalizeSupplyChainAuditSnapshot(incompletePayload) === null,
  "incomplete audit does not hydrate a clean findings snapshot",
);

assert(
  isSupplyChainAuditIncomplete({
    exit_code: 2,
    evaluation: { decision: "block" },
  }) === false,
  "blocked completed audits with non-zero exit code stay complete",
);

console.log("supply-chain-audit-result.test.ts: all assertions passed");
