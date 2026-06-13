import {
  isSupplyChainAuditIncomplete,
  resolveSupplyChainAuditFailure,
} from "./supply-chain-audit-result";
import { normalizeSupplyChainAuditSnapshot } from "./supply-chain-audit-normalize";
import { parsePackageFirewallActionResult } from "./supply-chain-firewall-action-result";

function assert(condition: boolean, message: string): void {
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
  exit_code: 1,
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

const parsed = parsePackageFirewallActionResult("audit", { result: incompletePayload });
assert(parsed?.tone === "warning", "incomplete audit action result uses warning tone");
assert(
  parsed?.summary === "Workspace audit did not complete.",
  "incomplete audit action result summary is explicit",
);

console.log("supply-chain-audit-result.test.ts: all assertions passed");
