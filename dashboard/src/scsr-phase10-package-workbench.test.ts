import {
  derivePackageWorkbenchFromReceipts,
  filterPackageWorkbenchFindings,
  normalizeSupplyChainAuditSnapshot,
  sortPackageWorkbenchFindings,
} from "./supply-chain-audit-normalize";
import type { GuardReceipt } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const auditPayload = {
  generated_at: "2026-06-09T12:00:00.000Z",
  source: "cloud",
  manifest_paths: ["package.json"],
  lockfile_paths: ["package-lock.json"],
  inventory: {
    total_packages: 3,
    direct_package_count: 2,
    transitive_package_count: 1,
    sbom_package_count: 1,
  },
  evaluation: {
    decision: "warn",
    packages: [
      {
        name: "left-pad",
        ecosystem: "npm",
        namespace: null,
        decision: "warn",
        reasons: [{ code: "outdated", message: "Outdated dependency", severity: "medium" }],
        status: "known",
      },
      {
        name: "minimist",
        ecosystem: "npm",
        namespace: null,
        decision: "block",
        reasons: [{ code: "known_malware", message: "Known malware CVE-2021-44906", severity: "critical" }],
        related_advisory_ids: ["GHSA-vh95-rmgr-6w4w"],
        status: "known",
      },
      {
        name: "chalk",
        ecosystem: "npm",
        namespace: null,
        decision: "monitor",
        reasons: [],
        status: "known",
      },
    ],
  },
};

const snapshot = normalizeSupplyChainAuditSnapshot(auditPayload, "receipt-audit-1");
assert(snapshot !== null, "SCSR166: audit payload normalizes into workbench snapshot");
assert(snapshot!.findings.length === 3, "SCSR167: all evaluated packages surface as findings");
assert(snapshot!.inventory.totalPackages === 3, "SCSR168: inventory totals normalize");

const sorted = sortPackageWorkbenchFindings(snapshot!.findings, "severity");
assert(sorted[0]?.packageName === "minimist", "SCSR169: severity sort prioritizes critical blockers");

const filtered = filterPackageWorkbenchFindings(snapshot!.findings, {
  ecosystem: "npm",
  decision: "block",
  severity: "all",
  search: "",
});
assert(filtered.length === 1 && filtered[0]?.packageName === "minimist", "SCSR170: decision filter works");

const minimist = snapshot!.findings.find((finding) => finding.packageName === "minimist");
assert(minimist !== undefined, "SCSR171: minimist finding exists");
assert(
  minimist!.advisoryAliases.some((alias) => alias.includes("CVE-2021-44906")),
  "SCSR172: CVE alias stub parses from reason text",
);
assert(
  minimist!.advisoryAliases.some((alias) => alias.startsWith("GHSA-")),
  "SCSR173: GHSA alias stub surfaces from advisory ids",
);

const camelCaseAliases = normalizeSupplyChainAuditSnapshot({
  generated_at: "2026-06-09T12:00:00.000Z",
  evaluation: {
    decision: "block",
    packages: [
      {
        name: "lodash",
        ecosystem: "npm",
        decision: "block",
        relatedAdvisoryIds: ["GHSA-xx99-yy88-zz77"],
        reasons: [{ code: "advisory", message: "Known issue", severity: "high", advisoryId: "CVE-2024-12345" }],
      },
    ],
  },
});
const lodashFinding = camelCaseAliases?.findings.find((finding) => finding.packageName === "lodash");
assert(lodashFinding !== undefined, "SCSR173-B: camelCase advisory ids normalize");
assert(
  lodashFinding!.advisoryAliases.includes("GHSA-xx99-yy88-zz77"),
  "SCSR173-B: relatedAdvisoryIds preserved",
);
assert(
  lodashFinding!.advisoryAliases.includes("CVE-2024-12345"),
  "SCSR173-B: reason advisoryId preserved",
);

const receipt: GuardReceipt = {
  receipt_id: "receipt-audit-1",
  harness: "package-firewall",
  artifact_id: "workspace-audit",
  artifact_hash: "hash",
  policy_decision: "block",
  capabilities_summary: "Workspace audit completed with warn decision across 3 packages.",
  changed_capabilities: [],
  provenance_summary: "",
  user_override: null,
  artifact_name: "Workspace supply-chain audit",
  source_scope: "/workspace",
  timestamp: "2026-06-09T12:00:00.000Z",
  scanner_evidence: [
    {
      operation: "audit",
      audit_decision: "warn",
      blocked_package_count: 1,
      manifest_paths: ["package.json"],
      lockfile_paths: ["package-lock.json"],
      total_packages: 3,
      package_findings: auditPayload.evaluation.packages,
    },
  ] as unknown as GuardReceipt["scanner_evidence"],
};

const derived = derivePackageWorkbenchFromReceipts([receipt]);
assert(derived !== null, "SCSR174: latest audit receipt hydrates workbench snapshot");
assert(derived!.findings.length === 3, "SCSR175: receipt package_findings hydrate findings table");

assert(
  normalizeSupplyChainAuditSnapshot({ generated_at: "2026-06-09T12:00:00.000Z" }) === null,
  "SCSR175-B: empty audit payload returns null snapshot",
);
assert(
  normalizeSupplyChainAuditSnapshot({
    generated_at: "2026-06-09T12:00:00.000Z",
    lockfile_paths: ["package-lock.json"],
    audit_status: "incomplete",
    exit_code: 1,
  }) === null,
  "SCSR175-C: incomplete lockfile-only audit does not masquerade as clean findings",
);

console.log("scsr-phase10-package-workbench.test.ts: all assertions passed");
