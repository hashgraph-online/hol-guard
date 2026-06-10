import type {
  GuardReceipt,
  PackageWorkbenchFilters,
  PackageWorkbenchSortKey,
  SupplyChainAuditDecision,
  SupplyChainAuditFinding,
  SupplyChainAuditFindingReason,
  SupplyChainAuditInventory,
  SupplyChainAuditSeverity,
  SupplyChainAuditSnapshot,
} from "./guard-types";

const SEVERITY_RANK: Record<SupplyChainAuditSeverity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0,
};

const DECISION_RANK: Record<SupplyChainAuditDecision, number> = {
  block: 4,
  ask: 3,
  warn: 2,
  monitor: 1,
  allow: 0,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function readStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  return value
    .filter((entry): entry is string => typeof entry === "string" && entry.trim().length > 0)
    .map((entry) => entry.trim());
}

function normalizeSeverity(value: unknown): SupplyChainAuditSeverity {
  const raw = readString(value)?.toLowerCase();
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") {
    return raw;
  }
  return "unknown";
}

function normalizeDecision(value: unknown): SupplyChainAuditDecision {
  const raw = readString(value)?.toLowerCase();
  if (raw === "block" || raw === "ask" || raw === "warn" || raw === "monitor" || raw === "allow") {
    return raw;
  }
  return "monitor";
}

function normalizeInventory(record: Record<string, unknown> | null): SupplyChainAuditInventory {
  if (record === null) {
    return {
      totalPackages: 0,
      directPackageCount: 0,
      transitivePackageCount: 0,
      sbomPackageCount: 0,
    };
  }
  return {
    totalPackages: typeof record.total_packages === "number" ? record.total_packages : 0,
    directPackageCount:
      typeof record.direct_package_count === "number" ? record.direct_package_count : 0,
    transitivePackageCount:
      typeof record.transitive_package_count === "number" ? record.transitive_package_count : 0,
    sbomPackageCount: typeof record.sbom_package_count === "number" ? record.sbom_package_count : 0,
  };
}

function normalizeReasons(value: unknown): SupplyChainAuditFindingReason[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const reasons: SupplyChainAuditFindingReason[] = [];
  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }
    const message = readString(entry.message) ?? readString(entry.summary) ?? "Flagged by Guard supply-chain policy.";
    reasons.push({
      code: readString(entry.code) ?? "supply_chain",
      message,
      severity: normalizeSeverity(entry.severity),
    });
  }
  return reasons;
}

function resolveFindingSeverity(
  packageRecord: Record<string, unknown>,
  reasons: SupplyChainAuditFindingReason[],
): SupplyChainAuditSeverity {
  const normalized = normalizeSeverity(packageRecord.normalized_severity);
  if (normalized !== "unknown") {
    return normalized;
  }
  let highest: SupplyChainAuditSeverity = "unknown";
  for (const reason of reasons) {
    if (SEVERITY_RANK[reason.severity] > SEVERITY_RANK[highest]) {
      highest = reason.severity;
    }
  }
  if (highest !== "unknown") {
    return highest;
  }
  const decision = normalizeDecision(packageRecord.decision);
  if (decision === "block") {
    return "high";
  }
  if (decision === "ask") {
    return "medium";
  }
  if (decision === "warn") {
    return "medium";
  }
  return "low";
}

function buildAdvisoryAliasStubs(
  packageRecord: Record<string, unknown>,
  reasons: SupplyChainAuditFindingReason[],
): string[] {
  const aliases = new Set<string>();
  const advisoryIds = packageRecord.related_advisory_ids;
  if (Array.isArray(advisoryIds)) {
    for (const entry of advisoryIds) {
      if (typeof entry !== "string" || entry.trim().length === 0) {
        continue;
      }
      const trimmed = entry.trim();
      if (trimmed.startsWith("GHSA-") || trimmed.startsWith("CVE-")) {
        aliases.add(trimmed);
        continue;
      }
      aliases.add(`GHSA-${trimmed.slice(0, 8).toLowerCase()}`);
    }
  }
  for (const reason of reasons) {
    const match = reason.message.match(/\b(CVE-\d{4}-\d+)\b/i);
    if (match !== null) {
      aliases.add(match[1].toUpperCase());
    }
    const ghsaMatch = reason.message.match(/\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b/i);
    if (ghsaMatch !== null) {
      aliases.add(ghsaMatch[1].toUpperCase());
    }
  }
  if (aliases.size === 0) {
    const severity = resolveFindingSeverity(packageRecord, reasons);
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.medium) {
      aliases.add("GHSA-alias-pending");
      aliases.add("CVE-alias-pending");
    }
  }
  return Array.from(aliases);
}

function normalizePackageFinding(
  packageRecord: Record<string, unknown>,
  index: number,
): SupplyChainAuditFinding | null {
  const packageName = readString(packageRecord.name);
  if (packageName === null) {
    return null;
  }
  const ecosystem = readString(packageRecord.ecosystem) ?? "unknown";
  const namespace = readString(packageRecord.namespace);
  const reasons = normalizeReasons(packageRecord.reasons);
  const decision = normalizeDecision(packageRecord.decision);
  const severity = resolveFindingSeverity(packageRecord, reasons);
  const slug = `${ecosystem}:${namespace ? `${namespace}/` : ""}${packageName}`;
  return {
    id: `${slug}:${index}`,
    packageName,
    ecosystem,
    namespace,
    decision,
    severity,
    reasons,
    advisoryAliases: buildAdvisoryAliasStubs(packageRecord, reasons),
    status: readString(packageRecord.status),
  };
}

function normalizePackageFindings(value: unknown): SupplyChainAuditFinding[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const findings: SupplyChainAuditFinding[] = [];
  let index = 0;
  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }
    const finding = normalizePackageFinding(entry, index);
    index += 1;
    if (finding !== null) {
      findings.push(finding);
    }
  }
  return findings;
}

function packageRecordsFromEvaluation(evaluation: Record<string, unknown> | null): SupplyChainAuditFinding[] {
  if (evaluation === null) {
    return [];
  }
  const fromPackages = normalizePackageFindings(evaluation.packages);
  if (fromPackages.length > 0) {
    return fromPackages;
  }
  return normalizePackageFindings(evaluation.package_findings);
}

function isAuditEvidence(value: unknown): value is Record<string, unknown> & { operation: "audit" } {
  return isRecord(value) && value.operation === "audit";
}

export function normalizeSupplyChainAuditSnapshot(
  raw: unknown,
  receiptId: string | null = null,
): SupplyChainAuditSnapshot | null {
  if (!isRecord(raw)) {
    return null;
  }
  const evaluation = isRecord(raw.evaluation) ? raw.evaluation : null;
  const findingsFromEvidence = normalizePackageFindings(raw.package_findings);
  const findings =
    findingsFromEvidence.length > 0 ? findingsFromEvidence : packageRecordsFromEvaluation(evaluation);
  const generatedAt =
    readString(raw.generated_at) ?? readString(raw.generatedAt) ?? new Date(0).toISOString();
  const inventory = normalizeInventory(isRecord(raw.inventory) ? raw.inventory : null);
  const decision = normalizeDecision(evaluation?.decision ?? raw.audit_decision);
  const manifestPaths = readStringArray(raw.manifest_paths);
  const lockfilePaths = readStringArray(raw.lockfile_paths);
  const hasAuditContext =
    findings.length > 0 ||
    inventory.totalPackages > 0 ||
    manifestPaths.length > 0 ||
    lockfilePaths.length > 0 ||
    evaluation !== null;
  if (!hasAuditContext) {
    return null;
  }
  return {
    generatedAt,
    source: readString(raw.source),
    decision,
    inventory,
    findings,
    manifestPaths,
    lockfilePaths,
    receiptId,
  };
}

export function derivePackageWorkbenchFromReceipts(receipts: GuardReceipt[]): SupplyChainAuditSnapshot | null {
  const auditReceipts = receipts
    .filter((receipt) => receipt.harness === "package-firewall")
    .filter((receipt) =>
      (receipt.scanner_evidence ?? []).some((entry) => isAuditEvidence(entry as unknown)),
    )
    .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
  for (const receipt of auditReceipts) {
    const evidenceRaw = (receipt.scanner_evidence ?? []).find((entry) => isAuditEvidence(entry as unknown));
    if (evidenceRaw === undefined || !isRecord(evidenceRaw)) {
      continue;
    }
    const snapshot = normalizeSupplyChainAuditSnapshot(
      {
        generated_at: receipt.timestamp,
        evaluation: {
          decision: evidenceRaw.audit_decision,
          packages: evidenceRaw.package_findings,
        },
        inventory: {
          total_packages: evidenceRaw.total_packages,
        },
        manifest_paths: evidenceRaw.manifest_paths,
        lockfile_paths: evidenceRaw.lockfile_paths,
      },
      receipt.receipt_id,
    );
    if (snapshot !== null) {
      return snapshot;
    }
  }
  return null;
}

export function sortPackageWorkbenchFindings(
  findings: SupplyChainAuditFinding[],
  sortKey: PackageWorkbenchSortKey,
): SupplyChainAuditFinding[] {
  const sorted = [...findings];
  sorted.sort((left, right) => {
    if (sortKey === "severity") {
      const severityDelta = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
      if (severityDelta !== 0) {
        return severityDelta;
      }
      return left.packageName.localeCompare(right.packageName);
    }
    if (sortKey === "ecosystem") {
      const ecosystemDelta = left.ecosystem.localeCompare(right.ecosystem);
      if (ecosystemDelta !== 0) {
        return ecosystemDelta;
      }
      return left.packageName.localeCompare(right.packageName);
    }
    if (sortKey === "decision") {
      const decisionDelta = DECISION_RANK[right.decision] - DECISION_RANK[left.decision];
      if (decisionDelta !== 0) {
        return decisionDelta;
      }
      return left.packageName.localeCompare(right.packageName);
    }
    return left.packageName.localeCompare(right.packageName);
  });
  return sorted;
}

export function filterPackageWorkbenchFindings(
  findings: SupplyChainAuditFinding[],
  filters: PackageWorkbenchFilters,
): SupplyChainAuditFinding[] {
  const query = filters.search.trim().toLowerCase();
  return findings.filter((finding) => {
    if (filters.ecosystem !== "all" && finding.ecosystem !== filters.ecosystem) {
      return false;
    }
    if (filters.decision !== "all" && finding.decision !== filters.decision) {
      return false;
    }
    if (filters.severity !== "all" && finding.severity !== filters.severity) {
      return false;
    }
    if (query.length === 0) {
      return true;
    }
    const haystack = [
      finding.packageName,
      finding.ecosystem,
      finding.namespace ?? "",
      finding.decision,
      finding.severity,
      ...finding.reasons.map((reason) => `${reason.code} ${reason.message}`),
      ...finding.advisoryAliases,
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(query);
  });
}

export function packageWorkbenchEcosystems(findings: SupplyChainAuditFinding[]): string[] {
  return Array.from(new Set(findings.map((finding) => finding.ecosystem))).sort();
}
