import {
  isSupplyChainAuditIncomplete,
  resolveSupplyChainAuditFailure,
} from "./supply-chain-audit-result";

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

export type PackageFirewallActionResultDetail = {
  emptyState: boolean;
  lines: string[];
  summary: string;
  tone: "success" | "warning" | "neutral";
};

function parseAuditActionResult(result: Record<string, unknown>): PackageFirewallActionResultDetail {
  if (isSupplyChainAuditIncomplete(result)) {
    const failureMessage = resolveSupplyChainAuditFailure(result);
    const manifestPaths = readStringArray(result.manifest_paths);
    const lockfilePaths = readStringArray(result.lockfile_paths);
    const lines: string[] = [];
    if (manifestPaths.length > 0) {
      lines.push(`Manifests found: ${manifestPaths.join(", ")}.`);
    }
    if (lockfilePaths.length > 0) {
      lines.push(`Lockfiles found: ${lockfilePaths.join(", ")}.`);
    }
    if (failureMessage !== null) {
      lines.push(failureMessage);
    }
    return {
      emptyState: false,
      lines,
      summary: "Workspace audit did not complete.",
      tone: "warning",
    };
  }

  const evaluation = isRecord(result.evaluation) ? result.evaluation : null;
  const decision = readString(evaluation?.decision) ?? readString(result.decision) ?? "monitor";
  const manifestPaths = readStringArray(result.manifest_paths);
  const lockfilePaths = readStringArray(result.lockfile_paths);
  const inventory = isRecord(result.inventory) ? result.inventory : null;
  const packageCount = typeof inventory?.packages === "number" ? inventory.packages : null;
  const lockfileWarnings = Array.isArray(result.lockfile_warnings)
    ? result.lockfile_warnings.filter(isRecord)
    : [];

  const lines: string[] = [];
  if (manifestPaths.length > 0) {
    lines.push(`Manifests scanned: ${manifestPaths.join(", ")}.`);
  }
  if (lockfilePaths.length > 0) {
    lines.push(`Lockfiles scanned: ${lockfilePaths.join(", ")}.`);
  }
  if (packageCount !== null) {
    lines.push(`${packageCount} dependency ${packageCount === 1 ? "entry" : "entries"} indexed.`);
  }
  for (const warning of lockfileWarnings.slice(0, 3)) {
    const message = readString(warning.message);
    if (message !== null) {
      lines.push(message);
    }
  }

  const emptyState = manifestPaths.length === 0 && lockfilePaths.length === 0;
  if (emptyState) {
    lines.push("No workspace manifests or lockfiles were found for this audit scope.");
  }

  return {
    emptyState,
    lines,
    summary: `Workspace audit completed with ${decision} decision.`,
    tone: decision === "block" || decision === "ask" ? "warning" : "success",
  };
}

function parseSyncActionResult(result: Record<string, unknown>): PackageFirewallActionResultDetail {
  const syncedAt =
    readString(result.synced_at) ??
    readString(result.generated_at) ??
    readString(result.updated_at);
  const receiptsStored = typeof result.receipts_stored === "number" ? result.receipts_stored : null;
  const bundleVersion = readString(result.bundle_version);
  const tier = readString(result.tier);

  const lines: string[] = [];
  if (syncedAt !== null) {
    lines.push(`Cloud sync marker: ${syncedAt}.`);
  }
  if (receiptsStored !== null) {
    lines.push(`${receiptsStored} receipt${receiptsStored === 1 ? "" : "s"} stored locally.`);
  }
  if (bundleVersion !== null) {
    lines.push(`Advisory bundle ${bundleVersion}${tier ? ` (${tier})` : ""} is now active.`);
  }

  return {
    emptyState: lines.length === 0,
    lines,
    summary: syncedAt
      ? "Cloud intel sync completed. Feed freshness should update on the next status refresh."
      : "Cloud intel sync completed.",
    tone: "success",
  };
}

function parseTestActionResult(result: Record<string, unknown>): PackageFirewallActionResultDetail {
  const interceptProved = result.intercept_proved === true;
  const testedManagers = readStringArray(result.tested_managers);
  const pathRepairRequired = readStringArray(result.path_repair_required);
  const managerResults = Array.isArray(result.manager_results)
    ? result.manager_results.filter(isRecord)
    : [];

  const lines: string[] = [];
  for (const entry of managerResults) {
    const manager = readString(entry.manager) ?? "manager";
    if (entry.intercept_ran === true) {
      lines.push(
        `${manager}: intercept probe ran${
          entry.evaluator_invoked === true ? " with evaluator proof" : ""
        }.`,
      );
      continue;
    }
    const skippedReason = readString(entry.skipped_reason);
    if (skippedReason !== null) {
      lines.push(`${manager}: skipped (${skippedReason.replaceAll("_", " ")}).`);
      continue;
    }
    lines.push(`${manager}: no intercept proof recorded.`);
  }

  if (pathRepairRequired.length > 0) {
    lines.push(`PATH repair still required for ${pathRepairRequired.join(", ")}.`);
  }

  if (lines.length === 0 && testedManagers.length > 0) {
    lines.push(`Tested ${testedManagers.join(", ")}.`);
  }
  if (lines.length === 0) {
    lines.push("Intercept test completed.");
  }

  return {
    emptyState: false,
    lines,
    summary: interceptProved
      ? "Intercept test proved Guard blocked the package manager call."
      : "Intercept test finished without full proof. Review manager details below.",
    tone: interceptProved ? "success" : "warning",
  };
}

export function parsePackageFirewallActionResult(
  op: string,
  body: unknown,
): PackageFirewallActionResultDetail | null {
  if (!isRecord(body)) {
    return null;
  }
  let result: Record<string, unknown>;
  if (isRecord(body.result)) {
    result = body.result;
  } else if (isRecord(body.result_detail)) {
    result = body.result_detail;
  } else {
    result = body;
  }
  if (!isRecord(result)) {
    return null;
  }

  if (op === "audit") {
    return parseAuditActionResult(result);
  }
  if (op === "sync") {
    return parseSyncActionResult(result);
  }
  if (op === "test") {
    return parseTestActionResult(result);
  }
  return null;
}

function readActionResultRecord(body: unknown): Record<string, unknown> | null {
  if (!isRecord(body)) {
    return null;
  }
  if (isRecord(body.result_detail)) {
    return body.result_detail;
  }
  if (isRecord(body.result)) {
    return body.result;
  }
  return body;
}

export type InterceptProofManagerResult = {
  manager: string;
  interceptRan: boolean;
  evaluatorInvoked: boolean;
  skippedReason: string | null;
  detail: string;
};

export type InterceptProofSnapshot = {
  interceptProved: boolean;
  testedManagers: string[];
  pathRepairRequired: string[];
  managerResults: InterceptProofManagerResult[];
  receiptId: string | null;
  timestamp: string | null;
  summary: string;
  tone: "success" | "warning";
};

function buildInterceptProofManagerResult(entry: Record<string, unknown>): InterceptProofManagerResult {
  const manager = readString(entry.manager) ?? "manager";
  const interceptRan = entry.intercept_ran === true;
  const evaluatorInvoked = entry.evaluator_invoked === true;
  const skippedReason = readString(entry.skipped_reason);
  let detail = `${manager}: no intercept proof recorded.`;
  if (interceptRan) {
    detail = evaluatorInvoked
      ? `${manager}: intercept probe ran with evaluator proof.`
      : `${manager}: intercept probe ran.`;
  } else if (skippedReason !== null) {
    detail = `${manager}: skipped (${skippedReason.replaceAll("_", " ")}).`;
  }
  return {
    manager,
    interceptRan,
    evaluatorInvoked,
    skippedReason,
    detail,
  };
}

export function parseInterceptProofSnapshot(body: unknown): InterceptProofSnapshot | null {
  const result = readActionResultRecord(body);
  if (result === null) {
    return null;
  }
  const managerResultsRaw = Array.isArray(result.manager_results)
    ? result.manager_results.filter(isRecord)
    : [];
  const testedManagers = readStringArray(result.tested_managers);
  const pathRepairRequired = readStringArray(result.path_repair_required);
  const interceptProved = result.intercept_proved === true;
  const managerResults = managerResultsRaw.map(buildInterceptProofManagerResult);
  const hasProofContext =
    managerResults.length > 0 || testedManagers.length > 0 || pathRepairRequired.length > 0;
  if (!hasProofContext && result.intercept_proved === undefined) {
    return null;
  }

  const receipt = isRecord(body) && isRecord(body.receipt) ? body.receipt : null;
  const receiptId = receipt !== null ? readString(receipt.id) : null;
  const timestamp = receipt !== null ? readString(receipt.timestamp) : null;
  const summary = interceptProved
    ? "Intercept test proved Guard blocked the package manager call."
    : "Intercept test finished without full proof. Review manager details below.";

  return {
    interceptProved,
    testedManagers,
    pathRepairRequired,
    managerResults,
    receiptId,
    timestamp,
    summary,
    tone: interceptProved ? "success" : "warning",
  };
}
