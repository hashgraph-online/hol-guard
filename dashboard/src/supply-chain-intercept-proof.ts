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

function readResultRecord(body: unknown): Record<string, unknown> | null {
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

function formatSkippedReason(raw: string): string {
  return raw.replaceAll("_", " ");
}

function buildManagerResultDetail(entry: Record<string, unknown>): InterceptProofManagerResult {
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
    detail = `${manager}: skipped (${formatSkippedReason(skippedReason)}).`;
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
  const result = readResultRecord(body);
  if (result === null) {
    return null;
  }
  const managerResultsRaw = Array.isArray(result.manager_results)
    ? result.manager_results.filter(isRecord)
    : [];
  const testedManagers = readStringArray(result.tested_managers);
  const pathRepairRequired = readStringArray(result.path_repair_required);
  const interceptProved = result.intercept_proved === true;
  const managerResults = managerResultsRaw.map(buildManagerResultDetail);
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
