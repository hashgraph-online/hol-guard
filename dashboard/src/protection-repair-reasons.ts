function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export const REASON_CODE_ID = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;

export function checkReasonMapValue(value: unknown): Record<string, string> {
  if (!isRecord(value)) return {};
  const reasons: Record<string, string> = {};
  for (const [checkId, reason] of Object.entries(value)) {
    if (!REASON_CODE_ID.test(checkId) || checkId.length > 96) continue;
    if (typeof reason !== "string" || reason.length > 96 || !REASON_CODE_ID.test(reason)) continue;
    reasons[checkId] = reason;
  }
  return reasons;
}
