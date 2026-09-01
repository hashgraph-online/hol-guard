type RepairState = {
  status: "working" | "success" | "error";
  message: string;
  failedHarnesses?: string[];
};

export function recoverySummary(
  failCount: number,
  unknownCount: number,
  needsConnectedApp: boolean,
  failedLabels: string[] = [],
): string {
  if (needsConnectedApp) {
    return "Connect an AI app to start local protection. Repair cannot finish until at least one app is connected.";
  }
  if (failCount === 0) {
    return "Complete the remaining local proof here. Guard repairs and rechecks every local protection layer in one pass.";
  }
  const namedFail = failedLabels[0]?.trim();
  const failedChecks =
    failCount === 1 && namedFail
      ? namedFail
      : `${failCount} failed check${failCount === 1 ? "" : "s"}`;
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  if (failCount === 1 && namedFail) {
    return `Repair ${failedChecks} here${remainingProofs}. Guard repairs and rechecks every local protection layer in one pass.`;
  }
  return `Repair the ${failedChecks} here${remainingProofs}. Guard repairs and rechecks every local protection layer in one pass.`;
}

export function repairButtonLabel(
  repairState: RepairState | null,
  needsConnectedApp: boolean,
): string {
  if (repairState?.status === "working") return "Repairing…";
  if (needsConnectedApp) return "Connect an app";
  if (repairState?.status === "error") return "Retry repair";
  return "Repair protection";
}
