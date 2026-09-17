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
  unsupportedCount = 0,
): string {
  const unsupportedNote = unsupportedCount > 0
    ? " Containment remains unavailable on this platform, so full protection cannot be reached here."
    : "";
  const protectionScope = unsupportedCount > 0 ? "supported" : "local";
  if (needsConnectedApp) {
    return `Connect an AI app to start local protection. Repair cannot finish until at least one app is connected.${unsupportedNote}`;
  }
  if (failCount === 0) {
    return `Complete the remaining ${protectionScope} proof here. Guard repairs and rechecks every ${unsupportedCount > 0 ? "repairable" : "local"} protection layer in one pass.${unsupportedNote}`;
  }
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  const namedFail = failedLabels[0]?.trim() ?? "";
  if (failCount === 1 && namedFail) {
    return `Repair ${namedFail} here${remainingProofs}. Guard repairs and rechecks every ${protectionScope} protection layer in one pass.${unsupportedNote}`;
  }
  const failedNoun = failCount === 1 ? "check" : "checks";
  return `Repair the ${failCount} failed ${failedNoun} here${remainingProofs}. Guard repairs and rechecks every ${protectionScope} protection layer in one pass.${unsupportedNote}`;
}

export function repairButtonLabel(
  repairState: RepairState | null,
  needsConnectedApp: boolean,
  hasUnsupportedGaps = false,
): string {
  if (repairState?.status === "working") return "Repairing…";
  if (needsConnectedApp) return "Connect an app";
  if (repairState?.status === "error") return "Retry repair";
  return hasUnsupportedGaps ? "Repair supported protection" : "Repair protection";
}
