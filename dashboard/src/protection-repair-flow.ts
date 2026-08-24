export class ProtectionRepairFlowError extends Error {
  readonly failedHarnesses: string[];

  constructor(message: string, failedHarnesses: string[]) {
    super(message);
    this.name = "ProtectionRepairFlowError";
    this.failedHarnesses = failedHarnesses;
  }
}

export function activeFailedHarnesses(failedHarnesses: string[], repairHarnesses: string[]): string[] {
  const repairable = new Set(repairHarnesses);
  return Array.from(new Set(failedHarnesses)).filter((harness) => repairable.has(harness));
}
