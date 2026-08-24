export class ProtectionRepairFlowError extends Error {
  readonly failedHarnesses: string[];

  constructor(message: string, failedHarnesses: string[]) {
    super(message);
    this.name = "ProtectionRepairFlowError";
    this.failedHarnesses = failedHarnesses;
  }
}
