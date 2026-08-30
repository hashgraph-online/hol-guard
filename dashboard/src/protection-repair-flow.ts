import {
  GuardProtectionRepairError,
  repairApprovalCenter,
  repairProtectionCheck,
  runHarnessAction,
} from "./guard-api";
import type { GuardRuntimeSnapshot } from "./guard-types";
import { protectionHealthFor, remainingProtectionRepairMessage } from "./protection-health";

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

export async function runAutomaticProtectionRepair(input: {
  harnesses: string[];
  displayName: (harness: string) => string;
  refreshStateAfterAction: () => Promise<GuardRuntimeSnapshot | null>;
}): Promise<string> {
  const failures: string[] = [];
  const failedHarnesses = new Set<string>();
  try {
    await repairApprovalCenter();
  } catch {
    failures.push("local runtime");
  }
  for (const harness of input.harnesses) {
    try {
      await runHarnessAction({ harness, action: "repair", dryRun: false });
    } catch (error: unknown) {
      failedHarnesses.add(harness);
      failures.push(
        error instanceof Error && error.message.trim()
          ? error.message
          : `${input.displayName(harness)} hooks`,
      );
    }
  }
  try {
    await repairProtectionCheck("all");
  } catch (error: unknown) {
    if (error instanceof GuardProtectionRepairError) {
      for (const harness of error.failedHarnesses) failedHarnesses.add(harness);
    }
    failures.push(error instanceof Error ? error.message : "integrity protection");
  }
  const refreshedSnapshot = await input.refreshStateAfterAction();
  if (refreshedSnapshot === null) {
    const detail = failures.length > 0 ? ` Repair reported: ${failures.join(", ")}.` : "";
    throw new ProtectionRepairFlowError(
      `Guard could not recheck protection. Check again in a moment.${detail}`,
      [],
    );
  }
  const remainingHealth = protectionHealthFor(refreshedSnapshot);
  if (remainingHealth.state === "protected") {
    return "Automatic repairs completed. Guard rechecked every protection layer below.";
  }
  const remaining = remainingProtectionRepairMessage(remainingHealth, input.displayName);
  throw new ProtectionRepairFlowError(
    remaining.message,
    [...failedHarnesses].filter((harness) => remaining.failedHookHarnesses.includes(harness)),
  );
}
