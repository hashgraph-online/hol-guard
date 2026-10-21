import {
  GuardProtectionRepairError,
  repairApprovalCenter,
  repairProtectionCheck,
  runHarnessAction,
} from "./guard-api";
import type { GuardProtectionCheck, GuardRuntimeSnapshot } from "./guard-types";
import {
  hasRepairableProtectionGap,
  isUnsupportedPlatformCheck,
  protectionHealthFor,
  remainingProtectionRepairMessage,
  repairableProtectionGaps,
} from "./protection-health";
import { protectionReasonText } from "./protection-reason-copy";

export class ProtectionRepairFlowError extends Error {
  readonly failedHarnesses: string[];
  readonly signature: string;
  readonly checkReasons: Record<string, string>;

  constructor(
    message: string,
    failedHarnesses: string[],
    signature = "",
    checkReasons: Record<string, string> = {},
  ) {
    super(message);
    this.name = "ProtectionRepairFlowError";
    this.failedHarnesses = failedHarnesses;
    this.signature = signature;
    this.checkReasons = checkReasons;
  }
}

export function protectionGapSignature(checks: GuardProtectionCheck[]): string {
  return repairableProtectionGaps(checks)
    .map((check) => `${check.check_id}:${check.status}:${check.reason_code}`)
    .sort()
    .join("|");
}

export const RECHECK_UNAVAILABLE_SIGNATURE = "recheck_unavailable";

export type ProtectionRepairOutcomeTracker = {
  signature: string;
  count: number;
  healthSignature: string;
};

export function nextProtectionRepairOutcome(
  tracker: ProtectionRepairOutcomeTracker | null,
  signature: string,
  healthSignature = signature,
): ProtectionRepairOutcomeTracker {
  return tracker?.signature === signature
    ? { signature, count: tracker.count + 1, healthSignature }
    : { signature, count: 1, healthSignature };
}

export function repairOutcomeIsStalled(
  tracker: ProtectionRepairOutcomeTracker | null,
  currentSignature: string,
): boolean {
  return (
    tracker !== null &&
    tracker.count >= 2 &&
    tracker.healthSignature === currentSignature
  );
}

export function resetRepairOutcomeTracker(
  tracker: ProtectionRepairOutcomeTracker | null,
  currentSignature: string,
): ProtectionRepairOutcomeTracker | null {
  return tracker !== null && tracker.healthSignature !== currentSignature ? null : tracker;
}

function gapReasons(checks: GuardProtectionCheck[]): Record<string, string> {
  const reasons: Record<string, string> = {};
  for (const check of repairableProtectionGaps(checks)) {
    reasons[check.check_id] = check.reason_code;
  }
  return reasons;
}

export function activeFailedHarnesses(failedHarnesses: string[], repairHarnesses: string[]): string[] {
  const repairable = new Set(repairHarnesses);
  return Array.from(new Set(failedHarnesses)).filter((harness) => repairable.has(harness));
}

function protectionRepairUnfinishedDetail(checkReasons: Record<string, string>): string {
  const details = Object.entries(checkReasons)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([, reason]) => protectionReasonText(reason) ?? `Reason code: ${reason}`);
  return `Guard could not finish: ${details.join(" ")}`;
}

export function protectionRepairFinishMessage(checkReasons: Record<string, string>): string {
  return `Protection checks pass, but ${protectionRepairUnfinishedDetail(checkReasons)}`;
}

export async function runAutomaticProtectionRepair(input: {
  harnesses: string[];
  displayName: (harness: string) => string;
  refreshStateAfterAction: () => Promise<GuardRuntimeSnapshot | null>;
}): Promise<string> {
  const failures: string[] = [];
  const failedHarnesses = new Set<string>();
  let repairCheckReasons: Record<string, string> = {};
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
      repairCheckReasons = error.checkReasons;
    }
    failures.push(error instanceof Error ? error.message : "integrity protection");
  }
  const refreshedSnapshot = await input.refreshStateAfterAction();
  if (refreshedSnapshot === null) {
    const detail = failures.length > 0 ? ` Repair reported: ${failures.join(", ")}.` : "";
    throw new ProtectionRepairFlowError(
      `Guard could not recheck protection. Check again in a moment.${detail}`,
      [],
      RECHECK_UNAVAILABLE_SIGNATURE,
      repairCheckReasons,
    );
  }
  const remainingHealth = protectionHealthFor(refreshedSnapshot);
  if (remainingHealth.state === "protected") {
    if (Object.keys(repairCheckReasons).length > 0) {
      return protectionRepairFinishMessage(repairCheckReasons);
    }
    return "Automatic repairs completed. Guard rechecked every protection layer below.";
  }
  if (!hasRepairableProtectionGap(remainingHealth.checks)) {
    const hasUnsupportedGaps = remainingHealth.checks.some(isUnsupportedPlatformCheck);
    if (hasUnsupportedGaps) {
      const base = "Supported protection repairs completed. Containment remains unavailable on this platform; Guard remains fail-closed.";
      return Object.keys(repairCheckReasons).length > 0
        ? `${base} ${protectionRepairUnfinishedDetail(repairCheckReasons)}`
        : base;
    }
    if (Object.keys(repairCheckReasons).length > 0) {
      return protectionRepairFinishMessage(repairCheckReasons);
    }
    return "Automatic repairs completed. Guard rechecked every repairable protection layer below.";
  }
  const remaining = remainingProtectionRepairMessage(remainingHealth, input.displayName);
  throw new ProtectionRepairFlowError(
    remaining.message,
    [...failedHarnesses].filter((harness) => remaining.failedHookHarnesses.includes(harness)),
    protectionGapSignature(remainingHealth.checks),
    { ...repairCheckReasons, ...gapReasons(remainingHealth.checks) },
  );
}
