import type {
  SupplyChainRepairRemainingStep,
  SupplyChainRepairResult,
  SupplyChainRepairStepFailure,
} from "./supply-chain-repair-types";

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function stringValue(value: unknown): string | null {
  return typeof value === "string" && value.trim() ? value : null;
}

function remainingStep(candidate: Record<string, unknown>): SupplyChainRepairRemainingStep | null {
  const step = stringValue(candidate.step);
  const message = stringValue(candidate.message);
  const action = stringValue(candidate.action);
  if (step === "intelligence_sync" && action === "connect" && message !== null) {
    return { step, message, action };
  }
  return null;
}

function failedStep(candidate: Record<string, unknown>): SupplyChainRepairStepFailure | null {
  const step = stringValue(candidate.step);
  const message = stringValue(candidate.message);
  if (
    (step === "package_shims" || step === "runtime_activation" || step === "intelligence_sync") &&
    message !== null
  ) {
    return { step, message };
  }
  return null;
}

export function normalizeSupplyChainRepairResult(result: Record<string, unknown>): SupplyChainRepairResult {
  const failures: SupplyChainRepairStepFailure[] = [];
  if (Array.isArray(result.failed_steps)) {
    for (const candidate of result.failed_steps) {
      if (!isRecord(candidate)) continue;
      const parsed = failedStep(candidate);
      if (parsed !== null) failures.push(parsed);
    }
  }
  const remaining: SupplyChainRepairRemainingStep[] = [];
  if (Array.isArray(result.remaining_steps)) {
    for (const candidate of result.remaining_steps) {
      if (!isRecord(candidate)) continue;
      const parsed = remainingStep(candidate);
      if (parsed !== null) remaining.push(parsed);
    }
  }
  const completedSteps = Array.isArray(result.completed_steps)
    ? result.completed_steps.filter((value): value is string => typeof value === "string")
    : [];
  const requiredSteps = ["package_shims", "runtime_activation", "intelligence_sync"];
  const completedWithoutFailures =
    Array.isArray(result.failed_steps) &&
    result.failed_steps.length === 0 &&
    remaining.length === 0 &&
    requiredSteps.every((step) => completedSteps.includes(step));
  return {
    repaired: result.repaired === true || (!("repaired" in result) && completedWithoutFailures),
    completed_steps: completedSteps,
    failed_steps: failures,
    remaining_steps: remaining,
    message: stringValue(result.message) ?? "Supply-chain repair finished.",
  };
}
