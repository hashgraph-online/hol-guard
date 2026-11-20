import type { GuardHarnessAction, GuardHarnessActionResult, GuardHarnessSetupStep } from "../guard-types";

export function setupStepsFor(result: GuardHarnessActionResult | null, active: boolean): GuardHarnessSetupStep[] {
  if (!result) return [];
  if (Array.isArray(result.steps) && result.steps.length > 0) return result.steps;
  if (result.verification?.steps) return result.verification.steps;
  if (!active && result.contract?.setup_steps) return result.contract.setup_steps;
  if (active && result.contract?.verify_steps) return result.contract.verify_steps;
  return [];
}

export function setupNotesFor(result: GuardHarnessActionResult | null): string[] {
  const notes = result?.managed_install?.manifest?.["notes"];
  return Array.isArray(notes) ? notes.filter((note): note is string => typeof note === "string") : [];
}

export function setupActionLabel(action: GuardHarnessAction): string {
  if (action === "install") return "connect";
  if (action === "verify") return "test";
  if (action === "repair") return "repair";
  return "disconnect";
}

export function setupSuccessTitle(action: GuardHarnessAction, displayName: string): string {
  if (action === "install") return `${displayName} connected`;
  if (action === "verify") return `${displayName} test complete`;
  if (action === "repair") return `${displayName} repaired`;
  return `${displayName} disconnected`;
}
