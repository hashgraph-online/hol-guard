import type { PackageFirewallStatusResponse } from "./guard-types";
import type { SupplyChainRepairResult } from "./supply-chain-repair-types";

export type SupplyChainFixAllPhase =
  | "idle"
  | "checking"
  | "access_required"
  | "working"
  | "approval"
  | "connecting"
  | "success"
  | "incomplete"
  | "error";

export type SupplyChainFixAllRemainingAction = "connect" | "check_access";

export type SupplyChainFixAllState = {
  phase: SupplyChainFixAllPhase;
  message: string | null;
  completedSteps: string[];
  failedSteps: string[];
  remainingAction?: SupplyChainFixAllRemainingAction | null;
  remainingSteps?: string[];
};

export const IDLE_SUPPLY_CHAIN_FIX_ALL_STATE: SupplyChainFixAllState = {
  phase: "idle",
  message: null,
  completedSteps: [],
  failedSteps: [],
};

export function supplyChainFixAllWorkingState(): SupplyChainFixAllState {
  return {
    phase: "working",
    message: "Repairing package tools and turning on routing…",
    completedSteps: [],
    failedSteps: [],
  };
}

export function supplyChainFixAllNeedsCloudConnect(state: SupplyChainFixAllState): boolean {
  return state.remainingAction === "connect" && state.failedSteps.length === 0;
}

export function supplyChainFixAllStateFromRepair(result: SupplyChainRepairResult): SupplyChainFixAllState {
  const remainingAction = result.remaining_steps.some((step) => step.action === "check_access")
    ? "check_access"
    : result.remaining_steps.some((step) => step.action === "connect")
    ? "connect"
    : null;
  return {
    phase: result.repaired ? "success" : remainingAction === "check_access" ? "access_required" : "incomplete",
    message: result.message,
    completedSteps: result.completed_steps,
    failedSteps: result.failed_steps.map((failure) => failure.message),
    remainingAction,
    remainingSteps: result.remaining_steps.map((step) => step.message),
  };
}

export function supplyChainFixAllConnectState(
  phase: "connecting" | "error" | "incomplete",
  message: string,
  remainingSteps: string[] = [],
): SupplyChainFixAllState {
  return {
    phase,
    message,
    completedSteps: [],
    failedSteps: [],
    remainingAction: "connect",
    remainingSteps,
  };
}

export function supplyChainFixAllButtonLabel(
  phase: SupplyChainFixAllPhase,
  remainingAction: SupplyChainFixAllRemainingAction | null = null,
  failedCount = 0,
): string {
  if (phase === "checking") return "Checking access…";
  if (phase === "access_required") return "Check Cloud access";
  if (phase === "working") return "Fixing…";
  if (phase === "approval") return "Approval required";
  if (phase === "connecting") return "Connecting…";
  if (
    (phase === "incomplete" || phase === "error") &&
    remainingAction === "connect" &&
    failedCount === 0
  ) {
    return "Connect Guard Cloud";
  }
  if (phase === "incomplete" || phase === "error") return "Retry remaining";
  return "Restore protection";
}

export function supplyChainFixAllIsPending(phase: SupplyChainFixAllPhase): boolean {
  return phase === "checking" || phase === "working" || phase === "approval" || phase === "connecting";
}

export function supplyChainFixAllAccessState(
  message = "Package protection access could not be verified on this device. Check Cloud access to refresh your plan. Your local approval password cannot change Cloud access.",
): SupplyChainFixAllState {
  return {
    phase: "access_required",
    message,
    completedSteps: [],
    failedSteps: [],
    remainingAction: "check_access",
  };
}

export function supplyChainFixAllCanRepair(data: PackageFirewallStatusResponse): boolean {
  return data.entitlement.allowed
    || (data.protection?.installed_managers.length ?? 0) > 0
    || data.package_shims.some((entry) => entry.installed);
}

export function supplyChainFixAllRequiresConnection(data: PackageFirewallStatusResponse): boolean {
  if (data.entitlement.allowed) return false;
  if (data.entitlement.reason === "guard_cloud_reconnect_required") return true;
  if (data.entitlement.reason !== "guard_cloud_connect_required") return false;
  return !supplyChainFixAllCanRepair(data);
}
