import { GuardHarnessActionError } from "./guard-api";
import {
  isGuardHarnessActionError,
  isSupplyChainSyncConnectError,
  readHarnessActionErrorCode,
} from "./harness-action-errors";
import type { PackageFirewallStatusResponse } from "./guard-types";
import { isSupplyChainAuditIncomplete, resolveSupplyChainAuditFailure } from "./supply-chain-audit-result";
import {
  resolveSupplyChainAuditRecoveryGate,
  type SupplyChainAuditRecoveryGate,
} from "./supply-chain-audit-recovery";

export { isSupplyChainAuditIncomplete, resolveSupplyChainAuditFailure };

export const SUPPLY_CHAIN_AUDIT_CONNECT_ERROR_CODES = [
  "guard_cloud_connect_required",
  "guard_cloud_reconnect_required",
] as const;

export type SupplyChainAuditConnectErrorCode =
  (typeof SUPPLY_CHAIN_AUDIT_CONNECT_ERROR_CODES)[number];

export type SupplyChainAuditConnectGate = {
  mode: "connect" | "repair";
  headline: string;
  detail: string;
  resumeAfterConnect: boolean;
};

export function isSupplyChainAuditConnectError(error: unknown): error is GuardHarnessActionError {
  return isGuardHarnessActionError(error) && isSupplyChainSyncConnectError(error);
}

export function resolveSupplyChainSyncConnectRecoveryGate(
  error: unknown,
): SupplyChainAuditRecoveryGate | null {
  if (!isSupplyChainSyncConnectError(error)) {
    return null;
  }
  const code = readHarnessActionErrorCode(error);
  if (code === "guard_cloud_reconnect_required") {
    return resolveSupplyChainAuditRecoveryGate({
      audit_status: "incomplete",
      audit_outcome: "expired",
    });
  }
  return resolveSupplyChainAuditRecoveryGate({
    audit_status: "incomplete",
    audit_outcome: "not_connected",
  });
}

export function packageAuditNeedsCloudConnect(data: PackageFirewallStatusResponse): boolean {
  const auditAction = data.actions.audit;
  return auditAction === "connect_required" || auditAction === "reconnect_required";
}

function resolveAuditConnectMode(data: PackageFirewallStatusResponse): "connect" | "repair" {
  if (data.entitlement.reason === "guard_cloud_reconnect_required") {
    return "repair";
  }
  if (
    data.entitlement.reason === "guard_cloud_connect_required" &&
    (data.entitlement.tier !== "unknown" || data.package_shims.some((shim) => shim.installed))
  ) {
    return "repair";
  }
  return "connect";
}

export function resolveSupplyChainAuditConnectGate(
  data: PackageFirewallStatusResponse,
  options?: { resumeAfterConnect?: boolean },
): SupplyChainAuditConnectGate | null {
  if (!packageAuditNeedsCloudConnect(data) || data.connect_flow === null) {
    return null;
  }
  const mode = resolveAuditConnectMode(data);
  if (mode === "repair") {
    return {
      mode,
      headline: "Reconnect Guard Cloud to run the workspace audit",
      detail:
        "Guard needs a fresh Cloud sign-in on this machine before it can scan workspace packages and surface findings here.",
      resumeAfterConnect: options?.resumeAfterConnect ?? false,
    };
  }
  return {
    mode,
    headline: "Sign in to Guard Cloud before running the audit",
    detail:
      "Package audits run through Guard Cloud. Sign in once on this machine, then Guard can scan dependencies and list flagged packages.",
    resumeAfterConnect: options?.resumeAfterConnect ?? false,
  };
}

export function supplyChainAuditConnectUserMessage(error: unknown): string | null {
  if (!isSupplyChainAuditConnectError(error)) {
    return null;
  }
  const code = error.payload?.error;
  if (code === "guard_cloud_reconnect_required") {
    return "Reconnect HOL Guard Cloud, then run the workspace audit again.";
  }
  return "Sign in to HOL Guard Cloud on this machine, then run the workspace audit.";
}

export function isSupplyChainAuditWorkspaceRequiredError(error: unknown): boolean {
  return error instanceof GuardHarnessActionError && error.payload?.error === "workspace_dir_required";
}

export function isSupplyChainAuditWorkspaceInvalidError(error: unknown): boolean {
  return error instanceof GuardHarnessActionError && error.payload?.error === "workspace_dir_invalid";
}

export function supplyChainAuditUserMessage(error: unknown): string | null {
  if (error instanceof GuardHarnessActionError) {
    if (isSupplyChainAuditWorkspaceRequiredError(error)) {
      return "Choose a project folder with a package manifest or lockfile, then run the audit again.";
    }
    if (error.payload?.error === "folder_picker_busy") {
      return "A folder selection is already open. Use that dialog, or paste the project folder path.";
    }
    if (error.payload?.error === "folder_picker_unavailable") {
      return "Folder selection is unavailable right now. Paste the project folder path instead.";
    }
    if (isSupplyChainAuditWorkspaceInvalidError(error)) {
      return "Guard could not use that project folder. Choose an existing local folder and run the audit again.";
    }
    return supplyChainAuditConnectUserMessage(error);
  }
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return null;
}
