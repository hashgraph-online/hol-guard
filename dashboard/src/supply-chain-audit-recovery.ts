import { isSupplyChainAuditIncomplete } from "./supply-chain-audit-result";

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readString(value: unknown): string | null {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

export type SupplyChainAuditRecoveryAction = "sync" | "connect" | "retry_audit";

export type SupplyChainAuditRecoveryObstacle =
  | "sync_required"
  | "cloud_auth"
  | "inventory_empty"
  | "no_project_files"
  | "unknown";

export type SupplyChainAuditRecoveryGate = {
  obstacle: SupplyChainAuditRecoveryObstacle;
  headline: string;
  detail: string;
  steps: Array<{ title: string; body: string }>;
  primaryAction: SupplyChainAuditRecoveryAction;
  primaryLabel: string;
  autoRetryAuditAfterPrimary: boolean;
};

const SYNC_RECOVERY_STEPS = [
  {
    title: "Sync intel",
    body: "Guard downloads the latest signed supply-chain bundle on this device.",
  },
  {
    title: "Run audit",
    body: "Guard scans workspace manifests and lists flagged packages automatically.",
  },
] as const;

export function resolveSupplyChainAuditRecoveryGate(
  detail: unknown,
): SupplyChainAuditRecoveryGate | null {
  if (!isSupplyChainAuditIncomplete(detail)) {
    return null;
  }
  const outcome = readString(detail.audit_outcome);
  const message = readString(detail.message);
  const supplyChain = isRecord(detail.supply_chain) ? detail.supply_chain : null;
  const supplyStatus = readString(supplyChain?.status);

  if (outcome === "sync_required" || supplyStatus === "sync_required") {
    return {
      obstacle: "sync_required",
      headline: "Sync supply-chain intel before auditing",
      detail:
        message ??
        "Guard needs the latest signed package intelligence on this device. Sync once, then Guard reruns the workspace audit for you.",
      steps: [...SYNC_RECOVERY_STEPS],
      primaryAction: "sync",
      primaryLabel: "Sync supply-chain intel",
      autoRetryAuditAfterPrimary: true,
    };
  }

  if (
    outcome === "not_connected" ||
    outcome === "expired" ||
    outcome === "degraded" ||
    supplyStatus === "not_connected" ||
    supplyStatus === "expired" ||
    supplyStatus === "degraded"
  ) {
    return {
      obstacle: "cloud_auth",
      headline: "Reconnect Guard Cloud before auditing",
      detail:
        message ??
        "Guard Cloud sign-in is missing or stale on this machine. Reconnect once, then Guard can sync intel and rerun the audit.",
      steps: [
        {
          title: "Reconnect Cloud",
          body: "Approve Guard Cloud access in your browser on this device.",
        },
        {
          title: "Sync and audit",
          body: "Guard refreshes supply-chain intel, then reruns the workspace audit.",
        },
      ],
      primaryAction: "connect",
      primaryLabel: "Reconnect Guard Cloud",
      autoRetryAuditAfterPrimary: true,
    };
  }

  if (outcome === "inventory_empty") {
    return {
      obstacle: "inventory_empty",
      headline: "Refresh intel before auditing packages",
      detail:
        message ??
        "Guard found project files but could not index packages yet. Syncing intel often fixes stale inventory, then Guard reruns the audit.",
      steps: [...SYNC_RECOVERY_STEPS],
      primaryAction: "sync",
      primaryLabel: "Sync and retry audit",
      autoRetryAuditAfterPrimary: true,
    };
  }

  if (outcome === "no_project_files") {
    return {
      obstacle: "no_project_files",
      headline: "Add project manifests before auditing",
      detail:
        message ??
        "Guard could not find supported manifests or lockfiles in the audit workspace. Open the connected project folder, add package files, then try the audit again.",
      steps: [
        {
          title: "Open workspace",
          body: "Use the connected app project folder with package.json, lockfiles, or Python manifests.",
        },
        {
          title: "Run audit",
          body: "Guard indexes dependencies and surfaces flagged packages.",
        },
      ],
      primaryAction: "retry_audit",
      primaryLabel: "Run audit again",
      autoRetryAuditAfterPrimary: false,
    };
  }

  return {
    obstacle: "unknown",
    headline: "Finish setup before auditing",
    detail:
      message ??
      "The workspace audit did not complete. Sync supply-chain intel, then try the audit again.",
    steps: [...SYNC_RECOVERY_STEPS],
    primaryAction: "sync",
    primaryLabel: "Sync supply-chain intel",
    autoRetryAuditAfterPrimary: true,
  };
}
