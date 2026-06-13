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

export function isSupplyChainAuditIncomplete(detail: Record<string, unknown>): boolean {
  const auditStatus = readString(detail.audit_status);
  if (auditStatus === "incomplete") {
    return true;
  }
  const exitCode = typeof detail.exit_code === "number" ? detail.exit_code : null;
  if (exitCode !== null && exitCode !== 0) {
    return true;
  }
  return false;
}

export function resolveSupplyChainAuditFailure(detail: Record<string, unknown>): string | null {
  if (!isSupplyChainAuditIncomplete(detail)) {
    return null;
  }
  const outcome = readString(detail.audit_outcome);
  const message = readString(detail.message);
  const supplyChain = isRecord(detail.supply_chain) ? detail.supply_chain : null;
  const supplyStatus = readString(supplyChain?.status);
  if (outcome === "sync_required" || supplyStatus === "sync_required") {
    return (
      message ??
      "Guard supply-chain intel is not synced on this device. Run Sync, then audit again."
    );
  }
  if (outcome === "inventory_empty") {
    return (
      message ??
      "Guard found project files but could not index any packages for audit."
    );
  }
  if (outcome === "no_project_files") {
    return (
      message ??
      "No supported manifests or lockfiles were found in the audit workspace."
    );
  }
  if (message !== null) {
    return message;
  }
  return "Workspace audit did not complete. Review supply-chain status and try again.";
}
