import type { GuardReceipt, GuardRuntimeSnapshot } from "./guard-types";

export type SupplyChainEvidenceRailKind = "block" | "audit" | "sync";

export type SupplyChainEvidenceRailItem = {
  kind: SupplyChainEvidenceRailKind;
  timestamp: string | null;
  title: string;
  detail: string;
  receiptId: string | null;
  harness: string | null;
  tone: "green" | "attention" | "slate";
};

export type SupplyChainEvidenceRailSnapshot = {
  block: SupplyChainEvidenceRailItem;
  audit: SupplyChainEvidenceRailItem;
  sync: SupplyChainEvidenceRailItem;
};

export type SupplyChainCloudDegradedState = {
  active: boolean;
  title: string;
  detail: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function readOperation(value: unknown): string | null {
  if (!isRecord(value) || typeof value.operation !== "string") {
    return null;
  }
  const trimmed = value.operation.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function receiptEvidenceOperations(receipt: GuardReceipt): string[] {
  const operations: string[] = [];
  for (const entry of receipt.scanner_evidence ?? []) {
    const operation = readOperation(entry);
    if (operation !== null) {
      operations.push(operation);
    }
  }
  return operations;
}

function isPackageBlockReceipt(receipt: GuardReceipt): boolean {
  if (receipt.policy_decision !== "block") {
    return false;
  }
  const operations = receiptEvidenceOperations(receipt);
  if (operations.includes("audit") || operations.includes("sync")) {
    return false;
  }
  if (receipt.harness === "package-firewall") {
    return true;
  }
  const artifactName = receipt.artifact_name?.toLowerCase() ?? "";
  const artifactId = receipt.artifact_id.toLowerCase();
  const summary = receipt.capabilities_summary.toLowerCase();
  return (
    artifactName.includes("package") ||
    artifactId.includes("package") ||
    summary.includes("install") ||
    summary.includes("package")
  );
}

function emptyRailItem(kind: SupplyChainEvidenceRailKind): SupplyChainEvidenceRailItem {
  const labels: Record<SupplyChainEvidenceRailKind, { title: string; detail: string }> = {
    block: {
      title: "No blocked installs yet",
      detail: "Guard will record the last prevented package install here.",
    },
    audit: {
      title: "No workspace audit yet",
      detail: "Run an audit to scan lockfiles and manifest paths on this machine.",
    },
    sync: {
      title: "No policy sync yet",
      detail: "Sync pulls the latest Guard supply-chain policy to this device.",
    },
  };
  return {
    kind,
    timestamp: null,
    title: labels[kind].title,
    detail: labels[kind].detail,
    receiptId: null,
    harness: null,
    tone: "slate",
  };
}

function blockRailItem(receipt: GuardReceipt): SupplyChainEvidenceRailItem {
  const label = receipt.artifact_name?.trim();
  return {
    kind: "block",
    timestamp: receipt.timestamp,
    title: label !== undefined && label.length > 0 ? `Blocked: ${label}` : "Blocked package install",
    detail:
      receipt.capabilities_summary.trim().length > 0
        ? receipt.capabilities_summary
        : "Guard blocked a package install before it completed.",
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: "attention",
  };
}

function auditRailItem(receipt: GuardReceipt): SupplyChainEvidenceRailItem {
  const evidence = (receipt.scanner_evidence ?? []).find(
    (entry) => readOperation(entry) === "audit",
  );
  const decision =
    isRecord(evidence) && typeof evidence.audit_decision === "string"
      ? evidence.audit_decision
      : receipt.policy_decision;
  const blockedCount =
    isRecord(evidence) && typeof evidence.blocked_package_count === "number"
      ? evidence.blocked_package_count
      : 0;
  const totalPackages =
    isRecord(evidence) && typeof evidence.total_packages === "number"
      ? evidence.total_packages
      : blockedCount;
  const detail =
    receipt.capabilities_summary.trim().length > 0
      ? receipt.capabilities_summary
      : `Workspace audit returned ${decision} across ${totalPackages} package(s).`;
  return {
    kind: "audit",
    timestamp: receipt.timestamp,
    title: blockedCount > 0 ? `Audit flagged ${blockedCount} package(s)` : "Workspace audit completed",
    detail,
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: blockedCount > 0 || decision === "block" ? "attention" : "green",
  };
}

function syncRailItem(receipt: GuardReceipt): SupplyChainEvidenceRailItem {
  return {
    kind: "sync",
    timestamp: receipt.timestamp,
    title: "Policy sync completed",
    detail:
      receipt.capabilities_summary.trim().length > 0
        ? receipt.capabilities_summary
        : "Guard refreshed local supply-chain policy from the connected source.",
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: "green",
  };
}

function latestReceiptMatching(
  receipts: GuardReceipt[],
  predicate: (receipt: GuardReceipt) => boolean,
): GuardReceipt | null {
  const matches = receipts
    .filter(predicate)
    .sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
  return matches[0] ?? null;
}

export function deriveSupplyChainEvidenceRail(
  receipts: GuardReceipt[],
): SupplyChainEvidenceRailSnapshot {
  const blockReceipt = latestReceiptMatching(receipts, isPackageBlockReceipt);
  const auditReceipt = latestReceiptMatching(receipts, (receipt) => {
    if (receipt.harness !== "package-firewall") {
      return false;
    }
    return receiptEvidenceOperations(receipt).includes("audit");
  });
  const syncReceipt = latestReceiptMatching(receipts, (receipt) => {
    if (receipt.harness !== "package-firewall") {
      return false;
    }
    return receiptEvidenceOperations(receipt).includes("sync");
  });

  return {
    block: blockReceipt !== null ? blockRailItem(blockReceipt) : emptyRailItem("block"),
    audit: auditReceipt !== null ? auditRailItem(auditReceipt) : emptyRailItem("audit"),
    sync: syncReceipt !== null ? syncRailItem(syncReceipt) : emptyRailItem("sync"),
  };
}

export function resolveSupplyChainCloudDegradedState(
  snapshot: GuardRuntimeSnapshot,
): SupplyChainCloudDegradedState {
  if (snapshot.cloud_state !== "local_only") {
    return {
      active: false,
      title: "",
      detail: "",
    };
  }
  return {
    active: true,
    title: "Guard Cloud unavailable on this device",
    detail:
      snapshot.cloud_state_detail.trim().length > 0
        ? snapshot.cloud_state_detail
        : "Local protection still runs, but live intel, fleet sync, and cross-device evidence stay offline until you connect Guard Cloud.",
  };
}

export function supplyChainEvidenceHref(
  receiptId: string | null,
  harness: string | null,
): string | null {
  if (receiptId === null) {
    return null;
  }
  const params = new URLSearchParams();
  if (harness !== null && harness.trim().length > 0) {
    params.set("harness", harness);
  }
  params.set("search", receiptId);
  return `/evidence?${params.toString()}`;
}
