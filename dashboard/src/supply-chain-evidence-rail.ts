import type {
  GuardReceipt,
  GuardRuntimeSnapshot,
} from "./guard-types";
import { isSupplyChainScannerEvidence } from "./guard-types";
import { guardActionPresentation, isBlockedGuardAction } from "./guard-action";

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

function readOperation(value: NonNullable<GuardReceipt["scanner_evidence"]>[number]): string | null {
  if (!isSupplyChainScannerEvidence(value)) {
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
  if (!isBlockedGuardAction(receipt.policy_decision)) {
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
    (entry): entry is GuardSupplyChainScannerEvidence => readOperation(entry) === "audit",
  );
  const auditStatus =
    evidence !== undefined && typeof evidence.audit_status === "string"
      ? evidence.audit_status
      : null;
  if (auditStatus === "incomplete") {
    return {
      kind: "audit",
      timestamp: receipt.timestamp,
      title: "Workspace audit did not complete",
      detail:
        receipt.capabilities_summary.trim().length > 0
          ? receipt.capabilities_summary
          : "Guard could not index workspace packages for audit.",
      receiptId: receipt.receipt_id,
      harness: receipt.harness,
      tone: "attention",
    };
  }
  const action = guardActionPresentation(receipt.policy_decision);
  const blockedCount =
    evidence !== undefined && typeof evidence.blocked_package_count === "number"
      ? evidence.blocked_package_count
      : 0;
  const totalPackages =
    evidence !== undefined && typeof evidence.total_packages === "number"
      ? evidence.total_packages
      : blockedCount;
  const detail =
    receipt.capabilities_summary.trim().length > 0
      ? receipt.capabilities_summary
      : `Workspace audit returned ${action.copy} across ${totalPackages} package(s).`;
  let title = "Workspace audit completed";
  if (blockedCount > 0) {
    title = `Audit flagged ${blockedCount} package(s)`;
  } else if (action.action === "warn") {
    title = "Workspace audit completed with warning";
  } else if (action.action === "review") {
    title = "Workspace audit needs review";
  } else if (action.action === "require-reapproval") {
    title = "Workspace audit needs fresh approval";
  } else if (action.action === "sandbox-required") {
    title = "Workspace audit requires a sandbox";
  } else if (action.action === "block") {
    title = "Workspace audit blocked";
  }
  return {
    kind: "audit",
    timestamp: receipt.timestamp,
    title,
    detail,
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: blockedCount > 0 || action.action !== "allow" ? "attention" : "green",
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
