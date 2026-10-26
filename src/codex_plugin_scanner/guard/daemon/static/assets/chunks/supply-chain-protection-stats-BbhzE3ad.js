import { eh as isBlockedGuardAction, ei as isSupplyChainScannerEvidence, d3 as guardActionPresentation } from "../guard-dashboard.js";
function readOperation(value) {
  if (!isSupplyChainScannerEvidence(value)) {
    return null;
  }
  const trimmed = value.operation.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function receiptEvidenceOperations(receipt) {
  const operations = [];
  for (const entry of receipt.scanner_evidence ?? []) {
    const operation = readOperation(entry);
    if (operation !== null) {
      operations.push(operation);
    }
  }
  return operations;
}
function isPackageBlockReceipt(receipt) {
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
  return artifactName.includes("package") || artifactId.includes("package") || summary.includes("install") || summary.includes("package");
}
function emptyRailItem(kind) {
  const labels = {
    block: {
      title: "No blocked installs yet",
      detail: "Guard will record the last prevented package install here."
    },
    audit: {
      title: "No workspace audit yet",
      detail: "Run an audit to scan lockfiles and manifest paths on this machine."
    },
    sync: {
      title: "No policy sync yet",
      detail: "Sync pulls the latest Guard supply-chain policy to this device."
    }
  };
  return {
    kind,
    timestamp: null,
    title: labels[kind].title,
    detail: labels[kind].detail,
    receiptId: null,
    harness: null,
    tone: "slate"
  };
}
function blockRailItem(receipt) {
  const label = receipt.artifact_name?.trim();
  return {
    kind: "block",
    timestamp: receipt.timestamp,
    title: label !== void 0 && label.length > 0 ? `Blocked: ${label}` : "Blocked package install",
    detail: receipt.capabilities_summary.trim().length > 0 ? receipt.capabilities_summary : "Guard blocked a package install before it completed.",
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: "attention"
  };
}
function auditRailItem(receipt) {
  const evidence = (receipt.scanner_evidence ?? []).find(
    (entry) => readOperation(entry) === "audit"
  );
  const auditStatus = evidence !== void 0 && typeof evidence.audit_status === "string" ? evidence.audit_status : null;
  if (auditStatus === "incomplete") {
    return {
      kind: "audit",
      timestamp: receipt.timestamp,
      title: "Workspace audit did not complete",
      detail: receipt.capabilities_summary.trim().length > 0 ? receipt.capabilities_summary : "Guard could not index workspace packages for audit.",
      receiptId: receipt.receipt_id,
      harness: receipt.harness,
      tone: "attention"
    };
  }
  const action = guardActionPresentation(receipt.policy_decision);
  const blockedCount = evidence !== void 0 && typeof evidence.blocked_package_count === "number" ? evidence.blocked_package_count : 0;
  const totalPackages = evidence !== void 0 && typeof evidence.total_packages === "number" ? evidence.total_packages : blockedCount;
  const detail = receipt.capabilities_summary.trim().length > 0 ? receipt.capabilities_summary : `Workspace audit returned ${action.copy} across ${totalPackages} package(s).`;
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
    tone: blockedCount > 0 || action.action !== "allow" ? "attention" : "green"
  };
}
function syncRailItem(receipt) {
  return {
    kind: "sync",
    timestamp: receipt.timestamp,
    title: "Policy sync completed",
    detail: receipt.capabilities_summary.trim().length > 0 ? receipt.capabilities_summary : "Guard refreshed local supply-chain policy from the connected source.",
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: "green"
  };
}
function latestReceiptMatching(receipts, predicate) {
  const matches = receipts.filter(predicate).sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
  return matches[0] ?? null;
}
function deriveSupplyChainEvidenceRail(receipts) {
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
    sync: syncReceipt !== null ? syncRailItem(syncReceipt) : emptyRailItem("sync")
  };
}
function resolveSupplyChainCloudDegradedState(snapshot) {
  if (snapshot.cloud_state !== "local_only") {
    return {
      active: false,
      title: "",
      detail: ""
    };
  }
  return {
    active: true,
    title: "Guard Cloud unavailable on this device",
    detail: snapshot.cloud_state_detail.trim().length > 0 ? snapshot.cloud_state_detail : "Local protection still runs, but live intel, fleet sync, and cross-device evidence stay offline until you connect Guard Cloud."
  };
}
function supplyChainEvidenceHref(receiptId, harness) {
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
function resolveManagerCoverageManagers(protection) {
  if (protection === void 0) {
    return [];
  }
  return protection.detected_managers ?? [];
}
function resolveManagerCoverageStatus(protection, manager) {
  if (protection === void 0) {
    return "unprotected";
  }
  if (protection.protected_managers.includes(manager)) {
    return "protected";
  }
  if (protection.installed_managers.includes(manager)) {
    if (protection.path_status === "restart_required") {
      return "restart_required";
    }
    return "path_repair";
  }
  return "unprotected";
}
function collectPackageBlockReceipts(snapshot, loadedReceipts) {
  const blocks = /* @__PURE__ */ new Map();
  for (const receipt of [...snapshot.latest_receipts ?? [], ...loadedReceipts ?? []]) {
    if (isPackageBlockReceipt(receipt)) {
      blocks.set(receipt.receipt_id, receipt);
    }
  }
  return [...blocks.values()];
}
function buildSupplyChainStats(snapshot, loadedReceipts) {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const coverageManagers = resolveManagerCoverageManagers(protection);
  const protectedManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "protected"
  ).length;
  const stagedManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "restart_required"
  ).length;
  const repairRequiredManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "path_repair"
  ).length;
  const unprotectedManagers = coverageManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected"
  ).length;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((install) => install.active).length,
    // Managed installs are connected apps; an inactive one is not a blocked
    // package. Count the package blocks among the receipts Guard has loaded.
    preventedInstalls: collectPackageBlockReceipts(snapshot, loadedReceipts).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers
  };
}
export {
  resolveManagerCoverageStatus as a,
  buildSupplyChainStats as b,
  resolveSupplyChainCloudDegradedState as c,
  deriveSupplyChainEvidenceRail as d,
  collectPackageBlockReceipts as e,
  isPackageBlockReceipt as i,
  resolveManagerCoverageManagers as r,
  supplyChainEvidenceHref as s
};
