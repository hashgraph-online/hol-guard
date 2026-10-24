import { resolveFeedStaleness } from "./feed-health-workspace-Bb4acrba.js";
import { r as resolveHomeProtectionStatus } from "./home-protection-module-Du65PsUR.js";
import { b as buildSupplyChainStats, r as resolveManagerCoverageManagers, a as resolveManagerCoverageStatus } from "./supply-chain-protection-stats-CJkxdP0r.js";
import { d2 as guardActionPresentation, eb as isSupplyChainScannerEvidence, ec as isBlockedGuardAction } from "../guard-dashboard.js";
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
function resolveSupplyChainIssues(snapshot) {
  const issues = [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const stats = buildSupplyChainStats(snapshot);
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const unprotectedManagers = resolveManagerCoverageManagers(protection).filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected"
  );
  const cloudDegraded = resolveSupplyChainCloudDegradedState(snapshot);
  if (cloudDegraded.active) {
    issues.push({
      id: "cloud_connect",
      title: cloudDegraded.title,
      detail: cloudDegraded.detail.trim().length > 0 ? cloudDegraded.detail : "Connect Guard Cloud for live package warnings, synced policy, and cross-device evidence.",
      tone: "attention",
      actionLabel: "Connect Guard Cloud",
      action: { kind: "connect" }
    });
  }
  if (protection?.path_status === "missing_from_path") {
    issues.push({
      id: "path_missing",
      title: "Package installs are not being checked yet",
      detail: "Guard has not activated package protection yet. Turn on protection for your package tools, then finish activation here.",
      tone: "attention",
      actionLabel: "Protect package tools",
      action: { kind: "firewall_unprotected" }
    });
  } else if (stats.repairRequiredManagers > 0) {
    const coverageManagers = new Set(resolveManagerCoverageManagers(protection));
    const managers = protection !== void 0 ? protection.installed_managers.filter(
      (manager) => coverageManagers.has(manager) && !protection.protected_managers.includes(manager)
    ) : [];
    const managerLabel = managers.length > 0 ? managers.join(", ") : "installed tools";
    issues.push({
      id: "path_repair",
      title: "Fix your shell path before installs can be blocked",
      detail: `Guard set up protection for ${managerLabel}, but your shell path still needs a quick repair.`,
      tone: "attention",
      actionLabel: "Repair PATH in firewall",
      action: { kind: "firewall_repair" }
    });
  }
  if (protectionStatus === "partial" && stats.protectedManagers > 0 && unprotectedManagers.length > 0) {
    issues.push({
      id: "partial_protection",
      title: "Some package tools are still open",
      detail: `${stats.protectedManagers} protected, ${unprotectedManagers.length} still open: ${unprotectedManagers.join(", ")}.`,
      tone: "attention",
      actionLabel: "Review open tools",
      action: { kind: "firewall_unprotected" }
    });
  } else if (protectionStatus === "unprotected" && unprotectedManagers.length > 0) {
    issues.push({
      id: "unprotected_tools",
      title: "Package installs are not protected yet",
      detail: `Turn on protection for ${unprotectedManagers.join(", ")} to block risky installs before they run.`,
      tone: "attention",
      actionLabel: "Protect package tools",
      action: { kind: "firewall_unprotected" }
    });
  }
  if (snapshot.cloud_state !== "local_only") {
    const feedStaleness = resolveFeedStaleness(snapshot);
    if (feedStaleness.stale) {
      issues.push({
        id: "stale_intel",
        title: "Safety check data looks old on this device",
        detail: `${feedStaleness.ageLabel}. Sync policy or run a workspace audit so Guard evaluates packages against current warnings.`,
        tone: "attention",
        actionLabel: "Run workspace audit",
        action: { kind: "firewall_audit" }
      });
    }
  }
  return issues;
}
export {
  deriveSupplyChainEvidenceRail as d,
  resolveSupplyChainIssues as r,
  supplyChainEvidenceHref as s
};
