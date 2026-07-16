const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=["assets/chunks/supply-chain-workspace.js","assets/guard-dashboard.js","assets/index.css","assets/chunks/feed-health-workspace.js","assets/chunks/home-protection-module.js","assets/chunks/supply-chain-protection-stats.js","assets/chunks/audit-workspace.js"])))=>i.map(i=>d[i]);
import { aC as isSupplyChainAuditIncomplete, aD as isSupplyChainAuditEvidence, r as reactExports, aE as buildApprovalProofCredentials, aF as isApprovalProofSubmitDisabled, j as jsxRuntimeExports, S as SectionLabel, aG as ApprovalProofFieldInputs, A as ActionButton, av as GuardHarnessActionError, aH as readString$1, aI as isRecord$1, d as HiMiniCheckCircle, ax as HiMiniArrowPath, x as HiMiniExclamationTriangle, ad as Tag, l as formatRelativeTime, aJ as HiMiniClock, aK as IconActionButton, J as HiMiniXCircle, ay as HiMiniTrash, k as HiMiniShieldCheck, I as HiMiniWrenchScrewdriver, aL as HiMiniBeaker, aM as ActivationSummary, aN as ActionResultPanel, ae as HiMiniMagnifyingGlass, b as EmptyState, aO as HiMiniBugAnt, Z as fetchSettings, n as HiMiniXMark, aP as GuardModalLayer, aQ as ConnectFlowCard, aR as ApprovalProofInline, aS as HiMiniArrowTopRightOnSquare, aT as HiMiniCloudArrowDown, aU as fetchPackageFirewallStatus, aV as runPackageAudit, aW as resolveSupplyChainAuditFailure, aX as runPackageSync, aY as startPackageFirewallConnect, aZ as openPackageFirewallAuthorizeFallback, a_ as PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE, a$ as runPackageFirewallAction, b0 as parseInterceptProofSnapshot, b1 as activatePackageFirewallRuntime, b2 as EntitlementNotice, b3 as fetchReceipts, b4 as WorkspacePageHeader, b5 as __vitePreload } from "../guard-dashboard.js";
const SEVERITY_RANK = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  unknown: 0
};
const DECISION_RANK = {
  block: 4,
  ask: 3,
  warn: 2,
  monitor: 1,
  allow: 0
};
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function readString(value) {
  if (typeof value !== "string") {
    return null;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function readStringArray(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry) => typeof entry === "string" && entry.trim().length > 0).map((entry) => entry.trim());
}
function normalizeSeverity(value) {
  const raw = readString(value)?.toLowerCase();
  if (raw === "critical" || raw === "high" || raw === "medium" || raw === "low") {
    return raw;
  }
  return "unknown";
}
function normalizeDecision(value) {
  const raw = readString(value)?.toLowerCase();
  if (raw === "block" || raw === "ask" || raw === "warn" || raw === "monitor" || raw === "allow") {
    return raw;
  }
  return "monitor";
}
function normalizeInventory(record) {
  if (record === null) {
    return {
      totalPackages: 0,
      directPackageCount: 0,
      transitivePackageCount: 0,
      sbomPackageCount: 0
    };
  }
  return {
    totalPackages: typeof record.total_packages === "number" ? record.total_packages : 0,
    directPackageCount: typeof record.direct_package_count === "number" ? record.direct_package_count : 0,
    transitivePackageCount: typeof record.transitive_package_count === "number" ? record.transitive_package_count : 0,
    sbomPackageCount: typeof record.sbom_package_count === "number" ? record.sbom_package_count : 0
  };
}
function normalizeReasons(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  const reasons = [];
  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }
    const message = readString(entry.message) ?? readString(entry.summary) ?? "Flagged by Guard supply-chain policy.";
    const advisoryId = readString(entry.advisoryId) ?? readString(entry.advisory_id);
    if (advisoryId !== null && !message.includes(advisoryId)) {
      reasons.push({
        code: readString(entry.code) ?? "supply_chain",
        message: `${message} (${advisoryId})`,
        severity: normalizeSeverity(entry.severity)
      });
      continue;
    }
    reasons.push({
      code: readString(entry.code) ?? "supply_chain",
      message,
      severity: normalizeSeverity(entry.severity)
    });
  }
  return reasons;
}
function resolveFindingSeverity(packageRecord, reasons) {
  const normalized = normalizeSeverity(packageRecord.normalized_severity);
  if (normalized !== "unknown") {
    return normalized;
  }
  let highest = "unknown";
  for (const reason of reasons) {
    if (SEVERITY_RANK[reason.severity] > SEVERITY_RANK[highest]) {
      highest = reason.severity;
    }
  }
  if (highest !== "unknown") {
    return highest;
  }
  const decision = normalizeDecision(packageRecord.decision);
  if (decision === "block") {
    return "high";
  }
  if (decision === "ask") {
    return "medium";
  }
  if (decision === "warn") {
    return "medium";
  }
  return "low";
}
function addAdvisoryAlias(aliases, rawId) {
  const trimmed = rawId.trim();
  if (trimmed.length === 0) {
    return;
  }
  const upper = trimmed.toUpperCase();
  if (upper.startsWith("GHSA-") || upper.startsWith("CVE-") || upper.startsWith("PYSEC-") || upper.startsWith("GO-")) {
    aliases.add(upper);
  }
}
function readAdvisoryIdList(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry) => typeof entry === "string" && entry.trim().length > 0).map((entry) => entry.trim());
}
function buildAdvisoryAliases(packageRecord, reasons) {
  const precomputed = readAdvisoryIdList(packageRecord.advisoryAliases).concat(
    readAdvisoryIdList(packageRecord.advisory_aliases)
  );
  if (precomputed.length > 0) {
    const normalized = /* @__PURE__ */ new Set();
    for (const id of precomputed) {
      addAdvisoryAlias(normalized, id);
    }
    return Array.from(normalized);
  }
  const aliases = /* @__PURE__ */ new Set();
  const packageAdvisoryId = readString(packageRecord.advisoryId) ?? readString(packageRecord.advisory_id);
  if (packageAdvisoryId !== null) {
    addAdvisoryAlias(aliases, packageAdvisoryId);
  }
  for (const entry of [
    ...readAdvisoryIdList(packageRecord.advisoryIds),
    ...readAdvisoryIdList(packageRecord.advisory_ids),
    ...readAdvisoryIdList(packageRecord.related_advisory_ids),
    ...readAdvisoryIdList(packageRecord.relatedAdvisoryIds)
  ]) {
    addAdvisoryAlias(aliases, entry);
  }
  const rawReasons = packageRecord.reasons;
  if (Array.isArray(rawReasons)) {
    for (const entry of rawReasons) {
      if (!isRecord(entry)) {
        continue;
      }
      const advisoryId = readString(entry.advisoryId) ?? readString(entry.advisory_id);
      if (advisoryId !== null) {
        addAdvisoryAlias(aliases, advisoryId);
      }
    }
  }
  for (const reason of reasons) {
    const match = reason.message.match(/\b(CVE-\d{4}-\d+)\b/i);
    if (match !== null) {
      aliases.add(match[1].toUpperCase());
    }
    const ghsaMatch = reason.message.match(/\b(GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4})\b/i);
    if (ghsaMatch !== null) {
      aliases.add(ghsaMatch[1].toUpperCase());
    }
  }
  return Array.from(aliases);
}
function normalizePackageFinding(packageRecord, index) {
  const packageName = readString(packageRecord.name);
  if (packageName === null) {
    return null;
  }
  const ecosystem = readString(packageRecord.ecosystem) ?? "unknown";
  const namespace = readString(packageRecord.namespace);
  const reasons = normalizeReasons(packageRecord.reasons);
  const decision = normalizeDecision(packageRecord.decision);
  const severity = resolveFindingSeverity(packageRecord, reasons);
  const slug = `${ecosystem}:${namespace ? `${namespace}/` : ""}${packageName}`;
  return {
    id: `${slug}:${index}`,
    packageName,
    ecosystem,
    namespace,
    decision,
    severity,
    reasons,
    advisoryAliases: buildAdvisoryAliases(packageRecord, reasons),
    status: readString(packageRecord.status)
  };
}
function normalizePackageFindings(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  const findings = [];
  let index = 0;
  for (const entry of value) {
    if (!isRecord(entry)) {
      continue;
    }
    const finding = normalizePackageFinding(entry, index);
    index += 1;
    if (finding !== null) {
      findings.push(finding);
    }
  }
  return findings;
}
const INFORMATIONAL_REASON_CODES = /* @__PURE__ */ new Set(["unknown_package", "no_cached_match"]);
function isActionablePackageFinding(finding) {
  if (finding.decision === "block" || finding.decision === "ask" || finding.decision === "warn") {
    return true;
  }
  if (finding.reasons.length === 0) {
    return finding.decision !== "allow" && finding.decision !== "monitor";
  }
  return finding.reasons.some((reason) => !INFORMATIONAL_REASON_CODES.has(reason.code));
}
function deriveActionableFindings(packages) {
  return packages.filter(isActionablePackageFinding);
}
function packageRecordsFromEvaluation(evaluation) {
  if (evaluation === null) {
    return [];
  }
  const fromPackages = normalizePackageFindings(evaluation.packages);
  if (fromPackages.length > 0) {
    return fromPackages;
  }
  return normalizePackageFindings(evaluation.package_findings);
}
function normalizeSupplyChainAuditSnapshot(raw, receiptId = null) {
  if (!isRecord(raw)) {
    return null;
  }
  if (isSupplyChainAuditIncomplete(raw)) {
    return null;
  }
  const evaluation = isRecord(raw.evaluation) ? raw.evaluation : null;
  const inventoryPackages = normalizePackageFindings(raw.package_inventory);
  const evaluationPackages = packageRecordsFromEvaluation(evaluation);
  let packages;
  if (evaluationPackages.length > 0) {
    packages = evaluationPackages;
  } else if (inventoryPackages.length > 0) {
    packages = inventoryPackages;
  } else {
    packages = normalizePackageFindings(raw.package_findings);
  }
  const findingsFromEvidence = normalizePackageFindings(raw.package_findings);
  let findings;
  if (packages.length > 0) {
    findings = deriveActionableFindings(packages);
  } else if (findingsFromEvidence.length > 0) {
    findings = findingsFromEvidence;
  } else {
    findings = [];
  }
  const generatedAt = readString(raw.generated_at) ?? readString(raw.generatedAt) ?? (/* @__PURE__ */ new Date(0)).toISOString();
  const inventory = normalizeInventory(isRecord(raw.inventory) ? raw.inventory : null);
  const decision = normalizeDecision(evaluation?.decision ?? raw.audit_decision);
  const manifestPaths = readStringArray(raw.manifest_paths);
  const lockfilePaths = readStringArray(raw.lockfile_paths);
  const hasAuditContext = packages.length > 0 || findings.length > 0 || inventory.totalPackages > 0 || evaluation !== null;
  if (!hasAuditContext) {
    return null;
  }
  return {
    generatedAt,
    source: readString(raw.source),
    decision,
    inventory,
    packages,
    findings,
    manifestPaths,
    lockfilePaths,
    receiptId
  };
}
function derivePackageWorkbenchFromReceipts(receipts) {
  const auditReceipts = receipts.filter((receipt) => receipt.harness === "package-firewall").filter((receipt) => (receipt.scanner_evidence ?? []).some((entry) => isSupplyChainAuditEvidence(entry))).sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
  for (const receipt of auditReceipts) {
    const evidenceRaw = (receipt.scanner_evidence ?? []).find((entry) => isSupplyChainAuditEvidence(entry));
    if (evidenceRaw === void 0) {
      continue;
    }
    const snapshot = normalizeSupplyChainAuditSnapshot(
      {
        generated_at: receipt.timestamp,
        audit_status: evidenceRaw.audit_status,
        evaluation: {
          decision: evidenceRaw.audit_decision,
          packages: evidenceRaw.package_inventory ?? evidenceRaw.package_findings
        },
        inventory: {
          total_packages: evidenceRaw.total_packages
        },
        manifest_paths: evidenceRaw.manifest_paths,
        lockfile_paths: evidenceRaw.lockfile_paths
      },
      receipt.receipt_id
    );
    if (snapshot !== null) {
      return snapshot;
    }
  }
  return null;
}
function sortPackageWorkbenchFindings(findings, sortKey) {
  const sorted = [...findings];
  sorted.sort((left, right) => {
    if (sortKey === "severity") {
      const severityDelta = SEVERITY_RANK[right.severity] - SEVERITY_RANK[left.severity];
      if (severityDelta !== 0) {
        return severityDelta;
      }
      return left.packageName.localeCompare(right.packageName);
    }
    if (sortKey === "ecosystem") {
      const ecosystemDelta = left.ecosystem.localeCompare(right.ecosystem);
      if (ecosystemDelta !== 0) {
        return ecosystemDelta;
      }
      return left.packageName.localeCompare(right.packageName);
    }
    if (sortKey === "decision") {
      const decisionDelta = DECISION_RANK[right.decision] - DECISION_RANK[left.decision];
      if (decisionDelta !== 0) {
        return decisionDelta;
      }
      return left.packageName.localeCompare(right.packageName);
    }
    return left.packageName.localeCompare(right.packageName);
  });
  return sorted;
}
function filterPackageWorkbenchFindings(findings, filters) {
  const query = filters.search.trim().toLowerCase();
  return findings.filter((finding) => {
    if (filters.ecosystem !== "all" && finding.ecosystem !== filters.ecosystem) {
      return false;
    }
    if (filters.decision !== "all" && finding.decision !== filters.decision) {
      return false;
    }
    if (filters.severity !== "all" && finding.severity !== filters.severity) {
      return false;
    }
    if (query.length === 0) {
      return true;
    }
    const haystack = [
      finding.packageName,
      finding.ecosystem,
      finding.namespace ?? "",
      finding.decision,
      finding.severity,
      ...finding.reasons.map((reason) => `${reason.code} ${reason.message}`),
      ...finding.advisoryAliases
    ].join(" ").toLowerCase();
    return haystack.includes(query);
  });
}
function packageWorkbenchEcosystems(findings) {
  return Array.from(new Set(findings.map((finding) => finding.ecosystem))).sort();
}
const SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS = "min-w-0 max-w-full space-y-6 overflow-x-hidden";
function ApprovalProofModal(props) {
  const { title, detail, confirmLabel, approvalGate, onCancel, onConfirm } = props;
  const [password, setPassword] = reactExports.useState("");
  const [totpCode, setTotpCode] = reactExports.useState("");
  const handlePasswordChange = reactExports.useCallback((event) => {
    setPassword(event.target.value);
  }, []);
  const handleTotpChange = reactExports.useCallback((event) => {
    setTotpCode(event.target.value);
  }, []);
  const handleConfirm = reactExports.useCallback(() => {
    onConfirm(buildApprovalProofCredentials(approvalGate, { approvalPassword: password, approvalTotpCode: totpCode }));
  }, [approvalGate, onConfirm, password, totpCode]);
  const confirmDisabled = isApprovalProofSubmitDisabled(
    approvalGate,
    { approvalPassword: password, approvalTotpCode: totpCode },
    false
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "w-full max-w-md rounded-xl border border-slate-200 bg-white p-5 shadow-xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Approval required" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "mt-2 text-base font-semibold text-brand-dark", children: title }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: detail }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofFieldInputs,
      {
        approvalGate,
        approvalPassword: password,
        approvalTotpCode: totpCode,
        onApprovalPasswordChange: handlePasswordChange,
        onApprovalTotpCodeChange: handleTotpChange
      }
    ) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex justify-end gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onCancel, children: "Cancel" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleConfirm, disabled: confirmDisabled, children: confirmLabel })
    ] })
  ] }) });
}
const APPROVAL_GATE_REQUIRED_CODES = /* @__PURE__ */ new Set([
  "approval_gate_required",
  "approval_gate_password_required",
  "approval_gate_totp_required"
]);
const APPROVAL_GATE_NON_CREDENTIAL_CODES = /* @__PURE__ */ new Set([
  "approval_gate_locked",
  "approval_gate_grant_expired",
  "approval_gate_invalid_password",
  "approval_gate_totp_invalid",
  "approval_gate_recovery_required",
  "approval_gate_weak_password"
]);
const APPROVAL_CREDENTIAL_PROMPT_MESSAGE = /approval(?:\s+gate)?\s+password is required|totp code is required/i;
const SUPPLY_CHAIN_CONNECT_ERROR_CODES = /* @__PURE__ */ new Set([
  "guard_cloud_connect_required",
  "guard_cloud_reconnect_required"
]);
const GUARD_FETCH_NETWORK_ERROR_MESSAGE = /failed to fetch|networkerror|load failed/i;
function isGuardHarnessActionError(error) {
  if (error instanceof GuardHarnessActionError) {
    return true;
  }
  if (typeof error !== "object" || error === null) {
    return false;
  }
  const candidate = error;
  return candidate.name === "GuardHarnessActionError" && typeof candidate.status === "number";
}
function readHarnessActionErrorCode(error) {
  if (!isGuardHarnessActionError(error)) {
    return null;
  }
  const code = error.payload?.error;
  if (typeof code !== "string") {
    return null;
  }
  const trimmed = code.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function readHarnessActionErrorMessage(error) {
  if (!isGuardHarnessActionError(error)) {
    if (error instanceof Error && error.message.trim()) {
      return error.message.trim();
    }
    return null;
  }
  const message = error.payload?.message ?? error.message;
  if (typeof message !== "string") {
    return null;
  }
  const trimmed = message.trim();
  return trimmed.length > 0 ? trimmed : null;
}
function isApprovalCredentialPromptCode(code) {
  if (code === null) {
    return false;
  }
  if (APPROVAL_GATE_REQUIRED_CODES.has(code)) {
    return true;
  }
  return APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(code);
}
function isSupplyChainSyncConnectError(error) {
  const code = readHarnessActionErrorCode(error);
  return code !== null && SUPPLY_CHAIN_CONNECT_ERROR_CODES.has(code);
}
function isSupplyChainSyncRetryableError(error) {
  if (!isGuardHarnessActionError(error)) {
    return false;
  }
  if (readHarnessActionErrorCode(error) !== "supply_chain_sync_unavailable") {
    return false;
  }
  return error.payload?.retryable === true;
}
function readHarnessActionUserMessage(error, fallback) {
  if (error instanceof Error && GUARD_FETCH_NETWORK_ERROR_MESSAGE.test(error.message)) {
    return "Guard lost connection while syncing supply-chain intel. Confirm the local daemon is still running, then try again.";
  }
  const structuredMessage = readHarnessActionErrorMessage(error);
  if (structuredMessage !== null) {
    return structuredMessage;
  }
  return fallback;
}
function isApprovalGateRequiredError(error) {
  const code = readHarnessActionErrorCode(error);
  if (code !== null && APPROVAL_GATE_NON_CREDENTIAL_CODES.has(code)) {
    return false;
  }
  if (isApprovalCredentialPromptCode(code)) {
    return true;
  }
  const message = readHarnessActionErrorMessage(error);
  if (message !== null && APPROVAL_CREDENTIAL_PROMPT_MESSAGE.test(message)) {
    return true;
  }
  return false;
}
function resolveApprovalGateSyncFailure(error, options) {
  const hasCredentials = options?.hasCredentials === true;
  if (!hasCredentials && isApprovalGateRequiredError(error)) {
    return { kind: "approval_required" };
  }
  return {
    kind: "failed",
    message: readHarnessActionUserMessage(error, "Sync failed.")
  };
}
const SYNC_RECOVERY_STEPS = [
  {
    title: "Sync intel",
    body: "Guard downloads the latest signed supply-chain bundle on this device."
  },
  {
    title: "Run audit",
    body: "Guard scans workspace manifests and lists flagged packages automatically."
  }
];
function createSupplyChainSyncApprovalGate(options) {
  return {
    obstacle: "sync_required",
    headline: "Sync supply-chain intel before auditing",
    detail: "Enter your local approval password so Guard can download the latest signed supply-chain bundle on this device.",
    steps: [...SYNC_RECOVERY_STEPS],
    primaryAction: "sync",
    primaryLabel: "Sync supply-chain intel",
    autoRetryAuditAfterPrimary: options?.autoRetryAuditAfterPrimary ?? false
  };
}
function resolveSupplyChainAuditRecoveryGate(detail) {
  if (!isSupplyChainAuditIncomplete(detail)) {
    return null;
  }
  const outcome = readString$1(detail.audit_outcome);
  const message = readString$1(detail.message);
  const supplyChain = isRecord$1(detail.supply_chain) ? detail.supply_chain : null;
  const supplyStatus = readString$1(supplyChain?.status);
  if (outcome === "sync_required" || supplyStatus === "sync_required") {
    return {
      obstacle: "sync_required",
      headline: "Sync supply-chain intel before auditing",
      detail: message ?? "Guard needs the latest signed package intelligence on this device. Sync once, then Guard reruns the workspace audit for you.",
      steps: [...SYNC_RECOVERY_STEPS],
      primaryAction: "sync",
      primaryLabel: "Sync supply-chain intel",
      autoRetryAuditAfterPrimary: true
    };
  }
  if (outcome === "not_connected" || outcome === "expired" || outcome === "degraded" || supplyStatus === "not_connected" || supplyStatus === "expired" || supplyStatus === "degraded") {
    return {
      obstacle: "cloud_auth",
      headline: "Reconnect Guard Cloud before auditing",
      detail: message ?? "Guard Cloud sign-in is missing or stale on this machine. Reconnect once, then Guard can sync intel and rerun the audit.",
      steps: [
        {
          title: "Reconnect Cloud",
          body: "Approve Guard Cloud access in your browser on this device."
        },
        {
          title: "Sync and audit",
          body: "Guard refreshes supply-chain intel, then reruns the workspace audit."
        }
      ],
      primaryAction: "connect",
      primaryLabel: "Reconnect Guard Cloud",
      autoRetryAuditAfterPrimary: true
    };
  }
  if (outcome === "inventory_empty") {
    return {
      obstacle: "inventory_empty",
      headline: "Refresh intel before auditing packages",
      detail: message ?? "Guard found project files but could not index packages yet. Syncing intel often fixes stale inventory, then Guard reruns the audit.",
      steps: [...SYNC_RECOVERY_STEPS],
      primaryAction: "sync",
      primaryLabel: "Sync and retry audit",
      autoRetryAuditAfterPrimary: true
    };
  }
  if (outcome === "no_project_files") {
    return {
      obstacle: "no_project_files",
      headline: "Add project manifests before auditing",
      detail: message ?? "Guard could not find supported manifests or lockfiles in the audit workspace. Open the connected project folder, add package files, then try the audit again.",
      steps: [
        {
          title: "Open workspace",
          body: "Use the connected app project folder with package.json, lockfiles, or Python manifests."
        },
        {
          title: "Run audit",
          body: "Guard indexes dependencies and surfaces flagged packages."
        }
      ],
      primaryAction: "retry_audit",
      primaryLabel: "Run audit again",
      autoRetryAuditAfterPrimary: false
    };
  }
  return {
    obstacle: "unknown",
    headline: "Finish setup before auditing",
    detail: message ?? "The workspace audit did not complete. Sync supply-chain intel, then try the audit again.",
    steps: [...SYNC_RECOVERY_STEPS],
    primaryAction: "sync",
    primaryLabel: "Sync supply-chain intel",
    autoRetryAuditAfterPrimary: true
  };
}
function isSupplyChainAuditConnectError(error) {
  return isGuardHarnessActionError(error) && isSupplyChainSyncConnectError(error);
}
function resolveSupplyChainSyncConnectRecoveryGate(error) {
  if (!isSupplyChainSyncConnectError(error)) {
    return null;
  }
  const code = readHarnessActionErrorCode(error);
  if (code === "guard_cloud_reconnect_required") {
    return resolveSupplyChainAuditRecoveryGate({
      audit_status: "incomplete",
      audit_outcome: "expired"
    });
  }
  return resolveSupplyChainAuditRecoveryGate({
    audit_status: "incomplete",
    audit_outcome: "not_connected"
  });
}
function packageAuditNeedsCloudConnect(data) {
  const auditAction = data.actions.audit;
  return auditAction === "connect_required" || auditAction === "reconnect_required";
}
function resolveAuditConnectMode(data) {
  if (data.entitlement.reason === "guard_cloud_reconnect_required") {
    return "repair";
  }
  if (data.entitlement.reason === "guard_cloud_connect_required" && (data.entitlement.tier !== "unknown" || data.package_shims.some((shim) => shim.installed))) {
    return "repair";
  }
  return "connect";
}
function resolveSupplyChainAuditConnectGate(data, options) {
  if (!packageAuditNeedsCloudConnect(data) || data.connect_flow === null) {
    return null;
  }
  const mode = resolveAuditConnectMode(data);
  if (mode === "repair") {
    return {
      mode,
      headline: "Reconnect Guard Cloud to run the workspace audit",
      detail: "Guard needs a fresh Cloud sign-in on this machine before it can scan workspace packages and surface findings here.",
      resumeAfterConnect: options?.resumeAfterConnect ?? false
    };
  }
  return {
    mode,
    headline: "Sign in to Guard Cloud before running the audit",
    detail: "Package audits run through Guard Cloud. Sign in once on this machine, then Guard can scan dependencies and list flagged packages.",
    resumeAfterConnect: options?.resumeAfterConnect ?? false
  };
}
function supplyChainAuditConnectUserMessage(error) {
  if (!isSupplyChainAuditConnectError(error)) {
    return null;
  }
  const code = error.payload?.error;
  if (code === "guard_cloud_reconnect_required") {
    return "Reconnect HOL Guard Cloud, then run the workspace audit again.";
  }
  return "Sign in to HOL Guard Cloud on this machine, then run the workspace audit.";
}
function supplyChainAuditUserMessage(error) {
  if (error instanceof GuardHarnessActionError) {
    if (error.payload?.error === "workspace_dir_required") {
      return error.payload.message ?? "Guard needs a connected app project folder with package manifests before it can run the workspace audit.";
    }
    return supplyChainAuditConnectUserMessage(error);
  }
  if (error instanceof Error && error.message.trim()) {
    return error.message;
  }
  return null;
}
function resolveSupplyChainAuditWorkspaceDir(managedInstalls) {
  const ordered = [...managedInstalls].sort((left, right) => {
    if (left.active !== right.active) {
      return left.active ? -1 : 1;
    }
    return right.updated_at.localeCompare(left.updated_at);
  });
  for (const install of ordered) {
    const workspace = install.workspace?.trim();
    if (workspace) {
      return workspace;
    }
  }
  return null;
}
function resolveSupplyChainAuditWorkspaceTarget(input) {
  const managed = input.managedWorkspaceDir?.trim();
  if (managed) {
    return managed;
  }
  const status = input.statusWorkspaceDir?.trim();
  if (status) {
    return status;
  }
  return null;
}
function resolveShimStatus(shim) {
  if (!shim) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (!shim.installed && shim.detected) {
    return { label: "Detected, not protected", tone: "slate", icon: "warning" };
  }
  if (!shim.installed) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (shim.activation_state === "protected") {
    return { label: "Protected", tone: "green", icon: "check" };
  }
  if (shim.activation_state === "restart_required") {
    return { label: "Restart required", tone: "blue", icon: "restart" };
  }
  if (shim.path_broken) {
    return { label: "PATH broken", tone: "attention", icon: "warning" };
  }
  if (shim.activation_state === "repair_required") {
    return { label: "Needs PATH repair", tone: "attention", icon: "warning" };
  }
  return { label: "Unprotected", tone: "attention", icon: "warning" };
}
function actionIsAvailable$1(state) {
  return state === "available";
}
function ManagerRow({
  layout = "row",
  manager,
  shim,
  actions,
  anyPending,
  isMine,
  isConfirmingRemove,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onOpenDetails
}) {
  const status = resolveShimStatus(shim);
  const installState = actions.install ?? "disabled";
  const repairState = actions.repair ?? "disabled";
  const testState = actions.test ?? "disabled";
  const removeState = actions.remove ?? "disabled";
  const installAvailable = actionIsAvailable$1(installState);
  const repairAvailable = actionIsAvailable$1(repairState);
  const testAvailable = actionIsAvailable$1(testState);
  const removeAvailable = actionIsAvailable$1(removeState);
  const showInstall = (!shim || !shim.installed) && installAvailable;
  const showRepair = shim?.installed && (shim.activation_state === "repair_required" || shim.path_broken) && repairAvailable;
  const showTest = shim?.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim?.installed && removeAvailable;
  const handleInstall = reactExports.useCallback(() => onInstall(manager), [onInstall, manager]);
  const handleRepair = reactExports.useCallback(() => onRepair(manager), [onRepair, manager]);
  const handleTest = reactExports.useCallback(() => onTest(manager), [onTest, manager]);
  const handleRemoveRequest = reactExports.useCallback(() => onRemoveRequest(manager), [onRemoveRequest, manager]);
  const handleRemoveConfirm = reactExports.useCallback(() => onRemoveConfirm(manager), [onRemoveConfirm, manager]);
  const handleOpenDetails = reactExports.useCallback(() => onOpenDetails(manager), [onOpenDetails, manager]);
  const cardLayout = layout === "card";
  const outerClass = cardLayout ? "min-w-0 rounded-xl border border-slate-100 bg-white p-4 shadow-sm" : "border-b border-slate-100 last:border-b-0";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: outerClass, role: cardLayout ? "listitem" : "row", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: cardLayout ? "flex flex-col gap-3" : "flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex min-w-0 flex-col gap-1 ${cardLayout ? "" : "sm:flex-1"}`, role: "cell", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-wrap items-center gap-2", children: [
          status.icon === "check" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }) : status.icon === "restart" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: handleOpenDetails,
              className: "truncate text-left font-mono text-sm font-semibold text-brand-dark hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded",
              "aria-label": `Open ${manager} manager details`,
              children: manager
            }
          ),
          shim?.detected && /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: "Detected" }),
          isMine && /* @__PURE__ */ jsxRuntimeExports.jsx(
            HiMiniArrowPath,
            {
              className: "h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue",
              "aria-label": "Running…"
            }
          )
        ] }),
        shim?.path_summary !== null && shim?.path_summary !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: `break-all font-mono text-[11px] leading-relaxed text-slate-500 ${cardLayout ? "" : "sm:pl-6"}`, children: [
          "Shell path: ",
          shim.path_summary
        ] }),
        shim?.last_intercept_proof_at !== null && shim?.last_intercept_proof_at !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: `flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 ${cardLayout ? "" : "sm:pl-6"}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 shrink-0 text-brand-green", "aria-hidden": "true" }),
          "Last protection test ",
          formatRelativeTime(shim.last_intercept_proof_at)
        ] }) : shim?.installed ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: `flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500 ${cardLayout ? "" : "sm:pl-6"}`, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "h-3.5 w-3.5 shrink-0", "aria-hidden": "true" }),
          "No protection test recorded yet"
        ] }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex flex-wrap items-center gap-2 ${cardLayout ? "justify-between" : "sm:gap-3"}`, role: "cell", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: status.tone, children: status.label }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0 [&_button]:min-h-11 [&_button]:h-11", children: isConfirmingRemove ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "ghost",
              label: "Cancel",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4" }),
              onClick: onRemoveCancel,
              disabled: anyPending
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "danger",
              label: "Confirm",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4" }),
              onClick: handleRemoveConfirm,
              disabled: anyPending
            }
          )
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
          showInstall && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "primary",
              label: "Protect",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4" }),
              onClick: handleInstall,
              disabled: anyPending
            }
          ),
          showRepair && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "primary",
              label: "Fix PATH",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "h-4 w-4" }),
              onClick: handleRepair,
              disabled: anyPending
            }
          ),
          showTest && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "outline",
              label: "Test",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBeaker, { className: "h-4 w-4" }),
              onClick: handleTest,
              disabled: anyPending
            }
          ),
          showRemove && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "danger",
              label: "Remove",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4" }),
              onClick: handleRemoveRequest,
              disabled: anyPending
            }
          )
        ] }) })
      ] })
    ] }),
    shim?.activation_state === "restart_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: cardLayout ? "mt-2" : "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim." }) }),
    shim?.activation_state === "repair_required" && !shim.path_broken && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: cardLayout ? "mt-2" : "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart." }) }),
    shim?.path_broken && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: cardLayout ? "mt-2" : "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-brand-attention", children: "Restart your shell after repair so PATH exports reload." }) })
  ] });
}
function GlobalActionsBar({ anyPending, pendingOp, onAudit, onSync }) {
  const auditRunning = pendingOp?.op === "audit";
  const syncRunning = pendingOp?.op === "sync";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: onAudit, disabled: anyPending, "aria-busy": auditRunning, children: [
      auditRunning ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-3.5 w-3.5 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "mr-1.5 h-3.5 w-3.5", "aria-hidden": "true" }),
      "Audit"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: onSync, disabled: anyPending, "aria-busy": syncRunning, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: `mr-1.5 h-3.5 w-3.5 ${syncRunning ? "animate-spin" : ""}`,
          "aria-hidden": "true"
        }
      ),
      "Sync"
    ] })
  ] });
}
function FailureBanner({ failed }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5",
      role: "alert",
      "aria-live": "assertive",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
            failed.op,
            " failed",
            failed.manager !== null ? ` for ${failed.manager}` : ""
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-600", children: failed.message })
        ] })
      ]
    }
  );
}
function FirewallControlsView({
  activationAssistError,
  activatingRuntime,
  data,
  pendingOp,
  lastCompleted,
  lastFailed,
  confirmRemoveManager,
  showGlobalActions,
  statusFilter,
  managerFilter,
  onStatusFilterChange,
  onManagerFilterChange,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onAudit,
  onSync,
  onDismissResult,
  onActivateRuntime,
  onRefreshStatus,
  onOpenManagerDetails
}) {
  const anyPending = pendingOp !== null;
  const noDetectedManagers = data.detected_managers.length === 0;
  const filteredManagers = reactExports.useMemo(() => {
    const shimsByManager = new Map(data.package_shims.map((s) => [s.manager, s]));
    const visibleManagers = data.package_shims.filter((shim) => shim.detected || shim.installed || shim.tested).map((shim) => shim.manager);
    let managers;
    if (visibleManagers.length > 0) {
      managers = Array.from(new Set(visibleManagers)).sort();
    } else if (noDetectedManagers) {
      managers = [];
    } else {
      managers = data.supported_managers;
    }
    if (managerFilter) {
      const q = managerFilter.toLowerCase();
      managers = managers.filter((m) => m.toLowerCase().includes(q));
    }
    if (statusFilter !== "all") {
      managers = managers.filter((m) => {
        const shim = shimsByManager.get(m);
        const status = resolveShimStatus(shim);
        if (statusFilter === "protected") return status.tone === "green";
        if (statusFilter === "actionable") return status.tone === "attention";
        if (statusFilter === "unprotected") return status.tone !== "green";
        return true;
      });
    }
    return managers;
  }, [data, managerFilter, noDetectedManagers, statusFilter]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 px-4 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Package tools on this device" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-slate-500", children: "Detect, protect, test, and repair each package manager Guard can watch." })
      ] }),
      showGlobalActions && /* @__PURE__ */ jsxRuntimeExports.jsx(
        GlobalActionsBar,
        {
          anyPending,
          pendingOp,
          onAudit,
          onSync
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActivationSummary,
      {
        activationAssistError,
        lastAuditProofAt: data.last_audit_proof_at,
        activatingRuntime,
        onActivateRuntime,
        onRefreshStatus,
        protection: data.protection
      }
    ),
    lastFailed !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(FailureBanner, { failed: lastFailed }),
    lastCompleted !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionResultPanel, { completed: lastCompleted, onDismiss: onDismissResult }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-1 items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5 sm:flex-none sm:w-44", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-3.5 w-3.5 shrink-0 text-slate-400", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "search",
            placeholder: "Search tools…",
            value: managerFilter,
            onChange: onManagerFilterChange,
            "aria-label": "Filter package managers",
            className: "min-w-0 flex-1 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
          }
        )
      ] }),
      ["all", "protected", "actionable", "unprotected"].map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => onStatusFilterChange(s),
          "aria-pressed": statusFilter === s,
          className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${statusFilter === s ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
          children: s === "all" ? "All" : s === "protected" ? "Protected" : s === "actionable" ? "Needs action" : "Unprotected"
        },
        s
      ))
    ] }),
    filteredManagers.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: noDetectedManagers && managerFilter.length === 0 && statusFilter === "all" ? "No package managers detected" : "No package managers found",
        body: noDetectedManagers && managerFilter.length === 0 && statusFilter === "all" ? "Guard did not find npm, pip, pnpm, or other supported managers on this PATH. Install a package manager, open a new shell, then refresh status." : "No package managers match the current filter, or Guard has not detected any on this machine.",
        tone: "teach"
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid min-w-0 gap-3 sm:grid-cols-2 xl:grid-cols-3", role: "list", "aria-label": "Package manager controls", children: filteredManagers.map((manager) => {
      const shim = data.package_shims.find((s) => s.manager === manager);
      return /* @__PURE__ */ jsxRuntimeExports.jsx(
        ManagerRow,
        {
          layout: "card",
          manager,
          shim,
          actions: data.actions,
          anyPending,
          isMine: pendingOp?.manager === manager,
          isConfirmingRemove: confirmRemoveManager === manager,
          onInstall,
          onRepair,
          onTest,
          onRemoveRequest,
          onRemoveConfirm,
          onRemoveCancel,
          onOpenDetails: onOpenManagerDetails
        },
        manager
      );
    }) })
  ] });
}
function useResolvedApprovalGate(initialGate) {
  const [resolvedApprovalGate, setResolvedApprovalGate] = reactExports.useState(initialGate);
  reactExports.useEffect(() => {
    setResolvedApprovalGate(initialGate);
  }, [initialGate]);
  const resolveApprovalGate = reactExports.useCallback(async () => {
    if (resolvedApprovalGate !== null) {
      return resolvedApprovalGate;
    }
    try {
      const payload = await fetchSettings();
      const gate = payload.settings.approval_gate ?? null;
      setResolvedApprovalGate(gate);
      return gate;
    } catch {
      return null;
    }
  }, [resolvedApprovalGate]);
  return { resolvedApprovalGate, resolveApprovalGate };
}
function ManagerProofRow({
  manager,
  detail,
  interceptRan
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/80 px-3 py-2.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-sm font-semibold text-brand-dark", children: manager }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: interceptRan ? "green" : "attention", children: interceptRan ? "Proof recorded" : "Needs attention" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1.5 text-xs leading-relaxed text-slate-600", children: detail })
  ] });
}
function InterceptProofModal({ proof, onClose }) {
  const toneClass = proof.interceptProved ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-brand-attention/20 bg-brand-attention/[0.04]";
  const Icon = proof.interceptProved ? HiMiniCheckCircle : HiMiniExclamationTriangle;
  const iconClass = proof.interceptProved ? "text-brand-green" : "text-brand-attention";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      role: "dialog",
      "aria-label": "Intercept proof details",
      "aria-modal": "true",
      className: "fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4",
      "data-testid": "intercept-proof-modal",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute inset-0 bg-black/30 backdrop-blur-sm", onClick: onClose, "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl bg-white shadow-2xl", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base font-semibold text-brand-dark", children: "Intercept proof" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Guard ran a controlled package-manager call to verify shim interception." })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: onClose,
                "aria-label": "Close intercept proof modal",
                className: "flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 overflow-y-auto px-5 py-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `rounded-xl border px-4 py-3 ${toneClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `mt-0.5 h-4 w-4 shrink-0 ${iconClass}`, "aria-hidden": "true" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: proof.summary }),
                proof.timestamp !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-500", children: [
                  "Recorded ",
                  formatRelativeTime(proof.timestamp)
                ] })
              ] })
            ] }) }),
            proof.managerResults.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400", children: "Manager results" }),
              proof.managerResults.map((entry) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                ManagerProofRow,
                {
                  manager: entry.manager,
                  detail: entry.detail,
                  interceptRan: entry.interceptRan
                },
                entry.manager
              ))
            ] }) : null,
            proof.pathRepairRequired.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-amber-200 bg-amber-50/70 px-3 py-2.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium text-amber-950", children: "PATH repair still required" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-amber-900/90", children: [
                proof.pathRepairRequired.join(", "),
                " need repair before intercept proof can complete."
              ] })
            ] }) : null,
            proof.receiptId !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50 px-3 py-2.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Proof receipt" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-all font-mono text-xs text-brand-dark", children: proof.receiptId })
            ] }) : null
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-5 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: onClose, children: "Done" }) })
        ] })
      ]
    }
  );
}
function DetailRow({ label, value }) {
  if (value === null || value === void 0 || value.trim().length === 0) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-1 sm:grid-cols-[8rem_minmax(0,1fr)] sm:items-start", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[11px] font-semibold uppercase tracking-[0.14em] text-slate-400", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all font-mono text-xs text-brand-dark", children: value })
  ] });
}
function actionIsAvailable(state) {
  return state === "available";
}
function SupplyChainManagerDrawer({
  manager,
  shim,
  actions,
  anyPending,
  isMine,
  actionHandlers,
  onClose
}) {
  const status = resolveShimStatus(shim);
  const installAvailable = actionIsAvailable(actions.install);
  const repairAvailable = actionIsAvailable(actions.repair);
  const testAvailable = actionIsAvailable(actions.test);
  const removeAvailable = actionIsAvailable(actions.remove);
  const showInstall = (!shim || !shim.installed) && installAvailable;
  const showRepair = shim?.installed && (shim.activation_state === "repair_required" || shim.path_broken) && repairAvailable;
  const showTest = shim?.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim?.installed && removeAvailable;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      role: "dialog",
      "aria-label": `${manager} manager details`,
      "aria-modal": "true",
      className: "fixed inset-0 z-50 flex items-end sm:items-stretch sm:justify-end",
      "data-testid": "supply-chain-manager-drawer",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute inset-0 bg-black/30 backdrop-blur-sm", onClick: onClose, "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative flex h-[88vh] w-full max-w-md flex-col overflow-hidden rounded-t-2xl bg-white shadow-2xl sm:h-full sm:rounded-none", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-lg font-semibold text-brand-dark", children: manager }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: status.tone, children: status.label }),
                shim?.detected ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: "Detected" }) : null,
                shim?.tested ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: "Tested" }) : null
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: onClose,
                "aria-label": "Close manager details drawer",
                className: "flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-5 w-5", "aria-hidden": "true" })
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1 space-y-5 overflow-y-auto px-5 py-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Manager coverage", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400", children: "Coverage" }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "space-y-3", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(DetailRow, { label: "Activation", value: shim?.activation_state ?? "uninstalled" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(DetailRow, { label: "Integrity", value: shim?.integrity }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(DetailRow, { label: "PATH order", value: shim?.path_summary }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(DetailRow, { label: "Shim path", value: shim?.shim_path }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(DetailRow, { label: "Real binary", value: shim?.real_binary_path })
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { "aria-label": "Intercept proof", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-3 text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400", children: "Intercept proof" }),
              shim?.last_intercept_proof_at !== null && shim?.last_intercept_proof_at !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-brand-green/20 bg-brand-green/[0.04] px-3 py-2.5", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-600", children: [
                  "Last intercept proof ",
                  formatRelativeTime(shim.last_intercept_proof_at)
                ] })
              ] }) : shim?.installed ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/70 px-3 py-2.5", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600", "aria-hidden": "true" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-900/90", children: "No intercept proof recorded yet. Run a test after PATH protection is active." })
              ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Install Guard shims before recording intercept proof." })
            ] }),
            shim?.activation_state === "restart_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/20 bg-brand-blue/[0.04] px-3 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600", children: "Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim." }) }),
            shim?.path_broken && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-amber-200 bg-amber-50/70 px-3 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-900/90", children: "PATH order is broken. Repair routing, then restart your shell before testing intercepts." }) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 px-5 py-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
              showInstall && actionHandlers.install !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                IconActionButton,
                {
                  variant: "primary",
                  label: "Protect",
                  icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4" }),
                  onClick: () => actionHandlers.install?.(manager),
                  disabled: anyPending
                }
              ) : null,
              showRepair && actionHandlers.repair !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                IconActionButton,
                {
                  variant: "primary",
                  label: "Fix PATH",
                  icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "h-4 w-4" }),
                  onClick: () => actionHandlers.repair?.(manager),
                  disabled: anyPending
                }
              ) : null,
              showTest && actionHandlers.test !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                IconActionButton,
                {
                  variant: "outline",
                  label: "Test",
                  icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBeaker, { className: "h-4 w-4" }),
                  onClick: () => actionHandlers.test?.(manager),
                  disabled: anyPending
                }
              ) : null,
              showRemove && actionHandlers.removeRequest !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                IconActionButton,
                {
                  variant: "danger",
                  label: "Remove",
                  icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4" }),
                  onClick: () => actionHandlers.removeRequest?.(manager),
                  disabled: anyPending
                }
              ) : null,
              isMine ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1.5 text-xs font-medium text-brand-blue", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-3.5 w-3.5 animate-spin", "aria-hidden": "true" }),
                "Running…"
              ] }) : null
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onClose, children: "Close" }) })
          ] })
        ] })
      ]
    }
  );
}
function resolvePhaseLabel(phase) {
  if (phase === "syncing") {
    return "Syncing intel";
  }
  if (phase === "connecting") {
    return "Waiting for Cloud";
  }
  if (phase === "auditing") {
    return "Running audit";
  }
  if (phase === "approval") {
    return "Approval required";
  }
  if (phase === "failed") {
    return "Needs attention";
  }
  return "Setup required";
}
function resolvePhaseTone(phase) {
  if (phase === "failed") {
    return "attention";
  }
  if (phase === "auditing") {
    return "green";
  }
  return "blue";
}
function resolvePrimaryIcon(gate, phase) {
  if (phase === "auditing") {
    return HiMiniBugAnt;
  }
  if (gate.primaryAction === "connect") {
    return HiMiniShieldCheck;
  }
  if (gate.primaryAction === "retry_audit") {
    return HiMiniBugAnt;
  }
  return HiMiniCloudArrowDown;
}
function resolvePrimaryLabel(gate, phase) {
  if (phase === "syncing") {
    return "Syncing supply-chain intel";
  }
  if (phase === "connecting") {
    return "Waiting for Guard Cloud";
  }
  if (phase === "auditing") {
    return "Running workspace audit";
  }
  return gate.primaryLabel;
}
function resolveActiveStepIndex(gate, phase) {
  if (phase === "auditing") {
    return gate.steps.length;
  }
  if (phase === "syncing" || phase === "approval") {
    return gate.obstacle === "cloud_auth" ? 2 : 1;
  }
  if (phase === "connecting") {
    return 1;
  }
  return 0;
}
function AuditRecoveryModal({
  gate,
  phase,
  error,
  connectError,
  connectStarting,
  connectFlow,
  approvalGate,
  onClose,
  onPrimaryAction,
  onStartConnect,
  onApprovalSubmit,
  onApprovalBack
}) {
  const [approvalPassword, setApprovalPassword] = reactExports.useState("");
  const [approvalTotpCode, setApprovalTotpCode] = reactExports.useState("");
  const [approvalSubmitting, setApprovalSubmitting] = reactExports.useState(false);
  reactExports.useEffect(() => {
    if (phase === "syncing" || phase === "connecting" || phase === "auditing") {
      return;
    }
    if (phase === "approval") {
      setApprovalSubmitting(false);
      return;
    }
    setApprovalPassword("");
    setApprovalTotpCode("");
    setApprovalSubmitting(false);
  }, [phase]);
  const activeStep = resolveActiveStepIndex(gate, phase);
  const primaryBusy = phase === "syncing" || phase === "connecting" || phase === "auditing";
  const PrimaryIcon = resolvePrimaryIcon(gate, phase);
  const showConnectFlow = gate.primaryAction === "connect" && connectFlow !== null && phase !== "auditing";
  const showApprovalStep = phase === "approval";
  const handlePrimaryClick = reactExports.useCallback(() => {
    if (primaryBusy) {
      return;
    }
    onPrimaryAction();
  }, [onPrimaryAction, primaryBusy]);
  const handleApprovalPasswordChange = reactExports.useCallback((event) => {
    setApprovalPassword(event.target.value);
  }, []);
  const handleApprovalTotpCodeChange = reactExports.useCallback((event) => {
    setApprovalTotpCode(event.target.value);
  }, []);
  const handleApprovalSubmit = reactExports.useCallback(() => {
    setApprovalSubmitting(true);
    onApprovalSubmit(buildApprovalProofCredentials(approvalGate, { approvalPassword, approvalTotpCode }));
  }, [approvalGate, approvalPassword, approvalTotpCode, onApprovalSubmit]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(GuardModalLayer, { ariaLabel: "Finish workspace audit setup", onClose, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-white shadow-xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-5 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue", children: "Workspace audit" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: resolvePhaseTone(phase), children: resolvePhaseLabel(phase) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold tracking-[-0.02em] text-brand-dark", children: gate.headline }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-xl text-sm leading-relaxed text-slate-600", children: gate.detail })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: onClose,
          className: "shrink-0 text-sm font-medium text-slate-500 hover:text-brand-dark",
          children: "Close"
        }
      )
    ] }) }),
    showConnectFlow ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConnectFlowCard,
      {
        minimal: true,
        purpose: "audit",
        mode: "repair",
        connectFlow,
        connectStarting,
        connectError,
        headline: gate.headline,
        detail: gate.detail,
        onStartConnect
      }
    ) : showApprovalStep ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-5 py-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofInline,
      {
        approvalGate,
        approvalPassword,
        approvalTotpCode,
        error,
        submitLabel: "Sync supply-chain intel",
        submitBusy: approvalSubmitting,
        onApprovalPasswordChange: handleApprovalPasswordChange,
        onApprovalTotpCodeChange: handleApprovalTotpCodeChange,
        onSubmit: handleApprovalSubmit,
        onBack: onApprovalBack
      }
    ) }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-5 px-5 py-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "grid gap-3 sm:grid-cols-2", children: gate.steps.map((step, index) => {
        const stepNumber = index + 1;
        const isActive = stepNumber === activeStep;
        const isComplete = stepNumber < activeStep;
        return /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "li",
          {
            className: `rounded-xl border px-3 py-3 ${isActive ? "border-brand-blue/25 bg-brand-blue/[0.04]" : isComplete ? "border-slate-200 bg-slate-50/80" : "border-slate-200 bg-white"}`,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-500", children: [
                "Step ",
                stepNumber,
                isComplete ? " · Done" : isActive ? " · In progress" : ""
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-semibold text-brand-dark", children: step.title }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-slate-600", children: step.body })
            ]
          },
          step.title
        );
      }) }),
      error !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-attention", role: "alert", children: error }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: handlePrimaryClick, disabled: primaryBusy, children: [
          primaryBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-4 w-4 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(PrimaryIcon, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          resolvePrimaryLabel(gate, phase)
        ] }),
        gate.primaryAction === "connect" && connectFlow?.authorize_url ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: connectFlow.authorize_url, variant: "outline", children: [
          "Open sign-in",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "ml-1.5 h-3.5 w-3.5", "aria-hidden": "true" })
        ] }) : null
      ] })
    ] })
  ] }) });
}
function actionLabel(op) {
  return op.charAt(0).toUpperCase() + op.slice(1);
}
function LoadingRow({ width }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `h-4 animate-pulse rounded-md bg-slate-100 ${width}`, "aria-hidden": "true" });
}
function LoadingSkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "space-y-3 px-4 py-5",
      "aria-label": "Loading package firewall status",
      "aria-busy": "true",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingRow, { width: "w-1/3" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingRow, { width: "w-2/3" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingRow, { width: "w-1/2" })
      ]
    }
  );
}
function ErrorBanner({ message, onRetry }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 px-4 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationTriangle,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-attention", children: message })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onRetry, children: "Retry" })
  ] });
}
function RefreshButton({ disabled, spinning, onRefresh }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ActionButton,
    {
      variant: "ghost",
      onClick: onRefresh,
      disabled,
      "aria-label": "Refresh status",
      children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: `h-4 w-4 ${spinning ? "animate-spin" : ""}`,
          "aria-hidden": "true"
        }
      )
    }
  );
}
const PackageFirewallPanel = reactExports.forwardRef(function PackageFirewallPanel2(props, ref) {
  const {
    approvalGate,
    auditWorkspaceDir,
    onAuditConnectGateChange,
    onAuditErrorChange,
    onStateChanged,
    onAuditCompleted,
    onAuditStarted,
    onAuditRunningChange,
    runAuditRef
  } = props;
  const rootRef = reactExports.useRef(null);
  const recoveryConnectHandledRef = reactExports.useRef(false);
  const [panelLoad, setPanelLoad] = reactExports.useState({ phase: "loading" });
  const [pendingOp, setPendingOp] = reactExports.useState(null);
  const [lastCompleted, setLastCompleted] = reactExports.useState(null);
  const [lastFailed, setLastFailed] = reactExports.useState(null);
  const [connectError, setConnectError] = reactExports.useState(null);
  const [activationAssistError, setActivationAssistError] = reactExports.useState(null);
  const [startingConnect, setStartingConnect] = reactExports.useState(false);
  const [activatingRuntime, setActivatingRuntime] = reactExports.useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = reactExports.useState(null);
  const [pendingApprovalOp, setPendingApprovalOp] = reactExports.useState(null);
  const [statusFilter, setStatusFilter] = reactExports.useState("all");
  const [managerFilter, setManagerFilter] = reactExports.useState("");
  const [interceptProof, setInterceptProof] = reactExports.useState(null);
  const [managerDrawerTarget, setManagerDrawerTarget] = reactExports.useState(null);
  const [auditConnectGateActive, setAuditConnectGateActive] = reactExports.useState(false);
  const [resumeAuditAfterConnect, setResumeAuditAfterConnect] = reactExports.useState(false);
  const [auditRecoveryGate, setAuditRecoveryGate] = reactExports.useState(null);
  const [auditRecoveryPhase, setAuditRecoveryPhase] = reactExports.useState("ready");
  const [auditRecoveryError, setAuditRecoveryError] = reactExports.useState(null);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);
  const openSyncApprovalRecovery = reactExports.useCallback(
    async (options) => {
      await resolveApprovalGate();
      setAuditRecoveryGate(
        createSupplyChainSyncApprovalGate({
          autoRetryAuditAfterPrimary: options?.autoRetryAuditAfterPrimary ?? auditRecoveryGate?.autoRetryAuditAfterPrimary ?? false
        })
      );
      setAuditRecoveryPhase("approval");
      setAuditRecoveryError(null);
    },
    [resolveApprovalGate]
  );
  const closeAuditRecovery = reactExports.useCallback(() => {
    setAuditRecoveryGate(null);
    setAuditRecoveryPhase("ready");
    setAuditRecoveryError(null);
  }, []);
  const load = reactExports.useCallback(async () => {
    setPanelLoad({ phase: "loading" });
    try {
      const data = await fetchPackageFirewallStatus();
      setPanelLoad({ phase: "loaded", data });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load package firewall status.";
      setPanelLoad({ phase: "error", message });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  const refreshAfterOp = reactExports.useCallback(async () => {
    try {
      const data = await fetchPackageFirewallStatus();
      setPanelLoad({ phase: "loaded", data });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to refresh package firewall status.";
      setPanelLoad({ phase: "error", message });
    }
  }, []);
  reactExports.useEffect(() => {
    if (panelLoad.phase !== "loaded") {
      return;
    }
    const flow = panelLoad.data.connect_flow;
    if (flow === null || flow.state !== "running" && flow.state !== "starting") {
      return;
    }
    const handle = window.setTimeout(() => {
      void refreshAfterOp();
    }, flow.poll_after_ms ?? 1500);
    return () => window.clearTimeout(handle);
  }, [panelLoad, refreshAfterOp]);
  const openAuditConnectGate = reactExports.useCallback((resumeAfterConnect) => {
    setAuditConnectGateActive(true);
    setResumeAuditAfterConnect(resumeAfterConnect);
    setLastFailed(null);
    rootRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, []);
  const clearAuditConnectGate = reactExports.useCallback(() => {
    setAuditConnectGateActive(false);
    setResumeAuditAfterConnect(false);
  }, []);
  const runAuditOperation = reactExports.useCallback(
    async (options) => {
      const openRecoveryModal = options?.openRecoveryModal ?? true;
      setPendingOp({ op: "audit", manager: null });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      onAuditErrorChange?.(null);
      onAuditStarted?.();
      onAuditRunningChange?.(true);
      const statusWorkspaceDir = panelLoad.phase === "loaded" ? panelLoad.data.audit_workspace_dir ?? null : null;
      const workspaceDir = resolveSupplyChainAuditWorkspaceTarget({
        managedWorkspaceDir: auditWorkspaceDir,
        statusWorkspaceDir
      });
      try {
        const response = await runPackageAudit({ workspaceDir });
        const recoveryGate = resolveSupplyChainAuditRecoveryGate(response.result_detail);
        const failureMessage = resolveSupplyChainAuditFailure(response.result_detail);
        if (failureMessage !== null) {
          if (openRecoveryModal && recoveryGate !== null) {
            setAuditRecoveryGate(recoveryGate);
            setAuditRecoveryPhase("ready");
            setAuditRecoveryError(null);
            onAuditErrorChange?.(null);
            clearAuditConnectGate();
            await refreshAfterOp();
            await onStateChanged?.();
            return false;
          }
          setLastFailed({ op: "audit", manager: null, message: failureMessage });
          setLastCompleted(null);
          onAuditErrorChange?.(failureMessage);
          clearAuditConnectGate();
          await refreshAfterOp();
          await onStateChanged?.();
          return false;
        }
        setLastCompleted({ op: "audit", manager: null, response });
        onAuditCompleted?.(response.result_detail);
        clearAuditConnectGate();
        closeAuditRecovery();
        onAuditErrorChange?.(null);
        await refreshAfterOp();
        await onStateChanged?.();
        return true;
      } catch (err) {
        if (isSupplyChainAuditConnectError(err)) {
          openAuditConnectGate(true);
          return false;
        }
        const message = supplyChainAuditUserMessage(err) ?? "Operation failed.";
        setLastFailed({ op: "audit", manager: null, message });
        onAuditErrorChange?.(message);
        setAuditRecoveryPhase("failed");
        setAuditRecoveryError(message);
        return false;
      } finally {
        onAuditRunningChange?.(false);
        setPendingOp(null);
      }
    },
    [
      auditWorkspaceDir,
      clearAuditConnectGate,
      closeAuditRecovery,
      onAuditCompleted,
      onAuditStarted,
      onAuditErrorChange,
      onAuditRunningChange,
      onStateChanged,
      openAuditConnectGate,
      panelLoad,
      refreshAfterOp
    ]
  );
  const continueAuditAfterRecovery = reactExports.useCallback(async () => {
    setAuditRecoveryPhase("auditing");
    setAuditRecoveryError(null);
    const succeeded = await runAuditOperation({ openRecoveryModal: true });
    if (succeeded) {
      return;
    }
    setAuditRecoveryPhase((currentPhase) => currentPhase === "failed" ? "failed" : "ready");
  }, [runAuditOperation]);
  const runRecoverySync = reactExports.useCallback(
    async (credentials) => {
      setAuditRecoveryPhase("syncing");
      setAuditRecoveryError(null);
      try {
        const response = await runPackageSync(credentials);
        setLastCompleted({ op: "sync", manager: null, response });
        await refreshAfterOp();
        await onStateChanged?.();
        if (auditRecoveryGate?.autoRetryAuditAfterPrimary) {
          await continueAuditAfterRecovery();
          return;
        }
        setAuditRecoveryPhase("ready");
      } catch (err) {
        if (isSupplyChainSyncConnectError(err)) {
          const connectGate = resolveSupplyChainSyncConnectRecoveryGate(err);
          if (connectGate !== null) {
            setAuditRecoveryGate(connectGate);
            setAuditRecoveryPhase("ready");
            setAuditRecoveryError(null);
            return;
          }
        }
        if (isSupplyChainSyncRetryableError(err)) {
          const message = readHarnessActionUserMessage(
            err,
            "Guard Cloud is temporarily unavailable. Try syncing again in a few minutes."
          );
          setAuditRecoveryError(message);
          setAuditRecoveryPhase("ready");
          setLastFailed({ op: "sync", manager: null, message });
          return;
        }
        const failure = resolveApprovalGateSyncFailure(err, {
          hasCredentials: credentials !== void 0
        });
        if (failure.kind === "approval_required") {
          await openSyncApprovalRecovery({
            autoRetryAuditAfterPrimary: auditRecoveryGate?.autoRetryAuditAfterPrimary ?? true
          });
          return;
        }
        setAuditRecoveryError(failure.message);
        setAuditRecoveryPhase(credentials === void 0 ? "failed" : "approval");
        setLastFailed({ op: "sync", manager: null, message: failure.message });
      }
    },
    [
      auditRecoveryGate,
      continueAuditAfterRecovery,
      onStateChanged,
      openSyncApprovalRecovery,
      refreshAfterOp
    ]
  );
  const handleRecoveryApprovalBack = reactExports.useCallback(() => {
    setAuditRecoveryPhase("ready");
    setAuditRecoveryError(null);
  }, []);
  const handleRecoveryApprovalSubmit = reactExports.useCallback(
    (credentials) => {
      void runRecoverySync(credentials);
    },
    [runRecoverySync]
  );
  const handleStartConnect = reactExports.useCallback(async () => {
    setStartingConnect(true);
    setConnectError(null);
    setActivationAssistError(null);
    try {
      const connectFlow = await startPackageFirewallConnect();
      if (connectFlow?.authorize_url && !openPackageFirewallAuthorizeFallback(
        connectFlow.authorize_url,
        connectFlow.browser_opened
      )) {
        setConnectError(PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE);
      }
      await refreshAfterOp();
      await onStateChanged?.();
    } catch (error) {
      setConnectError(
        error instanceof Error ? error.message : "Unable to start Guard Cloud connect."
      );
    } finally {
      setStartingConnect(false);
    }
  }, [onStateChanged, refreshAfterOp]);
  const handleRecoveryPrimary = reactExports.useCallback(() => {
    if (auditRecoveryGate === null || auditRecoveryPhase !== "ready" && auditRecoveryPhase !== "failed") {
      return;
    }
    if (auditRecoveryGate.primaryAction === "sync") {
      void runRecoverySync();
      return;
    }
    if (auditRecoveryGate.primaryAction === "connect") {
      setAuditRecoveryPhase("connecting");
      setAuditRecoveryError(null);
      void handleStartConnect();
      return;
    }
    void continueAuditAfterRecovery();
  }, [
    auditRecoveryGate,
    auditRecoveryPhase,
    continueAuditAfterRecovery,
    handleStartConnect,
    runRecoverySync
  ]);
  reactExports.useEffect(() => {
    if (panelLoad.phase !== "loaded" || !auditConnectGateActive) {
      onAuditConnectGateChange?.(null);
      return;
    }
    const gate = resolveSupplyChainAuditConnectGate(panelLoad.data, {
      resumeAfterConnect: resumeAuditAfterConnect
    });
    if (gate === null || panelLoad.data.connect_flow === null) {
      onAuditConnectGateChange?.(null);
      return;
    }
    onAuditConnectGateChange?.({
      gate,
      connectError,
      connectStarting: startingConnect,
      connectFlow: panelLoad.data.connect_flow,
      onStartConnect: () => {
        void handleStartConnect();
      }
    });
  }, [
    auditConnectGateActive,
    connectError,
    handleStartConnect,
    onAuditConnectGateChange,
    panelLoad,
    resumeAuditAfterConnect,
    startingConnect
  ]);
  reactExports.useEffect(() => {
    if (panelLoad.phase !== "loaded" || !resumeAuditAfterConnect) {
      return;
    }
    if (!panelLoad.data.entitlement.allowed || packageAuditNeedsCloudConnect(panelLoad.data)) {
      return;
    }
    setResumeAuditAfterConnect(false);
    void runAuditOperation();
  }, [panelLoad, resumeAuditAfterConnect, runAuditOperation]);
  reactExports.useEffect(() => {
    if (auditRecoveryPhase === "connecting") {
      recoveryConnectHandledRef.current = false;
    }
  }, [auditRecoveryPhase]);
  reactExports.useEffect(() => {
    if (panelLoad.phase !== "loaded" || auditRecoveryGate === null) {
      return;
    }
    if (auditRecoveryPhase !== "connecting") {
      return;
    }
    if (recoveryConnectHandledRef.current) {
      return;
    }
    if (!panelLoad.data.entitlement.allowed || packageAuditNeedsCloudConnect(panelLoad.data)) {
      return;
    }
    recoveryConnectHandledRef.current = true;
    void runRecoverySync();
  }, [auditRecoveryGate, auditRecoveryPhase, panelLoad, runRecoverySync]);
  const handleAction = reactExports.useCallback(
    async (op, manager, credentials) => {
      setPendingOp({ op, manager });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      try {
        const response = await runPackageFirewallAction(op, manager, credentials);
        setLastCompleted({ op, manager, response });
        if (op === "test") {
          const proof = parseInterceptProofSnapshot(response);
          if (proof !== null) {
            setManagerDrawerTarget(null);
            setInterceptProof(proof);
          }
        }
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        if (credentials === void 0 && manager !== null && isApprovalGateRequiredError(err)) {
          await resolveApprovalGate();
          setPendingApprovalOp({ op, manager });
          return;
        }
        const message = err instanceof Error ? err.message : "Action failed.";
        setLastFailed({ op, manager, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, refreshAfterOp, resolveApprovalGate]
  );
  const handleGlobalOp = reactExports.useCallback(
    async (op) => {
      if (op === "audit") {
        if (panelLoad.phase === "loaded" && packageAuditNeedsCloudConnect(panelLoad.data)) {
          openAuditConnectGate(true);
          return;
        }
        await runAuditOperation();
        return;
      }
      setPendingOp({ op, manager: null });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      try {
        const response = await runPackageSync();
        setLastCompleted({ op, manager: null, response });
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        if (isApprovalGateRequiredError(err)) {
          await openSyncApprovalRecovery();
          return;
        }
        if (isSupplyChainSyncConnectError(err)) {
          const connectGate = resolveSupplyChainSyncConnectRecoveryGate(err);
          if (connectGate !== null) {
            setAuditRecoveryGate(connectGate);
            setAuditRecoveryPhase("ready");
            setAuditRecoveryError(null);
            return;
          }
        }
        if (isSupplyChainSyncRetryableError(err)) {
          const message2 = readHarnessActionUserMessage(
            err,
            "Guard Cloud is temporarily unavailable. Try syncing again in a few minutes."
          );
          setAuditRecoveryPhase("ready");
          setAuditRecoveryError(message2);
          setLastFailed({ op, manager: null, message: message2 });
          return;
        }
        const message = readHarnessActionUserMessage(err, "Operation failed.");
        setLastFailed({ op, manager: null, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, openAuditConnectGate, openSyncApprovalRecovery, panelLoad, refreshAfterOp, runAuditOperation]
  );
  const handleInstall = reactExports.useCallback(
    (manager) => void handleAction("install", manager),
    [handleAction]
  );
  const handleRepair = reactExports.useCallback(
    (manager) => void handleAction("repair", manager),
    [handleAction]
  );
  const handleTest = reactExports.useCallback(
    (manager) => void handleAction("test", manager),
    [handleAction]
  );
  const handleRemoveRequest = reactExports.useCallback(
    (manager) => setConfirmRemoveManager(manager),
    []
  );
  const handleRemoveConfirm = reactExports.useCallback(
    (manager) => {
      setConfirmRemoveManager(null);
      void handleAction("remove", manager);
    },
    [handleAction]
  );
  const handleRemoveCancel = reactExports.useCallback(() => setConfirmRemoveManager(null), []);
  const handleAudit = reactExports.useCallback(() => {
    if (panelLoad.phase === "loaded" && packageAuditNeedsCloudConnect(panelLoad.data)) {
      openAuditConnectGate(true);
      return;
    }
    void runAuditOperation();
  }, [openAuditConnectGate, panelLoad, runAuditOperation]);
  const handleSync = reactExports.useCallback(() => void handleGlobalOp("sync"), [handleGlobalOp]);
  reactExports.useEffect(() => {
    if (runAuditRef === void 0) {
      return;
    }
    runAuditRef.current = handleAudit;
    return () => {
      runAuditRef.current = null;
    };
  }, [handleAudit, runAuditRef]);
  const handleDismissResult = reactExports.useCallback(() => setLastCompleted(null), []);
  const handleRetry = reactExports.useCallback(() => void load(), [load]);
  const handleActivateRuntime = reactExports.useCallback(async () => {
    setActivatingRuntime(true);
    setActivationAssistError(null);
    try {
      await activatePackageFirewallRuntime();
      await refreshAfterOp();
      await onStateChanged?.();
    } catch (error) {
      setActivationAssistError(error instanceof Error ? error.message : "Unable to activate package protection.");
    } finally {
      setActivatingRuntime(false);
    }
  }, [onStateChanged, refreshAfterOp]);
  const handleApprovalCancel = reactExports.useCallback(() => setPendingApprovalOp(null), []);
  const handleApprovalConfirm = reactExports.useCallback(
    (credentials) => {
      const pendingApproval = pendingApprovalOp;
      if (pendingApproval === null) return;
      setPendingApprovalOp(null);
      void handleAction(pendingApproval.op, pendingApproval.manager, credentials);
    },
    [handleAction, pendingApprovalOp]
  );
  const handleStatusFilterChange = reactExports.useCallback((filter) => {
    setStatusFilter(filter);
  }, []);
  const handleManagerFilterChange = reactExports.useCallback((e) => {
    setManagerFilter(e.target.value);
  }, []);
  const handleOpenManagerDetails = reactExports.useCallback((manager) => {
    setManagerDrawerTarget(manager);
  }, []);
  const handleCloseManagerDrawer = reactExports.useCallback(() => {
    setManagerDrawerTarget(null);
  }, []);
  const handleCloseInterceptProof = reactExports.useCallback(() => {
    setInterceptProof(null);
  }, []);
  reactExports.useImperativeHandle(
    ref,
    () => ({
      scrollIntoView: () => {
        rootRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      },
      focusUnprotected: () => {
        setStatusFilter("unprotected");
        setManagerFilter("");
      },
      focusActionable: () => {
        setStatusFilter("actionable");
        setManagerFilter("");
      },
      runAudit: () => {
        handleAudit();
      },
      startConnect: handleStartConnect,
      activateRuntime: handleActivateRuntime
    }),
    [handleActivateRuntime, handleAudit, handleStartConnect]
  );
  const managerDrawerShim = panelLoad.phase === "loaded" && managerDrawerTarget !== null ? panelLoad.data.package_shims.find((entry) => entry.manager === managerDrawerTarget) : void 0;
  const auditConnectGate = panelLoad.phase === "loaded" && auditConnectGateActive ? resolveSupplyChainAuditConnectGate(panelLoad.data, { resumeAfterConnect: resumeAuditAfterConnect }) : null;
  const anyPending = pendingOp !== null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: rootRef, className: "rounded-2xl border border-slate-100 bg-white shadow-sm", "data-testid": "package-firewall-panel", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-4 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Package manager firewall" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-500", children: "Install Guard shims, activate PATH routing, and verify protection on this machine." })
      ] }),
      panelLoad.phase === "loaded" && /* @__PURE__ */ jsxRuntimeExports.jsx(RefreshButton, { disabled: anyPending, spinning: anyPending, onRefresh: handleRetry })
    ] }),
    panelLoad.phase === "loading" && /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSkeleton, {}),
    panelLoad.phase === "error" && /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorBanner, { message: panelLoad.message, onRetry: handleRetry }),
    panelLoad.phase === "loaded" && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      !panelLoad.data.entitlement.allowed && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EntitlementNotice,
        {
          connectError,
          connectPurpose: auditConnectGateActive ? "audit" : "package_firewall",
          connectStarting: startingConnect,
          data: panelLoad.data,
          headline: auditConnectGate?.headline,
          detail: auditConnectGate?.detail,
          onStartConnect: handleStartConnect
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FirewallControlsView,
        {
          data: panelLoad.data,
          pendingOp,
          lastCompleted,
          lastFailed,
          confirmRemoveManager,
          showGlobalActions: panelLoad.data.entitlement.allowed,
          statusFilter,
          managerFilter,
          onStatusFilterChange: handleStatusFilterChange,
          onManagerFilterChange: handleManagerFilterChange,
          onInstall: handleInstall,
          onRepair: handleRepair,
          onTest: handleTest,
          onRemoveRequest: handleRemoveRequest,
          onRemoveConfirm: handleRemoveConfirm,
          onRemoveCancel: handleRemoveCancel,
          onAudit: handleAudit,
          onSync: handleSync,
          onDismissResult: handleDismissResult,
          onActivateRuntime: handleActivateRuntime,
          onRefreshStatus: handleRetry,
          onOpenManagerDetails: handleOpenManagerDetails,
          activatingRuntime,
          activationAssistError
        }
      )
    ] }),
    pendingApprovalOp !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: `${actionLabel(pendingApprovalOp.op)} ${pendingApprovalOp.manager}`,
        detail: "Enter local approval proof before Guard changes package-manager protection on this device.",
        confirmLabel: actionLabel(pendingApprovalOp.op),
        approvalGate: resolvedApprovalGate,
        onCancel: handleApprovalCancel,
        onConfirm: handleApprovalConfirm
      }
    ),
    panelLoad.phase === "loaded" && managerDrawerTarget !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(
      SupplyChainManagerDrawer,
      {
        manager: managerDrawerTarget,
        shim: managerDrawerShim,
        actions: panelLoad.data.actions,
        anyPending,
        isMine: pendingOp?.manager === managerDrawerTarget,
        actionHandlers: {
          install: handleInstall,
          repair: handleRepair,
          test: handleTest,
          removeRequest: handleRemoveRequest
        },
        onClose: handleCloseManagerDrawer
      }
    ),
    interceptProof !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(InterceptProofModal, { proof: interceptProof, onClose: handleCloseInterceptProof }),
    auditRecoveryGate !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      AuditRecoveryModal,
      {
        gate: auditRecoveryGate,
        phase: auditRecoveryPhase,
        error: auditRecoveryError,
        connectError,
        connectStarting: startingConnect,
        connectFlow: panelLoad.phase === "loaded" ? panelLoad.data.connect_flow : null,
        approvalGate: resolvedApprovalGate,
        onClose: closeAuditRecovery,
        onPrimaryAction: handleRecoveryPrimary,
        onStartConnect: () => {
          setAuditRecoveryPhase("connecting");
          void handleStartConnect();
        },
        onApprovalSubmit: handleRecoveryApprovalSubmit,
        onApprovalBack: handleRecoveryApprovalBack
      }
    ) : null
  ] });
});
function useSupplyChainAuditSession({
  snapshot,
  onNavigate
}) {
  const [auditSnapshot, setAuditSnapshot] = reactExports.useState(null);
  const [auditRunning, setAuditRunning] = reactExports.useState(false);
  const [auditError, setAuditError] = reactExports.useState(null);
  const [auditConnectGate, setAuditConnectGate] = reactExports.useState(null);
  const [auditPhase, setAuditPhase] = reactExports.useState("idle");
  const runAuditRef = reactExports.useRef(null);
  const phaseTimersRef = reactExports.useRef([]);
  const auditPhaseRef = reactExports.useRef("idle");
  const setAuditPhaseLive = reactExports.useCallback((phase) => {
    auditPhaseRef.current = phase;
    setAuditPhase(phase);
  }, []);
  const clearPhaseTimers = reactExports.useCallback(() => {
    for (const timer of phaseTimersRef.current) {
      window.clearTimeout(timer);
    }
    phaseTimersRef.current = [];
  }, []);
  const schedulePhase = reactExports.useCallback(
    (phase, delayMs) => {
      const timer = window.setTimeout(() => {
        setAuditPhaseLive(phase);
        phaseTimersRef.current = phaseTimersRef.current.filter((entry) => entry !== timer);
      }, delayMs);
      phaseTimersRef.current.push(timer);
    },
    [setAuditPhaseLive]
  );
  reactExports.useEffect(() => {
    let cancelled = false;
    const loadReceiptEvidence = async () => {
      try {
        const receipts = await fetchReceipts();
        if (cancelled) {
          return;
        }
        setAuditSnapshot(derivePackageWorkbenchFromReceipts(receipts));
      } catch {
        if (!cancelled) {
          setAuditSnapshot(null);
        }
      }
    };
    void loadReceiptEvidence();
    return () => {
      cancelled = true;
    };
  }, [snapshot.generated_at, snapshot.receipt_count]);
  reactExports.useEffect(() => () => clearPhaseTimers(), [clearPhaseTimers]);
  const handleAuditStarted = reactExports.useCallback(() => {
    clearPhaseTimers();
    onNavigate("/audit");
    setAuditPhaseLive("preparing");
    schedulePhase("scanning", 400);
    schedulePhase("evaluating", 1600);
  }, [clearPhaseTimers, onNavigate, schedulePhase, setAuditPhaseLive]);
  const handleAuditCompleted = reactExports.useCallback(
    (resultDetail) => {
      clearPhaseTimers();
      setAuditPhaseLive("finalizing");
      const failureMessage = resolveSupplyChainAuditFailure(resultDetail);
      if (failureMessage !== null) {
        setAuditSnapshot(null);
        setAuditError(failureMessage);
        setAuditPhaseLive("idle");
        return;
      }
      const normalized = normalizeSupplyChainAuditSnapshot(resultDetail);
      setAuditSnapshot(normalized);
      setAuditError(null);
      const timer = window.setTimeout(() => setAuditPhaseLive("idle"), 600);
      phaseTimersRef.current.push(timer);
    },
    [clearPhaseTimers, setAuditPhaseLive]
  );
  const handleAuditErrorChange = reactExports.useCallback(
    (message) => {
      setAuditError(message);
      if (message !== null) {
        clearPhaseTimers();
        setAuditPhaseLive("idle");
      }
    },
    [clearPhaseTimers, setAuditPhaseLive]
  );
  const handleAuditRunningChange = reactExports.useCallback(
    (running) => {
      setAuditRunning(running);
      if (!running && auditPhaseRef.current !== "finalizing") {
        clearPhaseTimers();
        setAuditPhaseLive("idle");
      }
    },
    [clearPhaseTimers, setAuditPhaseLive]
  );
  const handleRunAudit = reactExports.useCallback(() => {
    runAuditRef.current?.();
  }, []);
  return {
    auditSnapshot,
    auditRunning,
    auditError,
    auditConnectGate,
    auditPhase,
    runAuditRef,
    setAuditConnectGate,
    handleAuditStarted,
    handleAuditCompleted,
    handleAuditErrorChange,
    handleAuditRunningChange,
    handleRunAudit
  };
}
const SupplyChainWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./supply-chain-workspace.js"), true ? __vite__mapDeps([0,1,2,3,4,5]) : void 0).then((m) => ({ default: m.SupplyChainWorkspace }))
);
const AuditWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./audit-workspace.js"), true ? __vite__mapDeps([6,1,2,5]) : void 0).then((m) => ({ default: m.AuditWorkspace }))
);
const FeedHealthWorkspace = reactExports.lazy(
  () => __vitePreload(() => import("./feed-health-workspace.js"), true ? __vite__mapDeps([3,1,2]) : void 0).then((m) => ({ default: m.FeedHealthWorkspace }))
);
const hubTabs = [
  { value: "supply-chain", label: "Supply Chain" },
  { value: "audit", label: "Audit" },
  { value: "feed-health", label: "Feed Health" }
];
function hubTitleForTab(tab) {
  return hubTabs.find((item) => item.value === tab)?.label ?? "Supply Chain";
}
function viewToTab(view) {
  if (view === "supply-chain" || view === "audit" || view === "feed-health") {
    return view;
  }
  return "supply-chain";
}
function SupplyChainHubWorkspace(props) {
  const tab = viewToTab(props.activeView);
  const firewallPanelRef = reactExports.useRef(null);
  const auditSession = useSupplyChainAuditSession({
    snapshot: props.snapshot,
    onNavigate: props.onNavigate
  });
  const auditWorkspaceDir = reactExports.useMemo(
    () => resolveSupplyChainAuditWorkspaceDir(props.snapshot.managed_installs ?? []),
    [props.snapshot.managed_installs]
  );
  const handleTabChange = reactExports.useCallback(
    (value) => {
      const path = value === "supply-chain" ? "/supply-chain" : `/${value}`;
      props.onNavigate(path);
    },
    [props.onNavigate]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkspacePageHeader,
      {
        eyebrow: "Supply chain",
        title: hubTitleForTab(tab),
        tabs: hubTabs,
        activeTab: tab,
        onTabChange: handleTabChange
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(reactExports.Suspense, { fallback: /* @__PURE__ */ jsxRuntimeExports.jsx(LazyFallback, {}), children: [
      tab === "supply-chain" && /* @__PURE__ */ jsxRuntimeExports.jsx(
        SupplyChainWorkspace,
        {
          snapshot: props.snapshot,
          onGoHome: props.onGoHome,
          onRuntimeRefresh: props.onRuntimeRefresh,
          firewallPanelRef,
          onAuditNavigate: () => props.onNavigate("/audit"),
          auditSnapshot: auditSession.auditSnapshot,
          auditRunning: auditSession.auditRunning
        }
      ),
      tab === "audit" && /* @__PURE__ */ jsxRuntimeExports.jsx(
        AuditWorkspace,
        {
          snapshot: props.snapshot,
          receipts: props.receipts,
          approvalGate: props.approvalGate,
          auditSession
        }
      ),
      tab === "feed-health" && /* @__PURE__ */ jsxRuntimeExports.jsx(FeedHealthWorkspace, { snapshot: props.snapshot, onOpenSettings: props.onOpenSettings })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: tab === "supply-chain" ? void 0 : "hidden", "aria-hidden": tab !== "supply-chain", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      PackageFirewallPanel,
      {
        ref: firewallPanelRef,
        approvalGate: props.approvalGate,
        auditWorkspaceDir,
        onAuditConnectGateChange: auditSession.setAuditConnectGate,
        onAuditErrorChange: auditSession.handleAuditErrorChange,
        onStateChanged: props.onRuntimeRefresh,
        onAuditStarted: auditSession.handleAuditStarted,
        onAuditCompleted: auditSession.handleAuditCompleted,
        onAuditRunningChange: auditSession.handleAuditRunningChange,
        runAuditRef: auditSession.runAuditRef
      }
    ) })
  ] });
}
function LazyFallback() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex min-h-[200px] items-center justify-center", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-48" }) });
}
const supplyChainHubWorkspace = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  SupplyChainHubWorkspace,
  hubTitleForTab
}, Symbol.toStringTag, { value: "Module" }));
export {
  ApprovalProofModal as A,
  SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS as S,
  supplyChainHubWorkspace as a,
  filterPackageWorkbenchFindings as f,
  isApprovalGateRequiredError as i,
  packageWorkbenchEcosystems as p,
  sortPackageWorkbenchFindings as s,
  useResolvedApprovalGate as u
};
