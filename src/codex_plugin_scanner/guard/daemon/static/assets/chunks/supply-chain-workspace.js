import { au as GuardHarnessActionError, r as reactExports, j as jsxRuntimeExports, d as HiMiniCheckCircle, aw as HiMiniArrowPath, w as HiMiniExclamationTriangle, ac as Tag, m as formatRelativeTime, aG as HiMiniClock, aH as IconActionButton, I as HiMiniXCircle, ax as HiMiniTrash, l as HiMiniShieldCheck, F as HiMiniWrenchScrewdriver, aI as HiMiniBeaker, aJ as ActivationSummary, aK as ActionResultPanel, ad as HiMiniMagnifyingGlass, b as EmptyState, A as ActionButton, aL as HiMiniBugAnt, o as HiMiniXMark, aM as fetchPackageFirewallStatus, aN as runPackageAudit, aO as startPackageFirewallConnect, aP as runPackageFirewallAction, aQ as parseInterceptProofSnapshot, aR as runPackageSync, aS as openPackageFirewallShell, S as SectionLabel, aT as EntitlementNotice, aU as fetchSupplyChainBundle, aE as HiMiniArrowTopRightOnSquare, B as Badge, aV as HiMiniDocumentMagnifyingGlass, aW as HiMiniShieldExclamation, aX as HiMiniComputerDesktop, t as HiMiniCloud, aY as ConnectFlowCard, aZ as HiMiniArrowDown, a_ as HiMiniArrowUp, ah as HiMiniArrowLeft, a$ as HiMiniArrowRight, b0 as HiMiniCloudArrowUp, b1 as HiMiniInformationCircle, b2 as fetchReceipts, h as harnessDisplayName, p as HiMiniChevronUp, q as HiMiniChevronDown } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal, b as buildSupplyChainStats } from "./supply-chain-protection-stats.js";
import { resolveFeedStaleness } from "./feed-health-workspace.js";
import { r as resolveHomeProtectionStatus } from "./home-protection-module.js";
import { S as SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-hub-workspace.js";
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
function isRecord$1(value) {
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
    if (!isRecord$1(entry)) {
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
  if (trimmed.startsWith("GHSA-") || trimmed.startsWith("CVE-")) {
    aliases.add(trimmed);
    return;
  }
  aliases.add(`GHSA-${trimmed.slice(0, 8).toLowerCase()}`);
}
function readAdvisoryIdList(value) {
  if (!Array.isArray(value)) {
    return [];
  }
  return value.filter((entry) => typeof entry === "string" && entry.trim().length > 0).map((entry) => entry.trim());
}
function buildAdvisoryAliasStubs(packageRecord, reasons) {
  const aliases = /* @__PURE__ */ new Set();
  const packageAdvisoryId = readString(packageRecord.advisoryId) ?? readString(packageRecord.advisory_id);
  if (packageAdvisoryId !== null) {
    addAdvisoryAlias(aliases, packageAdvisoryId);
  }
  for (const entry of [
    ...readAdvisoryIdList(packageRecord.related_advisory_ids),
    ...readAdvisoryIdList(packageRecord.relatedAdvisoryIds)
  ]) {
    addAdvisoryAlias(aliases, entry);
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
  if (aliases.size === 0) {
    const severity = resolveFindingSeverity(packageRecord, reasons);
    if (SEVERITY_RANK[severity] >= SEVERITY_RANK.medium) {
      aliases.add("GHSA-alias-pending");
      aliases.add("CVE-alias-pending");
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
    advisoryAliases: buildAdvisoryAliasStubs(packageRecord, reasons),
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
    if (!isRecord$1(entry)) {
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
function isAuditEvidence(value) {
  return isRecord$1(value) && value.operation === "audit";
}
function normalizeSupplyChainAuditSnapshot(raw, receiptId = null) {
  if (!isRecord$1(raw)) {
    return null;
  }
  const evaluation = isRecord$1(raw.evaluation) ? raw.evaluation : null;
  const findingsFromEvidence = normalizePackageFindings(raw.package_findings);
  const findings = findingsFromEvidence.length > 0 ? findingsFromEvidence : packageRecordsFromEvaluation(evaluation);
  const generatedAt = readString(raw.generated_at) ?? readString(raw.generatedAt) ?? (/* @__PURE__ */ new Date(0)).toISOString();
  const inventory = normalizeInventory(isRecord$1(raw.inventory) ? raw.inventory : null);
  const decision = normalizeDecision(evaluation?.decision ?? raw.audit_decision);
  const manifestPaths = readStringArray(raw.manifest_paths);
  const lockfilePaths = readStringArray(raw.lockfile_paths);
  const hasAuditContext = findings.length > 0 || inventory.totalPackages > 0 || manifestPaths.length > 0 || lockfilePaths.length > 0 || evaluation !== null;
  if (!hasAuditContext) {
    return null;
  }
  return {
    generatedAt,
    source: readString(raw.source),
    decision,
    inventory,
    findings,
    manifestPaths,
    lockfilePaths,
    receiptId
  };
}
function derivePackageWorkbenchFromReceipts(receipts) {
  const auditReceipts = receipts.filter((receipt) => receipt.harness === "package-firewall").filter(
    (receipt) => (receipt.scanner_evidence ?? []).some((entry) => isAuditEvidence(entry))
  ).sort((left, right) => Date.parse(right.timestamp) - Date.parse(left.timestamp));
  for (const receipt of auditReceipts) {
    const evidenceRaw = (receipt.scanner_evidence ?? []).find((entry) => isAuditEvidence(entry));
    if (evidenceRaw === void 0 || !isRecord$1(evidenceRaw)) {
      continue;
    }
    const snapshot = normalizeSupplyChainAuditSnapshot(
      {
        generated_at: receipt.timestamp,
        evaluation: {
          decision: evidenceRaw.audit_decision,
          packages: evidenceRaw.package_findings
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
const SUPPLY_CHAIN_AUDIT_CONNECT_ERROR_CODES = [
  "guard_cloud_connect_required",
  "guard_cloud_reconnect_required"
];
function isSupplyChainAuditConnectError(error) {
  if (!(error instanceof GuardHarnessActionError)) {
    return false;
  }
  const code = error.payload?.error;
  return typeof code === "string" && SUPPLY_CHAIN_AUDIT_CONNECT_ERROR_CODES.includes(code);
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
  if (shim.path_broken) {
    return { label: "PATH broken", tone: "attention", icon: "warning" };
  }
  if (shim.activation_state === "protected") {
    return { label: "Protected", tone: "green", icon: "check" };
  }
  if (shim.activation_state === "restart_required") {
    return { label: "Restart required", tone: "blue", icon: "restart" };
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
    shim?.activation_state === "repair_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: cardLayout ? "mt-2" : "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart." }) }),
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
  openingShell,
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
  onOpenShell,
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
        openingShell,
        onOpenShell,
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
    onAuditRunningChange,
    runAuditRef
  } = props;
  const rootRef = reactExports.useRef(null);
  const [panelLoad, setPanelLoad] = reactExports.useState({ phase: "loading" });
  const [pendingOp, setPendingOp] = reactExports.useState(null);
  const [lastCompleted, setLastCompleted] = reactExports.useState(null);
  const [lastFailed, setLastFailed] = reactExports.useState(null);
  const [connectError, setConnectError] = reactExports.useState(null);
  const [activationAssistError, setActivationAssistError] = reactExports.useState(null);
  const [startingConnect, setStartingConnect] = reactExports.useState(false);
  const [openingShell, setOpeningShell] = reactExports.useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = reactExports.useState(null);
  const [pendingApprovalOp, setPendingApprovalOp] = reactExports.useState(null);
  const [statusFilter, setStatusFilter] = reactExports.useState("all");
  const [managerFilter, setManagerFilter] = reactExports.useState("");
  const [interceptProof, setInterceptProof] = reactExports.useState(null);
  const [managerDrawerTarget, setManagerDrawerTarget] = reactExports.useState(null);
  const [auditConnectGateActive, setAuditConnectGateActive] = reactExports.useState(false);
  const [resumeAuditAfterConnect, setResumeAuditAfterConnect] = reactExports.useState(false);
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);
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
    if (flow === null || flow.state !== "running") {
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
    async () => {
      setPendingOp({ op: "audit", manager: null });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      onAuditErrorChange?.(null);
      onAuditRunningChange?.(true);
      const statusWorkspaceDir = panelLoad.phase === "loaded" ? panelLoad.data.audit_workspace_dir ?? null : null;
      const workspaceDir = resolveSupplyChainAuditWorkspaceTarget({
        managedWorkspaceDir: auditWorkspaceDir,
        statusWorkspaceDir
      });
      try {
        const response = await runPackageAudit({ workspaceDir });
        setLastCompleted({ op: "audit", manager: null, response });
        onAuditCompleted?.(response.result_detail);
        clearAuditConnectGate();
        onAuditErrorChange?.(null);
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        if (isSupplyChainAuditConnectError(err)) {
          openAuditConnectGate(true);
          return;
        }
        const message = supplyChainAuditUserMessage(err) ?? "Operation failed.";
        setLastFailed({ op: "audit", manager: null, message });
        onAuditErrorChange?.(message);
      } finally {
        onAuditRunningChange?.(false);
        setPendingOp(null);
      }
    },
    [
      auditWorkspaceDir,
      clearAuditConnectGate,
      onAuditCompleted,
      onAuditErrorChange,
      onAuditRunningChange,
      onStateChanged,
      openAuditConnectGate,
      panelLoad,
      refreshAfterOp
    ]
  );
  const handleStartConnect = reactExports.useCallback(async () => {
    setStartingConnect(true);
    setConnectError(null);
    setActivationAssistError(null);
    try {
      await startPackageFirewallConnect();
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
        if (credentials === void 0 && manager !== null && err instanceof GuardHarnessActionError && err.payload?.error === "approval_gate_required") {
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
        const message = err instanceof Error ? err.message : "Operation failed.";
        setLastFailed({ op, manager: null, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, openAuditConnectGate, panelLoad, refreshAfterOp, runAuditOperation]
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
  const handleOpenShell = reactExports.useCallback(async () => {
    setOpeningShell(true);
    setActivationAssistError(null);
    try {
      await openPackageFirewallShell();
    } catch (error) {
      setActivationAssistError(error instanceof Error ? error.message : "Unable to open a new shell.");
    } finally {
      setOpeningShell(false);
    }
  }, []);
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
      openShell: handleOpenShell
    }),
    [handleAudit, handleOpenShell, handleStartConnect]
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
          onOpenShell: handleOpenShell,
          onRefreshStatus: handleRetry,
          onOpenManagerDetails: handleOpenManagerDetails,
          openingShell,
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
    interceptProof !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(InterceptProofModal, { proof: interceptProof, onClose: handleCloseInterceptProof })
  ] });
});
function SeverityBadge({ severity }) {
  const tone = severity === "critical" || severity === "high" ? "destructive" : severity === "medium" ? "attention" : "default";
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone, children: severity });
}
function AdvisoryRow({ advisory }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3 px-4 py-3 border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-0.5 shrink-0", children: advisory.knownExploited ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 text-red-500", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: advisory.advisoryId }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SeverityBadge, { severity: advisory.normalizedSeverity }),
        advisory.knownExploited && /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "destructive", children: "Known exploited" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-600", children: advisory.title }),
      advisory.summary && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500 line-clamp-2", children: advisory.summary }),
      advisory.recommendedFixVersion && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-green", children: [
        "Fix: ",
        advisory.recommendedFixVersion
      ] })
    ] })
  ] });
}
function SupplyChainBundlePanel() {
  const [bundle, setBundle] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchSupplyChainBundle().then((data) => {
      if (cancelled) return;
      setBundle(data);
      setError(null);
    }).catch((err) => {
      if (cancelled) return;
      setError(err instanceof Error ? err.message : "Failed to load");
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const severityCounts = reactExports.useMemo(() => {
    if (!bundle) return null;
    const counts = {};
    for (const a of bundle.advisories) {
      counts[a.normalizedSeverity] = (counts[a.normalizedSeverity] ?? 0) + 1;
    }
    return counts;
  }, [bundle]);
  const topAdvisories = reactExports.useMemo(() => {
    if (!bundle) return [];
    const severityOrder = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      unknown: 4
    };
    return [...bundle.advisories].sort((a, b) => {
      const sevA = severityOrder[a.normalizedSeverity] ?? 99;
      const sevB = severityOrder[b.normalizedSeverity] ?? 99;
      if (sevA !== sevB) return sevA - sevB;
      return b.confidence - a.confidence;
    }).slice(0, 10);
  }, [bundle]);
  const handleOpenCloud = reactExports.useCallback(() => {
    window.open("https://hol.org/guard", "_blank", "noopener,noreferrer");
  }, []);
  if (loading) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain intel" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-8", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-32 mb-3" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-48 mb-2" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-40" })
      ] })
    ] });
  }
  if (error) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain intel" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "Could not load intel",
          body: error,
          tone: "error"
        }
      ) })
    ] });
  }
  if (!bundle) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain intel" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No intel available",
          body: "Guard has not synced a supply chain bundle yet. Connect to Guard Cloud for live advisory data.",
          tone: "teach"
        }
      ) })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain bundle" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              onClick: handleOpenCloud,
              className: "inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1.5 py-0.5",
              children: [
                "View in cloud",
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3 w-3", "aria-hidden": "true" })
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Signed advisory feed and package risk data." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4 space-y-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Version:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: bundle.bundleVersion })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Advisories:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: bundle.advisories.length })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Packages:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: bundle.packages.length })
          ] })
        ] }),
        bundle.expiresAt && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-400", children: [
          "Expires ",
          formatRelativeTime(bundle.expiresAt)
        ] })
      ] })
    ] }),
    severityCounts && Object.keys(severityCounts).length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Severity breakdown" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-3", children: ["critical", "high", "medium", "low"].map((sev) => {
        const count = severityCounts[sev] ?? 0;
        const tone = sev === "critical" || sev === "high" ? "destructive" : sev === "medium" ? "attention" : "default";
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.15em] text-slate-400", children: sev }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xl font-bold tabular-nums", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone, children: count }) })
        ] }, sev);
      }) }) })
    ] }),
    topAdvisories.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Top advisories" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Highest severity and confidence advisories in this bundle." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: topAdvisories.map((advisory) => /* @__PURE__ */ jsxRuntimeExports.jsx(AdvisoryRow, { advisory }, advisory.advisoryId)) }),
      bundle.advisories.length > 10 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: handleOpenCloud,
          className: "text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1.5 py-0.5",
          children: [
            "View all ",
            bundle.advisories.length,
            " advisories in Guard Cloud"
          ]
        }
      ) })
    ] })
  ] });
}
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function readOperation(value) {
  if (!isRecord(value) || typeof value.operation !== "string") {
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
  const decision = isRecord(evidence) && typeof evidence.audit_decision === "string" ? evidence.audit_decision : receipt.policy_decision;
  const blockedCount = isRecord(evidence) && typeof evidence.blocked_package_count === "number" ? evidence.blocked_package_count : 0;
  const totalPackages = isRecord(evidence) && typeof evidence.total_packages === "number" ? evidence.total_packages : blockedCount;
  const detail = receipt.capabilities_summary.trim().length > 0 ? receipt.capabilities_summary : `Workspace audit returned ${decision} across ${totalPackages} package(s).`;
  return {
    kind: "audit",
    timestamp: receipt.timestamp,
    title: blockedCount > 0 ? `Audit flagged ${blockedCount} package(s)` : "Workspace audit completed",
    detail,
    receiptId: receipt.receipt_id,
    harness: receipt.harness,
    tone: blockedCount > 0 || decision === "block" ? "attention" : "green"
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
const kindLabels = {
  block: "Last block",
  audit: "Last audit",
  sync: "Last sync"
};
const kindIcons = {
  block: HiMiniShieldExclamation,
  audit: HiMiniDocumentMagnifyingGlass,
  sync: HiMiniArrowPath
};
function EvidenceRailRow({ item }) {
  const Icon = kindIcons[item.kind];
  const href = supplyChainEvidenceHref(item.receiptId, item.harness);
  const tagTone = item.tone === "green" ? "green" : item.tone === "attention" ? "attention" : "slate";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "span",
      {
        className: "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-slate-50 text-slate-500",
        "aria-hidden": "true",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4" })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-1.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400", children: kindLabels[item.kind] }),
        item.timestamp !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: tagTone, children: formatRelativeTime(item.timestamp) }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Waiting" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: item.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: item.detail }),
      href !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href,
          className: "inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded",
          children: [
            "Open evidence",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
          ]
        }
      ) : null
    ] })
  ] }) });
}
function SupplyChainEvidenceRail({ rail }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: "overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm",
      "aria-label": "Recent supply chain evidence",
      "data-testid": "supply-chain-evidence-rail",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Recent activity" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-500", children: "The latest blocked install, project audit, and policy sync on this device." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "divide-y divide-slate-100", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceRailRow, { item: rail.block }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceRailRow, { item: rail.audit }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceRailRow, { item: rail.sync })
        ] })
      ]
    }
  );
}
const LOCAL_FREE_CAPABILITIES = [
  { label: "Block risky package installs on this device", available: true },
  { label: "Install and repair package tool protection", available: true },
  { label: "Run workspace audits with on-device rules", available: true },
  { label: "Review recent blocks and audits on this machine", available: true }
];
const CLOUD_CAPABILITIES = [
  { label: "Live package warnings from Guard Cloud", available: false },
  { label: "Sync policy and evidence across devices", available: false },
  { label: "Fleet visibility for connected machines", available: false },
  { label: "Cloud-backed audit and sync actions", available: false }
];
const CLOUD_ACTIVE_CAPABILITIES = CLOUD_CAPABILITIES.map(
  (item) => ({ ...item, available: true })
);
function resolveSupplyChainCloudCapabilities(snapshot) {
  if (snapshot.cloud_state === "paired_active") {
    return {
      mode: "paired_active",
      title: "Guard Cloud connected",
      detail: snapshot.cloud_state_detail.trim().length > 0 ? `${snapshot.cloud_state_detail} Local protection still runs on this device.` : "Live package warnings and synced policy are active. Local protection still runs on this device.",
      tone: "green",
      localHeading: "Still on this device",
      cloudHeading: "Now from Guard Cloud",
      localCapabilities: LOCAL_FREE_CAPABILITIES,
      cloudCapabilities: CLOUD_ACTIVE_CAPABILITIES
    };
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return {
      mode: "paired_waiting",
      title: "Guard Cloud pairing in progress",
      detail: snapshot.cloud_state_detail.trim().length > 0 ? snapshot.cloud_state_detail : "Finish connecting this machine to Guard Cloud. Local package protection stays available while pairing completes.",
      tone: "blue",
      localHeading: "Available now on this device",
      cloudHeading: "Unlocks after pairing",
      localCapabilities: LOCAL_FREE_CAPABILITIES,
      cloudCapabilities: CLOUD_CAPABILITIES
    };
  }
  return {
    mode: "local_only",
    title: "Local protection works on this device",
    detail: snapshot.cloud_state_detail.trim().length > 0 ? snapshot.cloud_state_detail : "You can block installs and run audits locally for free. Connect Guard Cloud for live warnings, synced policy, and cross-device evidence.",
    tone: "slate",
    localHeading: "Free on this device",
    cloudHeading: "Adds with Guard Cloud",
    localCapabilities: LOCAL_FREE_CAPABILITIES,
    cloudCapabilities: CLOUD_CAPABILITIES
  };
}
function CapabilityList({ heading, icon: Icon, items }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 rounded-xl border border-slate-100 bg-white/80 p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-3 flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4 shrink-0 text-slate-500", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: heading })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "space-y-2", children: items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex min-w-0 items-start gap-2 text-xs leading-relaxed", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniCheckCircle,
        {
          className: `mt-0.5 h-3.5 w-3.5 shrink-0 ${item.available ? "text-brand-green" : "text-slate-300"}`,
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: item.available ? "text-slate-600" : "text-slate-400", children: item.label })
    ] }, item.label)) })
  ] });
}
function panelToneClass(tone) {
  if (tone === "green") {
    return "border-brand-green/20 bg-brand-green/[0.04]";
  }
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
}
function SupplyChainCloudCapabilitiesPanel({ state }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: `rounded-2xl border px-4 py-4 ${panelToneClass(state.tone)}`,
      "aria-label": "Local and Guard Cloud capabilities",
      "data-testid": "supply-chain-cloud-capabilities",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: state.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-600", children: state.detail })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 grid min-w-0 gap-3 md:grid-cols-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            CapabilityList,
            {
              heading: state.localHeading,
              icon: HiMiniComputerDesktop,
              items: state.localCapabilities
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            CapabilityList,
            {
              heading: state.cloudHeading,
              icon: HiMiniCloud,
              items: state.cloudCapabilities
            }
          )
        ] })
      ]
    }
  );
}
const decisionTone = (decision) => {
  if (decision === "block") {
    return "destructive";
  }
  if (decision === "ask") {
    return "attention";
  }
  if (decision === "warn") {
    return "warning";
  }
  if (decision === "monitor") {
    return "info";
  }
  if (decision === "allow") {
    return "green";
  }
  return "default";
};
const severityTone = (severity) => {
  if (severity === "critical") {
    return "destructive";
  }
  if (severity === "high") {
    return "attention";
  }
  if (severity === "medium") {
    return "warning";
  }
  if (severity === "low") {
    return "info";
  }
  return "default";
};
function WorkbenchHeader({ auditSnapshot }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 text-xs text-slate-500", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(auditSnapshot.decision), children: auditSnapshot.decision }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
      auditSnapshot.inventory.totalPackages,
      " package",
      auditSnapshot.inventory.totalPackages === 1 ? "" : "s",
      " indexed"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "·" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
      "Last audit ",
      formatRelativeTime(auditSnapshot.generatedAt)
    ] }),
    auditSnapshot.source !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "capitalize", children: [
        auditSnapshot.source,
        " intel"
      ] })
    ] })
  ] });
}
function FindingDetailPanel({ finding }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-slate-50/70 px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: finding.packageName }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "default", children: finding.ecosystem }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(finding.decision), children: finding.decision }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: severityTone(finding.severity), children: finding.severity })
    ] }),
    finding.reasons.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 space-y-2", children: finding.reasons.map((reason) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "text-xs leading-relaxed text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-slate-700", children: reason.code }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-400", children: " · " }),
      reason.message
    ] }, `${finding.id}-${reason.code}`)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-500", children: "No advisory detail recorded for this package yet." }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Advisory aliases" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-wrap gap-1.5", children: finding.advisoryAliases.map((alias) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "span",
        {
          className: "rounded-full border border-slate-200 bg-white px-2.5 py-0.5 font-mono text-[11px] text-slate-600",
          children: alias
        },
        `${finding.id}-${alias}`
      )) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-[11px] text-slate-500", children: "CVE and GHSA aliases are stubbed here until linked advisory intel is available in Guard Cloud." })
    ] })
  ] });
}
function FindingRow({ finding, selected, onSelect }) {
  const handleSelect = reactExports.useCallback(() => {
    onSelect(finding.id);
  }, [finding.id, onSelect]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleSelect,
      "aria-pressed": selected,
      className: `flex w-full items-center justify-between gap-3 border-b border-slate-100 px-4 py-3 text-left transition-colors last:border-b-0 hover:bg-slate-50/70 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30 ${selected ? "bg-brand-blue/[0.04]" : ""}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-medium text-brand-dark", children: finding.packageName }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 truncate text-xs text-slate-500", children: [
            finding.ecosystem,
            finding.namespace !== null ? ` · ${finding.namespace}` : ""
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(finding.decision), children: finding.decision }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: severityTone(finding.severity), children: finding.severity })
        ] })
      ]
    }
  );
}
function SortButton({ label, sortKey, activeSort, direction, onSort }) {
  const handleClick = reactExports.useCallback(() => {
    onSort(sortKey);
  }, [onSort, sortKey]);
  const active = activeSort === sortKey;
  let sortIcon = null;
  if (active) {
    sortIcon = direction === "desc" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDown, { className: "h-3 w-3", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowUp, { className: "h-3 w-3", "aria-hidden": "true" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: handleClick,
      "aria-pressed": active,
      className: `inline-flex items-center gap-1 rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${active ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
      children: [
        label,
        sortIcon
      ]
    }
  );
}
function FilterChip({ label, active, onSelect }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      onClick: onSelect,
      "aria-pressed": active,
      className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${active ? "bg-brand-dark text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
      children: label
    }
  );
}
function WorkbenchControls({
  filters,
  ecosystems,
  sortKey,
  sortDirection,
  onSearchChange,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange,
  onSortChange
}) {
  const handleEcosystemAll = reactExports.useCallback(() => onEcosystemChange("all"), [onEcosystemChange]);
  const handleDecisionAll = reactExports.useCallback(() => onDecisionChange("all"), [onDecisionChange]);
  const handleDecisionBlock = reactExports.useCallback(() => onDecisionChange("block"), [onDecisionChange]);
  const handleDecisionAsk = reactExports.useCallback(() => onDecisionChange("ask"), [onDecisionChange]);
  const handleDecisionWarn = reactExports.useCallback(() => onDecisionChange("warn"), [onDecisionChange]);
  const handleSeverityAll = reactExports.useCallback(() => onSeverityChange("all"), [onSeverityChange]);
  const handleSeverityCritical = reactExports.useCallback(() => onSeverityChange("critical"), [onSeverityChange]);
  const handleSeverityHigh = reactExports.useCallback(() => onSeverityChange("high"), [onSeverityChange]);
  const handleSeverityMedium = reactExports.useCallback(() => onSeverityChange("medium"), [onSeverityChange]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "search",
            placeholder: "Search packages…",
            value: filters.search,
            onChange: onSearchChange,
            "aria-label": "Search package findings",
            className: "w-44 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "All ecosystems", active: filters.ecosystem === "all", onSelect: handleEcosystemAll }),
      ecosystems.map((ecosystem) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        EcosystemChip,
        {
          ecosystem,
          active: filters.ecosystem === ecosystem,
          onSelect: onEcosystemChange
        },
        ecosystem
      ))
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "All decisions", active: filters.decision === "all", onSelect: handleDecisionAll }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "Block", active: filters.decision === "block", onSelect: handleDecisionBlock }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "Ask", active: filters.decision === "ask", onSelect: handleDecisionAsk }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "Warn", active: filters.decision === "warn", onSelect: handleDecisionWarn }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mx-1 h-4 w-px bg-slate-200", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "All severities", active: filters.severity === "all", onSelect: handleSeverityAll }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "Critical", active: filters.severity === "critical", onSelect: handleSeverityCritical }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "High", active: filters.severity === "high", onSelect: handleSeverityHigh }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: "Medium", active: filters.severity === "medium", onSelect: handleSeverityMedium })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Sort" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortButton, { label: "Severity", sortKey: "severity", activeSort: sortKey, direction: sortDirection, onSort: onSortChange }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortButton, { label: "Package", sortKey: "package", activeSort: sortKey, direction: sortDirection, onSort: onSortChange }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortButton, { label: "Ecosystem", sortKey: "ecosystem", activeSort: sortKey, direction: sortDirection, onSort: onSortChange }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortButton, { label: "Decision", sortKey: "decision", activeSort: sortKey, direction: sortDirection, onSort: onSortChange })
    ] })
  ] });
}
function EcosystemChip({ ecosystem, active, onSelect }) {
  const handleSelect = reactExports.useCallback(() => {
    onSelect(ecosystem);
  }, [ecosystem, onSelect]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(FilterChip, { label: ecosystem, active, onSelect: handleSelect });
}
function WorkbenchAuditErrorBanner({ message }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "mb-4 flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5",
      role: "alert",
      "aria-live": "assertive",
      "data-testid": "workbench-audit-error",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Workspace audit could not start" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-slate-600", children: message })
        ] })
      ]
    }
  );
}
function WorkbenchEmptyState({ auditConnectGate, auditError, onRunAudit, auditRunning }) {
  if (auditConnectGate !== null && auditConnectGate !== void 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConnectFlowCard,
      {
        compact: true,
        connectError: auditConnectGate.connectError,
        connectStarting: auditConnectGate.connectStarting,
        connectFlow: auditConnectGate.connectFlow,
        detail: auditConnectGate.gate.detail,
        headline: auditConnectGate.gate.headline,
        mode: auditConnectGate.gate.mode,
        onStartConnect: auditConnectGate.onStartConnect,
        purpose: "audit"
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    auditError ? /* @__PURE__ */ jsxRuntimeExports.jsx(WorkbenchAuditErrorBanner, { message: auditError }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No workspace audit yet",
        body: "Run a package audit to index dependencies and surface flagged packages here.",
        tone: "teach",
        action: onRunAudit !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: onRunAudit, disabled: auditRunning, "aria-busy": auditRunning, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Run audit"
        ] }) : void 0
      }
    )
  ] });
}
function PackageWorkbenchPanel({
  auditConnectGate = null,
  auditError = null,
  auditSnapshot,
  onRunAudit,
  auditRunning = false
}) {
  const [filters, setFilters] = reactExports.useState({
    ecosystem: "all",
    decision: "all",
    severity: "all",
    search: ""
  });
  const [sortState, setSortState] = reactExports.useState({ sortKey: "severity", sortDirection: "desc" });
  const { sortKey, sortDirection } = sortState;
  const [selectedId, setSelectedId] = reactExports.useState("");
  const findings = auditSnapshot?.findings ?? [];
  const ecosystems = reactExports.useMemo(() => packageWorkbenchEcosystems(findings), [findings]);
  const filteredFindings = reactExports.useMemo(
    () => filterPackageWorkbenchFindings(findings, filters),
    [findings, filters]
  );
  const sortedFindings = reactExports.useMemo(() => {
    const sorted = sortPackageWorkbenchFindings(filteredFindings, sortKey);
    if (sortDirection === "asc") {
      return [...sorted].reverse();
    }
    return sorted;
  }, [filteredFindings, sortDirection, sortKey]);
  const selectedFinding = reactExports.useMemo(
    () => sortedFindings.find((finding) => finding.id === selectedId) ?? null,
    [selectedId, sortedFindings]
  );
  const handleSearchChange = reactExports.useCallback((event) => {
    setFilters((prev) => ({ ...prev, search: event.target.value }));
    setSelectedId("");
  }, []);
  const handleEcosystemChange = reactExports.useCallback((ecosystem) => {
    setFilters((prev) => ({ ...prev, ecosystem }));
    setSelectedId("");
  }, []);
  const handleDecisionChange = reactExports.useCallback((decision) => {
    setFilters((prev) => ({ ...prev, decision }));
    setSelectedId("");
  }, []);
  const handleSeverityChange = reactExports.useCallback((severity) => {
    setFilters((prev) => ({ ...prev, severity }));
    setSelectedId("");
  }, []);
  const handleSortChange = reactExports.useCallback((nextSortKey) => {
    setSortState((prev) => {
      if (prev.sortKey === nextSortKey) {
        return {
          sortKey: prev.sortKey,
          sortDirection: prev.sortDirection === "desc" ? "asc" : "desc"
        };
      }
      return { sortKey: nextSortKey, sortDirection: "desc" };
    });
  }, []);
  const handleSelectFinding = reactExports.useCallback((id) => {
    setSelectedId((prev) => prev === id ? "" : id);
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Audit findings" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-500", children: "Review flagged packages from the latest workspace audit. Filter, sort, and inspect advisory detail." }),
      auditSnapshot !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(WorkbenchHeader, { auditSnapshot }) })
    ] }),
    auditSnapshot === null && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      WorkbenchEmptyState,
      {
        auditConnectGate,
        auditError,
        onRunAudit,
        auditRunning
      }
    ) }),
    auditSnapshot !== null && findings.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No flagged packages",
        body: "The latest workspace audit completed without packages that need review.",
        tone: "teach"
      }
    ) }),
    auditSnapshot !== null && findings.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 px-4 py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        WorkbenchControls,
        {
          filters,
          ecosystems,
          sortKey,
          sortDirection,
          onSearchChange: handleSearchChange,
          onEcosystemChange: handleEcosystemChange,
          onDecisionChange: handleDecisionChange,
          onSeverityChange: handleSeverityChange,
          onSortChange: handleSortChange
        }
      ),
      sortedFindings.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "py-6 text-center text-sm text-slate-500", children: "No packages match the current filters." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "overflow-hidden rounded-xl border border-slate-100", role: "table", "aria-label": "Package audit findings", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "hidden border-b border-slate-100 bg-slate-50 px-4 py-2 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-3",
            role: "row",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Package" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Decision · Severity" })
            ]
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "rowgroup", children: sortedFindings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          FindingRow,
          {
            finding,
            selected: selectedId === finding.id,
            onSelect: handleSelectFinding
          },
          finding.id
        )) })
      ] }),
      selectedFinding !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(FindingDetailPanel, { finding: selectedFinding })
    ] })
  ] });
}
function resolveSupplyChainIssues(snapshot) {
  const issues = [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const stats = buildSupplyChainStats(snapshot);
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
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
      detail: "Guard has not hooked into your shell path yet. Turn on protection for your package tools, then open a new terminal.",
      tone: "attention",
      actionLabel: "Protect package tools",
      action: { kind: "firewall_unprotected" }
    });
  } else if (stats.repairRequiredManagers > 0) {
    const managers = protection !== void 0 ? protection.installed_managers.filter(
      (manager) => !protection.protected_managers.includes(manager)
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
  } else if (protection?.path_status === "restart_required" || stats.stagedManagers > 0) {
    issues.push({
      id: "path_restart",
      title: "Open a new terminal to finish setup",
      detail: "Guard updated your shell profile. Open a new terminal or restart your AI apps before running a protection test.",
      tone: "blue",
      actionLabel: "Open new shell",
      action: { kind: "open_shell" }
    });
  }
  if (protectionStatus === "partial" && protection !== void 0 && protection.protected_managers.length > 0 && protection.unprotected_managers.length > 0) {
    issues.push({
      id: "partial_protection",
      title: "Some package tools are still open",
      detail: `${protection.protected_managers.length} protected, ${protection.unprotected_managers.length} still open: ${protection.unprotected_managers.join(", ")}.`,
      tone: "attention",
      actionLabel: "Review open tools",
      action: { kind: "firewall_unprotected" }
    });
  } else if (protectionStatus === "unprotected" && protection !== void 0 && protection.unprotected_managers.length > 0) {
    issues.push({
      id: "unprotected_tools",
      title: "Package installs are not protected yet",
      detail: `Turn on protection for ${protection.unprotected_managers.join(", ")} to block risky installs before they run.`,
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
function protectionTitle(status) {
  if (status === "protected") {
    return "Package installs are protected on this device";
  }
  if (status === "partial") {
    return "Protection is only partly set up";
  }
  if (status === "staged") {
    return "Finish setup in a new terminal";
  }
  if (status === "unprotected") {
    return "Package installs are not protected yet";
  }
  return "Checking package protection on this device";
}
function protectionDetail(snapshot, status) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (status === "protected" && protection) {
    return `${protection.protected_managers.length} package tool${protection.protected_managers.length === 1 ? "" : "s"} active. Guard can block risky installs before they run.`;
  }
  if (status === "partial" && protection) {
    return `${protection.unprotected_managers.length} tool${protection.unprotected_managers.length === 1 ? "" : "s"} still open: ${protection.unprotected_managers.join(", ")}.`;
  }
  if (status === "staged") {
    return "Guard updated your shell profile. Open a new terminal, then run a protection test.";
  }
  if (status === "unprotected") {
    return "Turn on protection for npm, pip, and other tools in the firewall panel below.";
  }
  return "Refresh status after installing package tools on this machine.";
}
function protectionTone(status) {
  if (status === "protected") {
    return "green";
  }
  if (status === "staged") {
    return "blue";
  }
  if (status === "partial" || status === "unprotected") {
    return "attention";
  }
  return "slate";
}
function cloudLabel(snapshot) {
  const label = snapshot.cloud_state_label ?? "";
  if (snapshot.cloud_state === "paired_active") {
    return label.trim().length > 0 ? label : "Guard Cloud connected";
  }
  if (snapshot.cloud_state === "paired_waiting") {
    return label.trim().length > 0 ? label : "Pairing in progress";
  }
  return label.trim().length > 0 ? label : "On this device only";
}
function resolveSupplyChainWorkspaceHero(snapshot, options) {
  const protectionStatus = resolveHomeProtectionStatus(snapshot);
  const stats = buildSupplyChainStats(snapshot);
  const preventedLabel = stats.preventedInstalls > 0 ? `${stats.preventedInstalls} blocked install${stats.preventedInstalls === 1 ? "" : "s"}` : "No blocked installs yet";
  const openIssueCount = options?.openIssueCount ?? 0;
  if (openIssueCount > 0) {
    return {
      cloudMode: snapshot.cloud_state,
      cloudLabel: cloudLabel(snapshot),
      protectionStatus,
      title: "Work through the steps below",
      detail: `${openIssueCount} setup step${openIssueCount === 1 ? "" : "s"} need attention on this device.`,
      tone: protectionTone(protectionStatus),
      statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`
    };
  }
  return {
    cloudMode: snapshot.cloud_state,
    cloudLabel: cloudLabel(snapshot),
    protectionStatus,
    title: protectionTitle(protectionStatus),
    detail: protectionDetail(snapshot, protectionStatus),
    tone: protectionTone(protectionStatus),
    statLine: `${stats.protectedManagers} protected · ${stats.unprotectedManagers} open · ${preventedLabel}`
  };
}
function supplyChainCloudTagTone(mode) {
  if (mode === "paired_active") {
    return "green";
  }
  if (mode === "paired_waiting") {
    return "blue";
  }
  return "attention";
}
function issueSurfaceClass(tone) {
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  if (tone === "attention") {
    return "border-brand-attention/20 bg-brand-attention/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
}
function issueIcon(issue) {
  if (issue.id.startsWith("cloud")) {
    return HiMiniCloudArrowUp;
  }
  if (issue.id.startsWith("path")) {
    return issue.tone === "blue" ? HiMiniInformationCircle : HiMiniWrenchScrewdriver;
  }
  if (issue.id === "stale_intel") {
    return HiMiniArrowPath;
  }
  if (issue.id.includes("protection") || issue.id.includes("unprotected")) {
    return HiMiniShieldExclamation;
  }
  return HiMiniExclamationTriangle;
}
function issueIconClass(tone) {
  if (tone === "blue") {
    return "text-brand-blue";
  }
  if (tone === "attention") {
    return "text-brand-attention";
  }
  return "text-slate-500";
}
function SupplyChainIssueFocus({
  hero,
  issues,
  onIssueAction,
  actionPending = false
}) {
  const [activeIndex, setActiveIndex] = reactExports.useState(0);
  reactExports.useEffect(() => {
    if (activeIndex >= issues.length) {
      setActiveIndex(Math.max(0, issues.length - 1));
    }
  }, [activeIndex, issues.length]);
  const goPrevious = reactExports.useCallback(() => {
    setActiveIndex((index) => index <= 0 ? issues.length - 1 : index - 1);
  }, [issues.length]);
  const goNext = reactExports.useCallback(() => {
    setActiveIndex((index) => index >= issues.length - 1 ? 0 : index + 1);
  }, [issues.length]);
  if (issues.length === 0) {
    return null;
  }
  const issue = issues[activeIndex] ?? issues[0];
  const Icon = issueIcon(issue);
  const titleClass = "text-brand-dark";
  const detailClass = "text-slate-600";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: `overflow-hidden rounded-2xl border shadow-sm ${issueSurfaceClass(issue.tone)}`,
      "aria-label": "Supply chain status",
      "data-testid": "supply-chain-issue-focus",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 border-b border-slate-100/80 px-4 py-3 sm:px-5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: supplyChainCloudTagTone(hero.cloudMode), children: [
              hero.cloudMode === "local_only" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniComputerDesktop, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }),
              hero.cloudLabel
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-500", children: hero.statLine })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: issues.length === 1 ? "Next step" : `Step ${activeIndex + 1} of ${issues.length}` }),
          issues.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: goPrevious,
                className: "inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200/80 bg-white/80 text-slate-600 transition-colors hover:bg-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue",
                "aria-label": "Previous issue",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "h-4 w-4", "aria-hidden": "true" })
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: goNext,
                className: "inline-flex h-9 w-9 items-center justify-center rounded-lg border border-slate-200/80 bg-white/80 text-slate-600 transition-colors hover:bg-white focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-brand-blue",
                "aria-label": "Next issue",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "h-4 w-4", "aria-hidden": "true" })
              }
            )
          ] }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-5 sm:px-6 sm:py-6", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                className: `inline-flex h-11 w-11 shrink-0 items-center justify-center rounded-xl bg-white/90 ring-1 ring-black/[0.05] ${issueIconClass(issue.tone)}`,
                "aria-hidden": "true",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-5 w-5" })
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: `text-lg font-semibold tracking-tight sm:text-xl ${titleClass}`, children: issue.title }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-2 max-w-2xl text-sm leading-relaxed ${detailClass}`, children: issue.detail })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                variant: "primary",
                onClick: () => onIssueAction(issue.action),
                disabled: actionPending,
                "aria-busy": actionPending,
                children: issue.actionLabel
              }
            ),
            issues.length > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-2", role: "tablist", "aria-label": "Issue progress", children: issues.map((entry, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                role: "tab",
                "aria-selected": index === activeIndex,
                "aria-label": `Issue ${index + 1}: ${entry.title}`,
                onClick: () => setActiveIndex(index),
                className: [
                  "h-2.5 rounded-full transition-all",
                  index === activeIndex ? "w-7 bg-brand-blue" : "w-2.5 bg-slate-300/80"
                ].join(" ")
              },
              entry.id
            )) }) : null
          ] })
        ] })
      ]
    }
  );
}
function heroSurfaceClass(tone) {
  if (tone === "green") {
    return "border-brand-green/20 bg-brand-green/[0.04]";
  }
  if (tone === "blue") {
    return "border-brand-blue/20 bg-brand-blue/[0.04]";
  }
  if (tone === "attention") {
    return "border-brand-attention/20 bg-brand-attention/[0.04]";
  }
  return "border-slate-200 bg-slate-50/80";
}
function heroIcon(hero) {
  if (hero.protectionStatus === "protected") {
    return HiMiniCheckCircle;
  }
  if (hero.protectionStatus === "staged") {
    return HiMiniArrowPath;
  }
  if (hero.protectionStatus === "partial" || hero.protectionStatus === "unprotected") {
    return HiMiniExclamationTriangle;
  }
  return HiMiniComputerDesktop;
}
function heroIconClass(tone) {
  if (tone === "green") {
    return "text-brand-green";
  }
  if (tone === "blue") {
    return "text-brand-blue";
  }
  if (tone === "attention") {
    return "text-brand-attention";
  }
  return "text-slate-500";
}
function SupplyChainWorkspaceHero({ hero, compact = false }) {
  const Icon = heroIcon(hero);
  const titleClass = "text-brand-dark";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: `rounded-2xl border px-4 py-4 sm:px-5 sm:py-5 ${heroSurfaceClass(hero.tone)}`,
      "aria-label": "Supply chain protection status",
      "data-testid": "supply-chain-workspace-hero",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: supplyChainCloudTagTone(hero.cloudMode), children: [
            hero.cloudMode === "local_only" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniComputerDesktop, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "mr-1 inline h-3.5 w-3.5", "aria-hidden": "true" }),
            hero.cloudLabel
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-500", children: hero.statLine })
        ] }),
        !compact ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex items-start gap-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `mt-0.5 h-5 w-5 shrink-0 ${heroIconClass(hero.tone)}`, "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: `text-lg font-semibold tracking-tight ${titleClass}`, children: hero.title }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm leading-relaxed text-slate-600", children: hero.detail })
          ] })
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-slate-600", children: hero.detail })
      ]
    }
  );
}
function SupplyChainStatusHeader({
  hero,
  issues,
  onIssueAction,
  actionPending = false
}) {
  if (issues.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainWorkspaceHero, { hero });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainIssueFocus,
    {
      hero,
      issues,
      onIssueAction,
      actionPending
    }
  );
}
function AppFirewallRow({ install, protection }) {
  const [open, setOpen] = reactExports.useState(false);
  const toggle = reactExports.useCallback(() => setOpen((p) => !p), []);
  const protectedManagers = protection?.protected_managers ?? [];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 last:border-b-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: toggle,
        "aria-expanded": open,
        className: "flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2.5", children: [
            install.active ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: harnessDisplayName(install.harness) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 shrink-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: install.active ? "success" : "attention", children: install.active ? "Active" : "Inactive" }),
            open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
          ] })
        ]
      }
    ),
    open && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 pb-3 pt-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.15em] text-slate-400 mb-2", children: "Shim coverage" }),
      protectedManagers.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-1.5", children: protectedManagers.map((mgr) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "span",
        {
          className: "inline-flex items-center gap-1 rounded-full border border-brand-green/25 bg-brand-green/[0.06] px-2.5 py-0.5 text-xs font-medium text-brand-green-text",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3 w-3", "aria-hidden": "true" }),
            mgr
          ]
        },
        mgr
      )) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "No package manager shims active for this app." }),
      install.updated_at && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-slate-400", children: [
        "Updated ",
        formatRelativeTime(install.updated_at)
      ] })
    ] })
  ] });
}
function SupplyChainWorkspace({
  snapshot,
  approvalGate,
  onGoHome,
  onRuntimeRefresh
}) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  const managedInstalls = reactExports.useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs]
  );
  const [auditSnapshot, setAuditSnapshot] = reactExports.useState(null);
  const [evidenceRail, setEvidenceRail] = reactExports.useState(null);
  const [auditRunning, setAuditRunning] = reactExports.useState(false);
  const [auditError, setAuditError] = reactExports.useState(null);
  const [auditConnectGate, setAuditConnectGate] = reactExports.useState(null);
  const runAuditRef = reactExports.useRef(null);
  const firewallPanelRef = reactExports.useRef(null);
  const [issueActionPending, setIssueActionPending] = reactExports.useState(false);
  const handleIssueAction = reactExports.useCallback(
    async (action) => {
      const panel = firewallPanelRef.current;
      if (panel === null) {
        return;
      }
      if (action.kind === "firewall_unprotected") {
        panel.focusUnprotected();
        panel.scrollIntoView();
        return;
      }
      if (action.kind === "firewall_repair") {
        panel.focusActionable();
        panel.scrollIntoView();
        return;
      }
      if (action.kind === "firewall_audit") {
        panel.runAudit();
        panel.scrollIntoView();
        return;
      }
      setIssueActionPending(true);
      try {
        if (action.kind === "connect") {
          await panel.startConnect();
          await onRuntimeRefresh?.();
          return;
        }
        if (action.kind === "open_shell") {
          await panel.openShell();
        }
      } finally {
        setIssueActionPending(false);
      }
    },
    [onRuntimeRefresh]
  );
  const auditWorkspaceDir = reactExports.useMemo(
    () => resolveSupplyChainAuditWorkspaceDir(managedInstalls),
    [managedInstalls]
  );
  const supplyChainIssues = reactExports.useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
  const workspaceHero = reactExports.useMemo(
    () => resolveSupplyChainWorkspaceHero(snapshot, { openIssueCount: supplyChainIssues.length }),
    [snapshot, supplyChainIssues.length]
  );
  const cloudCapabilities = reactExports.useMemo(
    () => resolveSupplyChainCloudCapabilities(snapshot),
    [snapshot]
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
        setEvidenceRail(deriveSupplyChainEvidenceRail(receipts));
      } catch {
        if (!cancelled) {
          setAuditSnapshot(null);
          setEvidenceRail(null);
        }
      }
    };
    void loadReceiptEvidence();
    return () => {
      cancelled = true;
    };
  }, [snapshot.generated_at, snapshot.receipt_count]);
  const handleAuditCompleted = reactExports.useCallback((resultDetail) => {
    const normalized = normalizeSupplyChainAuditSnapshot(resultDetail);
    setAuditSnapshot(normalized);
    setAuditError(null);
  }, []);
  const handleAuditErrorChange = reactExports.useCallback((message) => {
    setAuditError(message);
  }, []);
  const handleAuditRunningChange = reactExports.useCallback((running) => {
    setAuditRunning(running);
  }, []);
  const handleRunAudit = reactExports.useCallback(() => {
    runAuditRef.current?.();
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS, "data-testid": "supply-chain-workspace", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-start justify-end gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onGoHome, children: "Back to Home" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SupplyChainStatusHeader,
      {
        hero: workspaceHero,
        issues: supplyChainIssues,
        onIssueAction: (action) => {
          void handleIssueAction(action);
        },
        actionPending: issueActionPending
      }
    ),
    supplyChainIssues.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainCloudCapabilitiesPanel, { state: cloudCapabilities }) : null,
    evidenceRail !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainEvidenceRail, { rail: evidenceRail }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      PackageWorkbenchPanel,
      {
        auditConnectGate,
        auditError,
        auditSnapshot,
        auditRunning,
        onRunAudit: handleRunAudit
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainBundlePanel, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      PackageFirewallPanel,
      {
        ref: firewallPanelRef,
        approvalGate,
        auditWorkspaceDir,
        onAuditConnectGateChange: setAuditConnectGate,
        onAuditErrorChange: handleAuditErrorChange,
        onStateChanged: onRuntimeRefresh,
        onAuditCompleted: handleAuditCompleted,
        onAuditRunningChange: handleAuditRunningChange,
        runAuditRef
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Connected apps" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-500", children: "Which package tools Guard is watching inside each connected app." })
      ] }),
      managedInstalls.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No apps connected",
          body: "Connect an AI app to see per-app package manager coverage here.",
          tone: "teach"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: managedInstalls.map((install) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        AppFirewallRow,
        {
          install,
          protection
        },
        `${install.harness}-${install.workspace ?? "global"}`
      )) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Safety check source" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm leading-relaxed text-slate-500", children: "Whether this device uses sample data or live Guard Cloud updates." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FeedHealthPanel, { snapshot, hideLocalOnlyWarning: supplyChainIssues.some((issue) => issue.id === "cloud_connect") })
    ] })
  ] });
}
function FeedHealthPanel({ snapshot, hideLocalOnlyWarning = false }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const isStale = snapshot.latest_receipts.length > 0 && Date.now() - new Date(snapshot.latest_receipts[0].timestamp).getTime() > 7 * 24 * 60 * 60 * 1e3;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4 space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Data source" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isSample ? "attention" : "green", children: isSample ? "On this device only" : "Live from Guard Cloud" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Last update" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStale ? "attention" : "green", children: isStale ? "Older than 7 days" : "Recent" })
      ] })
    ] }),
    isSample && !hideLocalOnlyWarning && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationTriangle,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-600", children: "This device is using sample safety data. Connect Guard Cloud for live package warnings and protection across your machines." })
    ] }),
    isStale && !isSample && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-600", children: "Safety checks have not refreshed recently. Make sure Guard is running, then sync policy or run an audit." })
    ] })
  ] });
}
export {
  SupplyChainWorkspace,
  buildSupplyChainStats
};
