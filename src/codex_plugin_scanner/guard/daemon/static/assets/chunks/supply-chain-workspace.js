import { r as reactExports, bL as fetchSupplyChainBundle, j as jsxRuntimeExports, S as SectionLabel, i as EmptyState, b0 as HiMiniArrowTopRightOnSquare, aj as Tag, s as formatRelativeTime, L as Badge, J as HiMiniExclamationTriangle, aY as HiMiniBugAnt, au as guardActionPresentation, bM as isSupplyChainScannerEvidence, bN as isBlockedGuardAction, ao as HiMiniArrowPath, bI as HiMiniDocumentMagnifyingGlass, bO as HiMiniShieldExclamation, bP as HiMiniComputerDesktop, B as HiMiniCloud, l as HiMiniCheckCircle, N as HiMiniWrenchScrewdriver, A as ActionButton, y as HiMiniChevronDown, P as HiMiniExclamationCircle, be as fetchReceipts, T as HiMiniXCircle, e as harnessDisplayName, x as HiMiniChevronUp } from "../guard-dashboard.js";
import { resolveFeedStaleness } from "./feed-health-workspace.js";
import { r as resolveHomeProtectionStatus } from "./home-protection-module.js";
import { b as buildSupplyChainStats, r as resolveManagerCoverageManagers, a as resolveManagerCoverageStatus } from "./supply-chain-protection-stats.js";
import { s as supplyChainFixAllIsPending, a as supplyChainFixAllButtonLabel, S as SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS } from "./supply-chain-hub-workspace.js";
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
          body: error
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
  } else if (protection?.path_status === "restart_required" || stats.stagedManagers > 0) {
    issues.push({
      id: "path_restart",
      title: "Finish activation in Guard",
      detail: "Guard saved your shell setup. Finish activation here, then run a protection check from this dashboard.",
      tone: "blue",
      actionLabel: "Finish activation",
      action: { kind: "activate_runtime" }
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
    return "Guard saved your shell setup. Finish activation here, then run a protection check.";
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
function recoverySummary(issueCount) {
  return `Fix ${issueCount} open issue${issueCount === 1 ? "" : "s"} in one guided pass. Guard repairs package tools, activates routing, refreshes safety intelligence, and rechecks status.`;
}
function SupplyChainRecovery({ issues, state, onFixAll }) {
  const [detailsOpen, setDetailsOpen] = reactExports.useState(false);
  const handleDetailsToggle = reactExports.useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const pending = supplyChainFixAllIsPending(state.phase);
  const showResult = state.message !== null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: "border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5",
      "aria-label": "Supply-chain recovery",
      "data-testid": "supply-chain-recovery",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniWrenchScrewdriver,
                {
                  className: "h-4 w-4 shrink-0 text-brand-attention",
                  "aria-hidden": "true"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-semibold text-brand-dark", children: "Restore supply-chain protection" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-3xl text-sm text-slate-600", children: recoverySummary(issues.length) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: onFixAll, disabled: pending, "aria-busy": pending, children: supplyChainFixAllButtonLabel(state.phase) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: showResult ? "mt-3" : "", "aria-live": "polite", children: showResult ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "p",
            {
              className: `flex items-start gap-2 text-sm ${state.phase === "error" || state.phase === "incomplete" ? "text-red-600" : "text-slate-600"}`,
              children: [
                state.phase === "success" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                  HiMiniCheckCircle,
                  {
                    className: "mt-0.5 h-4 w-4 shrink-0 text-emerald-500",
                    "aria-hidden": "true"
                  }
                ) : null,
                state.message
              ]
            }
          ),
          state.failedSteps.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1 text-xs text-red-600", children: state.failedSteps.map((failure, index) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { children: failure }, `${index}:${failure}`)) }) : null
        ] }) : null }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: handleDetailsToggle,
            "aria-expanded": detailsOpen,
            className: "mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
            children: [
              "View issue details",
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniChevronDown,
                {
                  className: `h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`,
                  "aria-hidden": "true"
                }
              )
            ]
          }
        ),
        detailsOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 border-t border-brand-attention/10", children: issues.map((issue) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "li",
          {
            className: "flex items-start gap-2 border-t border-brand-attention/10 py-3 first:border-t-0",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniExclamationCircle,
                {
                  className: "mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-attention",
                  "aria-hidden": "true"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-slate-600", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "block font-semibold text-brand-dark", children: issue.title }),
                issue.detail
              ] })
            ]
          },
          issue.id
        )) }) : null
      ]
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
function auditTeaserBody(auditRunning, auditSnapshot) {
  if (auditRunning) {
    return "Audit is running on the Audit tab.";
  }
  if (auditSnapshot !== null) {
    const packageLabel = auditSnapshot.findings.length === 1 ? "package" : "packages";
    return `${auditSnapshot.findings.length} ${packageLabel} need review across ${auditSnapshot.inventory.totalPackages} indexed.`;
  }
  return "Run an audit to index dependencies and surface packages that need review.";
}
function SupplyChainAuditTeaser({ auditSnapshot, auditRunning, onOpenAudit }) {
  const handleOpenAudit = reactExports.useCallback(() => {
    onOpenAudit();
  }, [onOpenAudit]);
  const teaserBody = auditTeaserBody(auditRunning, auditSnapshot);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-slate-100 bg-white px-4 py-4 shadow-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Workspace audit" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: teaserBody })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: handleOpenAudit, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
      "Open Audit tab"
    ] })
  ] }) });
}
function SupplyChainWorkspace({
  snapshot,
  onGoHome,
  onAuditNavigate,
  auditSnapshot,
  auditRunning,
  fixAllState,
  onFixAll
}) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  const managedInstalls = reactExports.useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs]
  );
  const [evidenceRail, setEvidenceRail] = reactExports.useState(null);
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
        setEvidenceRail(deriveSupplyChainEvidenceRail(receipts));
      } catch {
        if (!cancelled) {
          setEvidenceRail(null);
        }
      }
    };
    void loadReceiptEvidence();
    return () => {
      cancelled = true;
    };
  }, [snapshot.generated_at, snapshot.receipt_count]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: SUPPLY_CHAIN_WORKSPACE_SHELL_CLASS, "data-testid": "supply-chain-workspace", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-start justify-end gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onGoHome, children: "Back to Home" }) }),
    supplyChainIssues.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      SupplyChainRecovery,
      {
        issues: supplyChainIssues,
        state: fixAllState,
        onFixAll
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainWorkspaceHero, { hero: workspaceHero }),
    supplyChainIssues.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainCloudCapabilitiesPanel, { state: cloudCapabilities }) : null,
    evidenceRail !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainEvidenceRail, { rail: evidenceRail }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      SupplyChainAuditTeaser,
      {
        auditSnapshot,
        auditRunning,
        onOpenAudit: onAuditNavigate
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainBundlePanel, {}),
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
