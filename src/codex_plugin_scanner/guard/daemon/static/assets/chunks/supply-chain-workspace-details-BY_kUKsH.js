import { j as jsxRuntimeExports, r as reactExports, co as HiMiniArrowTopRightOnSquare, a4 as HiMiniExclamationTriangle, dp as HiMiniBugAnt, a6 as Badge, T as Tag, f as formatRelativeTime, A as ActionButton, dH as fetchReceipts, s as HiMiniCheckCircle, aA as HiMiniXCircle, h as harnessDisplayName, b as HiMiniChevronUp, c as HiMiniChevronDown, d as HiMiniArrowPath } from "../guard-dashboard.js";
import { m as missingBundleMessage, f as formatBundleExpiry, i as isBundleExpired, b as bundleRefreshKey, r as resolveIntelFreshness } from "./feed-health-workspace-DJk9Td4s.js";
import { u as useSupplyChainBundle } from "./supply-chain-hub-workspace-BOsywkJu.js";
import { s as supplyChainEvidenceHref, d as deriveSupplyChainEvidenceRail } from "./supply-chain-protection-stats-BbhzE3ad.js";
import { r as resolveSupplyChainIssues } from "./supply-chain-issues-DwbPYnX8.js";
import "./home-protection-module-DZsYd8li.js";
function SupplyChainDetailSection({
  id,
  title,
  lead,
  action,
  children,
  ...sectionProps
}) {
  const labelled = sectionProps["aria-label"] === void 0 ? { "aria-labelledby": id } : {};
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      ...labelled,
      ...sectionProps,
      className: "grid min-w-0 gap-x-10 gap-y-3 py-5 md:grid-cols-[minmax(0,13rem)_minmax(0,1fr)]",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { id, className: "text-sm font-semibold text-brand-dark", children: title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm leading-6 text-slate-600", children: lead }),
          action ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: action }) : null
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-w-0", children })
      ]
    }
  );
}
function SeverityBadge({ severity }) {
  const tone = severity === "critical" || severity === "high" ? "destructive" : severity === "medium" ? "attention" : "default";
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone, children: severity });
}
function AdvisoryRow({ advisory }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-start gap-3 py-3", children: [
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
const SEVERITY_LEVELS = ["critical", "high", "medium", "low"];
const SEVERITY_TEXT_CLASS = {
  critical: "text-brand-purple",
  high: "text-brand-purple",
  medium: "text-brand-attention-text",
  low: "text-brand-dark"
};
function IntelSection({ action, children }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainDetailSection,
    {
      id: "supply-chain-intel-heading",
      title: "Supply chain intel",
      lead: "The signed advisory feed Guard checks each install against.",
      action,
      children
    }
  );
}
function SupplyChainBundlePanel({
  refreshKey = "",
  cloudState
}) {
  const load = useSupplyChainBundle(refreshKey);
  const bundle = load.phase === "ready" ? load.bundle : null;
  const loading = load.phase === "loading";
  const error = load.phase === "error" ? load.message : null;
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
    return /* @__PURE__ */ jsxRuntimeExports.jsx(IntelSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 py-1", "aria-hidden": "true", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-48" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-40" })
    ] }) });
  }
  if (error) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(IntelSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-dark", children: "Could not load intel." }),
      " ",
      error
    ] }) });
  }
  if (!bundle) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(IntelSection, { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-dark", children: "No intel available." }),
      " ",
      missingBundleMessage(cloudState)
    ] }) });
  }
  const nowMs = Date.now();
  const expiry = bundle.expiresAt ? formatBundleExpiry(bundle.expiresAt, nowMs) : null;
  const expired = isBundleExpired(bundle, nowMs);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    IntelSection,
    {
      action: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: handleOpenCloud,
          className: "inline-flex items-center gap-1 rounded text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30",
          children: [
            "View in cloud",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3 w-3", "aria-hidden": "true" })
          ]
        }
      ),
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "flex flex-wrap gap-x-8 gap-y-2 text-sm", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-slate-600", children: "Bundle" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-mono font-medium text-brand-dark", children: bundle.bundleVersion })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-slate-600", children: "Advisories" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-medium tabular-nums text-brand-dark", children: bundle.advisories.length })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-slate-600", children: "Packages" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-medium tabular-nums text-brand-dark", children: bundle.packages.length })
          ] }),
          expiry !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-baseline gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-slate-600", children: expired ? "Expired" : "Expires" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: `font-medium ${expired ? "text-brand-attention-text" : "text-brand-dark"}`, children: expiry })
          ] })
        ] }),
        severityCounts && Object.keys(severityCounts).length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-3 flex flex-wrap gap-x-6 gap-y-1 text-sm", "aria-label": "Advisories by severity", children: SEVERITY_LEVELS.map((sev) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex items-baseline gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `font-semibold tabular-nums ${SEVERITY_TEXT_CLASS[sev]}`, children: severityCounts[sev] ?? 0 }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-600", children: sev })
        ] }, sev)) }),
        topAdvisories.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-xs font-medium text-slate-600", children: "Top advisories by severity and confidence" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-1 divide-y divide-slate-100", children: topAdvisories.map((advisory) => /* @__PURE__ */ jsxRuntimeExports.jsx(AdvisoryRow, { advisory }, advisory.advisoryId)) }),
          bundle.advisories.length > 10 && /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              onClick: handleOpenCloud,
              className: "mt-1 rounded text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30",
              children: [
                "View all ",
                bundle.advisories.length,
                " advisories in Guard Cloud"
              ]
            }
          )
        ] })
      ]
    }
  );
}
const kindLabels = {
  block: "Last block",
  audit: "Last audit",
  sync: "Last sync"
};
function EvidenceRailRow({ item }) {
  const href = supplyChainEvidenceHref(item.receiptId, item.harness);
  const tagTone = item.tone === "green" ? "green" : item.tone === "attention" ? "attention" : "slate";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "min-w-0 space-y-1 py-3 sm:py-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-medium text-slate-600", children: kindLabels[item.kind] }),
      item.timestamp !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: tagTone, children: formatRelativeTime(item.timestamp) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `text-sm ${item.timestamp !== null ? "font-medium text-brand-dark" : "text-slate-500"}`, children: item.title }),
    item.timestamp !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: item.detail }) : null,
    href !== null ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "a",
      {
        href,
        className: "inline-flex items-center gap-1 rounded text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30",
        children: [
          "Open evidence",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
        ]
      }
    ) : null
  ] });
}
function SupplyChainEvidenceRailPlaceholder() {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainDetailSection,
    {
      id: "supply-chain-evidence-heading",
      title: "Recent activity",
      lead: "The latest blocked install, project audit, and policy sync on this device.",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 sm:grid-cols-3", "aria-hidden": "true", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-10" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-10" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-10" })
      ] })
    }
  );
}
function SupplyChainEvidenceRail({ rail }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainDetailSection,
    {
      id: "supply-chain-evidence-heading",
      title: "Recent activity",
      lead: "The latest blocked install, project audit, and policy sync on this device.",
      "aria-label": "Recent supply chain evidence",
      "data-testid": "supply-chain-evidence-rail",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("ul", { className: "grid min-w-0 divide-y divide-slate-100 sm:grid-cols-3 sm:gap-6 sm:divide-y-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceRailRow, { item: rail.block }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceRailRow, { item: rail.audit }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceRailRow, { item: rail.sync })
      ] })
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
function CapabilityList({ heading, items }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h4", { className: "text-xs font-medium text-slate-600", children: heading }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1", children: items.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "min-w-0 text-sm leading-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: item.available ? "text-brand-dark" : "text-slate-500", children: item.label }),
      item.available ? null : /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-2 text-xs font-medium text-slate-500", children: "Not available" })
    ] }, item.label)) })
  ] });
}
function SupplyChainCloudCapabilitiesPanel({ state }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainDetailSection,
    {
      id: "supply-chain-cloud-heading",
      title: state.title,
      lead: state.detail,
      "aria-label": "Local and Guard Cloud capabilities",
      "data-testid": "supply-chain-cloud-capabilities",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid min-w-0 gap-x-10 gap-y-4 sm:grid-cols-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(CapabilityList, { heading: state.localHeading, items: state.localCapabilities }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(CapabilityList, { heading: state.cloudHeading, items: state.cloudCapabilities })
      ] })
    }
  );
}
function AppFirewallRow({ install, protection }) {
  const [open, setOpen] = reactExports.useState(false);
  const toggle = reactExports.useCallback(() => setOpen((p) => !p), []);
  const protectedManagers = protection?.protected_managers ?? [];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: toggle,
        "aria-expanded": open,
        className: "flex w-full items-center justify-between gap-3 py-2.5 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30",
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
    open && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "pb-3 pt-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-2 text-xs font-medium text-slate-600", children: "Shim coverage" }),
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
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    SupplyChainDetailSection,
    {
      id: "supply-chain-audit-heading",
      title: "Workspace audit",
      lead: "Index a project's dependencies and flag the packages that need review.",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: teaserBody }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: handleOpenAudit, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Open Audit tab"
        ] })
      ] })
    }
  );
}
function SupplyChainWorkspaceDetails({
  snapshot,
  onGoHome,
  onAuditNavigate,
  auditSnapshot,
  auditRunning
}) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  const managedInstalls = reactExports.useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs]
  );
  const [evidenceRail, setEvidenceRail] = reactExports.useState(void 0);
  const supplyChainIssues = reactExports.useMemo(() => resolveSupplyChainIssues(snapshot), [snapshot]);
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
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { "data-testid": "supply-chain-workspace", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Activity and sources" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 divide-y divide-slate-200 border-y border-slate-200", children: [
      evidenceRail === void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainEvidenceRailPlaceholder, {}) : evidenceRail !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainEvidenceRail, { rail: evidenceRail }) : null,
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SupplyChainAuditTeaser,
        {
          auditSnapshot,
          auditRunning,
          onOpenAudit: onAuditNavigate
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainBundlePanel, { refreshKey: bundleRefreshKey(snapshot), cloudState: snapshot.cloud_state }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SupplyChainDetailSection,
        {
          id: "supply-chain-apps-heading",
          title: "Connected apps",
          lead: "Which package tools Guard is watching inside each connected app.",
          children: managedInstalls.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-slate-600", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-dark", children: "No apps connected." }),
            " Connect an AI app to see per-app package manager coverage here."
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "divide-y divide-slate-100", children: managedInstalls.map((install) => /* @__PURE__ */ jsxRuntimeExports.jsx(
            AppFirewallRow,
            {
              install,
              protection
            },
            `${install.harness}-${install.workspace ?? "global"}`
          )) })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        SupplyChainDetailSection,
        {
          id: "supply-chain-source-heading",
          title: "Safety check source",
          lead: "Whether this device uses sample data or live Guard Cloud updates.",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(
            FeedHealthPanel,
            {
              snapshot,
              hideLocalOnlyWarning: supplyChainIssues.some((issue) => issue.id === "cloud_connect")
            }
          )
        }
      ),
      supplyChainIssues.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainCloudCapabilitiesPanel, { state: cloudCapabilities }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 -ml-3 sm:-ml-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onGoHome, children: "Back to Home" }) })
  ] });
}
function FeedHealthPanel({ snapshot, hideLocalOnlyWarning = false }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const bundleLoad = useSupplyChainBundle(bundleRefreshKey(snapshot));
  const freshness = resolveIntelFreshness({ cloudState, load: bundleLoad, nowMs: Date.now() });
  const needsRefresh = freshness.kind === "none" || freshness.kind === "expired";
  const generatedAt = freshness.kind === "current" && bundleLoad.phase === "ready" ? bundleLoad.bundle?.generatedAt : void 0;
  const updateLabel = generatedAt ? `Updated ${formatRelativeTime(generatedAt)}` : freshness.label;
  const sourceLabel = isSample ? "On this device only" : cloudState === "paired_waiting" ? "Guard Cloud connected, syncing" : "Live from Guard Cloud";
  const sourceTone = isSample ? "attention" : cloudState === "paired_waiting" ? "blue" : "green";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "flex flex-wrap gap-x-8 gap-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-sm text-slate-600", children: "Data source" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: sourceTone, children: sourceLabel }) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-sm text-slate-600", children: "Last update" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: freshness.tone, children: updateLabel }) })
      ] })
    ] }),
    isSample && !hideLocalOnlyWarning && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-start gap-2 text-sm leading-6 text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationTriangle,
        {
          className: "mt-1 h-4 w-4 shrink-0 text-brand-attention",
          "aria-hidden": "true"
        }
      ),
      "This device is using sample safety data. Connect Guard Cloud for live package warnings and protection across your machines."
    ] }),
    needsRefresh && !isSample && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "flex items-start gap-2 text-sm leading-6 text-slate-600", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: "mt-1 h-4 w-4 shrink-0 text-brand-attention",
          "aria-hidden": "true"
        }
      ),
      freshness.description
    ] })
  ] });
}
export {
  SupplyChainWorkspaceDetails
};
