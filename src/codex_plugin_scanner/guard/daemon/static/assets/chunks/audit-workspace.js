import { j as jsxRuntimeExports, an as Tag, t as formatRelativeTime, r as reactExports, A as ActionButton, bT as HiMiniChevronLeft, c as HiMiniChevronRight, aX as IconActionButton, x as HiMiniXMark, b0 as GuardModalLayer, bU as HiMiniFunnel, ao as HiMiniMagnifyingGlass, bV as HiMiniArrowDown, bW as HiMiniArrowUp, S as SectionLabel, ar as HiMiniArrowPath, a$ as HiMiniBugAnt, k as EmptyState, $ as HiMiniAdjustmentsHorizontal, b1 as ConnectFlowCard, K as HiMiniExclamationTriangle, bX as runAuditRemediation, M as Badge, bQ as isBlockedGuardAction, aQ as isSupplyChainAuditEvidence, m as HiMiniCheckCircle, R as HiMiniXCircle, e as harnessDisplayName, bl as HiMiniDocumentText, bk as guardAwareHref, q as HiMiniShieldCheck } from "../guard-dashboard.js";
import { p as packageWorkbenchEcosystems, f as filterPackageWorkbenchFindings, s as sortPackageWorkbenchFindings, u as useResolvedApprovalGate, i as isApprovalGateRequiredError, A as ApprovalProofModal } from "./supply-chain-hub-workspace.js";
import { r as resolveManagerCoverageStatus } from "./supply-chain-protection-stats.js";
const STEPS = [
  { id: "preparing", label: "Prepare workspace" },
  { id: "scanning", label: "Scan manifests and lockfiles" },
  { id: "evaluating", label: "Evaluate packages against Guard intel" },
  { id: "finalizing", label: "Prepare results" }
];
function stepState(stepId, phase, running) {
  const order = STEPS.map((step) => step.id);
  const stepIndex = order.indexOf(stepId);
  const phaseIndex = order.indexOf(phase);
  if (!running && phase === "idle") {
    return "pending";
  }
  if (phase === "finalizing" && stepId !== "finalizing") {
    return "done";
  }
  if (stepIndex < phaseIndex) {
    return "done";
  }
  if (stepIndex === phaseIndex) {
    return "active";
  }
  return "pending";
}
function stepTextClass(state) {
  if (state === "active") {
    return "font-medium text-brand-dark";
  }
  if (state === "done") {
    return "text-slate-600";
  }
  return "text-slate-400";
}
function stepBubbleClass(state) {
  if (state === "active") {
    return "bg-brand-blue text-white";
  }
  if (state === "done") {
    return "bg-brand-green/15 text-brand-green-text";
  }
  return "border border-slate-200 bg-white text-slate-400";
}
function AuditProgressStepList({ phase, running }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("ol", { className: "space-y-2", "aria-live": "polite", "aria-busy": running, "data-testid": "audit-run-progress", children: STEPS.map((step, index) => {
    const state = stepState(step.id, phase, running);
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: `flex items-center gap-2 text-sm ${stepTextClass(state)}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "span",
        {
          className: `inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] font-semibold ${stepBubbleClass(state)}`,
          "aria-hidden": "true",
          children: state === "done" ? "✓" : index + 1
        }
      ),
      step.label
    ] }, step.id);
  }) });
}
function auditProgressActive(phase, running) {
  return running || phase !== "idle";
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
function cloudIntelLabel(cloudState, source) {
  if (cloudState === "local_only") {
    return "Local intel only";
  }
  if (source !== null && source.length > 0) {
    return `${source} intel`;
  }
  return "Guard Cloud";
}
function cloudIntelTone(cloudState) {
  if (cloudState === "local_only") {
    return "attention";
  }
  if (cloudState === "paired_active") {
    return "green";
  }
  return "info";
}
function WorkbenchHeader({
  auditSnapshot,
  flaggedCount,
  packageCount,
  cloudState
}) {
  const manifestSummary = auditSnapshot.manifestPaths.length > 0 ? `${auditSnapshot.manifestPaths.length} manifest${auditSnapshot.manifestPaths.length === 1 ? "" : "s"}` : null;
  const lockfileSummary = auditSnapshot.lockfilePaths.length > 0 ? `${auditSnapshot.lockfilePaths.length} lockfile${auditSnapshot.lockfilePaths.length === 1 ? "" : "s"}` : null;
  const scanSummary = [manifestSummary, lockfileSummary].filter((entry) => entry !== null).join(" · ");
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 text-xs text-slate-500", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(auditSnapshot.decision), children: auditSnapshot.decision }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudIntelTone(cloudState), children: cloudIntelLabel(cloudState, auditSnapshot.source) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        auditSnapshot.inventory.totalPackages,
        " package",
        auditSnapshot.inventory.totalPackages === 1 ? "" : "s",
        " indexed"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        packageCount,
        " in table"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        flaggedCount,
        " need review"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { "aria-hidden": "true", children: "·" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        "Last audit ",
        formatRelativeTime(auditSnapshot.generatedAt)
      ] })
    ] }),
    scanSummary.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-[11px] text-slate-400", children: [
      "Scanned ",
      scanSummary,
      " across this workspace."
    ] }) : null
  ] });
}
function WorkbenchPagination({ page, pageCount, total, onPageChange }) {
  const handlePrevious = reactExports.useCallback(() => {
    onPageChange(Math.max(0, page - 1));
  }, [onPageChange, page]);
  const handleNext = reactExports.useCallback(() => {
    onPageChange(Math.min(pageCount - 1, page + 1));
  }, [onPageChange, page, pageCount]);
  if (pageCount <= 1) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
      "Showing ",
      total,
      " finding",
      total === 1 ? "" : "s"
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
      "Page ",
      page + 1,
      " of ",
      pageCount,
      " · ",
      total,
      " finding",
      total === 1 ? "" : "s"
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: handlePrevious, disabled: page === 0, children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronLeft, { className: "h-4 w-4", "aria-hidden": "true" }),
        "Previous"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: handleNext, disabled: page >= pageCount - 1, children: [
        "Next",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4", "aria-hidden": "true" })
      ] })
    ] })
  ] });
}
function humanizeReasonMessage(code, message) {
  if (code === "unknown_package") {
    return "Guard Cloud has not indexed this package yet. It is not treated as a security finding.";
  }
  if (code === "no_cached_match") {
    return "No local intel match yet. Sync Guard Cloud or retry after the next bundle refresh.";
  }
  return message;
}
function FindingDetailPanel({ finding, onClose }) {
  const handleClose = reactExports.useCallback(() => {
    onClose();
  }, [onClose]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-h-[min(85vh,40rem)] overflow-y-auto rounded-2xl border border-slate-100 bg-white shadow-xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky top-0 z-10 flex items-start justify-between gap-3 border-b border-slate-100 bg-white/95 px-4 py-3 backdrop-blur-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base font-semibold text-brand-dark", children: finding.packageName }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-slate-500", children: [
          finding.ecosystem,
          finding.namespace !== null ? ` · ${finding.namespace}` : ""
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        IconActionButton,
        {
          variant: "ghost",
          label: "Close finding detail",
          icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-4 w-4" }),
          onClick: handleClose
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: decisionTone(finding.decision), children: finding.decision }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: severityTone(finding.severity), children: finding.severity })
      ] }),
      finding.reasons.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 space-y-3", children: finding.reasons.map((reason) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "li",
        {
          className: "rounded-xl border border-slate-100 bg-slate-50/80 px-3 py-2.5 text-xs leading-relaxed text-slate-600",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-slate-700", children: reason.code }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-slate-400", children: " · " }),
            humanizeReasonMessage(reason.code, reason.message)
          ]
        },
        `${finding.id}-${reason.code}`
      )) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-4 text-xs text-slate-500", children: "No advisory detail recorded for this package yet." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Advisory aliases" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2 flex flex-wrap gap-1.5", children: finding.advisoryAliases.map((alias) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: "rounded-full border border-slate-200 bg-white px-2.5 py-0.5 font-mono text-[11px] text-slate-600",
            children: alias
          },
          `${finding.id}-${alias}`
        )) }),
        finding.advisoryAliases.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-[11px] text-slate-500", children: "No linked CVE or GHSA aliases for this finding." }) : null
      ] })
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
function FilterModalContent({
  filters,
  ecosystems,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange
}) {
  const options = reactExports.useMemo(() => {
    return {
      ecosystems: ["all", ...ecosystems],
      decisions: ["all", "block", "ask", "warn", "monitor", "allow"],
      severities: ["all", "critical", "high", "medium", "low", "unknown"]
    };
  }, [ecosystems]);
  const handleEcosystemChange = reactExports.useCallback(
    (event) => onEcosystemChange(event.target.value),
    [onEcosystemChange]
  );
  const handleDecisionChange = reactExports.useCallback(
    (event) => onDecisionChange(event.target.value),
    [onDecisionChange]
  );
  const handleSeverityChange = reactExports.useCallback(
    (event) => onSeverityChange(event.target.value),
    [onSeverityChange]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400", children: "Ecosystem" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          value: filters.ecosystem,
          onChange: handleEcosystemChange,
          className: "mt-1.5 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
          children: options.ecosystems.map((value) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value, children: value === "all" ? "All ecosystems" : value }, value))
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400", children: "Decision" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          value: filters.decision,
          onChange: handleDecisionChange,
          className: "mt-1.5 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
          children: options.decisions.map((value) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value, children: value === "all" ? "All decisions" : value }, value))
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400", children: "Severity" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "select",
        {
          value: filters.severity,
          onChange: handleSeverityChange,
          className: "mt-1.5 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
          children: options.severities.map((value) => /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value, children: value === "all" ? "All severities" : value }, value))
        }
      )
    ] })
  ] });
}
function SortModalContent({
  sortKey,
  sortDirection,
  onSortChange
}) {
  const handleSortChange = reactExports.useCallback(
    (event) => onSortChange(event.target.value),
    [onSortChange]
  );
  const toggleDirection = reactExports.useCallback(() => {
    onSortChange(sortKey);
  }, [onSortChange, sortKey]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400", children: "Sort by" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "select",
        {
          value: sortKey,
          onChange: handleSortChange,
          className: "mt-1.5 min-h-11 w-full rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "severity", children: "Severity" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "package", children: "Package" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "ecosystem", children: "Ecosystem" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("option", { value: "decision", children: "Decision" })
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: toggleDirection,
        className: "flex w-full items-center justify-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-2.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
        children: sortDirection === "desc" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowDown, { className: "h-4 w-4", "aria-hidden": "true" }),
          " Descending"
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
          " Ascending"
        ] })
      }
    )
  ] });
}
function FilterModal({
  filters,
  activeFilterCount,
  ecosystems,
  sortKey,
  sortDirection,
  onClose,
  onSearchChange,
  onEcosystemChange,
  onDecisionChange,
  onSeverityChange,
  onSortChange,
  onClearFilters
}) {
  const [activeView, setActiveView] = reactExports.useState("filters");
  const searchRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    if (searchRef.current) {
      searchRef.current.focus();
    }
  }, [activeView]);
  const handleClearSearch = reactExports.useCallback(() => {
    onSearchChange({ target: { value: "" } });
  }, [onSearchChange]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(GuardModalLayer, { ariaLabel: "Filter and sort package findings", onClose, panelClassName: "w-full max-w-md", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "max-h-[min(85vh,44rem)] overflow-y-auto rounded-2xl border border-slate-100 bg-white shadow-xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "sticky top-0 z-10 flex items-center justify-between border-b border-slate-100 bg-white/95 px-4 py-3 backdrop-blur-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFunnel, { className: "h-4 w-4 text-slate-500", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Filters" }),
        activeFilterCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-brand-blue px-2 py-0.5 text-[10px] font-semibold text-white", children: activeFilterCount }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        IconActionButton,
        {
          variant: "ghost",
          label: "Close filters",
          icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-4 w-4" }),
          onClick: onClose
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex gap-2 border-b border-slate-100 pb-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => setActiveView("filters"),
            "aria-pressed": activeView === "filters",
            className: `flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${activeView === "filters" ? "bg-brand-blue/10 text-brand-blue" : "text-slate-600 hover:bg-slate-50"}`,
            children: "Filters"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => setActiveView("sort"),
            "aria-pressed": activeView === "sort",
            className: `flex-1 rounded-lg px-3 py-2 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${activeView === "sort" ? "bg-brand-blue/10 text-brand-blue" : "text-slate-600 hover:bg-slate-50"}`,
            children: "Sort"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "pt-4", children: activeView === "filters" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[11px] font-semibold uppercase tracking-[0.12em] text-slate-400", children: "Search" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-1.5 flex items-center gap-2 rounded-lg border border-slate-200 bg-white px-3 py-2 focus-within:border-brand-blue focus-within:ring-2 focus-within:ring-brand-blue/20", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "input",
              {
                ref: searchRef,
                type: "search",
                value: filters.search,
                onChange: onSearchChange,
                placeholder: "Search packages, advisories, CVEs…",
                "aria-label": "Search package findings",
                className: "w-full bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none"
              }
            ),
            filters.search.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: handleClearSearch,
                "aria-label": "Clear search",
                className: "rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-3.5 w-3.5" })
              }
            ) : null
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          FilterModalContent,
          {
            filters,
            ecosystems,
            onEcosystemChange,
            onDecisionChange,
            onSeverityChange
          }
        )
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(SortModalContent, { sortKey, sortDirection, onSortChange }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: onClearFilters,
          className: "text-sm font-medium text-slate-500 hover:text-slate-700",
          children: "Reset all"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: onClose, children: "Show results" })
    ] }) })
  ] }) });
}
function ActiveFilterChip({ label, onRemove }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex items-center gap-1 rounded-full border border-slate-200 bg-white px-2.5 py-1 text-xs font-medium text-brand-dark", children: [
    label,
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: onRemove,
        "aria-label": `Remove ${label}`,
        className: "rounded p-0.5 text-slate-400 hover:bg-slate-100 hover:text-slate-600",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-3 w-3" })
      }
    )
  ] });
}
function buildFilterSummary(filters, sortKey, sortDirection) {
  const items = [];
  if (filters.ecosystem !== "all") {
    items.push({ key: "ecosystem", label: `Ecosystem: ${filters.ecosystem}` });
  }
  if (filters.decision !== "all") {
    items.push({ key: "decision", label: `Decision: ${filters.decision}` });
  }
  if (filters.severity !== "all") {
    items.push({ key: "severity", label: `Severity: ${filters.severity}` });
  }
  if (filters.search.trim().length > 0) {
    items.push({ key: "search", label: `Search: "${filters.search.trim()}"` });
  }
  if (sortKey !== "severity" || sortDirection !== "desc") {
    items.push({ key: "sort", label: `Sort: ${sortKey} ${sortDirection === "desc" ? "↓" : "↑"}` });
  }
  return items;
}
const WORKBENCH_PAGE_SIZE = 25;
function FilterChip({ label, active, count, onSelect }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "aria-pressed": active,
      onClick: onSelect,
      className: `inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${active ? "bg-brand-dark text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: label }),
        count !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: `rounded-full px-1.5 py-0.5 text-[10px] font-semibold ${active ? "bg-white/20 text-white" : "bg-slate-100 text-slate-500"}`,
            "aria-label": `${count} result${count === 1 ? "" : "s"}`,
            children: count
          }
        ) : null
      ]
    }
  );
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
function WorkbenchEmptyState({ auditConnectGate }) {
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
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    EmptyState,
    {
      title: "No workspace audit yet",
      body: "Run a workspace audit to index dependencies across npm, pnpm, PyPI, and other ecosystems found in this project.",
      tone: "teach"
    }
  );
}
function PackageWorkbenchPanel({
  auditConnectGate = null,
  auditError = null,
  auditSnapshot,
  onRunAudit,
  auditRunning = false,
  auditPhase = "idle",
  cloudState = null
}) {
  const [viewMode, setViewMode] = reactExports.useState("all");
  const [filters, setFilters] = reactExports.useState({
    ecosystem: "all",
    decision: "all",
    severity: "all",
    search: ""
  });
  const [sortState, setSortState] = reactExports.useState({ sortKey: "severity", sortDirection: "desc" });
  const { sortKey, sortDirection } = sortState;
  const [selectedId, setSelectedId] = reactExports.useState("");
  const [page, setPage] = reactExports.useState(0);
  const [filterModalOpen, setFilterModalOpen] = reactExports.useState(false);
  const findings = auditSnapshot?.findings ?? [];
  const packages = auditSnapshot?.packages ?? [];
  const tableSource = viewMode === "review" ? findings : packages;
  const progressActive = auditProgressActive(auditPhase, auditRunning);
  const showResults = auditSnapshot !== null && !progressActive && (auditConnectGate === null || auditConnectGate === void 0);
  const ecosystems = reactExports.useMemo(() => packageWorkbenchEcosystems(tableSource), [tableSource]);
  const filteredFindings = reactExports.useMemo(
    () => filterPackageWorkbenchFindings(tableSource, filters),
    [tableSource, filters]
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
  const pageCount = Math.max(1, Math.ceil(sortedFindings.length / WORKBENCH_PAGE_SIZE));
  const safePage = page >= pageCount ? 0 : page;
  const pagedFindings = reactExports.useMemo(() => {
    const start = safePage * WORKBENCH_PAGE_SIZE;
    return sortedFindings.slice(start, start + WORKBENCH_PAGE_SIZE);
  }, [safePage, sortedFindings]);
  const handleSearchChange = reactExports.useCallback((event) => {
    setFilters((prev) => ({ ...prev, search: event.target.value }));
    setSelectedId("");
    setPage(0);
  }, []);
  const handleEcosystemChange = reactExports.useCallback((ecosystem) => {
    setFilters((prev) => ({ ...prev, ecosystem }));
    setSelectedId("");
    setPage(0);
  }, []);
  const handleDecisionChange = reactExports.useCallback((decision) => {
    setFilters((prev) => ({ ...prev, decision }));
    setSelectedId("");
    setPage(0);
  }, []);
  const handleSeverityChange = reactExports.useCallback((severity) => {
    setFilters((prev) => ({ ...prev, severity }));
    setSelectedId("");
    setPage(0);
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
    setPage(0);
  }, []);
  const handleResetSort = reactExports.useCallback(() => {
    setSortState({ sortKey: "severity", sortDirection: "desc" });
  }, []);
  const handleSelectFinding = reactExports.useCallback((id) => {
    setSelectedId(id);
  }, []);
  const handleCloseFinding = reactExports.useCallback(() => {
    setSelectedId("");
  }, []);
  const handlePageChange = reactExports.useCallback((nextPage) => {
    setPage(nextPage);
    setSelectedId("");
  }, []);
  const handleViewAll = reactExports.useCallback(() => {
    setViewMode("all");
    setPage(0);
    setSelectedId("");
  }, []);
  const handleViewReview = reactExports.useCallback(() => {
    setViewMode("review");
    setPage(0);
    setSelectedId("");
  }, []);
  const handleRunAudit = reactExports.useCallback(() => {
    onRunAudit?.();
  }, [onRunAudit]);
  const openFilterModal = reactExports.useCallback(() => setFilterModalOpen(true), []);
  const closeFilterModal = reactExports.useCallback(() => setFilterModalOpen(false), []);
  const handleClearFilters = reactExports.useCallback(() => {
    setFilters({ ecosystem: "all", decision: "all", severity: "all", search: "" });
    setSortState({ sortKey: "severity", sortDirection: "desc" });
    setPage(0);
    setSelectedId("");
  }, []);
  const activeFilterCount = (filters.ecosystem !== "all" ? 1 : 0) + (filters.decision !== "all" ? 1 : 0) + (filters.severity !== "all" ? 1 : 0) + (filters.search.trim().length > 0 ? 1 : 0);
  const filterSummary = reactExports.useMemo(
    () => buildFilterSummary(filters, sortKey, sortDirection),
    [filters, sortKey, sortDirection]
  );
  const headerTitle = progressActive ? "Auditing workspace" : "Workspace audit";
  const headerBody = progressActive ? "Guard is scanning manifests, lockfiles, and package intel for this workspace." : "Browse indexed packages, filter by ecosystem, and open any row for advisory detail.";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", "data-testid": "workspace-audit-panel", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: headerTitle }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-500", children: headerBody })
        ] }),
        onRunAudit !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
          ActionButton,
          {
            variant: "outline",
            onClick: handleRunAudit,
            disabled: auditRunning,
            "aria-busy": auditRunning,
            children: [
              auditRunning ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-4 w-4 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
              auditSnapshot === null ? "Run audit" : "Run audit again"
            ]
          }
        ) : null
      ] }),
      auditSnapshot !== null && showResults ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        WorkbenchHeader,
        {
          auditSnapshot,
          flaggedCount: findings.length,
          packageCount: packages.length,
          cloudState
        }
      ) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-4 space-y-4", children: auditConnectGate !== null && auditConnectGate !== void 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(WorkbenchEmptyState, { auditConnectGate }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      auditError ? /* @__PURE__ */ jsxRuntimeExports.jsx(WorkbenchAuditErrorBanner, { message: auditError }) : null,
      progressActive ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-blue/15 bg-brand-blue/[0.03] px-4 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(AuditProgressStepList, { phase: auditPhase, running: auditRunning }) }) : null,
      auditSnapshot === null && !progressActive ? /* @__PURE__ */ jsxRuntimeExports.jsx(WorkbenchEmptyState, { auditConnectGate: null }) : null,
      showResults && auditSnapshot !== null && packages.length === 0 && auditSnapshot.inventory.totalPackages > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "Package list not loaded",
          body: "This audit indexed packages, but the detailed list was not stored yet. Run audit again to load the full inventory table.",
          tone: "teach"
        }
      ) : null,
      showResults && auditSnapshot !== null && packages.length === 0 && auditSnapshot.inventory.totalPackages === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No packages indexed",
          body: "The latest workspace audit completed, but no supported package manifests or lockfiles were found.",
          tone: "teach"
        }
      ) : null,
      showResults && packages.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        cloudState === "local_only" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-slate-500", children: "This device is using local intel only. Connect Guard Cloud and sync supply-chain intel for live CVE and malware coverage." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              FilterChip,
              {
                label: "All packages",
                count: packages.length,
                active: viewMode === "all",
                onSelect: handleViewAll
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              FilterChip,
              {
                label: "Needs review",
                count: findings.length,
                active: viewMode === "review",
                onSelect: handleViewReview
              }
            )
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: openFilterModal, children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
            "Filters",
            activeFilterCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1.5 rounded-full bg-brand-blue px-1.5 py-0.5 text-[10px] font-semibold text-white", children: activeFilterCount }) : null
          ] }) })
        ] }),
        filterSummary.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-center gap-2", children: filterSummary.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ActiveFilterChip,
          {
            label: item.label,
            onRemove: () => {
              if (item.key === "ecosystem") handleEcosystemChange("all");
              else if (item.key === "decision") handleDecisionChange("all");
              else if (item.key === "severity") handleSeverityChange("all");
              else if (item.key === "search") handleSearchChange({ target: { value: "" } });
              else if (item.key === "sort") handleResetSort();
            }
          },
          item.key
        )) }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          WorkbenchPagination,
          {
            page: safePage,
            pageCount,
            total: sortedFindings.length,
            onPageChange: handlePageChange
          }
        ),
        filterModalOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          FilterModal,
          {
            filters,
            activeFilterCount,
            ecosystems,
            sortKey,
            sortDirection,
            onClose: closeFilterModal,
            onSearchChange: handleSearchChange,
            onEcosystemChange: handleEcosystemChange,
            onDecisionChange: handleDecisionChange,
            onSeverityChange: handleSeverityChange,
            onSortChange: handleSortChange,
            onClearFilters: handleClearFilters
          }
        ) : null,
        sortedFindings.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "py-6 text-center text-sm text-slate-500", children: viewMode === "review" && findings.length === 0 ? "No packages need review in this audit." : "No packages match the current filters." }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "overflow-hidden rounded-xl border border-slate-100",
            role: "table",
            "aria-label": viewMode === "review" ? "Packages needing review" : "Indexed packages",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs(
                "div",
                {
                  className: "sticky top-0 z-[1] hidden border-b border-slate-100 bg-slate-50 px-4 py-2 sm:grid sm:grid-cols-[minmax(0,1fr)_auto] sm:gap-3",
                  role: "row",
                  children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Package" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Decision · Severity" })
                  ]
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "max-h-[min(60vh,32rem)] overflow-y-auto overscroll-y-contain", role: "rowgroup", children: pagedFindings.map((finding) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                FindingRow,
                {
                  finding,
                  selected: selectedId === finding.id,
                  onSelect: handleSelectFinding
                },
                finding.id
              )) })
            ]
          }
        )
      ] }) : null
    ] }) }),
    selectedFinding !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardModalLayer,
      {
        ariaLabel: `Finding detail for ${selectedFinding.packageName}`,
        onClose: handleCloseFinding,
        panelClassName: "w-full max-w-2xl",
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(FindingDetailPanel, { finding: selectedFinding, onClose: handleCloseFinding })
      }
    ) : null
  ] });
}
function auditSeverityForDecision(decision, blockedCount) {
  if (decision === "block" || blockedCount > 0) {
    return "high";
  }
  if (decision === "ask") {
    return "medium";
  }
  if (decision === "warn") {
    return "medium";
  }
  return "info";
}
function workspaceAuditTitle(decision) {
  if (decision === "block") {
    return "Workspace audit found blocked packages";
  }
  if (decision === "ask") {
    return "Workspace audit needs review";
  }
  return "Workspace audit completed";
}
function workspaceAuditRemediation(decision, blockedCount) {
  if (blockedCount > 0) {
    return "Review blocked packages in Evidence and update lockfiles before retrying installs.";
  }
  if (decision === "ask") {
    return "Review flagged packages and repair lockfiles before continuing.";
  }
  return "Re-run workspace audit after dependency changes.";
}
function buildPackageManagerAuditResult(manager, protection, generatedAt) {
  const coverage = resolveManagerCoverageStatus(protection, manager);
  if (coverage === "protected") {
    return null;
  }
  if (coverage === "restart_required") {
    return {
      id: `unprotected-${manager}`,
      severity: "medium",
      title: `${manager} is waiting for restart`,
      detail: `Guard already updated your shell profile for ${manager}. Open a new shell or restart AI apps so ${manager} resolves through Guard.`,
      harness: "global",
      workspace: null,
      timestamp: generatedAt,
      remediation: "Open a new shell or restart AI apps to finish package-manager interception.",
      remediationAction: null,
      resolved: false,
      evidenceHref: null
    };
  }
  if (coverage === "path_repair") {
    return {
      id: `unprotected-${manager}`,
      severity: "medium",
      title: `${manager} shim is installed but PATH still needs repair`,
      detail: `Guard already installed the ${manager} shim on this machine. Repair PATH so ${manager} commands resolve through Guard before package installs run.`,
      harness: "global",
      workspace: null,
      timestamp: generatedAt,
      remediation: "Repair PATH from Supply chain or run hol-guard package-shims repair for this manager.",
      remediationAction: {
        action: "package_shim_path",
        manager,
        label: "Repair PATH"
      },
      resolved: false,
      evidenceHref: `/evidence?harness=global&search=${encodeURIComponent(manager)}`
    };
  }
  return {
    id: `unprotected-${manager}`,
    severity: "high",
    title: `${manager} is not intercepted by Guard`,
    detail: `The ${manager} shim is missing from PATH. Installs via ${manager} bypass Guard's supply chain protection.`,
    harness: "global",
    workspace: null,
    timestamp: generatedAt,
    remediation: `Guard can install the shim and update PATH for ${manager} from this dashboard.`,
    remediationAction: {
      action: "package_shim_path",
      manager,
      label: "Install Guard"
    },
    resolved: false,
    evidenceHref: `/evidence?harness=global&search=${encodeURIComponent(manager)}`
  };
}
function deriveFrontendAuditResults(receipts, snapshot) {
  const results = [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (protection) {
    const managersNeedingAttention = protection.supported_managers.filter(
      (manager) => resolveManagerCoverageStatus(protection, manager) !== "protected"
    );
    for (const mgr of managersNeedingAttention) {
      const auditResult = buildPackageManagerAuditResult(mgr, protection, snapshot.generated_at);
      if (auditResult !== null) {
        results.push(auditResult);
      }
    }
  }
  const blockedReceipts = receipts.filter((r) => isBlockedGuardAction(r.policy_decision));
  for (const r of blockedReceipts.slice(0, 20)) {
    const evidenceParams = new URLSearchParams();
    evidenceParams.set("harness", r.harness || "global");
    if (r.artifact_name) {
      evidenceParams.set("search", r.artifact_name);
    }
    results.push({
      id: `blocked-${r.receipt_id}`,
      severity: "medium",
      title: r.artifact_name ? `Blocked: ${r.artifact_name}` : "Blocked action",
      detail: r.capabilities_summary || "Guard blocked this action based on policy.",
      harness: r.harness,
      workspace: r.source_scope ?? null,
      timestamp: r.timestamp,
      remediation: "Review the action in evidence and adjust policy if it was a false positive.",
      remediationAction: null,
      resolved: true,
      evidenceHref: `/evidence?${evidenceParams.toString()}`
    });
  }
  for (const receipt of receipts) {
    if (receipt.harness !== "package-firewall") {
      continue;
    }
    const evidence = receipt.scanner_evidence?.find(isSupplyChainAuditEvidence);
    if (evidence === void 0) {
      continue;
    }
    const decision = typeof evidence.audit_decision === "string" ? evidence.audit_decision : "monitor";
    const blockedCount = typeof evidence.blocked_package_count === "number" ? evidence.blocked_package_count : 0;
    const totalPackages = typeof evidence.total_packages === "number" ? evidence.total_packages : blockedCount;
    const manifestPaths = Array.isArray(evidence.manifest_paths) ? evidence.manifest_paths.filter((entry) => typeof entry === "string") : [];
    const lockfilePaths = Array.isArray(evidence.lockfile_paths) ? evidence.lockfile_paths.filter((entry) => typeof entry === "string") : [];
    const inventorySummary = [
      manifestPaths.length > 0 ? `${manifestPaths.length} manifest(s)` : null,
      lockfilePaths.length > 0 ? `${lockfilePaths.length} lockfile(s)` : null,
      `${totalPackages} package(s)`
    ].filter((entry) => entry !== null).join(", ");
    results.push({
      id: `workspace-audit-${receipt.receipt_id}`,
      severity: auditSeverityForDecision(decision, blockedCount),
      title: workspaceAuditTitle(decision),
      detail: receipt.capabilities_summary || `Guard scanned ${inventorySummary} and returned a ${decision} decision.`,
      harness: "package-firewall",
      workspace: receipt.source_scope,
      timestamp: receipt.timestamp,
      remediation: workspaceAuditRemediation(decision, blockedCount),
      remediationAction: null,
      resolved: decision === "monitor" && blockedCount === 0,
      evidenceHref: `/evidence?harness=package-firewall&search=${encodeURIComponent(receipt.receipt_id)}`
    });
  }
  if (snapshot.runtime_state === null) {
    results.push({
      id: "daemon-offline",
      severity: "critical",
      title: "Guard daemon is offline",
      detail: "The local Guard service is not running. No protection is active.",
      harness: "global",
      workspace: null,
      timestamp: snapshot.generated_at,
      remediation: "Start Guard with hol-guard bootstrap or check system logs.",
      remediationAction: null,
      resolved: false,
      evidenceHref: null
    });
  }
  return results;
}
function severityBadgeTone(severity) {
  if (severity === "critical") return "destructive";
  if (severity === "high") return "attention";
  if (severity === "medium") return "warning";
  if (severity === "low") return "info";
  return "default";
}
function AuditResultRow({ result, onMarkResolved, onRunRemediation, running, actionMessage }) {
  const [expanded, setExpanded] = reactExports.useState(false);
  const toggle = reactExports.useCallback(() => setExpanded((p) => !p), []);
  const handleResolve = reactExports.useCallback(() => onMarkResolved?.(result.id), [onMarkResolved, result.id]);
  const showInlineAction = !result.resolved && (result.remediationAction !== null || onMarkResolved);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `border-b border-slate-100 last:border-b-0 ${result.resolved ? "opacity-60" : ""}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 px-4 py-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4 hover:bg-slate-50/60", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: toggle,
          "aria-expanded": expanded,
          className: "flex min-w-0 flex-1 items-start gap-3 text-left focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 shrink-0", "aria-hidden": "true", children: result.resolved ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-brand-green" }) : result.severity === "critical" || result.severity === "high" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4 text-red-500" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 text-brand-attention" }) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-0.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: result.title }),
                /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: severityBadgeTone(result.severity), children: result.severity }),
                result.resolved && /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Resolved" })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
                harnessDisplayName(result.harness),
                result.workspace ? ` / ${result.workspace}` : "",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mx-1.5 text-slate-300", children: "·" }),
                formatRelativeTime(result.timestamp)
              ] })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              HiMiniChevronRight,
              {
                className: `mt-0.5 h-4 w-4 shrink-0 text-slate-300 transition-transform ${expanded ? "rotate-90" : ""}`,
                "aria-hidden": "true"
              }
            )
          ]
        }
      ),
      showInlineAction && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0 pl-7 sm:pl-0 sm:pt-0.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        AuditRowActions,
        {
          result,
          onMarkResolved,
          onRunRemediation,
          running
        }
      ) })
    ] }),
    actionMessage !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "px-4 pb-2 text-xs text-slate-500", children: actionMessage }),
    expanded && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 bg-slate-50/40 px-4 py-3 space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/80", children: result.detail }),
      result.remediation && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/70", children: result.remediation }),
      !result.resolved && onMarkResolved && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: handleResolve, children: "Mark as resolved" })
    ] })
  ] });
}
function AuditRowActions(props) {
  const { result, onMarkResolved, onRunRemediation, running } = props;
  const handleMarkResolved = reactExports.useCallback(() => onMarkResolved?.(result.id), [onMarkResolved, result.id]);
  const handleRunRemediation = reactExports.useCallback(() => onRunRemediation(result), [onRunRemediation, result]);
  if (result.remediationAction !== null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
      result.evidenceHref && /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: guardAwareHref(result.evidenceHref),
          className: "inline-flex h-9 w-9 items-center justify-center rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          "aria-label": `View evidence for ${result.title}`,
          title: "View evidence",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-4 w-4", "aria-hidden": "true" })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        IconActionButton,
        {
          variant: "primary",
          label: result.remediationAction.label,
          icon: running ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-4 w-4" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4" }),
          onClick: handleRunRemediation,
          disabled: running,
          spinning: running
        }
      )
    ] });
  }
  if (onMarkResolved) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
      result.evidenceHref && /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: guardAwareHref(result.evidenceHref),
          className: "inline-flex h-9 w-9 items-center justify-center rounded-lg p-1.5 text-slate-400 hover:bg-slate-100 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          "aria-label": `View evidence for ${result.title}`,
          title: "View evidence",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-4 w-4", "aria-hidden": "true" })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        IconActionButton,
        {
          variant: "outline",
          label: "Resolve",
          icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4" }),
          onClick: handleMarkResolved
        }
      )
    ] });
  }
  return null;
}
function AuditWorkspace({ snapshot, receipts, approvalGate, auditSession }) {
  const [filter, setFilter] = reactExports.useState({
    severityFilter: "all",
    harnessFilter: "",
    resolvedFilter: "open",
    searchQuery: ""
  });
  const [resolvedIds, setResolvedIds] = reactExports.useState(/* @__PURE__ */ new Set());
  const [pendingRemediation, setPendingRemediation] = reactExports.useState(null);
  const [runningRemediationId, setRunningRemediationId] = reactExports.useState(null);
  const [remediationMessages, setRemediationMessages] = reactExports.useState({});
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);
  const handleSearchChange = reactExports.useCallback((e) => {
    setFilter((f) => ({ ...f, searchQuery: e.target.value }));
  }, []);
  const handleSeverityChange = reactExports.useCallback((sev) => {
    setFilter((f) => ({ ...f, severityFilter: sev }));
  }, []);
  const handleResolvedFilterChange = reactExports.useCallback(
    (val) => {
      setFilter((f) => ({ ...f, resolvedFilter: val }));
    },
    []
  );
  const handleMarkResolved = reactExports.useCallback((id) => {
    setResolvedIds((prev) => /* @__PURE__ */ new Set([...prev, id]));
  }, []);
  const executeRemediation = reactExports.useCallback(
    async (result, credentials) => {
      if (result.remediationAction === null) return;
      setRunningRemediationId(result.id);
      setRemediationMessages((prev) => ({ ...prev, [result.id]: "Running remediation through the local daemon." }));
      try {
        await runAuditRemediation({
          ...result.remediationAction,
          ...credentials
        });
        setResolvedIds((prev) => /* @__PURE__ */ new Set([...prev, result.id]));
        setRemediationMessages((prev) => ({
          ...prev,
          [result.id]: "Remediation completed. Restart your shell before retrying package installs."
        }));
      } catch (error) {
        if (credentials === void 0 && isApprovalGateRequiredError(error)) {
          await resolveApprovalGate();
          setPendingRemediation(result);
          setRemediationMessages((prev) => {
            const next = { ...prev };
            delete next[result.id];
            return next;
          });
          return;
        }
        const message = error instanceof Error ? error.message : "Unable to run remediation.";
        setRemediationMessages((prev) => ({ ...prev, [result.id]: message }));
      } finally {
        setRunningRemediationId(null);
      }
    },
    [resolveApprovalGate]
  );
  const handleRunRemediation = reactExports.useCallback(
    (result) => {
      if (result.remediationAction === null) return;
      void executeRemediation(result);
    },
    [executeRemediation]
  );
  const handleCancelRemediationGate = reactExports.useCallback(() => setPendingRemediation(null), []);
  const handleConfirmRemediationGate = reactExports.useCallback(
    (credentials) => {
      const result = pendingRemediation;
      if (result === null) return;
      setPendingRemediation(null);
      void executeRemediation(result, credentials);
    },
    [executeRemediation, pendingRemediation]
  );
  const baseResults = reactExports.useMemo(
    () => deriveFrontendAuditResults(receipts, snapshot),
    [receipts, snapshot]
  );
  const results = reactExports.useMemo(() => {
    return baseResults.map((r) => ({ ...r, resolved: r.resolved || resolvedIds.has(r.id) })).filter((r) => {
      const matchesSeverity = filter.severityFilter === "all" || r.severity === filter.severityFilter;
      const matchesResolved = filter.resolvedFilter === "all" || filter.resolvedFilter === "open" && !r.resolved || filter.resolvedFilter === "resolved" && r.resolved;
      const matchesSearch = filter.searchQuery === "" || r.title.toLowerCase().includes(filter.searchQuery.toLowerCase()) || r.detail.toLowerCase().includes(filter.searchQuery.toLowerCase());
      return matchesSeverity && matchesResolved && matchesSearch;
    }).sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
      return order[a.severity] - order[b.severity];
    });
  }, [baseResults, filter, resolvedIds]);
  const openCount = reactExports.useMemo(
    () => baseResults.filter((r) => !r.resolved && !resolvedIds.has(r.id)).length,
    [baseResults, resolvedIds]
  );
  const criticalCount = reactExports.useMemo(
    () => baseResults.filter(
      (r) => (r.severity === "critical" || r.severity === "high") && !r.resolved && !resolvedIds.has(r.id)
    ).length,
    [baseResults, resolvedIds]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      PackageWorkbenchPanel,
      {
        auditConnectGate: auditSession.auditConnectGate,
        auditError: auditSession.auditError,
        auditSnapshot: auditSession.auditSnapshot,
        auditRunning: auditSession.auditRunning,
        auditPhase: auditSession.auditPhase,
        cloudState: snapshot.cloud_state,
        onRunAudit: auditSession.handleRunAudit
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Workspace audit results and open issues. Fix high-priority items inline." }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        criticalCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs(Badge, { tone: "destructive", children: [
          criticalCount,
          " critical"
        ] }),
        openCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Badge, { tone: "attention", children: [
          openCount,
          " open"
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "All clear" })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3 space-y-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Filters" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-3.5 w-3.5 text-slate-400 shrink-0", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              placeholder: "Search issues...",
              value: filter.searchQuery,
              onChange: handleSearchChange,
              "aria-label": "Search audit issues",
              className: "bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
            }
          )
        ] }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 self-center", children: "Severity:" }),
          ["all", "critical", "high", "medium", "low", "info"].map((sev) => /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: () => handleSeverityChange(sev),
              "aria-pressed": filter.severityFilter === sev,
              className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${filter.severityFilter === sev ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
              children: sev.charAt(0).toUpperCase() + sev.slice(1)
            },
            sev
          ))
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 self-center", children: "Status:" }),
          ["all", "open", "resolved"].map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              type: "button",
              onClick: () => handleResolvedFilterChange(s),
              "aria-pressed": filter.resolvedFilter === s,
              className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${filter.resolvedFilter === s ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
              children: s.charAt(0).toUpperCase() + s.slice(1)
            },
            s
          ))
        ] })
      ] }),
      results.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: openCount === 0 ? "No audit issues found" : "No results match your filter",
          body: openCount === 0 ? "Guard found no issues in the current workspace. Keep running to build more coverage." : "Try adjusting the severity or status filters to see more results.",
          tone: "teach"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "list", "aria-label": "Audit results", children: results.map((result) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "listitem", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        AuditResultRow,
        {
          result,
          onMarkResolved: handleMarkResolved,
          onRunRemediation: handleRunRemediation,
          running: runningRemediationId === result.id,
          actionMessage: remediationMessages[result.id] ?? null
        }
      ) }, result.id)) })
    ] }),
    pendingRemediation !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(
      RemediationApprovalModal,
      {
        result: pendingRemediation,
        approvalGate: resolvedApprovalGate,
        onCancel: handleCancelRemediationGate,
        onConfirm: handleConfirmRemediationGate
      }
    )
  ] });
}
function RemediationApprovalModal(props) {
  const { approvalGate, onCancel, onConfirm, result } = props;
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ApprovalProofModal,
    {
      title: result.remediationAction?.label ?? "Run remediation",
      detail: "Enter local approval proof before Guard changes package-manager protection on this device.",
      confirmLabel: "Run remediation",
      approvalGate,
      onCancel,
      onConfirm
    }
  );
}
export {
  AuditWorkspace,
  deriveFrontendAuditResults
};
