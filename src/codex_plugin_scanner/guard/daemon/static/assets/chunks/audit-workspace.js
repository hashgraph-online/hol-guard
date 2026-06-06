import { r as reactExports, ar as runAuditRemediation, a9 as GuardHarnessActionError, j as jsxRuntimeExports, B as Badge, S as SectionLabel, W as HiMiniMagnifyingGlass, E as EmptyState, g as HiMiniCheckCircle, h as HiMiniXCircle, b as HiMiniExclamationTriangle, i as harnessDisplayName, f as formatRelativeTime, s as HiMiniChevronRight, A as ActionButton, v as HiMiniWrenchScrewdriver } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
function deriveFrontendAuditResults(receipts, snapshot) {
  const results = [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (protection && protection.unprotected_managers.length > 0) {
    for (const mgr of protection.unprotected_managers) {
      const restartRequired = protection.path_status === "restart_required" && protection.installed_managers.includes(mgr);
      results.push({
        id: `unprotected-${mgr}`,
        severity: restartRequired ? "medium" : "high",
        title: restartRequired ? `${mgr} is waiting for restart` : `${mgr} is not intercepted by Guard`,
        detail: restartRequired ? `Guard already updated your shell profile for ${mgr}. Open a new shell or restart AI apps so ${mgr} resolves through Guard.` : `The ${mgr} shim is missing from PATH. Installs via ${mgr} bypass Guard's supply chain protection.`,
        harness: "global",
        workspace: null,
        timestamp: snapshot.generated_at,
        remediation: restartRequired ? "Open a new shell or restart AI apps to finish package-manager interception." : `Guard can install the shim and update PATH for ${mgr} from this dashboard.`,
        remediationAction: restartRequired ? null : {
          action: "package_shim_path",
          manager: mgr,
          label: `Install Guard for ${mgr}`
        },
        resolved: false
      });
    }
  }
  const blockedReceipts = receipts.filter((r) => r.policy_decision === "block");
  for (const r of blockedReceipts.slice(0, 20)) {
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
      resolved: true
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
      resolved: false
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
  reactExports.useCallback(() => onRunRemediation(result), [onRunRemediation, result]);
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
      !result.resolved && onMarkResolved && result.remediationAction === null && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: handleResolve, children: "Mark as resolved" })
    ] })
  ] });
}
function AuditRowActions(props) {
  const { result, onMarkResolved, onRunRemediation, running } = props;
  const handleMarkResolved = reactExports.useCallback(() => onMarkResolved?.(result.id), [onMarkResolved, result.id]);
  const handleRunRemediation = reactExports.useCallback(() => onRunRemediation(result), [onRunRemediation, result]);
  if (result.remediationAction !== null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full sm:w-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: handleRunRemediation, disabled: running, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
      running ? "Running..." : result.remediationAction.label
    ] }) });
  }
  if (onMarkResolved) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "w-full sm:w-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: handleMarkResolved, children: "Resolve" }) });
  }
  return null;
}
function AuditWorkspace({ snapshot, receipts, approvalGate }) {
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
        if (credentials === void 0 && error instanceof GuardHarnessActionError && error.payload?.error === "approval_gate_required") {
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
