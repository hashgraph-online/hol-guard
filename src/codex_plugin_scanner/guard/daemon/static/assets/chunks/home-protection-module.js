import { r as reactExports, j as jsxRuntimeExports, l as HiMiniShieldCheck, bf as HiMiniInformationCircle, x as HiMiniExclamationTriangle, S as SectionLabel, A as ActionButton, bj as HiMiniArrowRight, ad as Tag, m as formatRelativeTime, p as HiMiniChevronUp, q as HiMiniChevronDown, d as HiMiniCheckCircle, J as HiMiniXCircle } from "../guard-dashboard.js";
function resolveHomeProtectionStatus(snapshot) {
  const protection = snapshot.supply_chain?.package_manager_protection;
  if (!protection) return "unknown";
  if (protection.path_status === "restart_required" && protection.installed_managers.length > 0) {
    return "staged";
  }
  if (protection.unprotected_managers.length === 0 && protection.protected_managers.length > 0) {
    return "protected";
  }
  if (protection.protected_managers.length > 0) return "partial";
  return "unprotected";
}
function resolveLastBlockedInstall(managedInstalls) {
  const inactive = managedInstalls.filter((i) => !i.active);
  if (inactive.length === 0) return null;
  return inactive.sort((a, b) => +new Date(b.updated_at) - +new Date(a.updated_at))[0] ?? null;
}
function resolveIntelStaleness(snapshot) {
  const receipts = snapshot.latest_receipts;
  if (receipts.length === 0) {
    return { stale: false, label: "" };
  }
  const latest = receipts[0];
  const ageMs = Date.now() - new Date(latest.timestamp).getTime();
  const stale = ageMs > 7 * 24 * 60 * 60 * 1e3;
  return {
    stale,
    label: stale ? `Last activity ${formatRelativeTime(latest.timestamp)} -- intel may be stale` : ""
  };
}
function ProtectedManagerRow({ manager, protected: isProtected }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2 py-1.5 border-b border-slate-100 last:border-b-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-mono text-brand-dark", children: manager }),
    isProtected ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "green", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 mr-1", "aria-hidden": "true" }),
      "Protected"
    ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "attention", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-3.5 w-3.5 mr-1", "aria-hidden": "true" }),
      "Unprotected"
    ] })
  ] });
}
function HomeProtectionModule({
  snapshot,
  managedInstalls,
  onOpenFleet,
  onOpenSupplyChain
}) {
  const status = reactExports.useMemo(() => resolveHomeProtectionStatus(snapshot), [snapshot]);
  const lastBlocked = reactExports.useMemo(() => resolveLastBlockedInstall(managedInstalls), [managedInstalls]);
  const intelState = reactExports.useMemo(() => resolveIntelStaleness(snapshot), [snapshot]);
  const protection = snapshot.supply_chain?.package_manager_protection;
  const allManagers = reactExports.useMemo(() => {
    if (!protection) return [];
    const all = /* @__PURE__ */ new Set([
      ...protection.protected_managers,
      ...protection.unprotected_managers
    ]);
    return Array.from(all).sort();
  }, [protection]);
  const protectedCount = protection?.protected_managers.length ?? 0;
  const totalCount = allManagers.length;
  const defaultExpanded = totalCount <= 4;
  const [expanded, setExpanded] = reactExports.useState(defaultExpanded);
  const hasManagers = totalCount > 0;
  const statusBorderClass = status === "protected" ? "border-brand-green/20 bg-brand-green/[0.04]" : status === "staged" ? "border-brand-blue/20 bg-brand-blue/[0.04]" : status === "partial" ? "border-brand-attention/20 bg-brand-attention/[0.04]" : status === "unprotected" ? "border-red-200 bg-red-50/60" : "border-slate-200 bg-slate-50/60";
  const StatusIcon = status === "protected" ? HiMiniShieldCheck : status === "staged" ? HiMiniInformationCircle : status === "partial" || status === "unprotected" ? HiMiniExclamationTriangle : HiMiniInformationCircle;
  const statusIconClass = status === "protected" ? "text-brand-green" : status === "staged" ? "text-brand-blue" : status === "partial" || status === "unprotected" ? "text-brand-attention" : "text-slate-400";
  const statusLabel = status === "protected" ? "Package managers protected" : status === "staged" ? "Protection staged — restart shell or apps" : status === "partial" ? "Some package managers unprotected" : status === "unprotected" ? "Package managers unprotected" : "Supply chain status unknown";
  const handleToggle = () => setExpanded((prev) => !prev);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "section",
    {
      className: `rounded-2xl border ${statusBorderClass} p-5 shadow-sm`,
      "aria-label": "Package manager protection",
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80",
            "aria-hidden": "true",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(StatusIcon, { className: `h-5 w-5 ${statusIconClass}` })
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1 space-y-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Package manager protection" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm font-medium text-brand-dark", children: statusLabel }),
            protection?.shim_dir && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-slate-500 font-mono", children: [
              "Shim dir:",
              " ",
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-brand-dark/70", children: protection.shim_dir })
            ] })
          ] }),
          (status === "unprotected" || status === "unknown") && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: onOpenSupplyChain ?? onOpenFleet, variant: "secondary", children: [
              "Set up protection",
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "ml-1.5 h-3.5 w-3.5", "aria-hidden": "true" })
            ] }),
            onOpenSupplyChain && /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "button",
              {
                type: "button",
                onClick: onOpenSupplyChain,
                className: "inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded",
                children: [
                  "View supply chain",
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "h-3 w-3", "aria-hidden": "true" })
                ]
              }
            )
          ] }),
          status === "staged" && onOpenSupplyChain && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex items-center gap-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: onOpenSupplyChain, variant: "secondary", children: [
            "Finish activation",
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "ml-1.5 h-3.5 w-3.5", "aria-hidden": "true" })
          ] }) }),
          hasManagers && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(
                  Tag,
                  {
                    tone: status === "staged" ? "blue" : protectedCount === totalCount ? "green" : protectedCount > 0 ? "attention" : "slate",
                    children: status === "staged" ? `${protection?.installed_managers.length ?? totalCount} ready after restart` : `${protectedCount} of ${totalCount} protected`
                  }
                ),
                lastBlocked && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-slate-500", children: [
                  "Last blocked",
                  " ",
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-dark", children: lastBlocked.harness }),
                  " ",
                  formatRelativeTime(lastBlocked.updated_at)
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "button",
                {
                  type: "button",
                  onClick: handleToggle,
                  className: "inline-flex items-center gap-1 rounded-lg px-2 py-1 text-xs font-medium text-brand-blue transition-colors hover:bg-brand-blue/[0.06] focus:outline-none focus:ring-2 focus:ring-brand-blue/20",
                  "aria-expanded": expanded,
                  children: expanded ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                    "Hide managers",
                    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
                  ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
                    "Show all managers",
                    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-3.5 w-3.5", "aria-hidden": "true" })
                  ] })
                }
              )
            ] }),
            expanded && /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "div",
              {
                className: "divide-y divide-slate-100 rounded-xl border border-slate-100 bg-white/80 overflow-hidden",
                role: "table",
                "aria-label": "Package manager coverage",
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs(
                    "div",
                    {
                      className: "flex items-center justify-between gap-2 px-3 py-1.5 bg-slate-50",
                      role: "row",
                      children: [
                        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Manager" }),
                        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Status" })
                      ]
                    }
                  ),
                  /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "rowgroup", children: allManagers.map((mgr) => /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-3", role: "row", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
                    ProtectedManagerRow,
                    {
                      manager: mgr,
                      protected: protection?.protected_managers.includes(mgr) ?? false
                    }
                  ) }, mgr)) })
                ]
              }
            )
          ] }),
          intelState.stale && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              HiMiniExclamationTriangle,
              {
                className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600",
                "aria-hidden": "true"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-800", children: intelState.label })
          ] }),
          status === "partial" && onOpenSupplyChain && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              onClick: onOpenSupplyChain,
              className: "inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded",
              children: [
                "View full supply chain status",
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowRight, { className: "h-3 w-3", "aria-hidden": "true" })
              ]
            }
          ) })
        ] })
      ] })
    }
  );
}
export {
  HomeProtectionModule as H,
  resolveHomeProtectionStatus as r
};
