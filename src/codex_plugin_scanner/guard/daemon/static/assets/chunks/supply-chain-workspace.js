import { r as reactExports, j as jsxRuntimeExports, A as ActionButton, S as SectionLabel, T as Tag, b as HiMiniInformationCircle, E as EmptyState, d as HiMiniCheckCircle, a as HiMiniExclamationTriangle, e as HiMiniXCircle, h as harnessDisplayName, B as Badge, m as HiMiniChevronUp, n as HiMiniChevronDown, f as formatRelativeTime, ab as HiMiniArrowPath } from "../guard-dashboard.js";
import { b as resolvePackageManagerProtectionCopy } from "./runtime-overview.js";
function buildSupplyChainStats(snapshot) {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((i) => i.active).length,
    preventedInstalls: managedInstalls.filter((i) => !i.active).length,
    protectedManagers: protection?.protected_managers.length ?? 0,
    unprotectedManagers: protection?.unprotected_managers.length ?? 0
  };
}
function StatCard({ label, value, tone = "slate" }) {
  const toneClass = tone === "green" ? "text-brand-green" : tone === "attention" ? "text-brand-attention" : tone === "blue" ? "text-brand-blue" : "text-brand-dark";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-1.5 text-2xl font-bold tabular-nums ${toneClass}`, children: value })
  ] });
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
function SupplyChainWorkspace({ snapshot, onGoHome }) {
  const [filter, setFilter] = reactExports.useState({
    statusFilter: "all",
    managerFilter: ""
  });
  const handleManagerFilterChange = reactExports.useCallback((e) => {
    setFilter((f) => ({ ...f, managerFilter: e.target.value }));
  }, []);
  const handleStatusFilterChange = reactExports.useCallback((status) => {
    setFilter((f) => ({ ...f, statusFilter: status }));
  }, []);
  const stats = reactExports.useMemo(() => buildSupplyChainStats(snapshot), [snapshot]);
  const protection = snapshot.supply_chain?.package_manager_protection;
  const copy = reactExports.useMemo(() => resolvePackageManagerProtectionCopy(protection), [protection]);
  const allManagers = reactExports.useMemo(() => {
    if (!protection) return [];
    const all = /* @__PURE__ */ new Set([...protection.protected_managers, ...protection.unprotected_managers]);
    return Array.from(all).sort();
  }, [protection]);
  const filteredManagers = reactExports.useMemo(() => {
    return allManagers.filter((mgr) => {
      const matchesText = filter.managerFilter === "" || mgr.toLowerCase().includes(filter.managerFilter.toLowerCase());
      const isProtected = protection?.protected_managers.includes(mgr) ?? false;
      const matchesStatus = filter.statusFilter === "all" || filter.statusFilter === "protected" && isProtected || filter.statusFilter === "unprotected" && !isProtected;
      return matchesText && matchesStatus;
    });
  }, [allManagers, filter, protection]);
  const managedInstalls = reactExports.useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h1", { className: "text-lg font-semibold text-brand-dark", children: "Supply Chain" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-500", children: "Package manager firewall status, prevented installs, and feed health." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onGoHome, children: "Back to Home" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2 lg:grid-cols-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Active apps", value: stats.activeApps, tone: "green" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Prevented installs", value: stats.preventedInstalls, tone: stats.preventedInstalls > 0 ? "attention" : "slate" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Protected managers", value: stats.protectedManagers, tone: "green" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Unprotected managers", value: stats.unprotectedManagers, tone: stats.unprotectedManagers > 0 ? "attention" : "slate" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Package manager firewall" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: copy.pathTone === "green" ? "green" : copy.pathTone === "attention" ? "attention" : "slate", children: copy.pathLabel })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: copy.pathDetail })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              placeholder: "Filter by manager...",
              value: filter.managerFilter,
              onChange: handleManagerFilterChange,
              "aria-label": "Filter package managers",
              className: "bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
            }
          )
        ] }),
        ["all", "protected", "unprotected"].map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => handleStatusFilterChange(s),
            "aria-pressed": filter.statusFilter === s,
            className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${filter.statusFilter === s ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
            children: s.charAt(0).toUpperCase() + s.slice(1)
          },
          s
        ))
      ] }) }),
      filteredManagers.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No package managers found",
          body: "No package managers match the current filter, or Guard has not detected any on this machine.",
          tone: "teach"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "table", "aria-label": "Package manager firewall status", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-[1fr_auto] gap-2 border-b border-slate-100 bg-slate-50 px-4 py-2", role: "row", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Manager" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Status" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "rowgroup", children: filteredManagers.map((mgr) => {
          const isProtected = protection?.protected_managers.includes(mgr) ?? false;
          return /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "div",
            {
              role: "row",
              className: "grid grid-cols-[1fr_auto] gap-2 border-b border-slate-100 px-4 py-2.5 last:border-b-0",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-mono text-brand-dark", role: "cell", children: mgr }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "cell", children: isProtected ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "green", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 mr-1 inline", "aria-hidden": "true" }),
                  "Protected"
                ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "attention", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-3.5 w-3.5 mr-1 inline", "aria-hidden": "true" }),
                  "Unprotected"
                ] }) })
              ]
            },
            mgr
          );
        }) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "App shim coverage" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Package manager hooks active per connected app." })
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
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Feed health" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Intel feed source mode and freshness." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FeedHealthPanel, { snapshot })
    ] })
  ] });
}
function FeedHealthPanel({ snapshot }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const isStale = snapshot.latest_receipts.length > 0 && Date.now() - new Date(snapshot.latest_receipts[0].timestamp).getTime() > 7 * 24 * 60 * 60 * 1e3;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4 space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Source mode:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isSample ? "attention" : "green", children: isSample ? "Local-only (sample intel)" : "Live cloud feed" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Freshness:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStale ? "attention" : "green", children: isStale ? "Stale (7+ days)" : "Fresh" })
      ] })
    ] }),
    isSample && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationTriangle,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-800", children: "Running on local-only (sample) intel. Connect this machine to Guard Cloud for live feed data and cross-device protection." })
    ] }),
    isStale && !isSample && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-800", children: "Feed data is stale. Guard has not processed new actions recently. Check that the daemon is running." })
    ] })
  ] });
}
export {
  SupplyChainWorkspace,
  buildSupplyChainStats
};
