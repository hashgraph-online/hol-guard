import { r as reactExports, j as jsxRuntimeExports, S as SectionLabel, T as Tag, aa as HiMiniMagnifyingGlass, o as EmptyState, m as harnessDisplayName, B as Badge, au as HiMiniDocumentText, aI as guardAwareHref, ao as HiMiniTrash, A as ActionButton, g as HiMiniCheckCircle, aJ as HiMiniBarsArrowUp, aK as HiMiniBarsArrowDown, f as formatRelativeTime } from "../guard-dashboard.js";
function groupPoliciesByHarness(policies) {
  const map = /* @__PURE__ */ new Map();
  for (const p of policies) {
    const key = p.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, p]);
  }
  return map;
}
function resolveSecurityModeCopy(level) {
  if (level === "strict") {
    return {
      label: "Strict mode",
      description: "Guard asks before most actions including new network connections and file writes. Higher noise, maximum protection.",
      tone: "attention"
    };
  }
  if (level === "balanced") {
    return {
      label: "Balanced (default)",
      description: "Guard asks for secrets, destructive commands, and new network destinations. Low noise, solid coverage.",
      tone: "green"
    };
  }
  if (level === "gentle" || level === "relaxed") {
    return {
      label: "Low noise",
      description: "Guard only asks for the highest-risk actions. Minimal interruptions.",
      tone: "slate"
    };
  }
  return {
    label: level ?? "Custom",
    description: "Custom policy rules apply. Review individual rules below.",
    tone: "slate"
  };
}
function resolveCloudPolicyBundleCopy(snapshot) {
  const bundleVersion = snapshot.cloud_policy_bundle_version?.trim();
  if (!bundleVersion) {
    return null;
  }
  const rollout = snapshot.cloud_policy_rollout_state?.trim() || "unknown";
  const syncError = snapshot.cloud_policy_sync_error?.trim();
  if (syncError) {
    return {
      label: `Cloud bundle ${bundleVersion}`,
      detail: `Guard Cloud Controls owns rollout and authoring. Latest sync issue: ${syncError}.`,
      tone: "attention"
    };
  }
  return {
    label: `Cloud bundle ${bundleVersion}`,
    detail: `Guard Cloud Controls owns authoring and rollout. This local workspace reflects rollout state ${rollout}.`,
    tone: "green"
  };
}
function policyTargetLabel(policy) {
  return policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global";
}
function extractEvidenceSearchTerm(policy) {
  const target = policyTargetLabel(policy);
  if (!target || target === "Global") return null;
  if (target.startsWith("family:")) {
    return target.slice("family:".length);
  }
  return target;
}
function policyEvidenceHref(policy) {
  const params = new URLSearchParams();
  params.set("harness", policy.harness || "global");
  const searchTerm = extractEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  return `/evidence?${params.toString()}`;
}
function sortPolicies(policies, sort) {
  if (sort === null) return policies;
  const sorted = [...policies];
  const dir = sort.direction === "asc" ? 1 : -1;
  sorted.sort((a, b) => {
    switch (sort.key) {
      case "app":
        return a.harness.localeCompare(b.harness) * dir;
      case "scope":
        return a.scope.localeCompare(b.scope) * dir;
      case "action":
        return a.action.localeCompare(b.action) * dir;
      case "target":
        return policyTargetLabel(a).localeCompare(policyTargetLabel(b)) * dir;
      case "updated":
        return (new Date(a.updated_at || 0).getTime() - new Date(b.updated_at || 0).getTime()) * dir;
      default:
        return 0;
    }
  });
  return sorted;
}
function PolicyRow({ policy, onClear }) {
  const handleClear = reactExports.useCallback(() => onClear?.(policy), [onClear, policy]);
  const actionTone = policy.action === "allow" ? "success" : policy.action === "block" ? "destructive" : policy.action === "warn" ? "warning" : "default";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5 text-sm text-brand-dark min-w-0", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: harnessDisplayName(policy.harness) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5 text-sm text-slate-500", children: policy.scope }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: actionTone, children: policy.action }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5 text-xs text-slate-500 max-w-[200px]", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate block", title: policyTargetLabel(policy), children: policyTargetLabel(policy) }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5 text-xs text-slate-400 whitespace-nowrap", children: policy.updated_at ? formatRelativeTime(policy.updated_at) : null }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-0.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: guardAwareHref(policyEvidenceHref(policy)),
          className: "inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          "aria-label": `View evidence for ${harnessDisplayName(policy.harness)}`,
          title: "View evidence",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-4 w-4", "aria-hidden": "true" })
        }
      ),
      onClear && /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: handleClear,
          "aria-label": `Clear policy for ${harnessDisplayName(policy.harness)}`,
          className: "inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-500 focus:outline-none focus:ring-2 focus:ring-red-300/50 transition-colors",
          title: "Clear policy",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4", "aria-hidden": "true" })
        }
      )
    ] }) })
  ] });
}
function SortHeader({ label, sortKey, activeSort, onSort, className }) {
  const isActive = activeSort?.key === sortKey;
  const ariaSort = isActive ? activeSort.direction === "asc" ? "ascending" : "descending" : "none";
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "th",
    {
      scope: "col",
      "aria-sort": ariaSort,
      className: `px-4 py-2.5 text-left ${className ?? ""}`,
      children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: () => onSort(sortKey),
          className: "group inline-flex items-center gap-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 transition-colors hover:text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1 -ml-1",
          "aria-label": `Sort by ${label}, ${isActive ? activeSort.direction === "asc" ? "descending" : "ascending" : "ascending"}`,
          children: [
            label,
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-3.5 w-3.5 items-center justify-center", "aria-hidden": "true", children: isActive ? activeSort.direction === "asc" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBarsArrowUp, { className: "h-3 w-3 text-brand-blue" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBarsArrowDown, { className: "h-3 w-3 text-brand-blue" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBarsArrowUp, { className: "h-3 w-3 text-slate-300 opacity-0 group-hover:opacity-100 transition-opacity" }) })
          ]
        }
      )
    }
  );
}
function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings
}) {
  const [activeView, setActiveView] = reactExports.useState("rules");
  const [filter, setFilter] = reactExports.useState({
    searchQuery: "",
    harnessFilter: "",
    scopeFilter: ""
  });
  const [sort, setSort] = reactExports.useState({ key: "updated", direction: "desc" });
  const handleSearchChange = reactExports.useCallback((e) => {
    setFilter((f) => ({ ...f, searchQuery: e.target.value }));
  }, []);
  const handleViewChange = reactExports.useCallback((v) => {
    setActiveView(v);
  }, []);
  const handleSort = reactExports.useCallback((key) => {
    setSort((current) => {
      if (current?.key === key) {
        if (current.direction === "asc") {
          return { key, direction: "desc" };
        }
        return { key, direction: "asc" };
      }
      return { key, direction: "asc" };
    });
  }, []);
  const securityLevel = snapshot.security_level;
  const modeCopy = reactExports.useMemo(() => resolveSecurityModeCopy(securityLevel), [securityLevel]);
  const filteredPolicies = reactExports.useMemo(() => {
    return policies.filter((p) => {
      const q = filter.searchQuery.toLowerCase();
      if (q === "") return true;
      return p.harness.toLowerCase().includes(q) || (p.artifact_id ?? "").toLowerCase().includes(q) || (p.workspace ?? "").toLowerCase().includes(q) || (p.publisher ?? "").toLowerCase().includes(q) || p.scope.toLowerCase().includes(q) || p.action.toLowerCase().includes(q);
    });
  }, [policies, filter.searchQuery]);
  const sortedPolicies = reactExports.useMemo(
    () => sortPolicies(filteredPolicies, sort),
    [filteredPolicies, sort]
  );
  const exceptionPolicies = reactExports.useMemo(
    () => sortedPolicies.filter((p) => p.action !== "allow" && p.action !== "block"),
    [sortedPolicies]
  );
  reactExports.useMemo(() => groupPoliciesByHarness(policies), [policies]);
  const cloudBundleCopy = reactExports.useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Local remembered decisions and synced Guard Cloud bundle posture." }) }),
      snapshot.dashboard_url && /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: snapshot.dashboard_url,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center justify-center rounded-lg border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark hover:bg-slate-50 focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          children: "Open Guard Cloud Controls"
        }
      )
    ] }),
    cloudBundleCopy && /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: `rounded-2xl p-4 shadow-sm ${cloudBundleCopy.tone === "attention" ? "border border-amber-200/70 bg-amber-50/70" : cloudBundleCopy.tone === "slate" ? "border border-slate-200/70 bg-slate-50/70" : "border border-emerald-200/70 bg-emerald-50/70"}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudBundleCopy.tone, children: cloudBundleCopy.label })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: cloudBundleCopy.detail })
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 mb-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: modeCopy.tone, children: modeCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: modeCopy.description }),
      snapshot.dashboard_url && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "a",
        {
          href: snapshot.dashboard_url,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center justify-center rounded-lg px-4 py-2 text-sm font-medium text-brand-blue hover:bg-brand-blue/5 focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          children: "Review rollout in Guard Cloud Controls"
        }
      ) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 border-b border-slate-100 pb-3", children: [
      ["rules", "exceptions", "strict"].map((v) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => handleViewChange(v),
          "aria-pressed": activeView === v,
          className: `rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${activeView === v ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
          children: v === "rules" ? "Remembered rules" : v === "exceptions" ? "Exceptions" : "Strict config"
        },
        v
      )),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "ml-auto flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-3.5 w-3.5 text-slate-400 shrink-0", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "search",
            placeholder: "Search policies...",
            value: filter.searchQuery,
            onChange: handleSearchChange,
            "aria-label": "Search policies",
            className: "bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-36 sm:w-48"
          }
        )
      ] })
    ] }),
    activeView === "rules" && /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyTable,
      {
        policies: sortedPolicies.filter((p) => p.action === "allow" || p.action === "block"),
        sort,
        onSort: handleSort,
        onClearPolicy
      }
    ),
    activeView === "exceptions" && /* @__PURE__ */ jsxRuntimeExports.jsx(ExceptionsView, { policies: exceptionPolicies, onClearPolicy }),
    activeView === "strict" && /* @__PURE__ */ jsxRuntimeExports.jsx(StrictModeView, { snapshot, onOpenSettings })
  ] });
}
function PolicyTable({ policies, sort, onSort, onClearPolicy }) {
  const allPolicies = policies;
  if (allPolicies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No remembered rules yet",
        body: "Guard will remember your decisions as you approve or block actions. They appear here so you can review and remove them.",
        tone: "teach"
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm overflow-hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full min-w-[640px] text-sm", "aria-label": "Policy rules", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-b border-slate-100 bg-slate-50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "App", sortKey: "app", activeSort: sort, onSort }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "Scope", sortKey: "scope", activeSort: sort, onSort }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "Action", sortKey: "action", activeSort: sort, onSort }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "Target", sortKey: "target", activeSort: sort, onSort }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "Updated", sortKey: "updated", activeSort: sort, onSort }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Actions" }) })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: allPolicies.map((p) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      PolicyRow,
      {
        policy: p,
        onClear: onClearPolicy
      },
      `${p.harness}-${p.scope}-${policyTargetLabel(p)}-${p.updated_at ?? ""}`
    )) })
  ] }) }) });
}
function ExceptionsView({
  policies,
  onClearPolicy
}) {
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No exceptions configured",
        body: "Exceptions are non-allow/block rules that customize Guard behavior for specific repos, harnesses, or environments.",
        tone: "teach"
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm overflow-hidden", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full min-w-[500px] text-sm", "aria-label": "Exception rules", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-b border-slate-100 bg-slate-50", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "App" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Action" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Reason" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Actions" }) })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: policies.map((p) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "tr",
      {
        className: "border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5 text-sm font-medium text-brand-dark", children: harnessDisplayName(p.harness) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: p.action }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5 text-sm text-slate-500 max-w-[240px]", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate block", children: p.reason ?? "No reason recorded" }) }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-0.5", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "a",
              {
                href: guardAwareHref(policyEvidenceHref(p)),
                className: "inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-slate-100 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
                "aria-label": `View evidence for ${harnessDisplayName(p.harness)}`,
                title: "View evidence",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-4 w-4", "aria-hidden": "true" })
              }
            ),
            onClearPolicy && /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                type: "button",
                onClick: () => onClearPolicy(p),
                "aria-label": `Remove exception for ${harnessDisplayName(p.harness)}`,
                className: "inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-500 transition-colors",
                title: "Remove exception",
                children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4", "aria-hidden": "true" })
              }
            )
          ] }) })
        ]
      },
      `${p.harness}-${p.scope}-${p.artifact_id ?? "global"}`
    )) })
  ] }) }) });
}
function StrictModeView({
  snapshot,
  onOpenSettings
}) {
  const securityLevel = snapshot.security_level;
  const isStrict = securityLevel === "strict";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Strict mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStrict ? "green" : "slate", children: isStrict ? "Enabled" : "Disabled" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75 mb-4", children: "Strict mode enables maximum coverage. Guard asks before new network connections, subprocess launches, file writes, and all harness starts. Expect more interruptions." }),
      !isStrict && onOpenSettings && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable strict mode" }),
      isStrict && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 text-sm text-brand-green", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
        "Strict mode is active"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Repo and environment rules" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 mb-3 text-sm text-slate-500", children: "Per-repo and per-environment policy overrides can be set in your Guard config file." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg border border-slate-100 bg-slate-50/60 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs text-slate-600", children: "~/.config/hol-guard/guard.yaml" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-400", children: "See the docs for repo_rules and env_rules configuration options." })
      ] })
    ] })
  ] });
}
export {
  PolicyWorkspace,
  groupPoliciesByHarness,
  resolveCloudPolicyBundleCopy,
  resolveSecurityModeCopy
};
