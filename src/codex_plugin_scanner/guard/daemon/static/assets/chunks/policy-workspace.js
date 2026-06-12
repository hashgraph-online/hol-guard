import { j as jsxRuntimeExports, b as EmptyState, A as ActionButton, a$ as HiMiniInbox, Q as HiMiniCog6Tooth, aU as HiMiniCloudArrowUp, S as SectionLabel, a9 as Tag, d as HiMiniCheckCircle, b0 as HiMiniBarsArrowUp, b1 as HiMiniBarsArrowDown, r as reactExports, b2 as policyActionLabel, b3 as scopeLabel, h as harnessDisplayName, B as Badge, m as formatRelativeTime, aY as HiMiniDocumentText, aZ as guardAwareHref, au as HiMiniTrash, aa as HiMiniMagnifyingGlass } from "../guard-dashboard.js";
const CLOUD_POLICY_SOURCES = /* @__PURE__ */ new Set(["cloud-sync", "team-policy", "policy-bundle"]);
function isCloudManagedPolicy(source) {
  return CLOUD_POLICY_SOURCES.has(source);
}
function policyTargetLabel(policy) {
  return policy.artifact_id ?? policy.publisher ?? policy.workspace ?? "Global";
}
function resolvePolicyEvidenceSearchTerm(policy) {
  if (policy.artifact_hash) {
    const normalized = policy.artifact_hash.replace(/^sha256:/i, "").trim();
    if (normalized.length >= 8) {
      return normalized.slice(0, 12);
    }
  }
  if (policy.artifact_id) {
    if (policy.artifact_id.startsWith("family:")) {
      return policy.artifact_id.slice("family:".length);
    }
    const segments = policy.artifact_id.split(":");
    const tail = segments[segments.length - 1]?.trim() ?? "";
    if (tail.length >= 12) {
      return tail;
    }
    return policy.artifact_id;
  }
  if (policy.publisher) {
    return policy.publisher;
  }
  if (policy.workspace) {
    return policy.workspace;
  }
  return null;
}
function resolvePolicyEvidenceHref(policy) {
  const params = new URLSearchParams();
  const searchTerm = resolvePolicyEvidenceSearchTerm(policy);
  if (searchTerm) {
    params.set("search", searchTerm);
  }
  if (!searchTerm && policy.harness && policy.harness !== "global") {
    params.set("harness", policy.harness);
  }
  const query = params.toString();
  return query.length > 0 ? `/evidence?${query}` : "/evidence";
}
function resolveCloudPolicyControlsUrl(snapshot) {
  const dashboardUrl = snapshot.dashboard_url?.trim();
  if (dashboardUrl) {
    return dashboardUrl;
  }
  const connectUrl = snapshot.connect_url?.trim();
  return connectUrl && connectUrl.length > 0 ? connectUrl : null;
}
function resolvePolicyRuleSummary(policy, labels) {
  const target = policyTargetLabel(policy);
  const reason = policy.reason?.trim();
  const targetPhrase = target === "Global" ? "all matching actions" : `"${target}"`;
  let summary = "";
  if (policy.scope === "global") {
    summary = `${labels.actionLabel} ${targetPhrase} on this device.`;
  } else if (policy.scope === "harness") {
    summary = `${labels.actionLabel} ${targetPhrase} anywhere in ${labels.appName}.`;
  } else if (policy.scope === "workspace") {
    const project = policy.workspace?.trim() || "this project";
    summary = `${labels.actionLabel} ${targetPhrase} in ${project} (${labels.scopeLabel}).`;
  } else if (policy.scope === "publisher") {
    const publisher = policy.publisher?.trim() || "this source";
    summary = `${labels.actionLabel} actions from ${publisher} in ${labels.appName}.`;
  } else {
    summary = `${labels.actionLabel} ${targetPhrase} in ${labels.appName} (${labels.scopeLabel}).`;
  }
  if (reason) {
    return `${summary} Reason: ${reason}.`;
  }
  return summary;
}
function resolvePolicySourceLabel(source) {
  if (source === "cloud-sync" || source === "team-policy" || source === "policy-bundle") {
    return "Guard Cloud";
  }
  if (source === "manual") {
    return "Remembered locally";
  }
  return "Local device";
}
function resolveActionTone(action) {
  if (action === "allow") {
    return "success";
  }
  if (action === "block") {
    return "destructive";
  }
  if (action === "warn" || action === "require-reapproval") {
    return "warning";
  }
  return "default";
}
function resolveSortDirectionHint(isActive, direction) {
  if (!isActive) {
    return "ascending";
  }
  if (direction === "asc") {
    return "descending";
  }
  return "ascending";
}
function PolicyRow({ policy, cloudControlsUrl, onClear }) {
  const handleClear = reactExports.useCallback(() => onClear?.(policy), [onClear, policy]);
  const cloudManaged = isCloudManagedPolicy(policy.source);
  const summary = resolvePolicyRuleSummary(policy, {
    appName: harnessDisplayName(policy.harness),
    scopeLabel: scopeLabel(policy.scope),
    actionLabel: policyActionLabel(policy.action)
  });
  const target = policyTargetLabel(policy);
  const canClear = onClear !== void 0 && !cloudManaged;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-b border-slate-100 last:border-b-0 align-top hover:bg-slate-50/40 transition-colors", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-4 py-3 text-sm text-brand-dark min-w-[120px]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: harnessDisplayName(policy.harness) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-slate-400", children: [
        policy.scope,
        " scope"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("td", { className: "px-4 py-3 min-w-[240px]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: resolveActionTone(policy.action), children: policyActionLabel(policy.action) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudManaged ? "blue" : "green", children: resolvePolicySourceLabel(policy.source) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm leading-relaxed text-brand-dark", children: summary }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "mt-2 text-xs text-slate-500", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer font-medium text-brand-blue hover:underline", children: "Rule details" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "mt-2 space-y-1.5 rounded-lg border border-slate-100 bg-slate-50/70 px-3 py-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "font-semibold text-slate-600", children: "Target" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-mono break-all text-slate-700", children: target })
          ] }),
          policy.workspace ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "font-semibold text-slate-600", children: "Project" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all text-slate-700", children: policy.workspace })
          ] }) : null,
          policy.publisher ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "font-semibold text-slate-600", children: "Publisher" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "break-all text-slate-700", children: policy.publisher })
          ] }) : null,
          policy.reason ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "font-semibold text-slate-600", children: "Reason" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "text-slate-700", children: policy.reason })
          ] }) : null,
          policy.artifact_hash ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "font-semibold text-slate-600", children: "Artifact hash" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "font-mono break-all text-slate-700", children: policy.artifact_hash })
          ] }) : null
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3 text-xs text-slate-400 whitespace-nowrap", children: policy.updated_at ? formatRelativeTime(policy.updated_at) : null }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("td", { className: "px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1", children: [
      !cloudManaged ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: guardAwareHref(resolvePolicyEvidenceHref(policy)),
          className: "inline-flex items-center gap-1 rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-xs font-medium text-slate-600 hover:border-brand-blue/30 hover:text-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniDocumentText, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
            "View evidence"
          ]
        }
      ) : null,
      cloudManaged && cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cloudControlsUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "inline-flex items-center gap-1 rounded-lg border border-brand-blue/20 bg-brand-blue/[0.05] px-2.5 py-1.5 text-xs font-medium text-brand-blue hover:bg-brand-blue/[0.1] focus:outline-none focus:ring-2 focus:ring-brand-blue/30 transition-colors",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-3.5 w-3.5", "aria-hidden": "true" }),
            "View on cloud"
          ]
        }
      ) : null,
      canClear ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: handleClear,
          "aria-label": `Clear policy for ${harnessDisplayName(policy.harness)}`,
          className: "inline-flex h-8 w-8 items-center justify-center rounded p-1.5 text-slate-400 hover:bg-red-50 hover:text-red-500 focus:outline-none focus:ring-2 focus:ring-red-300/50 transition-colors",
          title: "Clear policy",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4", "aria-hidden": "true" })
        }
      ) : null
    ] }) })
  ] });
}
function SortHeader({
  label,
  sortKey,
  activeSort,
  onSort,
  className,
  sortable = true
}) {
  const isActive = activeSort?.key === sortKey;
  let ariaSort = "none";
  if (isActive) {
    ariaSort = activeSort.direction === "asc" ? "ascending" : "descending";
  }
  const directionHint = resolveSortDirectionHint(isActive, activeSort?.direction);
  if (!sortable) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: `px-4 py-2.5 text-left ${className ?? ""}`, children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: label }) });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", "aria-sort": ariaSort, className: `px-4 py-2.5 text-left ${className ?? ""}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      onClick: () => onSort(sortKey),
      className: "group inline-flex items-center gap-1 rounded px-1 -ml-1 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400 transition-colors hover:text-brand-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30",
      "aria-label": `Sort by ${label}, ${directionHint}`,
      children: [
        label,
        /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex h-3.5 w-3.5 items-center justify-center", "aria-hidden": "true", children: [
          isActive && activeSort.direction === "asc" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBarsArrowUp, { className: "h-3 w-3 text-brand-blue" }) : null,
          isActive && activeSort.direction === "desc" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBarsArrowDown, { className: "h-3 w-3 text-brand-blue" }) : null,
          !isActive ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBarsArrowUp, { className: "h-3 w-3 text-slate-300 opacity-0 transition-opacity group-hover:opacity-100" }) : null
        ] })
      ]
    }
  ) });
}
function PolicyTableSection({
  title,
  description,
  policies,
  sort,
  onSort,
  cloudControlsUrl,
  onClearPolicy,
  emptyTitle,
  emptyBody,
  sortable = true
}) {
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: description })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(EmptyState, { title: emptyTitle, body: emptyBody, tone: "teach" })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-base font-semibold text-brand-dark", children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: description })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-hidden rounded-2xl border border-slate-100 bg-white shadow-sm", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "overflow-x-auto", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("table", { className: "w-full min-w-[760px] text-sm", "aria-label": title, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("thead", { children: /* @__PURE__ */ jsxRuntimeExports.jsxs("tr", { className: "border-b border-slate-100 bg-slate-50", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "App", sortKey: "app", activeSort: sort, onSort, sortable }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5 text-left text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "What this rule does" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SortHeader, { label: "Updated", sortKey: "updated", activeSort: sort, onSort, sortable }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("th", { scope: "col", className: "px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "sr-only", children: "Actions" }) })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("tbody", { children: policies.map((policy) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyRow,
        {
          policy,
          cloudControlsUrl,
          onClear: onClearPolicy
        },
        `${policy.harness}-${policy.scope}-${policyTargetLabel(policy)}-${policy.updated_at ?? ""}-${policy.source}`
      )) })
    ] }) }) })
  ] });
}
function ExceptionsView({
  policies,
  cloudControlsUrl,
  onClearPolicy,
  onOpenInbox,
  onOpenSettings,
  sort,
  onSort
}) {
  if (policies.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No exceptions yet",
          body: "Exceptions are created when Inbox decisions use custom responses such as Warn or Require review, or when repo and environment overrides are configured.",
          tone: "teach"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
        onOpenInbox ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: onOpenInbox, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInbox, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Review Inbox"
        ] }) : null,
        onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCog6Tooth, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          "Configure in Settings"
        ] }) : null,
        cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "a",
          {
            href: cloudControlsUrl,
            target: "_blank",
            rel: "noopener noreferrer",
            className: "inline-flex items-center gap-1 rounded-lg border border-brand-blue/20 bg-white px-4 py-2 text-sm font-medium text-brand-blue hover:bg-brand-blue/[0.05]",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
              "View on cloud"
            ]
          }
        ) : null
      ] })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    PolicyTableSection,
    {
      title: "Active exceptions",
      description: "Custom responses and overrides that are not simple allow or block rules.",
      policies,
      sort,
      onSort,
      cloudControlsUrl,
      onClearPolicy,
      emptyTitle: "No exceptions configured",
      emptyBody: "Exceptions appear after custom Inbox decisions or repo overrides."
    }
  );
}
function StrictModeView({
  snapshot,
  onOpenSettings
}) {
  const securityLevel = snapshot.security_level;
  const isStrict = securityLevel === "strict";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: `rounded-2xl border p-5 ${isStrict ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-slate-50/40"}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Strict mode" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStrict ? "green" : "slate", children: isStrict ? "Enabled" : "Disabled" })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-4 text-sm text-brand-dark/75", children: "Strict mode enables maximum coverage. Guard asks before new network connections, subprocess launches, file writes, and all harness starts." }),
          !isStrict && onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Enable strict mode" }) : null,
          isStrict ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 text-sm text-brand-green", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Strict mode is active"
          ] }) : null
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Repo and environment rules" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 mb-3 text-sm text-slate-500", children: "Per-repo and per-environment policy overrides can be set in your Guard config file or Guard Cloud Controls." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg border border-slate-100 bg-slate-50/60 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs text-slate-600", children: "~/.config/hol-guard/guard.yaml" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-400", children: "See repo_rules and env_rules in the Guard docs." })
      ] })
    ] })
  ] });
}
function groupPoliciesByHarness(policies) {
  const map = /* @__PURE__ */ new Map();
  for (const policy of policies) {
    const key = policy.harness || "global";
    const existing = map.get(key) ?? [];
    map.set(key, [...existing, policy]);
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
function sortPolicies(policies, sort) {
  if (sort === null) {
    return policies;
  }
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
function resolveCloudBundleSurfaceClass(tone) {
  if (tone === "attention") {
    return "border border-amber-200/70 bg-amber-50/70";
  }
  if (tone === "slate") {
    return "border border-slate-200/70 bg-slate-50/70";
  }
  return "border border-emerald-200/70 bg-emerald-50/70";
}
function PolicyWorkspace({
  policies,
  snapshot,
  onClearPolicy,
  onOpenSettings,
  onOpenInbox
}) {
  const [activeView, setActiveView] = reactExports.useState("rules");
  const [filter, setFilter] = reactExports.useState({
    searchQuery: "",
    harnessFilter: "",
    scopeFilter: ""
  });
  const [sort, setSort] = reactExports.useState({ key: "updated", direction: "desc" });
  const handleSearchChange = reactExports.useCallback((event) => {
    setFilter((current) => ({ ...current, searchQuery: event.target.value }));
  }, []);
  const handleViewChange = reactExports.useCallback((view) => {
    setActiveView(view);
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
  const cloudControlsUrl = reactExports.useMemo(() => resolveCloudPolicyControlsUrl(snapshot), [snapshot]);
  const filteredPolicies = reactExports.useMemo(() => {
    return policies.filter((policy) => {
      const query = filter.searchQuery.toLowerCase();
      if (query === "") {
        return true;
      }
      return policy.harness.toLowerCase().includes(query) || (policy.artifact_id ?? "").toLowerCase().includes(query) || (policy.workspace ?? "").toLowerCase().includes(query) || (policy.publisher ?? "").toLowerCase().includes(query) || policy.scope.toLowerCase().includes(query) || policy.action.toLowerCase().includes(query) || (policy.reason ?? "").toLowerCase().includes(query);
    });
  }, [policies, filter.searchQuery]);
  const sortedPolicies = reactExports.useMemo(() => sortPolicies(filteredPolicies, sort), [filteredPolicies, sort]);
  const rememberedRules = reactExports.useMemo(
    () => sortedPolicies.filter((policy) => policy.action === "allow" || policy.action === "block"),
    [sortedPolicies]
  );
  const localRules = reactExports.useMemo(
    () => rememberedRules.filter((policy) => !isCloudManagedPolicy(policy.source)),
    [rememberedRules]
  );
  const cloudRules = reactExports.useMemo(
    () => rememberedRules.filter((policy) => isCloudManagedPolicy(policy.source)),
    [rememberedRules]
  );
  const exceptionPolicies = reactExports.useMemo(
    () => sortedPolicies.filter((policy) => policy.action !== "allow" && policy.action !== "block"),
    [sortedPolicies]
  );
  const cloudBundleCopy = reactExports.useMemo(() => resolveCloudPolicyBundleCopy(snapshot), [snapshot]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    cloudBundleCopy ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-2xl p-4 shadow-sm ${resolveCloudBundleSurfaceClass(cloudBundleCopy.tone)}`, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Guard Cloud bundle" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: cloudBundleCopy.tone, children: cloudBundleCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: cloudBundleCopy.detail }),
      cloudControlsUrl ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cloudControlsUrl,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:underline",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "h-4 w-4", "aria-hidden": "true" }),
            "View bundle in Guard Cloud Controls"
          ]
        }
      ) : null
    ] }) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/10 bg-brand-blue/[0.03] p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-2 flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Active mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: modeCopy.tone, children: modeCopy.label })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark/75", children: modeCopy.description }),
      onOpenSettings ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Open security settings" }) }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2 border-b border-slate-100 pb-3", children: [
      ["rules", "exceptions", "strict"].map((view) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => handleViewChange(view),
          "aria-pressed": activeView === view,
          className: `rounded-full px-4 py-1.5 text-sm font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${activeView === view ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
          children: view === "rules" ? "Remembered rules" : view === "exceptions" ? "Exceptions" : "Strict config"
        },
        view
      )),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "ml-auto flex items-center gap-1.5 rounded-lg border border-slate-200 bg-white px-3 py-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-3.5 w-3.5 shrink-0 text-slate-400", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "search",
            placeholder: "Search policies...",
            value: filter.searchQuery,
            onChange: handleSearchChange,
            "aria-label": "Search policies",
            className: "w-36 bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none sm:w-48"
          }
        )
      ] })
    ] }),
    activeView === "rules" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyTableSection,
        {
          title: "Remembered on this device",
          description: "Rules you created from Inbox approvals. You can clear them here or jump to the related evidence.",
          policies: localRules,
          sort,
          onSort: handleSort,
          cloudControlsUrl,
          onClearPolicy,
          emptyTitle: "No local remembered rules yet",
          emptyBody: "Approve or block actions in Inbox and Guard will remember your choice here."
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        PolicyTableSection,
        {
          title: "From Guard Cloud",
          description: "Synced bundle rules are read-only on this device. Open Guard Cloud Controls to review or edit rollout.",
          policies: cloudRules,
          sort,
          onSort: handleSort,
          cloudControlsUrl,
          emptyTitle: "No Guard Cloud rules synced yet",
          emptyBody: "Connect Guard Cloud to sync shared bundle rules to this device."
        }
      )
    ] }) : null,
    activeView === "exceptions" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ExceptionsView,
      {
        policies: exceptionPolicies,
        cloudControlsUrl,
        onClearPolicy,
        onOpenInbox,
        onOpenSettings,
        sort,
        onSort: handleSort
      }
    ) : null,
    activeView === "strict" ? /* @__PURE__ */ jsxRuntimeExports.jsx(StrictModeView, { snapshot, onOpenSettings }) : null
  ] });
}
export {
  PolicyWorkspace,
  groupPoliciesByHarness,
  policyTargetLabel,
  resolveCloudPolicyBundleCopy,
  resolveSecurityModeCopy
};
