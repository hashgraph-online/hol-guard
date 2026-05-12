import { r as reactExports, J as fetchApprovalPage, K as fetchPolicy, h as harnessDisplayName, j as jsxRuntimeExports, L as HiMiniArrowLeft, i as HiMiniChevronRight, G as GuardHero, A as ActionButton, P as ProofStrip, M as HiMiniHome, n as HiMiniBolt, N as HiMiniAdjustmentsHorizontal, S as SectionLabel, d as formatRelativeTime, m as HiMiniExclamationTriangle, T as Tag, O as detectCategory, Q as CATEGORIES, B as Badge, E as EmptyState, R as HiMiniCloud, U as HiMiniChartBar, V as runHarnessAction, W as GuardHarnessActionError, X as HiMiniRocketLaunch, c as HiMiniShieldCheck, Y as HiMiniArrowPath, H as HiMiniCheckCircle, Z as HiMiniTrash, l as HiMiniChevronDown, _ as formatHarnessCommand } from "../guard-dashboard.js";
import { u as useFocusTrap } from "./use-focus-trap.js";
const tabOrder = ["overview", "activity", "settings"];
function readTabFromUrl() {
  const queryTab = new URLSearchParams(window.location.search).get("tab");
  if (queryTab === "overview" || queryTab === "activity" || queryTab === "settings") return queryTab;
  const hash = window.location.hash.replace("#", "");
  if (hash === "activity" || hash === "settings") return hash;
  return "overview";
}
function writeTabToUrl(tab) {
  const url = new URL(window.location.href);
  if (tab === "overview") {
    url.searchParams.delete("tab");
    if (url.hash === "#activity" || url.hash === "#settings" || url.hash === "#overview") {
      url.hash = "";
    }
  } else {
    url.searchParams.set("tab", tab);
  }
  window.history.replaceState({}, "", url.toString());
}
function AppDetailWorkspace(props) {
  const [activeTab, setActiveTab] = reactExports.useState(readTabFromUrl);
  const [tabDirection, setTabDirection] = reactExports.useState("right");
  const touchStartX = reactExports.useRef(null);
  reactExports.useEffect(() => {
    function handleHashChange() {
      setActiveTab(readTabFromUrl());
    }
    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);
  const [harnessQueue, setHarnessQueue] = reactExports.useState({ kind: "loading" });
  const [harnessPolicy, setHarnessPolicy] = reactExports.useState({ kind: "loading" });
  const { harness, runtime, receipts, policies, inventory } = props;
  const loadTabData = reactExports.useCallback(() => {
    let cancelled = false;
    setHarnessQueue({ kind: "loading" });
    setHarnessPolicy({ kind: "loading" });
    Promise.allSettled([
      fetchApprovalPage({ harness, status: "pending" }),
      fetchPolicy(harness)
    ]).then(([queueResult, policyResult]) => {
      if (cancelled) return;
      if (queueResult.status === "fulfilled") {
        setHarnessQueue({ kind: "ready", items: queueResult.value.items ?? [] });
      } else {
        setHarnessQueue({
          kind: "error",
          message: queueResult.reason instanceof Error ? queueResult.reason.message : "Unable to load queue."
        });
      }
      if (policyResult.status === "fulfilled") {
        setHarnessPolicy({ kind: "ready", items: policyResult.value ?? [] });
      } else {
        setHarnessPolicy({
          kind: "error",
          message: policyResult.reason instanceof Error ? policyResult.reason.message : "Unable to load policy."
        });
      }
    });
    return () => {
      cancelled = true;
    };
  }, [harness]);
  reactExports.useEffect(() => {
    const cleanup = loadTabData();
    return cleanup;
  }, [loadTabData]);
  const install = runtime.managed_installs?.find((i) => i.harness === harness);
  const isActive = install?.active === true;
  const isObserved = runtime.items.some((i) => i.harness === harness) || receipts.some((r) => r.harness === harness) || policies.some((p) => p.harness === harness);
  const harnessReceipts = reactExports.useMemo(
    () => receipts.filter((r) => r.harness === harness).sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp)),
    [receipts, harness]
  );
  const harnessInventory = reactExports.useMemo(
    () => inventory.filter((i) => i.harness === harness && i.present),
    [inventory, harness]
  );
  const harnessPolicies = reactExports.useMemo(
    () => harnessPolicy.kind === "ready" ? harnessPolicy.items : policies.filter((p) => p.harness === harness),
    [harnessPolicy, policies, harness]
  );
  const pendingItems = reactExports.useMemo(
    () => harnessQueue.kind === "ready" ? harnessQueue.items : props.requests.filter((r) => r.harness === harness),
    [harnessQueue, props.requests, harness]
  );
  const totalActions = harnessReceipts.length;
  const blockedCount = harnessReceipts.filter((r) => r.policy_decision === "block").length;
  const allowedCount = harnessReceipts.filter((r) => r.policy_decision === "allow").length;
  const blockRate = totalActions > 0 ? Math.round(blockedCount / totalActions * 100) : 0;
  const lastActivity = harnessReceipts[0]?.timestamp ?? null;
  const isLoading = harnessQueue.kind === "loading" || harnessPolicy.kind === "loading";
  const queueError = harnessQueue.kind === "error" ? harnessQueue.message : null;
  const policyError = harnessPolicy.kind === "error" ? harnessPolicy.message : null;
  const status = isActive ? "active" : install !== void 0 ? "needs_setup" : isObserved ? "observed" : "unknown";
  const heroStatus = status === "active" ? "clear" : status === "needs_setup" ? "setup_gap" : "needs_review";
  const heroHeadline = status === "active" ? `${harnessDisplayName(harness)} is protected` : status === "needs_setup" ? `${harnessDisplayName(harness)} needs setup` : isObserved ? `${harnessDisplayName(harness)} is observed` : `${harnessDisplayName(harness)}`;
  const heroSub = status === "active" ? "Guard is watching this app. Review its activity and settings below." : status === "needs_setup" ? "Finish setup so Guard can protect this app." : isObserved ? "Guard has seen activity but install is not active." : "This app has not been seen yet.";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          onClick: props.onGoHome,
          className: "inline-flex items-center gap-1 rounded-full px-3 py-1.5 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-100",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowLeft, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Home"
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4 text-slate-300", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm text-muted-foreground", children: "Apps" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4 text-slate-300", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: harnessDisplayName(harness) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: heroStatus,
        headline: heroHeadline,
        subheadline: heroSub,
        cta: pendingItems.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
          ActionButton,
          {
            onClick: () => setActiveTab("activity"),
            "data-primary": "true",
            children: [
              "Review ",
              pendingItems.length,
              " pending"
            ]
          }
        ) : status === "needs_setup" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: () => setActiveTab("settings"), "data-primary": "true", children: "Open Settings" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: () => setActiveTab("activity"), "data-primary": "true", children: "View Activity" })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProofStrip,
      {
        items: [
          { label: "Pending", value: pendingItems.length, tone: pendingItems.length > 0 ? "blue" : "slate" },
          { label: "Total actions", value: totalActions, tone: totalActions > 0 ? "purple" : "slate" },
          { label: "Blocked", value: `${blockRate}%`, tone: blockRate > 0 ? "blue" : "slate" },
          { label: "Status", value: isActive ? "active" : "inactive", tone: isActive ? "green" : "slate" }
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex gap-1 rounded-xl border border-slate-200/70 bg-white/80 p-1 shadow-sm", children: [
        { key: "overview", label: "Overview", icon: HiMiniHome },
        { key: "activity", label: "Activity", icon: HiMiniBolt },
        { key: "settings", label: "Settings", icon: HiMiniAdjustmentsHorizontal }
      ].map((t) => {
        const Icon = t.icon;
        const isActive2 = activeTab === t.key;
        return /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => handleTabChange(t.key),
            className: `flex flex-1 items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-medium transition-all ${isActive2 ? "bg-brand-blue text-white shadow-sm" : "text-brand-dark hover:bg-slate-50"}`,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4" }),
              t.label
            ]
          },
          t.key
        );
      }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "px-1 text-[11px] text-muted-foreground lg:hidden", children: "Swipe or tap tabs to switch views" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: "min-h-[300px]",
        onTouchStart: handleTouchStart,
        onTouchEnd: handleTouchEnd,
        children: [
          isLoading && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-36 w-full" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-8 w-1/2" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-48 w-full" })
          ] }),
          !isLoading && /* @__PURE__ */ jsxRuntimeExports.jsxs(TabContent, { activeTab, direction: tabDirection, children: [
            activeTab === "overview" && /* @__PURE__ */ jsxRuntimeExports.jsx(
              AppOverviewTab,
              {
                harness,
                status,
                install,
                totalActions,
                allowedCount,
                blockedCount,
                blockRate,
                lastActivity,
                harnessReceipts,
                harnessInventory,
                pendingItems,
                onOpenRequest: props.onOpenRequest
              }
            ),
            activeTab === "activity" && /* @__PURE__ */ jsxRuntimeExports.jsx(
              AppActivityTab,
              {
                harness,
                pendingItems,
                harnessReceipts,
                onOpenRequest: props.onOpenRequest,
                queueError,
                onRetry: loadTabData
              }
            ),
            activeTab === "settings" && /* @__PURE__ */ jsxRuntimeExports.jsx(
              AppSettingsTab,
              {
                harness,
                status,
                install,
                harnessPolicies,
                onClearAppPolicies: props.onClearAppPolicies,
                onManagedInstallChanged: props.onManagedInstallChanged,
                policyError,
                onRetry: loadTabData
              }
            )
          ] })
        ]
      }
    )
  ] });
  function handleTabChange(next) {
    const currentIndex = tabOrder.indexOf(activeTab);
    const nextIndex = tabOrder.indexOf(next);
    setTabDirection(nextIndex > currentIndex ? "right" : "left");
    setActiveTab(next);
    writeTabToUrl(next);
  }
  function handleTouchStart(e) {
    touchStartX.current = e.changedTouches[0].screenX;
  }
  function handleTouchEnd(e) {
    if (touchStartX.current === null) return;
    const endX = e.changedTouches[0].screenX;
    const diff = touchStartX.current - endX;
    const threshold = 50;
    const currentIndex = tabOrder.indexOf(activeTab);
    if (diff > threshold && currentIndex < tabOrder.length - 1) {
      handleTabChange(tabOrder[currentIndex + 1]);
    } else if (diff < -threshold && currentIndex > 0) {
      handleTabChange(tabOrder[currentIndex - 1]);
    }
    touchStartX.current = null;
  }
}
function AppStatusBadge({ status }) {
  if (status === "active") return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Active" });
  if (status === "needs_setup") return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "attention", children: "Needs setup" });
  if (status === "observed") return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Observed" });
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Unknown" });
}
function AppOverviewTab(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Status" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: props.status === "active" ? "Guard is actively protecting this app." : props.status === "needs_setup" ? "Guard detected this app but it needs setup." : props.status === "observed" ? "Guard has seen activity from this app." : "This app has not been seen yet." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(AppStatusBadge, { status: props.status })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Total actions", value: props.totalActions }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Allowed", value: props.allowedCount, tone: "green" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Blocked", value: props.blockedCount, tone: props.blockedCount > 0 ? "attention" : "slate" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Block rate", value: `${props.blockRate}%`, tone: props.blockRate > 10 ? "attention" : "slate" })
        ] }),
        props.harnessReceipts.length >= 5 && /* @__PURE__ */ jsxRuntimeExports.jsx(RiskSnapshot, { receipts: props.harnessReceipts }),
        props.lastActivity && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs text-muted-foreground", children: [
          "Last activity: ",
          formatRelativeTime(props.lastActivity)
        ] }),
        props.harnessReceipts.length >= 3 && /* @__PURE__ */ jsxRuntimeExports.jsx(ActivitySparkline, { receipts: props.harnessReceipts }),
        props.blockedCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudValueBanner,
          {
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 text-brand-attention" }),
            title: "Team alerts available",
            body: "Cloud would alert your team when Guard blocks actions like this.",
            cta: { label: "Learn more", href: "https://hol.org/guard/pricing" }
          }
        )
      ] }),
      props.pendingItems.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Pending review" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
          "These actions from ",
          harnessDisplayName(props.harness),
          " need your decision."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-2", children: props.pendingItems.slice(0, 5).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => props.onOpenRequest(item.request_id),
            className: "flex w-full items-center justify-between rounded-xl border border-slate-200/70 bg-white px-4 py-3 text-left transition-shadow hover:shadow-sm",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: item.artifact_name ?? item.artifact_id }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-muted-foreground", children: [
                  item.artifact_type,
                  " · ",
                  formatRelativeTime(item.created_at)
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4 shrink-0 text-slate-300" })
            ]
          },
          item.request_id
        )) })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-6", children: [
      props.harnessReceipts.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Recent events" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "What Guard decided recently." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: props.harnessReceipts.slice(0, 5).map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "flex items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: receipt.policy_decision === "allow" ? "Allowed" : "Blocked" }),
                  " ",
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: receipt.artifact_name ?? receipt.artifact_id })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-muted-foreground", children: formatRelativeTime(receipt.timestamp) })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: receipt.policy_decision === "allow" ? "green" : "attention", children: receipt.policy_decision })
            ]
          },
          receipt.receipt_id
        )) })
      ] }),
      props.harnessInventory.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Discovered items" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Tools and plugins Guard found in this app." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-2", children: props.harnessInventory.slice(0, 8).map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "flex items-center justify-between rounded-lg border border-slate-200/70 px-3 py-2",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm text-brand-dark", children: item.artifact_name ?? item.artifact_id }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "shrink-0 text-[11px] text-muted-foreground", children: item.artifact_type })
            ]
          },
          item.artifact_id
        )) })
      ] })
    ] })
  ] });
}
function AppActivityTab(props) {
  const [filter, setFilter] = reactExports.useState("all");
  const [timeFilter, setTimeFilter] = reactExports.useState("all");
  const [categoryFilter, setCategoryFilter] = reactExports.useState("");
  const [search, setSearch] = reactExports.useState("");
  const [selectedIds, setSelectedIds] = reactExports.useState(/* @__PURE__ */ new Set());
  reactExports.useEffect(() => {
    function handleKeyDown(event) {
      if (event.key === " " && document.activeElement?.tagName !== "INPUT") {
        const focused = document.activeElement;
        if (focused?.closest('[role="listitem"]')) {
          const checkbox = focused.querySelector('input[type="checkbox"]');
          if (checkbox) {
            event.preventDefault();
            checkbox.click();
          }
        }
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);
  const filteredReceipts = reactExports.useMemo(() => {
    let items = props.harnessReceipts;
    if (filter === "allowed") items = items.filter((r) => r.policy_decision === "allow");
    if (filter === "blocked") items = items.filter((r) => r.policy_decision === "block");
    if (timeFilter === "today") {
      const start = /* @__PURE__ */ new Date();
      start.setHours(0, 0, 0, 0);
      items = items.filter((r) => new Date(r.timestamp) >= start);
    }
    if (timeFilter === "week") {
      const start = /* @__PURE__ */ new Date();
      start.setDate(start.getDate() - 7);
      items = items.filter((r) => new Date(r.timestamp) >= start);
    }
    if (categoryFilter) {
      items = items.filter((r) => detectCategory(r) === categoryFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      items = items.filter(
        (r) => (r.artifact_name ?? r.artifact_id).toLowerCase().includes(q)
      );
    }
    return items;
  }, [props.harnessReceipts, filter, timeFilter, search, categoryFilter]);
  const groups = reactExports.useMemo(() => {
    const today = [];
    const yesterday = [];
    const thisWeek = [];
    const earlier = [];
    const now = /* @__PURE__ */ new Date();
    const startOfToday = new Date(now.getFullYear(), now.getMonth(), now.getDate());
    const startOfYesterday = new Date(startOfToday);
    startOfYesterday.setDate(startOfYesterday.getDate() - 1);
    const startOfWeek = new Date(startOfToday);
    startOfWeek.setDate(startOfWeek.getDate() - startOfWeek.getDay());
    filteredReceipts.forEach((r) => {
      const d = new Date(r.timestamp);
      if (d >= startOfToday) today.push(r);
      else if (d >= startOfYesterday) yesterday.push(r);
      else if (d >= startOfWeek) thisWeek.push(r);
      else earlier.push(r);
    });
    return { today, yesterday, thisWeek, earlier };
  }, [filteredReceipts]);
  const hasPending = props.pendingItems.length > 0;
  const allReceiptIds = reactExports.useMemo(() => filteredReceipts.map((r) => r.receipt_id), [filteredReceipts]);
  const selectedCount = selectedIds.size;
  const toggleSelection = reactExports.useCallback((id) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);
  const selectAll = reactExports.useCallback(() => {
    setSelectedIds(new Set(allReceiptIds));
  }, [allReceiptIds]);
  const clearSelection = reactExports.useCallback(() => {
    setSelectedIds(/* @__PURE__ */ new Set());
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    props.queueError && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Unable to load activity" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: props.queueError }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: props.onRetry,
            className: "mt-3 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50",
            children: "Retry"
          }
        )
      ] })
    ] }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        [
          { key: "all", label: "All" },
          { key: "pending", label: `Pending (${props.pendingItems.length})` },
          { key: "allowed", label: "Allowed" },
          { key: "blocked", label: "Blocked" }
        ].map((c) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => {
              setFilter(c.key);
              clearSelection();
            },
            className: `rounded-full px-3 py-1.5 text-xs font-medium transition-all ${filter === c.key ? "bg-brand-blue text-white shadow-sm" : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"}`,
            children: c.label
          },
          c.key
        )),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mx-1 h-4 w-px bg-slate-200" }),
        CATEGORIES.slice(0, 5).map((cat) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => {
              setCategoryFilter(categoryFilter === cat.key ? "" : cat.key);
              clearSelection();
            },
            className: `rounded-full px-2.5 py-1 text-[10px] font-medium uppercase tracking-wider transition-all ${categoryFilter === cat.key ? `${cat.color} bg-slate-50 shadow-sm` : "border border-slate-200 bg-white text-slate-500 hover:bg-slate-50"}`,
            children: cat.label
          },
          cat.key
        )),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "ml-auto flex gap-2", children: [
          { key: "all", label: "All time" },
          { key: "today", label: "Today" },
          { key: "week", label: "This week" }
        ].map((c) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => {
              setTimeFilter(c.key);
              clearSelection();
            },
            className: `rounded-full px-3 py-1.5 text-xs font-medium transition-all ${timeFilter === c.key ? "bg-brand-dark text-white shadow-sm" : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"}`,
            children: c.label
          },
          c.key
        )) })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          value: search,
          onChange: (e) => {
            setSearch(e.target.value);
            clearSelection();
          },
          placeholder: "Search by name...",
          className: "mt-3 w-full rounded-xl border border-slate-200/70 bg-white px-4 py-2.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
    ] }),
    filter !== "pending" && filteredReceipts.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: selectedCount === allReceiptIds.length ? clearSelection : selectAll,
          className: "rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-brand-dark transition-colors hover:bg-slate-50",
          children: selectedCount === allReceiptIds.length ? "Deselect all" : "Select all"
        }
      ),
      selectedCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-muted-foreground", children: [
        selectedCount,
        " selected"
      ] })
    ] }),
    filter === "pending" && hasPending && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-3", children: props.pendingItems.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        onClick: () => props.onOpenRequest(item.request_id),
        className: "flex w-full items-center justify-between rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3 text-left transition-shadow hover:shadow-sm",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: item.artifact_name ?? item.artifact_id }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-muted-foreground", children: [
              item.artifact_type,
              " · ",
              formatRelativeTime(item.created_at)
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "info", children: "Pending" })
        ]
      },
      item.request_id
    )) }),
    filter !== "pending" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-6", children: filteredReceipts.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No activity yet",
        body: filter === "all" ? "Guard hasn't recorded any decisions for this app yet. Allow or block an action and it will appear here." : `No ${filter} decisions match your filters.`,
        tone: "teach"
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "Today", items: groups.today, selectedIds, onToggle: toggleSelection }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "Yesterday", items: groups.yesterday, selectedIds, onToggle: toggleSelection }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "This week", items: groups.thisWeek, selectedIds, onToggle: toggleSelection }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "Earlier", items: groups.earlier, selectedIds, onToggle: toggleSelection })
    ] }) })
  ] });
}
function ReceiptGroup({ title, items, selectedIds, onToggle }) {
  if (items.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-muted-foreground", children: [
        items.length,
        " events"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: items.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsx(ExpandableReceiptRow, { receipt, selected: selectedIds.has(receipt.receipt_id), onToggle }, receipt.receipt_id)) })
  ] });
}
function ExpandableReceiptRow({ receipt, selected, onToggle }) {
  const [expanded, setExpanded] = reactExports.useState(false);
  const decisionLabel = receipt.policy_decision === "allow" ? "Allowed" : "Blocked";
  const name = receipt.artifact_name ?? receipt.artifact_id;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200/70 bg-white overflow-hidden", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex w-full items-start gap-2 px-4 py-3", children: [
      onToggle !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("label", { className: "flex items-center pt-0.5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        "input",
        {
          type: "checkbox",
          checked: selected ?? false,
          onChange: () => onToggle(receipt.receipt_id),
          className: "h-4 w-4 rounded border-slate-300 text-brand-blue focus:ring-brand-blue",
          "aria-label": `Select ${name}`
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          onClick: () => setExpanded(!expanded),
          className: "flex flex-1 items-start justify-between gap-3 text-left transition-colors hover:bg-slate-50 rounded-lg -m-1 p-1",
          "aria-expanded": expanded,
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: decisionLabel }),
                " ",
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: name })
              ] }),
              receipt.capabilities_summary && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-muted-foreground", children: receipt.capabilities_summary }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-[11px] text-muted-foreground", children: formatRelativeTime(receipt.timestamp) })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: receipt.policy_decision === "allow" ? "green" : "attention", children: receipt.policy_decision }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniChevronDown,
                {
                  className: `h-4 w-4 text-slate-400 transition-transform ${expanded ? "rotate-180" : ""}`,
                  "aria-hidden": "true"
                }
              )
            ] })
          ]
        }
      )
    ] }),
    expanded && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in border-t border-slate-200/70 bg-slate-50/60 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("dl", { className: "grid grid-cols-1 gap-2 text-xs", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-muted-foreground", children: "Action ID" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 font-mono text-brand-dark", children: receipt.artifact_id })
      ] }),
      receipt.artifact_hash && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-muted-foreground", children: "Hash" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 font-mono text-brand-dark", children: receipt.artifact_hash })
      ] }),
      receipt.capabilities_summary && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-muted-foreground", children: "Capabilities" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 text-brand-dark", children: receipt.capabilities_summary })
      ] }),
      receipt.provenance_summary && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-muted-foreground", children: "Provenance" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 text-brand-dark", children: receipt.provenance_summary })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-muted-foreground", children: "Time" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 font-mono text-brand-dark", children: new Date(receipt.timestamp).toLocaleString() })
      ] })
    ] }) })
  ] });
}
function AppSettingsTab(props) {
  const [showClearConfirm, setShowClearConfirm] = reactExports.useState(false);
  const [clearing, setClearing] = reactExports.useState(false);
  const confirmRef = reactExports.useRef(null);
  useFocusTrap(showClearConfirm, confirmRef);
  const handleClear = reactExports.useCallback(async () => {
    if (!props.onClearAppPolicies) return;
    setClearing(true);
    await props.onClearAppPolicies(props.harness);
    setClearing(false);
    setShowClearConfirm(false);
  }, [props.onClearAppPolicies, props.harness]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-[minmax(0,1fr)_minmax(0,0.8fr)]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HarnessSetupPanel,
        {
          harness: props.harness,
          install: props.install,
          status: props.status,
          onManagedInstallChanged: props.onManagedInstallChanged
        }
      ),
      props.policyError && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Unable to load decisions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: props.policyError }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: props.onRetry,
              className: "mt-3 inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50",
              children: "Retry"
            }
          )
        ] })
      ] }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Remembered decisions" }),
          props.harnessPolicies.length > 0 && props.onClearAppPolicies && /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: () => setShowClearConfirm(true),
              className: "text-xs font-medium text-brand-attention hover:text-brand-dark transition-colors",
              children: "Clear all"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
          "Guard remembers these choices for ",
          harnessDisplayName(props.harness),
          ". Remove any to be asked again."
        ] }),
        props.harnessPolicies.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
          EmptyState,
          {
            title: "No remembered decisions",
            body: "Guard will remember choices here after you allow or block actions for this app.",
            tone: "teach"
          }
        ) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `mt-4 space-y-2 ${clearing ? "guard-fade-out" : ""}`, children: props.harnessPolicies.map((policy) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "flex items-center justify-between rounded-lg border border-slate-200/70 px-4 py-3 transition-all duration-200 hover:border-brand-blue/30 hover:shadow-sm",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: policy.scope === "global" ? "Every project" : policy.scope === "harness" ? "This app" : policy.scope === "artifact" && policy.artifact_id ? policy.artifact_id : policy.scope }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-muted-foreground", children: [
                  policy.action,
                  " · ",
                  policy.reason || "No reason given"
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: policy.action === "allow" ? "green" : policy.action === "block" ? "attention" : "blue", children: policy.action })
            ]
          },
          `${policy.scope}-${policy.artifact_id ?? policy.workspace ?? "global"}`
        )) })
      ] }),
      showClearConfirm && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: confirmRef, className: "guard-fade-in rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("h3", { className: "text-sm font-semibold text-brand-dark", children: [
            "Clear all remembered decisions for ",
            harnessDisplayName(props.harness),
            "?"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-sm text-muted-foreground", children: [
            "This will remove ",
            props.harnessPolicies.length,
            " remembered decision",
            props.harnessPolicies.length !== 1 ? "s" : "",
            ". Guard will ask again next time matching actions run."
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 flex flex-wrap gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                onClick: handleClear,
                disabled: clearing,
                className: "inline-flex min-h-9 items-center rounded-lg bg-brand-attention px-3 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50",
                children: clearing ? "Clearing…" : "Clear decisions"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "button",
              {
                onClick: () => setShowClearConfirm(false),
                className: "inline-flex min-h-9 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50",
                children: "Keep decisions"
              }
            )
          ] })
        ] })
      ] }) }),
      props.harnessPolicies.length > 0 && !showClearConfirm && /* @__PURE__ */ jsxRuntimeExports.jsx(
        CloudValueBanner,
        {
          icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "h-4 w-4 text-brand-blue" }),
          title: "Team policy sync",
          body: "Cloud keeps your team's rules consistent across all devices.",
          cta: { label: "Learn more", href: "https://hol.org/guard/pricing" }
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(HarnessCoverageAside, { status: props.status, install: props.install })
  ] });
}
function HarnessSetupPanel(props) {
  const [setupState, setSetupState] = reactExports.useState({ kind: "idle" });
  const [disconnectArmed, setDisconnectArmed] = reactExports.useState(false);
  const active = props.install?.active === true;
  const displayName = harnessDisplayName(props.harness);
  const refreshAfterMutation = reactExports.useCallback(async () => {
    await props.onManagedInstallChanged?.();
  }, [props.onManagedInstallChanged]);
  const loadPlan = reactExports.useCallback(async () => {
    setSetupState({ kind: "loading", action: active ? "verify" : "install" });
    try {
      const result = active ? await runHarnessAction({ harness: props.harness, action: "verify" }) : await runHarnessAction({ harness: props.harness, action: "install", dryRun: true });
      setSetupState({ kind: "ready", plan: result });
    } catch (error) {
      setSetupState({
        kind: "error",
        action: active ? "verify" : "install",
        message: error instanceof Error ? error.message : "Unable to load setup plan."
      });
    }
  }, [active, props.harness]);
  reactExports.useEffect(() => {
    void loadPlan();
  }, [loadPlan]);
  const runAction = reactExports.useCallback(
    async (action, options = {}) => {
      setSetupState({ kind: "loading", action });
      try {
        const result = await runHarnessAction({
          harness: props.harness,
          action,
          dryRun: options.dryRun,
          confirmationPhrase: options.confirmationPhrase
        });
        setDisconnectArmed(false);
        setSetupState({ kind: "success", action, result });
        if (action !== "verify" && options.dryRun !== true) {
          await refreshAfterMutation();
        }
      } catch (error) {
        if (error instanceof GuardHarnessActionError) {
          setSetupState({
            kind: "error",
            action,
            message: setupActionErrorMessage(error),
            confirmationPhrase: error.payload?.confirmation_phrase,
            confirmCommand: error.payload?.confirm_command
          });
        } else {
          setSetupState({
            kind: "error",
            action,
            message: error instanceof Error ? error.message : "Harness action failed."
          });
        }
      }
    },
    [props.harness, refreshAfterMutation]
  );
  const handleConnect = reactExports.useCallback(() => {
    void runAction("install", { dryRun: false });
  }, [runAction]);
  const handleVerify = reactExports.useCallback(() => {
    void runAction("verify");
  }, [runAction]);
  const handleRepair = reactExports.useCallback(() => {
    void runAction("repair", { dryRun: false });
  }, [runAction]);
  const handleRequestDisconnect = reactExports.useCallback(() => {
    setDisconnectArmed(true);
    void runAction("uninstall", { dryRun: true });
  }, [runAction]);
  const handleConfirmDisconnect = reactExports.useCallback(() => {
    const phrase = setupState.kind === "error" && setupState.confirmationPhrase ? setupState.confirmationPhrase : setupState.kind === "success" && setupState.result.confirmation_phrase ? setupState.result.confirmation_phrase : `disconnect-${props.harness}`;
    void runAction("uninstall", { dryRun: false, confirmationPhrase: phrase });
  }, [props.harness, runAction, setupState]);
  const handleCancelDisconnect = reactExports.useCallback(() => {
    setDisconnectArmed(false);
    void loadPlan();
  }, [loadPlan]);
  const busy = setupState.kind === "loading";
  const currentPlan = setupState.kind === "ready" ? setupState.plan : setupState.kind === "success" ? setupState.result : null;
  const steps = setupStepsFor(currentPlan, active);
  const notes = setupNotesFor(currentPlan);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.055] via-white to-brand-dark/[0.025] p-4 shadow-sm sm:p-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Local harness install" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "mt-2 text-lg font-semibold text-brand-dark", children: active ? `${displayName} is managed by Guard` : `Connect ${displayName} from this dashboard` }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-2xl text-sm text-muted-foreground", children: active ? "Run safe checks, repair managed hooks, or disconnect this app without leaving the dashboard." : "Guard will install the local managed hooks through the daemon. No copied shell command required." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 flex-wrap gap-2", children: [
        !active && /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: handleConnect, disabled: busy, "data-primary": "true", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniRocketLaunch, { className: "h-4 w-4", "aria-hidden": "true" }),
          busy && setupState.kind === "loading" && setupState.action === "install" ? "Connecting..." : "Connect app"
        ] }),
        active && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: handleVerify, disabled: busy, variant: "outline", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Test"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: handleRepair, disabled: busy, variant: "outline", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Repair"
          ] })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid gap-3 md:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SetupMetric, { label: "Install state", value: active ? "Protected" : props.status === "observed" ? "Observed" : "Not connected", active }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SetupMetric, { label: "Config source", value: props.install?.workspace ?? "Local machine" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(SetupMetric, { label: "Last changed", value: props.install ? formatRelativeTime(props.install.updated_at) : "Not yet" })
    ] }),
    setupState.kind === "error" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 rounded-xl border border-brand-attention/15 bg-brand-attention/[0.04] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-semibold text-brand-dark", children: [
          "Could not finish ",
          setupActionLabel(setupState.action)
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 break-words text-sm text-muted-foreground", children: setupState.message }),
        setupState.confirmCommand && /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-3 block overflow-x-auto rounded-lg bg-white/80 px-3 py-2 font-mono text-xs text-brand-dark", children: setupState.confirmCommand })
      ] })
    ] }) }),
    setupState.kind === "success" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 rounded-xl border border-brand-green/20 bg-brand-green/[0.045] p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-green", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: setupSuccessTitle(setupState.action, displayName) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: setupState.action === "verify" ? "Safe local check completed. No app config was changed." : "Dashboard action completed through the local Guard daemon." })
      ] })
    ] }) }),
    steps.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-5 space-y-2", children: steps.map((step) => /* @__PURE__ */ jsxRuntimeExports.jsx(HarnessSetupStepRow, { step }, step.step_id)) }),
    notes.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-xl border border-slate-200/70 bg-white/80 p-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-widest text-slate-400", children: "What changed" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 space-y-1.5", children: notes.slice(0, 4).map((note) => /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "break-words text-xs leading-relaxed text-muted-foreground", children: note }, note)) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-wrap items-center gap-2 border-t border-slate-200/70 pt-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: () => void loadPlan(),
          disabled: busy,
          className: "inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50",
          children: "Refresh setup"
        }
      ),
      active && !disconnectArmed && /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          onClick: handleRequestDisconnect,
          disabled: busy,
          className: "inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-brand-attention/20 bg-white px-3 text-sm font-medium text-brand-attention transition-colors hover:bg-brand-attention/[0.04] disabled:opacity-50",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4", "aria-hidden": "true" }),
            "Disconnect"
          ]
        }
      ),
      active && disconnectArmed && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: handleConfirmDisconnect,
            disabled: busy,
            className: "inline-flex min-h-10 items-center rounded-lg bg-brand-attention px-3 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50",
            children: busy && setupState.kind === "loading" && setupState.action === "uninstall" ? "Disconnecting..." : "Confirm disconnect"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: handleCancelDisconnect,
            disabled: busy,
            className: "inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50",
            children: "Keep connected"
          }
        )
      ] })
    ] })
  ] });
}
function HarnessSetupStepRow({ step }) {
  const commandText = formatHarnessCommand(step.command);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-slate-200/70 bg-white/80 p-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue", children: step.writes_config ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniAdjustmentsHorizontal, { className: "h-3.5 w-3.5", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: step.title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-muted-foreground", children: step.body }),
      commandText && /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "mt-2 block overflow-x-auto rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs text-brand-dark", children: commandText })
    ] })
  ] }) });
}
function HarnessCoverageAside(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Protection model" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Dashboard actions call the local Guard daemon directly. CLI commands are shown only as fallback copy for terminals or automation." }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 space-y-2 text-xs text-muted-foreground", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Runs locally on this machine." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Requires the one-time Guard token in this dashboard session." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { children: "Writes only the harness-managed Guard config for this app." })
      ] })
    ] }),
    props.install?.manifest ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Managed files" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ManifestPathList, { manifest: props.install.manifest })
    ] }) : props.status !== "active" ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "First run" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Connect this app here first. Then launch the app normally through the Guard wrapper so risky actions pause for review." })
    ] }) : null
  ] });
}
function ManifestPathList({ manifest }) {
  const pathEntries = Object.entries(manifest).filter(
    ([key, value]) => key.endsWith("_path") && typeof value === "string" && value.length > 0
  );
  if (pathEntries.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Guard has no managed file paths to show for this app yet." });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("dl", { className: "mt-3 space-y-2", children: pathEntries.slice(0, 5).map(([key, value]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("dt", { className: "text-[10px] font-semibold uppercase tracking-widest text-slate-400", children: key.replace(/_/g, " ") }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("dd", { className: "mt-0.5 break-all font-mono text-xs text-brand-dark", children: String(value) })
  ] }, key)) });
}
function SetupMetric(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 rounded-xl border border-slate-200/70 bg-white/80 p-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-widest text-slate-400", children: props.label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-1 truncate text-sm font-semibold ${props.active ? "text-brand-green" : "text-brand-dark"}`, children: props.value })
  ] });
}
function setupStepsFor(result, active) {
  if (!result) return [];
  if (Array.isArray(result.steps) && result.steps.length > 0) return result.steps;
  if (result.verification?.steps) return result.verification.steps;
  if (!active && result.contract?.setup_steps) return result.contract.setup_steps;
  if (active && result.contract?.verify_steps) return result.contract.verify_steps;
  return [];
}
function setupNotesFor(result) {
  const manifest = result?.managed_install?.manifest;
  const notes = manifest?.["notes"];
  return Array.isArray(notes) ? notes.filter((note) => typeof note === "string") : [];
}
function setupActionLabel(action) {
  if (action === "install") return "connect";
  if (action === "verify") return "test";
  if (action === "repair") return "repair";
  return "disconnect";
}
function setupActionErrorMessage(error) {
  if (error.payload?.error === "confirmation_required") {
    return "Disconnect requires confirmation so accidental clicks cannot remove local protection.";
  }
  return error.payload?.error ?? error.message;
}
function setupSuccessTitle(action, displayName) {
  if (action === "install") return `${displayName} connected`;
  if (action === "verify") return `${displayName} test complete`;
  if (action === "repair") return `${displayName} repaired`;
  return `${displayName} disconnected`;
}
function ActivitySparkline({ receipts }) {
  const days = 7;
  const data = reactExports.useMemo(() => {
    const result = [];
    const now = /* @__PURE__ */ new Date();
    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(now);
      d.setDate(d.getDate() - i);
      d.setHours(0, 0, 0, 0);
      const end = new Date(d);
      end.setDate(end.getDate() + 1);
      const dayReceipts = receipts.filter((r) => {
        const rt = new Date(r.timestamp);
        return rt >= d && rt < end;
      });
      result.push({
        date: d.toLocaleDateString("en-US", { weekday: "short" }),
        allowed: dayReceipts.filter((r) => r.policy_decision === "allow").length,
        blocked: dayReceipts.filter((r) => r.policy_decision === "block").length
      });
    }
    return result;
  }, [receipts]);
  const maxVal = Math.max(...data.map((d) => d.allowed + d.blocked), 1);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Last 7 days" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChartBar, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 flex items-end gap-2", children: data.map((day) => {
      const total = day.allowed + day.blocked;
      const height = total > 0 ? Math.max(20, total / maxVal * 100) : 4;
      return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-1 flex-col items-center gap-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex w-full gap-0.5", style: { height: `${height}px` }, children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "div",
            {
              className: "flex-1 rounded-t bg-brand-green/60",
              style: { height: `${day.allowed > 0 ? day.allowed / total * 100 : 0}%` },
              title: `${day.allowed} allowed`
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "div",
            {
              className: "flex-1 rounded-t bg-brand-attention/60",
              style: { height: `${day.blocked > 0 ? day.blocked / total * 100 : 0}%` },
              title: `${day.blocked} blocked`
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] text-muted-foreground", children: day.date })
      ] }, day.date);
    }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex items-center gap-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-1.5 text-[10px] text-muted-foreground", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-2 w-2 rounded-sm bg-brand-green/60" }),
        "Allowed"
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "flex items-center gap-1.5 text-[10px] text-muted-foreground", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-2 w-2 rounded-sm bg-brand-attention/60" }),
        "Blocked"
      ] })
    ] })
  ] });
}
function RiskSnapshot({ receipts }) {
  const analysis = reactExports.useMemo(() => {
    const blockedCount = receipts.filter((r) => r.policy_decision === "block").length;
    const allowedCount = receipts.filter((r) => r.policy_decision === "allow").length;
    return { blocked: blockedCount, allowed: allowedCount, total: receipts.length };
  }, [receipts]);
  if (analysis.total === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Activity breakdown" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 space-y-1.5 text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: analysis.allowed }),
        " ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "allowed" })
      ] }),
      analysis.blocked > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-attention", children: analysis.blocked }),
        " ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "blocked" })
      ] })
    ] })
  ] });
}
function TabContent({
  activeTab,
  direction,
  children
}) {
  const animationClass = direction === "right" ? "guard-tab-enter" : "guard-tab-enter-reverse";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `${animationClass}`, children }, activeTab);
}
function CloudValueBanner({
  icon,
  title,
  body,
  cta
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-purple/10 bg-brand-purple/[0.03] p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-0.5 shrink-0", children: icon }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: body }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "a",
        {
          href: cta.href,
          target: "_blank",
          rel: "noopener noreferrer",
          className: "mt-3 inline-flex items-center gap-1 text-sm font-medium text-brand-blue hover:text-brand-dark transition-colors",
          children: [
            cta.label,
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-3 w-3", "aria-hidden": "true" })
          ]
        }
      )
    ] })
  ] }) });
}
function StatCard({
  label,
  value,
  tone
}) {
  const toneClass = tone === "green" ? "text-brand-green" : tone === "attention" ? "text-brand-attention" : tone === "blue" ? "text-brand-blue" : "text-brand-dark";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-200/70 bg-white p-3 text-center", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `text-xl font-semibold ${toneClass}`, children: value }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-[10px] font-medium uppercase tracking-wider text-muted-foreground", children: label })
  ] });
}
export {
  AppDetailWorkspace
};
