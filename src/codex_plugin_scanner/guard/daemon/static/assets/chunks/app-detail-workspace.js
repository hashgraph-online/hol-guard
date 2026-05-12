import { j as jsxRuntimeExports, B as Badge, r as reactExports, S as SectionLabel, J as HiMiniChartBar, i as HiMiniChevronRight, d as formatRelativeTime, m as HiMiniExclamationTriangle, h as harnessDisplayName, E as EmptyState, T as Tag, l as HiMiniChevronDown, K as detectCategory, L as CATEGORIES, M as HiMiniCloud, N as fetchApprovalPage, O as fetchPolicy, Q as HiMiniArrowLeft, G as GuardHero, P as ProofStrip, R as HiMiniHome, n as HiMiniBolt, U as HiMiniAdjustmentsHorizontal } from "../guard-dashboard.js";
import { u as useFocusTrap } from "./use-focus-trap.js";
function AppStatusBadge({ status }) {
  if (status === "active") return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Active" });
  if (status === "needs_setup") return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "attention", children: "Needs setup" });
  if (status === "observed") return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Observed" });
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Unknown" });
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
const ActivitySparkline = reactExports.memo(function ActivitySparkline2({
  receipts
}) {
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
              className: "flex-1 rounded-t bg-brand-blue/60",
              style: { height: `${day.blocked > 0 ? day.blocked / total * 100 : 0}%` },
              title: `${day.blocked} stopped`
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "h-2 w-2 rounded-sm bg-brand-blue/60" }),
        "Stopped"
      ] })
    ] })
  ] });
});
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
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium text-brand-blue", children: analysis.blocked }),
        " ",
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "stopped" })
      ] })
    ] })
  ] });
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
function TabContent({
  activeTab,
  direction,
  children
}) {
  const animationClass = direction === "right" ? "guard-tab-enter" : "guard-tab-enter-reverse";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `${animationClass}`, children }, activeTab);
}
const AppOverviewTab = reactExports.memo(function AppOverviewTab2(props) {
  const {
    harness,
    status,
    totalActions,
    allowedCount,
    blockedCount,
    blockRate,
    lastActivity,
    harnessReceipts,
    harnessInventory,
    pendingItems,
    onOpenRequest,
    onViewActivityTab
  } = props;
  const recentEvents = reactExports.useMemo(() => harnessReceipts.slice(0, 5), [harnessReceipts]);
  const discoveredItems = reactExports.useMemo(() => harnessInventory.slice(0, 8), [harnessInventory]);
  const pendingPreview = reactExports.useMemo(() => pendingItems.slice(0, 5), [pendingItems]);
  const hasMorePending = pendingItems.length > 5;
  const hasMoreEvents = harnessReceipts.length > 5;
  const hasMoreInventory = harnessInventory.length > 8;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-6", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Status" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: status === "active" ? "Guard is actively protecting this app." : status === "needs_setup" ? "Guard detected this app but it needs setup." : status === "observed" ? "Guard has seen activity from this app." : "This app has not been seen yet." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(AppStatusBadge, { status })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 grid grid-cols-2 gap-3 sm:grid-cols-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Total actions", value: totalActions }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Allowed", value: allowedCount, tone: "green" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Stopped", value: blockedCount, tone: blockedCount > 0 ? "blue" : "slate" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Stop rate", value: `${blockRate}%`, tone: blockRate > 10 ? "blue" : "slate" })
        ] }),
        harnessReceipts.length >= 5 && /* @__PURE__ */ jsxRuntimeExports.jsx(RiskSnapshot, { receipts: harnessReceipts }),
        lastActivity && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-4 text-xs text-muted-foreground", children: [
          "Last activity: ",
          formatRelativeTime(lastActivity)
        ] }),
        harnessReceipts.length >= 3 && /* @__PURE__ */ jsxRuntimeExports.jsx(ActivitySparkline, { receipts: harnessReceipts }),
        blockedCount > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
          CloudValueBanner,
          {
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 text-brand-blue" }),
            title: "Team alerts available",
            body: "Cloud would alert your team when Guard stops actions like this.",
            cta: { label: "Learn more", href: "https://hol.org/guard/pricing" }
          }
        )
      ] }),
      pendingPreview.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-brand-blue/10 bg-brand-blue/[0.03] p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Pending review" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
          "These actions from ",
          harnessDisplayName(harness),
          " need your decision."
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-2", children: pendingPreview.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: () => onOpenRequest(item.request_id),
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
        )) }),
        hasMorePending && /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            onClick: onViewActivityTab,
            className: "mt-3 text-sm font-medium text-brand-blue hover:text-brand-dark transition-colors",
            children: [
              "Show all ",
              pendingItems.length,
              " pending"
            ]
          }
        )
      ] }),
      pendingPreview.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "Nothing waiting for review",
          body: "Guard has paused no actions from this app.",
          tone: "default"
        }
      ) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-6", children: [
      recentEvents.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Recent events" }),
          hasMoreEvents && /* @__PURE__ */ jsxRuntimeExports.jsx(
            "button",
            {
              onClick: onViewActivityTab,
              className: "text-xs font-medium text-brand-blue hover:text-brand-dark transition-colors",
              children: "View all"
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "What Guard decided recently." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: recentEvents.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "flex items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: receipt.policy_decision === "allow" ? "Allowed" : "Stopped" }),
                  " ",
                  /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: receipt.artifact_name ?? receipt.artifact_id })
                ] }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-muted-foreground", children: formatRelativeTime(receipt.timestamp) })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: receipt.policy_decision === "allow" ? "green" : "blue", children: receipt.policy_decision })
            ]
          },
          receipt.receipt_id
        )) })
      ] }),
      recentEvents.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No events yet",
          body: "Guard hasn't recorded any decisions for this app yet.",
          tone: "teach"
        }
      ) }),
      discoveredItems.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4 sm:p-5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Discovered items" }),
          hasMoreInventory && /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-muted-foreground", children: [
            "+",
            harnessInventory.length - 8,
            " more"
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Tools and plugins Guard found in this app." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-2", children: discoveredItems.map((item) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
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
});
const ReceiptGroup = reactExports.memo(function ReceiptGroup2({
  title,
  items
}) {
  if (items.length === 0) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between px-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "text-xs text-muted-foreground", children: [
        items.length,
        " events"
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-2", children: items.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsx(ExpandableReceiptRow, { receipt }, receipt.receipt_id)) })
  ] });
});
const ExpandableReceiptRow = reactExports.memo(function ExpandableReceiptRow2({
  receipt
}) {
  const [expanded, setExpanded] = reactExports.useState(false);
  const decisionLabel = receipt.policy_decision === "allow" ? "Allowed" : "Stopped";
  const name = receipt.artifact_name ?? receipt.artifact_id;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      onClick: () => setExpanded((prev) => !prev),
      className: "flex w-full items-start justify-between gap-3 rounded-xl border border-slate-200/70 bg-white px-4 py-3 text-left transition-colors hover:bg-slate-50",
      "aria-expanded": expanded,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: decisionLabel }),
            " ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: name })
          ] }),
          receipt.capabilities_summary && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-muted-foreground", children: receipt.capabilities_summary }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-[11px] text-muted-foreground", children: formatRelativeTime(receipt.timestamp) }),
          expanded && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-fade-in mt-3 grid grid-cols-1 gap-2 border-t border-slate-200/70 pt-3 text-xs", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "Action ID" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 font-mono text-brand-dark", children: receipt.artifact_id })
            ] }),
            receipt.artifact_hash && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "Hash" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 font-mono text-brand-dark", children: receipt.artifact_hash })
            ] }),
            receipt.capabilities_summary && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "Capabilities" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-brand-dark", children: receipt.capabilities_summary })
            ] }),
            receipt.provenance_summary && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "Provenance" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-brand-dark", children: receipt.provenance_summary })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-muted-foreground", children: "Time" }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 font-mono text-brand-dark", children: new Date(receipt.timestamp).toLocaleString() })
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex shrink-0 items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: receipt.policy_decision === "allow" ? "green" : "blue", children: receipt.policy_decision }),
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
  );
});
const AppActivityTab = reactExports.memo(function AppActivityTab2(props) {
  const [filter, setFilter] = reactExports.useState("all");
  const [timeFilter, setTimeFilter] = reactExports.useState("all");
  const [categoryFilter, setCategoryFilter] = reactExports.useState("");
  const [search, setSearch] = reactExports.useState("");
  const [showFilters, setShowFilters] = reactExports.useState(false);
  const handleSearchChange = reactExports.useCallback((e) => {
    setSearch(e.target.value);
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
          { key: "blocked", label: "Stopped" }
        ].map((c) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setFilter(c.key),
            className: `rounded-full px-3 py-1.5 text-xs font-medium transition-all ${filter === c.key ? "bg-brand-blue text-white shadow-sm" : "border border-slate-200 bg-white text-brand-dark hover:bg-slate-50"}`,
            children: c.label
          },
          c.key
        )),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mx-1 h-4 w-px bg-slate-200" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setShowFilters((s) => !s),
            className: "rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-brand-dark transition-all hover:bg-slate-50",
            children: showFilters ? "Hide filters" : "Filters"
          }
        )
      ] }),
      showFilters && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-fade-in mt-3 flex flex-wrap items-center gap-2 border-t border-slate-100 pt-3", children: [
        CATEGORIES.slice(0, 5).map((cat) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => setCategoryFilter(categoryFilter === cat.key ? "" : cat.key),
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
            onClick: () => setTimeFilter(c.key),
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
          onChange: handleSearchChange,
          placeholder: "Search by name...",
          className: "mt-3 w-full rounded-xl border border-slate-200/70 bg-white px-4 py-2.5 text-sm text-brand-dark placeholder:text-slate-400 focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        }
      )
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
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "rounded-full bg-brand-blue/10 px-2 py-0.5 text-[10px] font-medium text-brand-blue", children: "Pending" })
        ]
      },
      item.request_id
    )) }),
    filter !== "pending" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-6", children: filteredReceipts.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No activity yet",
        body: filter === "all" ? "Guard hasn't recorded any decisions for this app yet. Allow or stop an action and it will appear here." : `No ${filter} decisions match your filters.`,
        tone: "teach"
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "Today", items: groups.today }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "Yesterday", items: groups.yesterday }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "This week", items: groups.thisWeek }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptGroup, { title: "Earlier", items: groups.earlier })
    ] }) })
  ] });
});
const AppSettingsTab = reactExports.memo(function AppSettingsTab2(props) {
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
              className: "text-xs font-medium text-slate-500 hover:text-brand-dark transition-colors",
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
            body: "Guard will remember choices here after you allow or stop actions for this app.",
            tone: "teach"
          }
        ) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `mt-4 space-y-2 ${clearing ? "guard-fade-out" : ""}`, children: props.harnessPolicies.map((policy) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "div",
          {
            className: "flex items-center justify-between rounded-lg border border-slate-200/70 px-4 py-3 transition-all duration-200 hover:border-brand-blue/30 hover:shadow-sm",
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: policy.scope === "global" ? "Every app" : policy.scope === "harness" ? "This app" : policy.scope === "artifact" && policy.artifact_id ? policy.artifact_id : policy.scope }),
                /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-0.5 text-xs text-muted-foreground", children: [
                  policy.action,
                  " · ",
                  policy.reason || "No reason given"
                ] })
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: policy.action === "allow" ? "green" : policy.action === "block" ? "blue" : "blue", children: policy.action })
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
      props.harnessPolicies.length > 0 && !showClearConfirm && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-purple/10 bg-brand-purple/[0.03] p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-purple", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Team policy sync" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: "Cloud keeps your team's rules consistent across all devices." })
        ] })
      ] }) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-6", children: props.status === "needs_setup" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "rounded-xl border border-brand-attention/10 bg-brand-attention/[0.03] p-4 sm:p-5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Setup needed" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "This app is detected but not active. Run Guard with this app once to complete setup." }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 rounded-xl bg-white/60 p-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs text-brand-dark", children: `npx @hol/guard install ${props.harness}` }) })
      ] })
    ] }) }) })
  ] });
});
const tabOrder = ["overview", "activity", "settings"];
const tabDefs = [
  { key: "overview", label: "Overview", icon: HiMiniHome },
  { key: "activity", label: "Activity", icon: HiMiniBolt },
  { key: "settings", label: "Settings", icon: HiMiniAdjustmentsHorizontal }
];
function readTabFromUrl() {
  const hash = window.location.hash.replace("#", "");
  if (hash === "activity" || hash === "settings") return hash;
  return "overview";
}
function writeTabToUrl(tab) {
  const url = new URL(window.location.href);
  url.hash = tab;
  window.history.replaceState({}, "", url.toString());
}
function AppDetailWorkspace(props) {
  const [activeTab, setActiveTab] = reactExports.useState(readTabFromUrl);
  const [tabDirection, setTabDirection] = reactExports.useState("right");
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
  const handleViewActivityTab = reactExports.useCallback(() => {
    handleTabChange("activity");
  }, []);
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
          "button",
          {
            onClick: () => handleTabChange("activity"),
            className: "inline-flex min-h-9 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90",
            children: [
              "Review ",
              pendingItems.length,
              " pending"
            ]
          }
        ) : status === "needs_setup" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => handleTabChange("settings"),
            className: "inline-flex min-h-9 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90",
            children: "Open Settings"
          }
        ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            onClick: () => handleTabChange("activity"),
            className: "inline-flex min-h-9 items-center rounded-lg bg-brand-blue px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90",
            children: "View Activity"
          }
        )
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProofStrip,
      {
        items: [
          { label: "Pending", value: pendingItems.length, tone: pendingItems.length > 0 ? "blue" : "slate" },
          { label: "Total actions", value: totalActions, tone: totalActions > 0 ? "purple" : "slate" },
          { label: "Stopped", value: `${blockRate}%`, tone: blockRate > 0 ? "blue" : "slate" },
          { label: "Status", value: isActive ? "active" : "inactive", tone: isActive ? "green" : "slate" }
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "div",
      {
        className: "relative",
        role: "tablist",
        "aria-label": "App detail tabs",
        onKeyDown: handleTabKeyDown,
        children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex gap-1 border-b border-slate-200/70", children: tabDefs.map((t) => {
          const Icon = t.icon;
          const isActiveTab = activeTab === t.key;
          return /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              role: "tab",
              "aria-selected": isActiveTab,
              "aria-controls": `tabpanel-${t.key}`,
              id: `tab-${t.key}`,
              onClick: () => handleTabChange(t.key),
              className: `group relative flex min-w-[44px] items-center justify-center gap-2 px-4 py-2.5 text-sm font-medium transition-colors ${isActiveTab ? "text-brand-blue" : "text-brand-dark hover:text-brand-blue"}`,
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: "h-4 w-4", "aria-hidden": "true" }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "hidden sm:inline", children: t.label }),
                isActiveTab && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "absolute bottom-0 left-0 right-0 h-0.5 bg-brand-blue" })
              ]
            },
            t.key
          );
        }) })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "div",
      {
        className: "min-h-[300px]",
        role: "tabpanel",
        id: `tabpanel-${activeTab}`,
        "aria-labelledby": `tab-${activeTab}`,
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
                onOpenRequest: props.onOpenRequest,
                onViewActivityTab: handleViewActivityTab
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
                harnessPolicies,
                onClearAppPolicies: props.onClearAppPolicies,
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
  function handleTabKeyDown(e) {
    const currentIndex = tabOrder.indexOf(activeTab);
    if (e.key === "ArrowRight" && currentIndex < tabOrder.length - 1) {
      e.preventDefault();
      handleTabChange(tabOrder[currentIndex + 1]);
    } else if (e.key === "ArrowLeft" && currentIndex > 0) {
      e.preventDefault();
      handleTabChange(tabOrder[currentIndex - 1]);
    }
  }
}
export {
  AppDetailWorkspace
};
