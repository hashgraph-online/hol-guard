import { j as jsxRuntimeExports, A as ActionButton, S as SectionLabel, z as HiMiniExclamationTriangle, aD as HiMiniArrowPath, d as HiMiniCheckCircle, bS as HiMiniSignal, L as HiMiniXCircle, aP as HiMiniClock, m as formatRelativeTime, C as Badge, ai as Tag } from "../guard-dashboard.js";
function resolveFeedSourceMode(cloudState) {
  if (cloudState === "local_only") return "sample";
  if (cloudState === "paired_waiting") return "full";
  return "live";
}
function resolveFeedStaleness(snapshot) {
  const receipts = snapshot.latest_receipts;
  if (receipts.length === 0) {
    return { stale: false, ageLabel: "No activity yet", lastActivity: null };
  }
  const latest = receipts[0].timestamp;
  const ageMs = Date.now() - new Date(latest).getTime();
  const stale = ageMs > 7 * 24 * 60 * 60 * 1e3;
  return {
    stale,
    ageLabel: stale ? `Last activity ${formatRelativeTime(latest)} (stale)` : `Last activity ${formatRelativeTime(latest)}`,
    lastActivity: latest
  };
}
function FeedSourceBadge({ mode }) {
  if (mode === "live") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "green", children: "Live cloud feed" });
  }
  if (mode === "full") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: "Full feed (syncing)" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "attention", children: "Sample only (local-only mode)" });
}
function FeedHealthCard({ label, value, tone, description, icon: Icon }) {
  const toneClasses = {
    green: "border-brand-green/20 bg-brand-green/[0.04]",
    attention: "border-brand-attention/20 bg-brand-attention/[0.04]",
    slate: "border-slate-200 bg-slate-50/40",
    red: "border-red-200 bg-red-50/40"
  };
  const iconClasses = {
    green: "text-brand-green",
    attention: "text-brand-attention",
    slate: "text-slate-400",
    red: "text-red-500"
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-xl border p-4 ${toneClasses[tone]}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 mb-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `h-4 w-4 shrink-0 ${iconClasses[tone]}`, "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: label })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: value }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500", children: description })
  ] });
}
function FeedHealthWorkspace({ snapshot, onOpenSettings }) {
  const sourceMode = resolveFeedSourceMode(snapshot.cloud_state);
  const staleState = resolveFeedStaleness(snapshot);
  const daemonRunning = snapshot.runtime_state !== null;
  const cloudLabel = snapshot.cloud_state_label;
  const cloudDetail = snapshot.cloud_state_detail;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Intel feed source mode, freshness, and cloud sync status." }) }),
      onOpenSettings && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onOpenSettings, children: "Open Settings" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white p-5 shadow-sm space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Source mode" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(FeedSourceBadge, { mode: sourceMode })
      ] }),
      sourceMode === "sample" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", role: "alert", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          HiMiniExclamationTriangle,
          {
            className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600",
            "aria-hidden": "true"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-amber-800", children: "Sample intel only" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-700 mt-0.5", children: "Guard is running in local-only mode. Threat intel is based on bundled sample data. Connect this machine to Guard Cloud for live feed updates." })
        ] })
      ] }),
      sourceMode === "full" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-3 py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Full feed syncing" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600 mt-0.5", children: "Guard Cloud is connected. Local Guard is finishing the first shared proof automatically." })
        ] })
      ] }),
      sourceMode === "live" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-brand-green/20 bg-brand-green/[0.04] px-3 py-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Live feed active" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600 mt-0.5", children: "Guard is receiving live cloud intel. Threat data is up to date." })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FeedHealthCard,
        {
          label: "Feed freshness",
          value: staleState.stale ? "Stale" : "Fresh",
          tone: staleState.stale ? "attention" : "green",
          description: staleState.ageLabel,
          icon: staleState.stale ? HiMiniExclamationTriangle : HiMiniCheckCircle
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FeedHealthCard,
        {
          label: "Daemon status",
          value: daemonRunning ? "Running" : "Offline",
          tone: daemonRunning ? "green" : "red",
          description: daemonRunning ? "Guard daemon is active and processing." : "Guard daemon is not running. No protection active.",
          icon: daemonRunning ? HiMiniSignal : HiMiniXCircle
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FeedHealthCard,
        {
          label: "Cloud sync",
          value: cloudLabel,
          tone: snapshot.cloud_state === "paired_active" ? "green" : snapshot.cloud_state === "local_only" ? "slate" : "attention",
          description: cloudDetail,
          icon: HiMiniArrowPath
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FeedHealthCard,
        {
          label: "Last activity",
          value: staleState.lastActivity ? formatRelativeTime(staleState.lastActivity) : "None",
          tone: staleState.lastActivity ? "green" : "slate",
          description: staleState.lastActivity ? "Most recent action processed by Guard." : "No actions have been processed yet.",
          icon: HiMiniClock
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white p-5 shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Cloud sync health" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 mb-3 text-sm text-slate-500", children: snapshot.cloud_sync_health.detail }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap items-center gap-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        Badge,
        {
          tone: snapshot.cloud_sync_health.state === "healthy" ? "success" : snapshot.cloud_sync_health.state === "pending" ? "attention" : snapshot.cloud_sync_health.state === "disabled" ? "default" : "destructive",
          children: snapshot.cloud_sync_health.label
        }
      ) }),
      onOpenSettings && snapshot.cloud_state === "local_only" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: onOpenSettings, children: "Connect to cloud" }) })
    ] })
  ] });
}
export {
  FeedHealthWorkspace,
  resolveFeedSourceMode,
  resolveFeedStaleness
};
