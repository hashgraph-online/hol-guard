import { s as HiMiniCheckCircle, bS as HiMiniInformationCircle, a4 as HiMiniExclamationTriangle, j as jsxRuntimeExports, A as ActionButton, S as SectionLabel, d as HiMiniArrowPath, ek as HiMiniSignal, aA as HiMiniXCircle, ct as HiMiniClock, f as formatRelativeTime, a6 as Badge, T as Tag } from "../guard-dashboard.js";
import { u as useSupplyChainBundle } from "./supply-chain-hub-workspace-BOsywkJu.js";
function missingBundleMessage(cloudState) {
  if (cloudState === "local_only") {
    return "Guard has not synced a supply chain bundle yet. Connect to Guard Cloud for live advisory data.";
  }
  return "Guard Cloud is connected, but no signed advisory bundle has synced to this device yet. Use Sync on this page to fetch it.";
}
function bundleRefreshKey(snapshot) {
  return [
    snapshot.cloud_policy_bundle_hash ?? "",
    snapshot.cloud_policy_last_ack_at ?? "",
    snapshot.cloud_sync_health?.last_synced_at ?? ""
  ].join("|");
}
const MINUTE_MS = 6e4;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;
function formatSpan(spanMs) {
  if (spanMs < MINUTE_MS) return "less than a minute";
  if (spanMs < HOUR_MS) return `${Math.floor(spanMs / MINUTE_MS)}m`;
  if (spanMs < DAY_MS) return `${Math.floor(spanMs / HOUR_MS)}h`;
  return `${Math.floor(spanMs / DAY_MS)}d`;
}
function formatBundleExpiry(expiresAt, nowMs) {
  const expiry = Date.parse(expiresAt);
  if (Number.isNaN(expiry)) return null;
  const delta = expiry - nowMs;
  if (delta > 0) return `in ${formatSpan(delta)}`;
  const span = formatSpan(-delta);
  return span === "less than a minute" ? "just now" : `${span} ago`;
}
function isBundleExpired(bundle, nowMs) {
  const expiry = Date.parse(bundle.expiresAt);
  return !Number.isNaN(expiry) && expiry <= nowMs;
}
function resolveIntelFreshness(input) {
  const { cloudState, load, nowMs } = input;
  if (cloudState === "local_only") {
    return {
      kind: "sample",
      label: "Sample data",
      description: "Guard checks installs against bundled sample advisories. Connect Guard Cloud for a signed live feed.",
      tone: "slate"
    };
  }
  if (load.phase === "loading") {
    return {
      kind: "loading",
      label: "Checking",
      description: "Reading the advisory bundle cached on this device.",
      tone: "slate"
    };
  }
  if (load.phase === "error") {
    return {
      kind: "unavailable",
      label: "Unavailable",
      description: `Guard could not read the advisory bundle. ${load.message}`.trim(),
      tone: "attention"
    };
  }
  const bundle = load.bundle;
  if (bundle === null) {
    return {
      kind: "none",
      label: "Not synced",
      description: "Guard Cloud is connected, but no signed advisory bundle is cached on this device yet. Sync from the Supply Chain tab to fetch it.",
      tone: "attention"
    };
  }
  const expiry = formatBundleExpiry(bundle.expiresAt, nowMs);
  if (isBundleExpired(bundle, nowMs)) {
    return {
      kind: "expired",
      label: "Expired",
      description: `Bundle ${bundle.bundleVersion} expired ${expiry ?? "earlier"}. Sync from the Supply Chain tab to refresh it.`,
      tone: "attention"
    };
  }
  const generated = Date.parse(bundle.generatedAt);
  const generatedText = Number.isNaN(generated) ? `Bundle ${bundle.bundleVersion}` : `Bundle ${bundle.bundleVersion} generated ${formatSpan(Math.max(0, nowMs - generated))} ago`;
  return {
    kind: "current",
    label: "Fresh",
    description: expiry === null ? `${generatedText}.` : `${generatedText}, expires ${expiry}.`,
    tone: "green"
  };
}
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
function LiveFeedNotice({ freshness }) {
  if (freshness.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-slate-200 bg-slate-50/60 px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClock, { className: "mt-0.5 h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Checking the intel feed" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600 mt-0.5", children: freshness.description })
      ] })
    ] });
  }
  if (freshness.kind === "current") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-brand-green/20 bg-brand-green/[0.04] px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mt-0.5 h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: "Live feed active" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-600 mt-0.5", children: "Guard Cloud is connected and Guard is receiving its signed intel bundle." })
      ] })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", role: "alert", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600", "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-amber-800", children: "Live feed connected, intel not current" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-700 mt-0.5", children: freshness.description })
    ] })
  ] });
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
  const bundleLoad = useSupplyChainBundle(bundleRefreshKey(snapshot));
  const freshness = resolveIntelFreshness({
    cloudState: snapshot.cloud_state,
    load: bundleLoad,
    nowMs: Date.now()
  });
  const FreshnessIcon = freshness.kind === "current" ? HiMiniCheckCircle : freshness.kind === "loading" || freshness.kind === "sample" ? HiMiniInformationCircle : HiMiniExclamationTriangle;
  const daemonRunning = snapshot.runtime_state !== null;
  const cloudLabel = snapshot.cloud_state_label;
  const cloudDetail = snapshot.cloud_state_detail;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Intel feed source mode, freshness, and cloud sync status." }) }),
      onOpenSettings && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: () => onOpenSettings(), children: "Open Settings" })
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
      sourceMode === "live" && /* @__PURE__ */ jsxRuntimeExports.jsx(LiveFeedNotice, { freshness })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FeedHealthCard,
        {
          label: "Feed freshness",
          value: freshness.label,
          tone: freshness.tone,
          description: freshness.description,
          icon: FreshnessIcon
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
      onOpenSettings && snapshot.cloud_state === "local_only" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "secondary", onClick: () => onOpenSettings(), children: "Connect to cloud" }) })
    ] })
  ] });
}
const feedHealthWorkspace = /* @__PURE__ */ Object.freeze(/* @__PURE__ */ Object.defineProperty({
  __proto__: null,
  FeedHealthWorkspace,
  resolveFeedSourceMode,
  resolveFeedStaleness
}, Symbol.toStringTag, { value: "Module" }));
export {
  resolveFeedStaleness as a,
  bundleRefreshKey as b,
  feedHealthWorkspace as c,
  formatBundleExpiry as f,
  isBundleExpired as i,
  missingBundleMessage as m,
  resolveIntelFreshness as r
};
