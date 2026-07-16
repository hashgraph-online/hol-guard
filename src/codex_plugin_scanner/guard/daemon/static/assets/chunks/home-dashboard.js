import { g as getHeatmapLevel, j as jsxRuntimeExports, S as SectionLabel, E as EvidenceInsightsShareButton, G as GuardStatMetric, H as HomeInsightsMetrics, a as EvidenceActivityHeatmapMini, r as reactExports, u as useReceiptAnalytics, h as harnessDisplayName, i as isDisplayableHarness, b as EmptyState, A as ActionButton, c as EvidenceInsightsShareModal, d as HiMiniCheckCircle, e as GuardHero, f as formatNumber, k as HiMiniShieldCheck, D as DeviceProofCard, l as formatRelativeTime, m as HiMiniSparkles, n as HiMiniXMark, o as HiMiniChevronUp, p as HiMiniChevronDown, q as resolveCloudIntelCopy, s as HiMiniCloud, t as HiMiniQuestionMarkCircle, v as useFocusTrap, w as approvalProofRequiresPassword, x as HiMiniExclamationTriangle, y as HiMiniBolt, B as Badge, z as HiMiniChevronRight, C as HiMiniMinusCircle } from "../guard-dashboard.js";
import { H as HomeProtectionModule } from "./home-protection-module.js";
function HomeInsightsSkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 gap-px border-t border-slate-100 bg-slate-100 sm:grid-cols-4", children: Array.from({ length: 4 }, (_, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2 bg-white px-4 py-3.5 sm:py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-3 w-16 rounded" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-6 w-20 rounded" })
    ] }, index)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 px-5 py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton mb-3 h-3 w-28 rounded" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-5 gap-2", children: Array.from({ length: 5 }, (_, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col items-center gap-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-5 w-full max-w-5 rounded-[3px]" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-2.5 w-7 rounded" })
      ] }, index)) })
    ] })
  ] });
}
function EvidenceInsightsHomePreview({
  overviewStats,
  analytics,
  analyticsLoading = false,
  onOpenInsights,
  onShare
}) {
  const insightsAvailable = analytics !== null && analytics.total > 0;
  const showInsightsSection = analyticsLoading || insightsAvailable;
  const showInsightsFooter = Boolean(onOpenInsights) && (analyticsLoading || insightsAvailable);
  const miniHeatmapDays = analytics?.daily_activity?.slice(-5).map((day) => ({
    date: day.date_key,
    level: getHeatmapLevel(day.total, analytics?.peak_day_total || 1)
  })) ?? [];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3 border-b border-slate-100 px-5 py-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Your Guard stats" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "What needs you now, plus patterns from recorded actions on this machine." })
      ] }),
      onShare && insightsAvailable ? /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceInsightsShareButton, { onClick: onShare, className: "shrink-0" }) : null
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-3 gap-px bg-slate-100", children: overviewStats.map((item, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardStatMetric,
      {
        label: item.label,
        value: item.value,
        tone: item.tone,
        compact: true,
        animationDelayMs: index * 40
      },
      item.label
    )) }),
    showInsightsSection ? analyticsLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx(HomeInsightsSkeleton, {}) : analytics !== null && analytics.total > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HomeInsightsMetrics, { analytics }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-t border-slate-100 px-5 py-4", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Last 5 days" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(EvidenceActivityHeatmapMini, { cells: miniHeatmapDays }) })
      ] })
    ] }) : null : null,
    showInsightsFooter ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-5 py-4", children: insightsAvailable && onOpenInsights ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: onOpenInsights,
        className: "text-sm font-semibold text-brand-blue transition-colors hover:text-brand-blue/80 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30 focus-visible:ring-offset-2",
        children: "See all insights →"
      }
    ) : analyticsLoading ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-36 rounded" }) : null }) : null
  ] });
}
const safeLocalStorage = {
  getItem(key) {
    try {
      return typeof window !== "undefined" ? window.localStorage.getItem(key) : null;
    } catch {
      return null;
    }
  },
  setItem(key, value) {
    try {
      if (typeof window !== "undefined") {
        window.localStorage.setItem(key, value);
      }
    } catch {
      return;
    }
  }
};
const STREAK_MILESTONE_MESSAGES = {
  7: "One week of Guard activity on this machine.",
  14: "Two weeks of consistent Guard coverage.",
  30: "A full month of daily Guard coverage."
};
function resolveCloudUpsellVisible(pendingCount, cloudState) {
  if (pendingCount > 0) return false;
  return cloudState === "local_only";
}
function buildEmptyStateCopy() {
  return {
    title: "No apps connected",
    body: "Connect an AI app so Guard can start protecting it. Guard works with Codex, Claude Code, Cursor, Grok, Hermes, Kimi, and more.",
    installHint: "hol-guard apps connect <app>"
  };
}
function buildDaemonErrorCopy() {
  return {
    title: "Guard is not responding",
    body: "The local Guard service is not reachable. Go to Settings to repair the connection and restore protection.",
    primaryCta: "Go to Settings",
    secondaryCta: "Open review queue"
  };
}
function redactHomeArtifactLabel(value) {
  if (typeof value !== "string" || value.trim().length === 0) {
    return "a local action";
  }
  const trimmed = value.trim();
  if (trimmed.includes("/") || trimmed.includes("\\") || trimmed.includes("~") || trimmed.includes(":") || trimmed.length > 48) {
    return "a local action";
  }
  return trimmed;
}
function buildRecentProtectionCopy(receipt) {
  const decisionLabel = receipt.policy_decision === "block" ? "blocked" : "allowed";
  return `${harnessDisplayName(receipt.harness)} ${decisionLabel} ${redactHomeArtifactLabel(receipt.artifact_name)}`;
}
function HomeWorkspace(props) {
  const [toastMessage, setToastMessage] = reactExports.useState(null);
  const [clearPassword, setClearPassword] = reactExports.useState("");
  const [clearTotpCode, setClearTotpCode] = reactExports.useState("");
  const [clearError, setClearError] = reactExports.useState(null);
  const [clearSubmitting, setClearSubmitting] = reactExports.useState(false);
  const [shareOpen, setShareOpen] = reactExports.useState(false);
  const handleShareOpen = reactExports.useCallback(() => {
    setShareOpen(true);
  }, []);
  const handleShareClose = reactExports.useCallback(() => {
    setShareOpen(false);
  }, []);
  const toastTimerRef = reactExports.useRef(null);
  const analyticsEnabled = props.runtime.kind === "ready" && (props.runtime.snapshot?.receipt_count ?? 0) > 0;
  const analyticsState = useReceiptAnalytics(analyticsEnabled);
  reactExports.useEffect(() => {
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    };
  }, []);
  const showToast = reactExports.useCallback((message) => {
    setToastMessage(message);
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current);
    toastTimerRef.current = setTimeout(() => setToastMessage(null), 3e3);
  }, []);
  const handleClearPolicies = reactExports.useCallback((scope) => {
    props.onClearPolicies(scope);
  }, [props.onClearPolicies]);
  const handleClearPasswordChange = reactExports.useCallback((event) => {
    setClearPassword(event.target.value);
    setClearError(null);
  }, []);
  const handleClearTotpCodeChange = reactExports.useCallback((event) => {
    setClearTotpCode(event.target.value);
    setClearError(null);
  }, []);
  const handleConfirmClearWithToast = reactExports.useCallback(async () => {
    const confirm = props.clearConfirm;
    setClearSubmitting(true);
    setClearError(null);
    try {
      await props.onConfirmClear({
        ...clearPassword ? { approval_password: clearPassword } : {},
        ...clearTotpCode ? { approval_totp_code: clearTotpCode } : {}
      });
      setClearPassword("");
      setClearTotpCode("");
      if (confirm?.harness) {
        showToast(`Cleared for ${harnessDisplayName(confirm.harness)}`);
      } else if (confirm?.all) {
        showToast("Cleared all decisions");
      }
    } catch (error) {
      setClearError(error instanceof Error ? error.message : "Unable to clear remembered decisions.");
    } finally {
      setClearSubmitting(false);
    }
  }, [clearPassword, clearTotpCode, props.clearConfirm, props.onConfirmClear, showToast]);
  const snapshot = props.runtime.kind === "ready" ? props.runtime.snapshot : null;
  const queuedCount = props.requests.kind === "ready" ? props.requests.items.length : 0;
  const policyItems = props.policies.kind === "ready" ? props.policies.items : [];
  const managedInstalls = (snapshot?.managed_installs ?? []).filter((item) => isDisplayableHarness(item.harness));
  const activeInstalls = managedInstalls.filter((item) => item.active);
  const observedHarnesses = snapshot ? Array.from(
    new Set([
      ...snapshot.items.map((item) => item.harness),
      ...snapshot.latest_receipts.map((receipt) => receipt.harness),
      ...policyItems.map((policy) => policy.harness)
    ].filter(isDisplayableHarness))
  ).sort() : [];
  const clearHarnesses = activeInstalls.length > 0 ? activeInstalls.map((i) => i.harness) : observedHarnesses;
  const watchedAppsCount = activeInstalls.length > 0 ? activeInstalls.length : observedHarnesses.length;
  const state = reactExports.useMemo(
    () => deriveHomeState({
      hasActiveInstalls: activeInstalls.length > 0,
      hasObservedHarnesses: observedHarnesses.length > 0,
      queuedCount,
      watchedAppsCount
    }),
    [activeInstalls.length, observedHarnesses.length, queuedCount, watchedAppsCount]
  );
  const dailyStory = reactExports.useMemo(
    () => snapshot ? buildDailyStory(snapshot.latest_receipts, queuedCount) : null,
    [snapshot, queuedCount]
  );
  const streak = reactExports.useMemo(() => {
    if (analyticsState.kind === "ready") {
      return analyticsState.data.active_day_streak;
    }
    return snapshot ? computeStreak(snapshot.latest_receipts) : 0;
  }, [analyticsState, snapshot]);
  const cloudUpsellVisible = reactExports.useMemo(
    () => snapshot ? resolveCloudUpsellVisible(queuedCount, snapshot.cloud_state) : false,
    [snapshot, queuedCount]
  );
  const ctaAction = state.ctaTarget === "inbox" ? props.onOpenInbox : state.ctaTarget === "protect" ? props.onOpenFleet : props.onOpenEvidence;
  if (props.runtime.kind === "loading" || props.requests.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-36 w-full" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-16 w-full" })
    ] });
  }
  if (props.runtime.kind === "error") {
    const errorCopy = buildDaemonErrorCopy();
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: errorCopy.title,
        body: errorCopy.body,
        action: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 sm:flex-row", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onOpenSettings, children: errorCopy.primaryCta }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onOpenInbox, children: errorCopy.secondaryCta })
        ] }),
        tone: "teach"
      }
    );
  }
  if (!snapshot) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    shareOpen && analyticsState.kind === "ready" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EvidenceInsightsShareModal,
      {
        analytics: analyticsState.data,
        runtime: snapshot,
        onClose: handleShareClose
      }
    ) : null,
    toastMessage && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-fade-in fixed bottom-6 right-6 z-50 flex items-center gap-3 rounded-xl border border-brand-green/25 bg-brand-green-bg/90 px-4 py-3 shadow-lg backdrop-blur", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-green-text", children: toastMessage })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: state.heroStatus,
        headline: state.headline,
        subheadline: state.subheadline,
        cta: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: ctaAction, "data-primary": "true", children: state.ctaLabel })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      EvidenceInsightsHomePreview,
      {
        overviewStats: [
          { label: "Pending", value: formatNumber(queuedCount), tone: queuedCount > 0 ? "blue" : "slate" },
          { label: "Apps", value: formatNumber(watchedAppsCount), tone: watchedAppsCount > 0 ? "green" : "slate" },
          { label: "Recorded", value: formatNumber(snapshot.receipt_count ?? 0), tone: "slate" }
        ],
        analytics: analyticsState.kind === "ready" ? analyticsState.data : null,
        analyticsLoading: analyticsState.kind === "loading" && analyticsEnabled,
        runtime: snapshot,
        onOpenInsights: props.onOpenInsights,
        onShare: handleShareOpen
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(StreakMilestoneBanner, { streak }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      NewAppDiscoveryBanner,
      {
        managedInstalls,
        observedHarnesses,
        receipts: snapshot.latest_receipts,
        policies: policyItems,
        onOpenAppDetail: props.onOpenAppDetail
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-6 lg:grid-cols-[minmax(0,1.3fr)_minmax(0,0.9fr)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-6", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          AppsAtAGlance,
          {
            managedInstalls,
            observedHarnesses,
            queuedItems: props.requests.kind === "ready" ? props.requests.items : [],
            onOpenAppDetail: props.onOpenAppDetail
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          HomeProtectionModule,
          {
            snapshot,
            managedInstalls,
            onOpenFleet: props.onOpenFleet,
            onOpenSupplyChain: props.onOpenSupplyChain
          }
        ),
        dailyStory && /* @__PURE__ */ jsxRuntimeExports.jsxs(
          CollapsibleCard,
          {
            id: "daily-brief",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-green", "aria-hidden": "true" }),
            label: dailyStory.title,
            defaultOpen: true,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-muted-foreground", children: dailyStory.body }),
              dailyStory.stats && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", children: dailyStory.stats.map((s) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
                "span",
                {
                  className: "rounded-full bg-white/70 px-3 py-1 text-xs font-medium text-brand-dark",
                  children: [
                    s.value,
                    " ",
                    s.label
                  ]
                },
                s.label
              )) })
            ]
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "space-y-6", children: [
        snapshot.latest_receipts.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(RecentProtectionSection, { receipts: snapshot.latest_receipts }),
        policyItems.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 p-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Reset remembered decisions" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Clear remembered decisions when you want Guard to ask again next time. This does not remove your history." }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", children: clearHarnesses.slice(0, 4).map((harness) => /* @__PURE__ */ jsxRuntimeExports.jsx(
            ClearHarnessButton,
            {
              harness,
              onClearPolicies: handleClearPolicies
            },
            harness
          )) })
        ] })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2 lg:grid-cols-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(DeviceProofCard, { device: snapshot.device, proofStatus: snapshot.proof_status }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        CloudStatusCard,
        {
          snapshot,
          showUpsell: cloudUpsellVisible,
          onOpenSettings: props.onOpenSettings
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(KeyboardHelpCard, { onOpenHelp: props.onOpenHelp })
    ] }),
    props.clearConfirm && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ClearConfirmDialog,
      {
        clearConfirm: props.clearConfirm,
        approvalGate: props.approvalGate,
        clearPassword,
        clearTotpCode,
        clearError,
        clearSubmitting,
        onClearPasswordChange: handleClearPasswordChange,
        onClearTotpCodeChange: handleClearTotpCodeChange,
        onCancelClear: props.onCancelClear,
        onConfirmClear: handleConfirmClearWithToast
      }
    )
  ] });
}
function ClearConfirmDialog(props) {
  const dialogRef = reactExports.useRef(null);
  useFocusTrap(true, dialogRef);
  const needsProof = props.approvalGate?.enabled === true && props.approvalGate.configured === true;
  const needsPassword = approvalProofRequiresPassword(props.approvalGate);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm", role: "dialog", "aria-modal": "true", "aria-label": "Confirm clear decisions", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: dialogRef, className: "guard-fade-in w-full max-w-md rounded-2xl border border-brand-attention/20 bg-white p-6 shadow-2xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Clear remembered decisions?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
          "This will remove ",
          props.clearConfirm.all ? "all saved approvals" : `decisions for ${props.clearConfirm.harness ?? "this app"}`,
          ". Guard will ask again next time matching actions run."
        ] }),
        needsProof && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 grid gap-3", children: needsPassword ? /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Approval password" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "password",
              autoComplete: "current-password",
              value: props.clearPassword,
              onChange: props.onClearPasswordChange,
              className: "mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            }
          )
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("label", { className: "block", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500", children: "Authenticator code" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "text",
              inputMode: "numeric",
              pattern: "[0-9]*",
              maxLength: 6,
              value: props.clearTotpCode,
              onChange: props.onClearTotpCodeChange,
              placeholder: "123456",
              autoComplete: "one-time-code",
              className: "mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
            }
          )
        ] }) }),
        props.clearError !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-sm text-brand-dark", children: props.clearError })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: props.onCancelClear,
          className: "inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50",
          children: "Keep decisions"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: props.onConfirmClear,
          disabled: props.clearSubmitting,
          className: "inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-60",
          children: props.clearSubmitting ? "Clearing..." : "Clear decisions"
        }
      )
    ] })
  ] }) });
}
function deriveHomeState(input) {
  const { hasActiveInstalls, hasObservedHarnesses, queuedCount, watchedAppsCount } = input;
  if (queuedCount > 0) {
    return {
      heroStatus: "needs_review",
      headline: queuedCount === 1 ? "1 action needs review" : `${queuedCount} actions need review`,
      subheadline: "Guard stopped something. Review and decide whether to allow or block it.",
      ctaLabel: "Review now",
      ctaTarget: "inbox"
    };
  }
  if (!hasActiveInstalls && !hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Guard is ready",
      subheadline: "Connect your first AI app so Guard can start protecting it.",
      ctaLabel: "Open Protect",
      ctaTarget: "protect"
    };
  }
  if (!hasActiveInstalls && hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Finish setup",
      subheadline: "Guard detected apps but they need setup to be fully protected.",
      ctaLabel: "Open Protect",
      ctaTarget: "protect"
    };
  }
  return {
    heroStatus: "clear",
    headline: "All clear",
    subheadline: `Guard is watching your AI work. ${watchedAppsCount} app${watchedAppsCount !== 1 ? "s" : ""} protected. Nothing needs you right now.`,
    ctaLabel: "View history",
    ctaTarget: "evidence"
  };
}
function buildDailyStory(receipts, queuedCount) {
  const today = /* @__PURE__ */ new Date();
  today.setHours(0, 0, 0, 0);
  const todayReceipts = receipts.filter((r) => new Date(r.timestamp) >= today);
  const allowedToday = todayReceipts.filter((r) => r.policy_decision === "allow").length;
  const blockedToday = todayReceipts.filter((r) => r.policy_decision === "block").length;
  if (queuedCount > 0) {
    const actionText = queuedCount === 1 ? "1 action is" : `${queuedCount} actions are`;
    const pronoun = queuedCount === 1 ? "it" : "them";
    return {
      title: "Needs your attention",
      body: `${actionText} waiting for review. Guard paused ${pronoun} to keep you safe.`,
      stats: [{ label: "pending review", value: queuedCount }]
    };
  }
  if (allowedToday + blockedToday > 0) {
    return {
      title: "Today so far",
      body: `Guard allowed ${allowedToday} action${allowedToday !== 1 ? "s" : ""} and blocked ${blockedToday}.`,
      stats: [
        { label: "allowed", value: allowedToday },
        { label: "blocked", value: blockedToday }
      ]
    };
  }
  if (receipts.length > 0) {
    const last = receipts[0];
    return {
      title: "All quiet",
      body: `No new activity today. Last decision was ${formatRelativeTime(last.timestamp)}.`
    };
  }
  return null;
}
function computeStreak(receipts) {
  if (receipts.length === 0) return 0;
  const sortedByTime = [...receipts].sort((a, b) => +new Date(b.timestamp) - +new Date(a.timestamp));
  const mostRecent = new Date(sortedByTime[0].timestamp);
  const now = /* @__PURE__ */ new Date();
  const diffHours = (now.getTime() - mostRecent.getTime()) / (1e3 * 60 * 60);
  if (diffHours > 48) return 0;
  const dates = new Set(receipts.map((r) => new Date(r.timestamp).toDateString()));
  const sortedDates = Array.from(dates).sort((a, b) => +new Date(b) - +new Date(a));
  let streak = 0;
  const today = /* @__PURE__ */ new Date();
  today.setHours(0, 0, 0, 0);
  let checkDate = new Date(today);
  for (const dateStr of sortedDates) {
    const d = new Date(dateStr);
    d.setHours(0, 0, 0, 0);
    if (d.getTime() === checkDate.getTime()) {
      streak++;
      checkDate.setDate(checkDate.getDate() - 1);
    } else if (d.getTime() < checkDate.getTime()) {
      break;
    }
  }
  return streak;
}
function AppsAtAGlance(props) {
  const pendingByHarness = reactExports.useMemo(() => {
    const map = /* @__PURE__ */ new Map();
    for (const item of props.queuedItems) {
      map.set(item.harness, (map.get(item.harness) ?? 0) + 1);
    }
    return map;
  }, [props.queuedItems]);
  const sortedHarnesses = reactExports.useMemo(() => {
    const all = Array.from(
      /* @__PURE__ */ new Set([
        ...props.managedInstalls.map((i) => i.harness),
        ...props.observedHarnesses
      ])
    );
    return all.sort((a, b) => {
      const aInstall = props.managedInstalls.find((i) => i.harness === a);
      const bInstall = props.managedInstalls.find((i) => i.harness === b);
      const aPending = pendingByHarness.get(a) ?? 0;
      const bPending = pendingByHarness.get(b) ?? 0;
      const aScore = (aInstall?.active ? 3 : aInstall !== void 0 ? 2 : props.observedHarnesses.includes(a) ? 1 : 0) + (aPending > 0 ? 4 : 0);
      const bScore = (bInstall?.active ? 3 : bInstall !== void 0 ? 2 : props.observedHarnesses.includes(b) ? 1 : 0) + (bPending > 0 ? 4 : 0);
      return bScore - aScore;
    });
  }, [props.managedInstalls, props.observedHarnesses, pendingByHarness]);
  if (sortedHarnesses.length === 0) {
    const emptyCopy = buildEmptyStateCopy();
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: emptyCopy.title,
        body: emptyCopy.body,
        tone: "teach"
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Apps at a glance" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Guard is watching these apps on this machine." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "divide-y divide-slate-100 border-t border-slate-100", role: "list", "aria-label": "Apps at a glance", children: sortedHarnesses.map((harness, index) => {
      const install = props.managedInstalls.find((i) => i.harness === harness);
      const isObserved = props.observedHarnesses.includes(harness);
      const pending = pendingByHarness.get(harness) ?? 0;
      return /* @__PURE__ */ jsxRuntimeExports.jsx(
        AppGlanceRow,
        {
          harness,
          install,
          isObserved,
          pending,
          onOpenAppDetail: props.onOpenAppDetail
        },
        harness
      );
    }) })
  ] });
}
function AppGlanceRow(props) {
  const handleOpen = reactExports.useCallback(() => {
    props.onOpenAppDetail(props.harness);
  }, [props.onOpenAppDetail, props.harness]);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "listitem", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      type: "button",
      "data-app-item": true,
      onClick: handleOpen,
      className: "flex w-full items-center justify-between gap-3 py-2.5 text-left transition-colors hover:bg-slate-50/60 focus:bg-brand-blue/[0.04] focus:outline-none focus:ring-2 focus:ring-brand-blue/30",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(AppStatusIcon, { install: props.install, isObserved: props.isObserved }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-medium text-brand-dark", children: harnessDisplayName(props.harness) })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          props.pending > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs(Badge, { tone: "info", children: [
            props.pending,
            " pending"
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(AppStatusBadge, { install: props.install, isObserved: props.isObserved }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4 shrink-0 text-slate-300", "aria-hidden": "true" })
        ] })
      ]
    }
  ) });
}
function AppStatusIcon(props) {
  if (props.install?.active === true) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" });
  }
  if (props.install !== void 0 && !props.install.active) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMinusCircle, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" });
  }
  if (props.isObserved) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMinusCircle, { className: "h-4 w-4 shrink-0 text-slate-400", "aria-hidden": "true" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMinusCircle, { className: "h-4 w-4 shrink-0 text-slate-300", "aria-hidden": "true" });
}
function AppStatusBadge(props) {
  if (props.install?.active === true) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "success", children: "Active" });
  }
  if (props.install !== void 0 && !props.install.active) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "attention", children: "Needs setup" });
  }
  if (props.isObserved) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "attention", children: "Needs setup" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "attention", children: "Needs setup" });
}
function ClearHarnessButton(props) {
  const handleClick = reactExports.useCallback(() => {
    void props.onClearPolicies({ harness: props.harness });
  }, [props.onClearPolicies, props.harness]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "outline", onClick: handleClick, children: [
    "Clear ",
    props.harness
  ] });
}
function CloudStatusCard(props) {
  const copy = resolveCloudIntelCopy(props.snapshot.cloud_state);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { className: "rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.04] p-5 shadow-sm sm:p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-white/80 text-brand-blue", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloud, { className: "h-5 w-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Cloud sync" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm font-medium text-brand-dark", children: copy.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-muted-foreground", children: copy.detail }),
      props.showUpsell && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: props.onOpenSettings, children: "Open sync settings" }) })
    ] })
  ] }) });
}
function KeyboardHelpCard(props) {
  if (!props.onOpenHelp) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("section", { className: "rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-slate-100 text-brand-dark", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniQuestionMarkCircle, { className: "h-5 w-5", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Shortcuts" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "Press ? for help or / to jump to pending review. Every Home action also works with Tab and Enter." }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: props.onOpenHelp, children: "Show shortcuts" }) })
    ] })
  ] }) });
}
function RecentReceiptRow(props) {
  const { receipt } = props;
  const copy = buildRecentProtectionCopy(receipt);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 border-b border-slate-200/70 px-4 py-3 last:border-b-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-w-0", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-dark", children: copy }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "shrink-0 text-[11px] text-muted-foreground", children: formatRelativeTime(receipt.timestamp) })
  ] });
}
function RecentProtectionSection(props) {
  const recent = props.receipts.slice(0, 3);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "rounded-2xl border border-slate-200/70 bg-white/80 p-5 shadow-sm sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Recent protection" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: "What Guard stopped or allowed recently." }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 overflow-hidden rounded-xl border border-slate-200/70", children: recent.map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsx(RecentReceiptRow, { receipt }, receipt.receipt_id)) })
  ] });
}
const MILESTONE_STREAKS = [7, 14, 30];
function StreakMilestoneBanner({ streak }) {
  const milestone = MILESTONE_STREAKS.includes(streak) ? streak : null;
  const storageKey = milestone ? `guard-streak-milestone-dismissed-${milestone}` : "";
  const [dismissed, setDismissed] = reactExports.useState(() => {
    if (!storageKey) return true;
    return safeLocalStorage.getItem(storageKey) === "1";
  });
  const handleDismiss = reactExports.useCallback(() => {
    setDismissed(true);
    if (storageKey) safeLocalStorage.setItem(storageKey, "1");
  }, [storageKey]);
  if (!milestone || dismissed) return null;
  const messages = STREAK_MILESTONE_MESSAGES;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-fade-in relative overflow-hidden rounded-2xl border border-brand-purple/20 bg-brand-purple/[0.04] p-5 shadow-sm sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute -right-6 -top-6 h-24 w-24 rounded-full bg-brand-purple/10" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-purple/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSparkles, { className: "h-5 w-5 text-brand-purple", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(SectionLabel, { children: [
          streak,
          " day coverage"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-sm text-muted-foreground", children: messages[milestone] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          onClick: handleDismiss,
          className: "shrink-0 rounded-full p-1.5 text-muted-foreground transition-colors hover:bg-white/70 hover:text-brand-dark",
          "aria-label": "Dismiss streak celebration",
          children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-4 w-4", "aria-hidden": "true" })
        }
      )
    ] })
  ] });
}
function NewAppDiscoveryBanner(props) {
  const discovered = resolveNewAppDiscoveries(props.managedInstalls, props.observedHarnesses);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children: discovered.map((harness) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    NewAppBanner,
    {
      harness,
      onOpenAppDetail: props.onOpenAppDetail
    },
    harness
  )) });
}
function resolveNewAppDiscoveries(managedInstalls, observedHarnesses) {
  const activeHarnesses = new Set(managedInstalls.filter((i) => isDisplayableHarness(i.harness)).map((i) => i.harness));
  return observedHarnesses.filter((h) => isDisplayableHarness(h) && !activeHarnesses.has(h));
}
function NewAppBanner(props) {
  const storageKey = `guard-new-app-dismissed-${props.harness}`;
  const [dismissed, setDismissed] = reactExports.useState(() => {
    return safeLocalStorage.getItem(storageKey) === "1";
  });
  const handleDismiss = reactExports.useCallback((e) => {
    e.stopPropagation();
    setDismissed(true);
    safeLocalStorage.setItem(storageKey, "1");
  }, [storageKey]);
  const handleOpen = reactExports.useCallback(() => {
    props.onOpenAppDetail(props.harness);
  }, [props.onOpenAppDetail, props.harness]);
  if (dismissed) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-fade-in flex w-full items-center gap-3 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3 text-left transition-colors hover:bg-brand-blue/[0.08]", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBolt, { className: "h-4 w-4 text-brand-blue", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
        "Guard discovered ",
        harnessDisplayName(props.harness)
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard saw this app but it is not set up yet. Open to connect it." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: handleOpen,
        className: "inline-flex min-h-11 items-center justify-center rounded-lg px-3 text-sm font-semibold text-brand-blue transition-colors hover:bg-white/70",
        children: "Open"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      "button",
      {
        type: "button",
        onClick: handleDismiss,
        className: "shrink-0 rounded-full p-1.5 text-slate-400 transition-colors hover:bg-white/70 hover:text-brand-dark",
        "aria-label": `Dismiss ${harnessDisplayName(props.harness)} discovery`,
        children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-4 w-4", "aria-hidden": "true" })
      }
    )
  ] });
}
function CollapsibleCard(props) {
  const storageKey = `guard-collapsed-${props.id}`;
  const [isOpen, setIsOpen] = reactExports.useState(() => {
    const saved = safeLocalStorage.getItem(storageKey);
    return saved === null ? props.defaultOpen ?? true : saved === "1";
  });
  const toggle = reactExports.useCallback(() => {
    setIsOpen((prev) => {
      const next = !prev;
      safeLocalStorage.setItem(storageKey, next ? "1" : "0");
      return next;
    });
  }, [storageKey]);
  const borderClass = props.id === "daily-brief" ? "border-brand-green/15 bg-brand-green/[0.04]" : "border-brand-purple/15 bg-brand-purple/[0.04]";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `rounded-2xl border ${borderClass} p-5 shadow-sm sm:p-6`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        onClick: toggle,
        className: "flex w-full items-center gap-3 text-left",
        "aria-expanded": isOpen,
        "aria-controls": `collapsible-content-${props.id}`,
        children: [
          props.icon,
          /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex-1", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: props.label }) }),
          isOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 shrink-0 text-muted-foreground", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 shrink-0 text-muted-foreground", "aria-hidden": "true" })
        ]
      }
    ),
    isOpen && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { id: `collapsible-content-${props.id}`, className: "mt-3 guard-fade-in", children: props.children })
  ] });
}
export {
  HomeWorkspace,
  STREAK_MILESTONE_MESSAGES,
  buildDaemonErrorCopy,
  buildDailyStory,
  buildEmptyStateCopy,
  buildRecentProtectionCopy,
  computeStreak,
  deriveHomeState,
  redactHomeArtifactLabel,
  resolveCloudUpsellVisible,
  resolveNewAppDiscoveries,
  safeLocalStorage
};
