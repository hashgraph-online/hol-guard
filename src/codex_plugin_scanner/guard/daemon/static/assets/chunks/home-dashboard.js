<<<<<<< HEAD
import { r as reactExports, j as jsxRuntimeExports, E as EmptyState, A as ActionButton, H as HiMiniCheckCircle, G as GuardHero, P as ProofStrip, f as formatNumber, a as HiMiniFire, b as HiMiniCalendarDays, c as HiMiniShieldCheck, S as SectionLabel, h as harnessDisplayName, d as formatRelativeTime, e as HiMiniSparkles, g as HiMiniXMark, B as Badge, i as HiMiniChevronRight, k as HiMiniChevronUp, l as HiMiniChevronDown, m as HiMiniExclamationTriangle, n as HiMiniBolt, o as HiMiniMinusCircle } from "../guard-dashboard.js";
=======
import { r as reactExports, j as jsxRuntimeExports, E as EmptyState, A as ActionButton, H as HiMiniCheckCircle, G as GuardHero, P as ProofStrip, f as formatNumber, a as HiMiniFire, b as HiMiniCalendarDays, c as HiMiniShieldCheck, S as SectionLabel, h as harnessDisplayName, d as formatRelativeTime, e as HiMiniSparkles, g as HiMiniXMark, B as Badge, i as HiMiniChevronRight, k as HiMiniChevronUp, l as HiMiniChevronDown, m as HiMiniExclamationTriangle, n as HiMiniMinusCircle } from "../guard-dashboard.js";
>>>>>>> caba3931d0561139d5a66783684c5991a0e8f4fc
import { u as useFocusTrap } from "./use-focus-trap.js";
function HomeWorkspace(props) {
  const [toastMessage, setToastMessage] = reactExports.useState(null);
  const toastTimerRef = reactExports.useRef(null);
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
  const snapshot = props.runtime.kind === "ready" ? props.runtime.snapshot : null;
  const queuedCount = props.requests.kind === "ready" ? props.requests.items.length : 0;
  const policyItems = props.policies.kind === "ready" ? props.policies.items : [];
  const managedInstalls = snapshot?.managed_installs ?? [];
  const activeInstalls = managedInstalls.filter((item) => item.active);
  const observedHarnesses = snapshot ? Array.from(
    /* @__PURE__ */ new Set([
      ...snapshot.items.map((item) => item.harness),
      ...snapshot.latest_receipts.map((receipt) => receipt.harness),
      ...policyItems.map((policy) => policy.harness)
    ])
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
  const dailyStory = reactExports.useMemo(() => snapshot ? buildDailyStory(snapshot.latest_receipts, queuedCount) : null, [snapshot, queuedCount]);
  const streak = reactExports.useMemo(() => snapshot ? computeStreak(snapshot.latest_receipts) : 0, [snapshot]);
  const weeklySummary = reactExports.useMemo(() => snapshot ? buildWeeklySummary(snapshot.latest_receipts) : null, [snapshot]);
  const ctaAction = state.ctaTarget === "inbox" ? props.onOpenInbox : state.ctaTarget === "fleet" ? props.onOpenFleet : props.onOpenEvidence;
  if (props.runtime.kind === "loading" || props.requests.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-36 w-full" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-16 w-full" })
    ] });
  }
  if (props.runtime.kind === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "Guard is not connected",
        body: props.runtime.message,
        action: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: props.onOpenInbox, children: "Open review queue" }),
        tone: "teach"
      }
    );
  }
  if (!snapshot) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
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
      ProofStrip,
      {
        items: [
          { label: "Pending", value: formatNumber(queuedCount), tone: queuedCount > 0 ? "blue" : "slate" },
          { label: "Apps", value: formatNumber(watchedAppsCount), tone: watchedAppsCount > 0 ? "green" : "slate" },
          { label: "Streak", value: formatNumber(streak), tone: streak > 1 ? "purple" : "slate", icon: streak > 1 ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniFire, { className: "h-3.5 w-3.5 text-brand-purple", "aria-hidden": "true" }) : null, hint: streak > 0 ? "Consecutive days with Guard activity. Resets after 48h of inactivity." : "Guard activity streak" },
          { label: "History", value: formatNumber(snapshot?.receipt_count ?? 0), tone: "purple" }
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(StreakMilestoneBanner, { streak }),
<<<<<<< HEAD
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
=======
>>>>>>> caba3931d0561139d5a66783684c5991a0e8f4fc
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
        weeklySummary && /* @__PURE__ */ jsxRuntimeExports.jsxs(
          CollapsibleCard,
          {
            id: "weekly-summary",
            icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCalendarDays, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-purple", "aria-hidden": "true" }),
            label: "This week",
            defaultOpen: true,
            children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-muted-foreground", children: weeklySummary.body }),
              weeklySummary.stats && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", children: weeklySummary.stats.map((s) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
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
    props.clearConfirm && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ClearConfirmDialog,
      {
        clearConfirm: props.clearConfirm,
        onCancelClear: props.onCancelClear,
        onConfirmClear: async () => {
          const confirm = props.clearConfirm;
          await props.onConfirmClear();
          if (confirm?.harness) {
            showToast(`Cleared for ${harnessDisplayName(confirm.harness)}`);
          } else if (confirm?.all) {
            showToast("Cleared all decisions");
          }
        }
      }
    )
  ] });
}
function ClearConfirmDialog(props) {
  const dialogRef = reactExports.useRef(null);
  useFocusTrap(true, dialogRef);
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm", role: "dialog", "aria-modal": "true", "aria-label": "Confirm clear decisions", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { ref: dialogRef, className: "guard-fade-in w-full max-w-md rounded-2xl border border-brand-attention/20 bg-white p-6 shadow-2xl", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mt-0.5 h-5 w-5 shrink-0 text-brand-attention", "aria-hidden": "true" }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-lg font-semibold tracking-tight text-brand-dark", children: "Clear remembered decisions?" }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-sm text-muted-foreground", children: [
          "This will remove ",
          props.clearConfirm.all ? "all saved approvals" : `decisions for ${props.clearConfirm.harness ?? "this app"}`,
          ". Guard will ask again next time matching actions run."
        ] })
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
          className: "inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90",
          children: "Clear decisions"
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
      ctaLabel: "Open Apps",
      ctaTarget: "fleet"
    };
  }
  if (!hasActiveInstalls && hasObservedHarnesses) {
    return {
      heroStatus: "setup_gap",
      headline: "Finish setup",
      subheadline: "Guard detected apps but they need setup to be fully protected.",
      ctaLabel: "Open Apps",
      ctaTarget: "fleet"
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
    return {
      title: "Needs your attention",
      body: `${queuedCount} action${queuedCount === 1 ? " is" : "s are"} waiting for review. Guard paused them to keep you safe.`,
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
function buildWeeklySummary(receipts) {
  const now = /* @__PURE__ */ new Date();
  const startOfWeek = new Date(now);
  startOfWeek.setDate(now.getDate() - now.getDay());
  startOfWeek.setHours(0, 0, 0, 0);
  const weekReceipts = receipts.filter((r) => new Date(r.timestamp) >= startOfWeek);
  if (weekReceipts.length === 0) return null;
  const allowed = weekReceipts.filter((r) => r.policy_decision === "allow").length;
  const blocked = weekReceipts.filter((r) => r.policy_decision === "block").length;
  const uniqueApps = new Set(weekReceipts.map((r) => r.harness)).size;
  return {
    body: `Guard reviewed ${weekReceipts.length} actions across ${uniqueApps} app${uniqueApps !== 1 ? "s" : ""} this week.`,
    stats: [
      { label: "allowed", value: allowed },
      { label: "blocked", value: blocked },
      { label: "apps", value: uniqueApps }
    ]
  };
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
  const [focusedIndex, setFocusedIndex] = reactExports.useState(-1);
  const listRef = reactExports.useRef(null);
  const handleKeyDown = reactExports.useCallback(
    (e, index) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        const next = Math.min(index + 1, sortedHarnesses.length - 1);
        setFocusedIndex(next);
        const nextBtn = listRef.current?.querySelectorAll("button[data-app-item]")[next];
        nextBtn?.focus();
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        const prev = Math.max(index - 1, 0);
        setFocusedIndex(prev);
        const prevBtn = listRef.current?.querySelectorAll("button[data-app-item]")[prev];
        prevBtn?.focus();
      } else if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        props.onOpenAppDetail(sortedHarnesses[index]);
      }
    },
    [sortedHarnesses, props.onOpenAppDetail]
  );
  if (sortedHarnesses.length === 0) {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No apps connected yet",
        body: "Connect an AI app so Guard can start protecting it. Guard works with Codex, Claude Code, Cursor, Hermes, OpenClaw, and more.",
        tone: "teach"
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Apps at a glance" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Guard is watching these apps on this machine." })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { ref: listRef, className: "divide-y divide-slate-100 border-t border-slate-100", role: "list", "aria-label": "Apps at a glance", children: sortedHarnesses.map((harness, index) => {
      const install = props.managedInstalls.find((i) => i.harness === harness);
      const isObserved = props.observedHarnesses.includes(harness);
      const pending = pendingByHarness.get(harness) ?? 0;
      return /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          "data-app-item": true,
          onClick: () => props.onOpenAppDetail(harness),
          onKeyDown: (e) => handleKeyDown(e, index),
          onFocus: () => setFocusedIndex(index),
          onBlur: () => setFocusedIndex(-1),
          className: `flex w-full items-center justify-between gap-3 py-2.5 text-left transition-colors hover:bg-slate-50/60 ${focusedIndex === index ? "bg-brand-blue/[0.04]" : ""}`,
          role: "listitem",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2.5", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(AppStatusIcon, { install, isObserved }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-medium text-brand-dark", children: harnessDisplayName(harness) })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              pending > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs(Badge, { tone: "info", children: [
                pending,
                " pending"
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(AppStatusBadge, { install, isObserved }),
              /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4 shrink-0 text-slate-300", "aria-hidden": "true" })
            ] })
          ]
        },
        harness
      );
    }) })
  ] });
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
    return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Observed" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "default", children: "Unknown" });
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
function RecentReceiptRow(props) {
  const { receipt } = props;
  const decisionLabel = receipt.policy_decision === "allow" ? "allowed" : "blocked";
  const name = receipt.artifact_name ?? receipt.artifact_id;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3 border-b border-slate-200/70 px-4 py-3 last:border-b-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "min-w-0", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-medium", children: harnessDisplayName(receipt.harness) }),
      " ",
      decisionLabel,
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono text-xs", children: name })
    ] }) }),
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
    if (typeof window === "undefined" || !storageKey) return true;
    return localStorage.getItem(storageKey) === "1";
  });
  const handleDismiss = reactExports.useCallback(() => {
    setDismissed(true);
    if (storageKey) localStorage.setItem(storageKey, "1");
  }, [storageKey]);
  if (!milestone || dismissed) return null;
  const messages = {
    7: "One week of consistent protection! Guard is watching out for you every day.",
    14: "Two weeks strong! Your security routine is paying off.",
    30: "A full month of daily protection! You are building a great security habit."
  };
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "guard-fade-in relative overflow-hidden rounded-2xl border border-brand-purple/20 bg-brand-purple/[0.04] p-5 shadow-sm sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "absolute -right-6 -top-6 h-24 w-24 rounded-full bg-brand-purple/10" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "relative flex items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-full bg-brand-purple/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniSparkles, { className: "h-5 w-5 text-brand-purple", "aria-hidden": "true" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex-1", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(SectionLabel, { children: [
          streak,
          " day streak!"
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
<<<<<<< HEAD
function NewAppDiscoveryBanner(props) {
  const activeHarnesses = new Set(props.managedInstalls.map((i) => i.harness));
  const discovered = props.observedHarnesses.filter((h) => !activeHarnesses.has(h));
  return /* @__PURE__ */ jsxRuntimeExports.jsx(jsxRuntimeExports.Fragment, { children: discovered.map((harness) => /* @__PURE__ */ jsxRuntimeExports.jsx(
    NewAppBanner,
    {
      harness,
      onOpenAppDetail: props.onOpenAppDetail
    },
    harness
  )) });
}
function NewAppBanner(props) {
  const storageKey = `guard-new-app-dismissed-${props.harness}`;
  const [dismissed, setDismissed] = reactExports.useState(() => {
    if (typeof window === "undefined") return false;
    return localStorage.getItem(storageKey) === "1";
  });
  const handleDismiss = reactExports.useCallback((e) => {
    e.stopPropagation();
    setDismissed(true);
    localStorage.setItem(storageKey, "1");
  }, [storageKey]);
  if (dismissed) return null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "button",
    {
      onClick: () => props.onOpenAppDetail(props.harness),
      className: "guard-fade-in flex w-full items-center gap-3 rounded-xl border border-brand-blue/15 bg-brand-blue/[0.04] px-4 py-3 text-left transition-colors hover:bg-brand-blue/[0.08]",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "inline-flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-brand-blue/10", children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBolt, { className: "h-4 w-4 text-brand-blue", "aria-hidden": "true" }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
            "Guard discovered ",
            harnessDisplayName(props.harness)
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard saw this app but it is not set up yet. Open to connect it." })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "span",
          {
            onClick: handleDismiss,
            className: "shrink-0 rounded-full p-1.5 text-slate-400 transition-colors hover:bg-white/70 hover:text-brand-dark",
            "aria-label": `Dismiss ${harnessDisplayName(props.harness)} discovery`,
            role: "button",
            children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXMark, { className: "h-4 w-4", "aria-hidden": "true" })
          }
        )
      ]
    }
  );
}
=======
>>>>>>> caba3931d0561139d5a66783684c5991a0e8f4fc
function CollapsibleCard(props) {
  const storageKey = `guard-collapsed-${props.id}`;
  const [isOpen, setIsOpen] = reactExports.useState(() => {
    if (typeof window === "undefined") return props.defaultOpen ?? true;
    const saved = localStorage.getItem(storageKey);
    return saved === null ? props.defaultOpen ?? true : saved === "1";
  });
  const toggle = reactExports.useCallback(() => {
    setIsOpen((prev) => {
      const next = !prev;
      localStorage.setItem(storageKey, next ? "1" : "0");
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
  HomeWorkspace
};
