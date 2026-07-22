import { r as reactExports, j as jsxRuntimeExports, O as HiMiniWrenchScrewdriver, A as ActionButton, e as harnessDisplayName, m as HiMiniCheckCircle, P as HiMiniExclamationCircle, i as isConnectableAppHarness, p as protectionHealthFor, n as GuardHero, Q as ProofStrip, S as SectionLabel, k as EmptyState, c as HiMiniChevronRight, R as HiMiniEye, T as HiMiniXCircle, U as HiMiniClipboardDocumentCheck, V as HiMiniClipboard } from "../guard-dashboard.js";
import { S as SUPPORTED_APPS_BRIEF, A as APP_STATUS_LABELS } from "./app-catalog.js";
const PROTECTION_CHECK_ACTIONS = {
  harness_hooks: {
    label: "App hooks",
    detail: "One or more app hooks need setup or repair.",
    fallbackHref: "/settings?section=apps",
    cta: "Repair app hooks"
  },
  daemon: {
    label: "Local runtime",
    detail: "The local Guard runtime needs attention before protection can finish.",
    fallbackHref: "/settings",
    cta: "Repair local runtime"
  },
  policy_engine: {
    label: "Policy engine",
    detail: "Guard could not confirm the local policy engine is ready.",
    fallbackHref: "/policy",
    cta: "Repair policy engine"
  },
  rule_packs: {
    label: "Rule packs",
    detail: "Guard cannot confirm the active rule-pack proof yet.",
    fallbackHref: "/policy",
    cta: "Repair rule packs"
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail: "Local decision-plane compatibility is unproven or failed.",
    fallbackHref: "/settings",
    cta: "Repair decision plane"
  },
  containment_compatibility: {
    label: "Containment",
    detail: "Containment compatibility is unproven or failed.",
    fallbackHref: "/settings",
    cta: "Repair containment"
  },
  sandbox: {
    label: "Sandbox",
    detail: "Sandbox enforcement could not be confirmed.",
    fallbackHref: "/settings",
    cta: "Repair sandbox"
  },
  decision_stream: {
    label: "Command evidence",
    detail: "Command activity evidence is incomplete or unavailable.",
    fallbackHref: "/evidence?view=commands",
    cta: "Check command evidence"
  },
  tamper_checks: {
    label: "Integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks.",
    fallbackHref: "/settings?section=security",
    cta: "Repair integrity"
  }
};
function actionForCheck(check, repairHarness) {
  if (check.check_id === "harness_hooks" && repairHarness) {
    return {
      checkId: check.check_id,
      label: "App hooks",
      detail: `${harnessDisplayName(repairHarness)} hooks need setup or repair.`,
      fallbackHref: `/apps/${repairHarness}?tab=settings`,
      cta: `Repair ${harnessDisplayName(repairHarness)}`
    };
  }
  const action = PROTECTION_CHECK_ACTIONS[check.check_id];
  return action ? { checkId: check.check_id, ...action } : {
    checkId: check.check_id,
    label: check.check_id.replace(/_/g, " "),
    detail: "Guard could not confirm this protection proof.",
    fallbackHref: "/settings",
    cta: "Try automatic repair"
  };
}
function primaryProtectionRecoveryAction(health, repairHarness) {
  const gaps = health.checks.filter((check) => check.status !== "pass");
  const ordered = [
    ...gaps.filter((check) => check.status === "fail"),
    ...gaps.filter((check) => check.status !== "fail")
  ];
  const first = ordered[0];
  return first ? actionForCheck(first, repairHarness) : null;
}
function ProtectionGapItem({
  action,
  check,
  repairState,
  onRepair
}) {
  const handleRepair = reactExports.useCallback(() => {
    void onRepair(check.check_id);
  }, [check.check_id, onRepair]);
  const working = repairState?.status === "working";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { className: "flex flex-col gap-2 rounded-xl border border-brand-attention/10 bg-white/70 px-3 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 text-xs text-slate-600", children: [
      repairState?.status === "success" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniCheckCircle,
        {
          className: "mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-500",
          "aria-hidden": "true"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationCircle,
        {
          className: `mt-0.5 h-3.5 w-3.5 shrink-0 ${check.status === "fail" ? "text-brand-attention" : "text-slate-400"}`,
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "font-semibold text-brand-dark", children: action.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1 text-[10px] font-medium uppercase tracking-wide text-slate-400", children: check.status === "fail" ? "Failed" : "Unproven" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block", children: action.detail })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        ActionButton,
        {
          onClick: handleRepair,
          disabled: working,
          variant: "outline",
          children: working ? "Repairing…" : action.cta
        }
      ),
      repairState?.status === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: action.fallbackHref, variant: "ghost", children: "Open diagnostics" }) : null
    ] }),
    repairState ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      "p",
      {
        className: `text-xs ${repairState.status === "error" ? "text-red-600" : "text-slate-500"}`,
        "aria-live": "polite",
        children: repairState.message
      }
    ) : null
  ] });
}
function FleetProtectionRecovery(props) {
  const [repairStates, setRepairStates] = reactExports.useState(
    {}
  );
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const failCount = gaps.filter((check) => check.status === "fail").length;
  const unknownCount = gaps.length - failCount;
  const handleRepair = reactExports.useCallback(
    async (checkId) => {
      setRepairStates((current) => ({
        ...current,
        [checkId]: { status: "working", message: "Repairing now…" }
      }));
      try {
        const message = await props.onRepairProtectionCheck(
          checkId,
          props.repairHarnesses
        );
        setRepairStates((current) => ({
          ...current,
          [checkId]: { status: "success", message }
        }));
      } catch (error) {
        const message = error instanceof Error ? error.message : "Guard could not complete this repair.";
        setRepairStates((current) => ({
          ...current,
          [checkId]: { status: "error", message }
        }));
      }
    },
    [props.onRepairProtectionCheck, props.repairHarnesses]
  );
  const handleRepairAll = reactExports.useCallback(async () => {
    const repairedGroups = /* @__PURE__ */ new Set();
    for (const check of gaps) {
      const group = check.check_id === "rule_packs" || check.check_id === "tamper_checks" || check.check_id === "policy_engine" ? "integrity" : check.check_id;
      if (repairedGroups.has(group)) continue;
      repairedGroups.add(group);
      await handleRepair(check.check_id);
    }
  }, [gaps, handleRepair]);
  const handleRepairAllClick = reactExports.useCallback(() => {
    void handleRepairAll();
  }, [handleRepairAll]);
  if (gaps.length === 0) return null;
  const anyWorking = Object.values(repairStates).some(
    (state) => state.status === "working"
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      id: "protection-recovery",
      className: "border-y border-brand-attention/20 bg-brand-attention/[0.04] px-4 py-4 sm:px-5",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniWrenchScrewdriver,
                {
                  className: "h-4 w-4 shrink-0 text-brand-attention",
                  "aria-hidden": "true"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-semibold text-brand-dark", children: "Restore full protection" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: failCount > 0 ? `Repair the ${failCount} failed check${failCount === 1 ? "" : "s"} here${unknownCount > 0 ? `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}` : ""}. Guard rechecks protection after each step.` : "Complete the remaining proof here. Guard rechecks protection after each step." })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairAllClick, disabled: anyWorking, children: anyWorking ? "Repairing…" : "Repair failed checks" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-4 grid gap-3 sm:grid-cols-2", children: gaps.map((check) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ProtectionGapItem,
          {
            action: actionForCheck(check, props.repairHarness),
            check,
            repairState: repairStates[check.check_id],
            onRepair: handleRepair
          },
          check.check_id
        )) })
      ]
    }
  );
}
const SUPPORTED_APPS_COPY = SUPPORTED_APPS_BRIEF;
function resolveFleetHeroCopy(cloudState, activeInstallCount, protectionState, urls) {
  const hasApps = activeInstallCount > 0;
  if (hasApps && protectionState !== "protected") {
    return {
      status: protectionState,
      headline: protectionState === "partial" ? "Apps are partially protected" : "App protection is degraded",
      subheadline: protectionState === "partial" ? "Core protection passes. Finish the remaining proofs below to reach full protection." : "Some protection checks failed or remain unproven. Use the steps below to restore full protection.",
      primaryCtaLabel: "Restore full protection",
      primaryCtaHref: "#protection-recovery",
      secondaryCtaLabel: cloudState === "local_only" ? "Connect this machine" : "Open Cloud Devices",
      secondaryCtaHref: cloudState === "local_only" ? urls.connect_url : urls.fleet_url
    };
  }
  if (cloudState === "local_only") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Your apps are covered" : "Connect an app to start",
      subheadline: hasApps ? "Guard is protecting your local AI apps." : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Connect this machine",
      primaryCtaHref: urls.connect_url,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url
    };
  }
  if (cloudState === "paired_waiting") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Apps covered, first proof pending" : "Connect an app to start",
      subheadline: hasApps ? "Guard is running. First cloud proof is on its way." : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Open Cloud Devices",
      primaryCtaHref: urls.fleet_url,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url
    };
  }
  return {
    status: hasApps ? "clear" : "setup_gap",
    headline: hasApps ? "Your apps are covered" : "Connect an app to start",
    subheadline: hasApps ? "Confirm that Guard is running and protecting your local AI apps." : SUPPORTED_APPS_COPY,
    primaryCtaLabel: "Open Cloud Devices",
    primaryCtaHref: urls.fleet_url,
    secondaryCtaLabel: "Open Home",
    secondaryCtaHref: urls.dashboard_url
  };
}
function collectHarnesses(snapshot) {
  const harnesses = /* @__PURE__ */ new Set();
  for (const item of snapshot.items) {
    if (isConnectableAppHarness(item.harness)) harnesses.add(item.harness);
  }
  for (const receipt of snapshot.latest_receipts) {
    if (isConnectableAppHarness(receipt.harness)) harnesses.add(receipt.harness);
  }
  return Array.from(harnesses).sort((a, b) => a.localeCompare(b));
}
function renderReceiptContext(receipt) {
  return `${harnessDisplayName(receipt.harness)} · ${receipt.policy_decision.replace(/-/g, " ")}`;
}
function formatCount(value) {
  return value.toLocaleString();
}
function resolveAppStatus(install, protectionHealth, hasInventory, hasReceipts) {
  if (install !== void 0) {
    const hookCheck = protectionHealth.checks.find((check) => check.check_id === "harness_hooks");
    if (!install.active || hookCheck?.status === "fail") return "needs_repair";
    if (protectionHealth.state === "protected") return "protected";
    if (protectionHealth.state === "partial") return "partial";
    return "needs_repair";
  }
  if (!hasInventory && !hasReceipts) return "not_found";
  return "found_unprotected";
}
function toInstallStatus(status) {
  if (status === "protected") return "active";
  if (status === "partial") return "partial";
  if (status === "needs_repair") return "partial";
  if (status === "found_unprotected") return "observed";
  return "not_installed";
}
function StatusIcon({ status }) {
  if (status === "protected") return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 text-emerald-500", "aria-hidden": "true" });
  if (status === "found_unprotected") return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniEye, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" });
  if (status === "needs_repair") return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "h-4 w-4 text-brand-purple", "aria-hidden": "true" });
  if (status === "not_found") return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4 text-slate-300", "aria-hidden": "true" });
  return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationCircle, { className: "h-4 w-4 text-brand-attention", "aria-hidden": "true" });
}
function StatusBadge({ status }) {
  if (status === "partial") return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-brand-blue", children: "Partially protected" });
  if (status === "needs_repair") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-brand-attention", children: "Needs repair" });
  }
  const installStatus = toInstallStatus(status);
  const label = APP_STATUS_LABELS[installStatus];
  if (installStatus === "active") return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-emerald-600", children: label });
  if (installStatus === "partial") return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-brand-purple", children: label });
  if (installStatus === "observed") return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-medium text-slate-500", children: label });
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-400", children: label });
}
function AppRow({ harness, status, inventoryCount, policyCount, onOpenAppDetail }) {
  const isClickable = onOpenAppDetail !== void 0;
  const handleClick = reactExports.useCallback(() => {
    onOpenAppDetail?.(harness);
  }, [onOpenAppDetail, harness]);
  const handleKeyDown = reactExports.useCallback(
    (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        onOpenAppDetail?.(harness);
      }
    },
    [onOpenAppDetail, harness]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: `flex items-center justify-between gap-3 py-3 transition-colors ${isClickable ? "cursor-pointer hover:bg-slate-50/60" : ""}`,
      onClick: isClickable ? handleClick : void 0,
      role: isClickable ? "button" : void 0,
      tabIndex: isClickable ? 0 : void 0,
      onKeyDown: isClickable ? handleKeyDown : void 0,
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusIcon, { status }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: harnessDisplayName(harness) }),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-400", children: [
              formatCount(inventoryCount),
              " actions · ",
              formatCount(policyCount),
              " decisions"
            ] })
          ] })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(StatusBadge, { status }),
          isClickable && /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronRight, { className: "h-4 w-4 text-slate-300", "aria-hidden": "true" })
        ] })
      ]
    }
  );
}
function FleetWorkspace(props) {
  const harnesses = collectHarnesses(props.runtime);
  const managedInstalls = (props.runtime.managed_installs ?? []).filter((i) => isConnectableAppHarness(i.harness));
  const activeInstalls = managedInstalls.filter((i) => i.active);
  const inventory = props.inventory.kind === "ready" ? props.inventory.items.filter((i) => isConnectableAppHarness(i.harness)) : [];
  const visibleHarnesses = Array.from(
    new Set([
      ...managedInstalls.map((i) => i.harness),
      ...harnesses,
      ...inventory.map((i) => i.harness),
      ...props.policies.map((p) => p.harness)
    ].filter(isConnectableAppHarness))
  ).sort((a, b) => a.localeCompare(b));
  const runtimeState = props.runtime.runtime_state;
  const protectionHealth = protectionHealthFor(props.runtime);
  const receiptHarnesses = new Set(props.runtime.latest_receipts.map((r) => r.harness).filter(isConnectableAppHarness));
  const repairHarness = managedInstalls.find((install) => !install.active)?.harness ?? visibleHarnesses.find((harness) => protectionHealthFor(props.runtime, harness).checks.some(
    (check) => check.check_id === "harness_hooks" && check.status === "fail"
  ));
  const repairHarnesses = Array.from(new Set(managedInstalls.map((install) => install.harness)));
  const recoveryPrimary = primaryProtectionRecoveryAction(protectionHealth, repairHarness);
  const heroCopy = resolveFleetHeroCopy(
    props.runtime.cloud_state,
    activeInstalls.length,
    protectionHealth.state,
    {
      fleet_url: props.runtime.fleet_url,
      dashboard_url: props.runtime.dashboard_url,
      connect_url: props.runtime.connect_url
    }
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-8", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      GuardHero,
      {
        status: heroCopy.status,
        headline: heroCopy.headline,
        subheadline: heroCopy.subheadline,
        cta: protectionHealth.state !== "protected" && recoveryPrimary ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: "#protection-recovery", children: "Repair protection" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.primaryCtaHref, children: heroCopy.primaryCtaLabel }),
        secondaryCta: protectionHealth.state !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: "#protection-recovery", variant: "outline", children: "View all steps" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.secondaryCtaHref, variant: "outline", children: heroCopy.secondaryCtaLabel })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProofStrip,
      {
        items: [
          { label: "Needs review", value: formatCount(props.runtime.pending_count), tone: props.runtime.pending_count > 0 ? "blue" : "slate" },
          { label: "History", value: formatCount(props.runtime.receipt_count), tone: "purple" },
          { label: "Watched apps", value: formatCount(activeInstalls.length > 0 ? activeInstalls.length : visibleHarnesses.length), tone: protectionHealth.state === "protected" ? "green" : "slate" },
          { label: "Runtime", value: runtimeState ? "active" : "offline", tone: runtimeState ? "green" : "slate" }
        ]
      }
    ),
    protectionHealth.state !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      FleetProtectionRecovery,
      {
        health: protectionHealth,
        repairHarness,
        repairHarnesses,
        onRepairProtectionCheck: props.onRepairProtectionCheck
      }
    ) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-8 lg:grid-cols-[minmax(0,1.4fr)_minmax(0,0.8fr)]", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "App coverage" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Which apps Guard is watching on this machine." })
        ] }),
        visibleHarnesses.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "divide-y divide-slate-100 border-t border-slate-100", children: visibleHarnesses.map((harness) => {
          const install = managedInstalls.find((i) => i.harness === harness);
          const harnessInventory = inventory.filter((i) => i.harness === harness && i.present);
          const harnessPolicies = props.policies.filter((p) => p.harness === harness);
          const hasReceipts = receiptHarnesses.has(harness);
          const appProtection = protectionHealthFor(props.runtime, harness);
          const status = resolveAppStatus(install, appProtection, harnessInventory.length > 0, hasReceipts);
          return /* @__PURE__ */ jsxRuntimeExports.jsx(
            AppRow,
            {
              harness,
              status,
              inventoryCount: harnessInventory.length,
              policyCount: harnessPolicies.length,
              onOpenAppDetail: props.onOpenAppDetail
            },
            harness
          );
        }) }) : /* @__PURE__ */ jsxRuntimeExports.jsx(
          EmptyState,
          {
            title: "No watched apps yet",
            body: "Run HOL Guard once with Codex, Claude Code, OpenCode, Copilot, Cursor, Gemini, Hermes, or another supported app and this machine will show coverage here.",
            tone: "teach"
          }
        ),
        props.inventory.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-500", children: props.inventory.message }) : null
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mb-4", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Recent choices" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "What Guard decided recently." })
        ] }),
        props.runtime.latest_receipts.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-0 divide-y divide-slate-100 border-t border-slate-100", children: props.runtime.latest_receipts.slice(0, 6).map((receipt) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "py-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "truncate text-sm font-medium text-brand-dark", children: receipt.artifact_name ?? receipt.artifact_id }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-400", children: renderReceiptContext(receipt) })
        ] }, receipt.receipt_id)) }) : /* @__PURE__ */ jsxRuntimeExports.jsx(
          EmptyState,
          {
            title: "No choices yet",
            body: "Allow or block an action once and HOL Guard will start building local history for this machine."
          }
        )
      ] })
    ] }),
    activeInstalls.length === 0 && /* @__PURE__ */ jsxRuntimeExports.jsx(
      SetupGuide,
      {
        hasReceipts: props.runtime.latest_receipts.length > 0,
        hasInventory: inventory.length > 0
      }
    )
  ] });
}
function SetupGuide(props) {
  const steps = [
    {
      id: "install",
      label: "Install Guard hook",
      description: "Run `hol-guard install` in your project to set up the approval hook.",
      command: "hol-guard install",
      done: props.hasInventory
    },
    {
      id: "run",
      label: "Run your AI app",
      description: "Start Codex, Claude Code, or another supported app. Guard will intercept risky actions.",
      done: props.hasReceipts
    },
    {
      id: "verify",
      label: "Verify in dashboard",
      description: "Check this dashboard to review app health and see receipts appear in History.",
      done: props.hasReceipts && props.hasInventory
    }
  ];
  const completedCount = steps.filter((s) => s.done).length;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.03] p-5 sm:p-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Setup guide" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: completedCount === steps.length ? "Guard is set up and running!" : `${completedCount} of ${steps.length} steps completed` })
      ] }),
      completedCount === steps.length && /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-6 w-6 text-brand-green", "aria-hidden": "true" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-4 space-y-3", children: steps.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      SetupStep,
      {
        stepNumber: index + 1,
        label: step.label,
        description: step.description,
        command: step.command,
        done: step.done
      },
      step.id
    )) })
  ] });
}
function SetupStep(props) {
  const [copied, setCopied] = reactExports.useState(false);
  const handleCopy = reactExports.useCallback(() => {
    if (!props.command) return;
    void navigator.clipboard.writeText(props.command).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2e3);
    });
  }, [props.command]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: `flex items-start gap-3 rounded-xl border p-3 ${props.done ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-slate-200 bg-white"}`, children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-xs font-bold ${props.done ? "bg-brand-green text-white" : "bg-slate-100 text-slate-500"}`, children: props.done ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4", "aria-hidden": "true" }) : props.stepNumber }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `text-sm font-medium ${props.done ? "text-brand-green-text" : "text-brand-dark"}`, children: props.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: props.description }),
      props.command && /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          onClick: handleCopy,
          className: "mt-1.5 inline-flex items-center gap-1.5 rounded-md border border-slate-200 bg-slate-50 px-2 py-1 text-xs font-mono text-brand-dark transition-colors hover:bg-slate-100",
          children: [
            copied ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboardDocumentCheck, { className: "h-3 w-3 text-brand-green", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniClipboard, { className: "h-3 w-3", "aria-hidden": "true" }),
            props.command
          ]
        }
      )
    ] })
  ] });
}
export {
  FleetWorkspace,
  resolveFleetHeroCopy
};
