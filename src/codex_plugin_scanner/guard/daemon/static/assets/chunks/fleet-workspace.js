import { n as isDisplayableHarness, j as jsxRuntimeExports, p as GuardHero, A as ActionButton, P as ProofStrip, S as SectionLabel, E as EmptyState, r as reactExports, i as harnessDisplayName, y as HiMiniChevronRight, g as HiMiniCheckCircle, C as HiMiniEye, D as HiMiniWrenchScrewdriver, h as HiMiniXCircle, F as HiMiniExclamationCircle, I as HiMiniClipboardDocumentCheck, J as HiMiniClipboard } from "../guard-dashboard.js";
import { S as SUPPORTED_APPS_BRIEF, A as APP_STATUS_LABELS } from "./app-catalog.js";
const SUPPORTED_APPS_COPY = SUPPORTED_APPS_BRIEF;
function resolveFleetHeroCopy(cloudState, activeInstallCount, urls) {
  const hasApps = activeInstallCount > 0;
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
    if (isDisplayableHarness(item.harness)) harnesses.add(item.harness);
  }
  for (const receipt of snapshot.latest_receipts) {
    if (isDisplayableHarness(receipt.harness)) harnesses.add(receipt.harness);
  }
  return Array.from(harnesses).sort((a, b) => a.localeCompare(b));
}
function renderReceiptContext(receipt) {
  return `${harnessDisplayName(receipt.harness)} · ${receipt.policy_decision.replace(/-/g, " ")}`;
}
function resolveAppStatus(install, hasInventory, hasReceipts) {
  if (install !== void 0) {
    if (install.active) return "protected";
    return "needs_repair";
  }
  if (!hasInventory && !hasReceipts) return "not_found";
  return "found_unprotected";
}
function toInstallStatus(status) {
  if (status === "protected") return "active";
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
              inventoryCount,
              " actions · ",
              policyCount,
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
  const managedInstalls = (props.runtime.managed_installs ?? []).filter((i) => isDisplayableHarness(i.harness));
  const activeInstalls = managedInstalls.filter((i) => i.active);
  const inventory = props.inventory.kind === "ready" ? props.inventory.items.filter((i) => isDisplayableHarness(i.harness)) : [];
  const visibleHarnesses = Array.from(
    new Set([
      ...managedInstalls.map((i) => i.harness),
      ...harnesses,
      ...inventory.map((i) => i.harness),
      ...props.policies.map((p) => p.harness)
    ].filter(isDisplayableHarness))
  ).sort((a, b) => a.localeCompare(b));
  const runtimeState = props.runtime.runtime_state;
  const receiptHarnesses = new Set(props.runtime.latest_receipts.map((r) => r.harness).filter(isDisplayableHarness));
  const heroCopy = resolveFleetHeroCopy(
    props.runtime.cloud_state,
    activeInstalls.length,
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
        cta: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.primaryCtaHref, children: heroCopy.primaryCtaLabel }),
        secondaryCta: /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.secondaryCtaHref, variant: "outline", children: heroCopy.secondaryCtaLabel })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProofStrip,
      {
        items: [
          { label: "Needs review", value: `${props.runtime.pending_count}`, tone: props.runtime.pending_count > 0 ? "blue" : "slate" },
          { label: "History", value: `${props.runtime.receipt_count}`, tone: "purple" },
          { label: "Watched apps", value: `${activeInstalls.length > 0 ? activeInstalls.length : visibleHarnesses.length}`, tone: activeInstalls.length > 0 ? "green" : "slate" },
          { label: "Runtime", value: runtimeState ? "active" : "offline", tone: runtimeState ? "green" : "slate" }
        ]
      }
    ),
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
          const status = resolveAppStatus(install, harnessInventory.length > 0, hasReceipts);
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
      description: "Check this dashboard to see Guard protecting your app. You will see receipts appear in History.",
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
