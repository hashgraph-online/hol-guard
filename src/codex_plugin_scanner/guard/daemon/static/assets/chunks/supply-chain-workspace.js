import { j as jsxRuntimeExports, T as Tag, A as ActionButton, al as HiMiniArrowPath, H as HiMiniShieldCheck, at as HiMiniArrowTopRightOnSquare, g as HiMiniCheckCircle, b as HiMiniExclamationTriangle, h as HiMiniXCircle, r as reactExports, av as fetchPackageFirewallStatus, aw as runPackageFirewallAction, aj as GuardHarnessActionError, ax as runPackageAudit, ay as runPackageSync, az as startPackageFirewallConnect, aA as openPackageFirewallShell, S as SectionLabel, a8 as HiMiniMagnifyingGlass, E as EmptyState, aB as HiMiniBugAnt, aC as IconActionButton, am as HiMiniTrash, C as HiMiniWrenchScrewdriver, aD as HiMiniBeaker, aE as fetchSupplyChainBundle, f as formatRelativeTime, B as Badge, l as harnessDisplayName, d as HiMiniChevronUp, e as HiMiniChevronDown } from "../guard-dashboard.js";
import { u as useResolvedApprovalGate, A as ApprovalProofModal } from "./use-resolved-approval-gate.js";
import { b as resolvePackageManagerProtectionCopy } from "./runtime-overview.js";
function UpgradeCta({ entitlement }) {
  const reconnectRequired = entitlement.reason === "guard_cloud_reconnect_required";
  const upgradeUrl = reconnectRequired ? "https://hol.org/guard/connect" : entitlement.upgrade_url ?? "https://hol.org/guard/pricing";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-3 rounded-xl border border-brand-blue/20 bg-gradient-to-br from-brand-blue/[0.04] to-brand-dark/[0.02] px-4 py-4 sm:flex-row sm:items-center sm:justify-between", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniShieldCheck,
        {
          className: "mt-0.5 h-5 w-5 shrink-0 text-brand-blue",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: reconnectRequired ? "Reconnect to restore active protection" : "Upgrade to enable active protection" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-relaxed text-slate-500", children: entitlement.upgrade_cta ?? entitlement.reason ?? "Package firewall actions require a Guard Cloud subscription." })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: upgradeUrl, variant: "primary", children: [
      reconnectRequired ? "Reconnect" : "Upgrade",
      /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "ml-1.5 h-3.5 w-3.5", "aria-hidden": "true" })
    ] })
  ] });
}
function ConnectStep({ body, current, done, index, title }) {
  const toneClass = done ? "border-brand-green/20 bg-brand-green/[0.04]" : current ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-slate-200 bg-white/85";
  const badgeClass = done ? "bg-brand-green/10 text-brand-green" : current ? "bg-brand-blue/10 text-brand-blue" : "bg-slate-100 text-slate-500";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `rounded-[18px] border px-3.5 py-3 ${toneClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex h-6 w-6 shrink-0 items-center justify-center rounded-full text-[11px] font-semibold ${badgeClass}`, children: done ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5", "aria-hidden": "true" }) : index }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-semibold text-brand-dark", children: title }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-500", children: body })
    ] })
  ] }) });
}
function resolveConnectSteps(connectFlow) {
  const running = connectFlow.state === "running";
  const failed = connectFlow.state === "failed";
  const browserOpened = connectFlow.browser_opened === true;
  return [
    {
      title: "Start local connect",
      body: failed ? "Guard started the local connect flow, but it needs another attempt." : "The local daemon opens a secure HOL Guard Cloud sign-in flow for this machine.",
      done: running || failed,
      current: !running && !failed
    },
    {
      title: "Approve in browser",
      body: browserOpened ? "Finish sign-in in the browser window Guard opened." : "If your browser did not open automatically, use the manual sign-in link below.",
      done: false,
      current: running
    },
    {
      title: "Unlock firewall actions",
      body: "Guard verifies package-firewall access before it changes package-manager routing.",
      done: false,
      current: false
    }
  ];
}
function isMacClient() {
  if (typeof navigator === "undefined") {
    return false;
  }
  const navigatorWithUserAgentData = navigator;
  const platformHint = navigatorWithUserAgentData.userAgentData?.platform ?? navigator.userAgent ?? navigator.platform;
  return platformHint.toLowerCase().includes("mac");
}
function ConnectFlowCard({
  compact = false,
  connectError,
  connectStarting,
  connectFlow,
  localRecoveryHint,
  mode,
  onStartConnect
}) {
  const manualHref = connectFlow.authorize_url ?? connectFlow.connect_url;
  const running = connectFlow.state === "running";
  const failed = connectFlow.state === "failed";
  const primaryBusy = connectStarting || running;
  const primaryLabel = running ? "Waiting for browser approval" : failed ? "Try connect again" : connectFlow.action_label;
  const steps = resolveConnectSteps(connectFlow);
  const statusTone = running ? "blue" : mode === "repair" ? "attention" : "blue";
  const statusLabel = running ? "Waiting for approval" : mode === "repair" ? "Repair required" : "Connection required";
  const showManualLink = connectFlow.authorize_url !== null || running || failed;
  if (compact) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue", children: "HOL Guard Cloud" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: statusTone, children: statusLabel })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base font-semibold tracking-[-0.02em] text-brand-dark", children: connectFlow.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-3xl text-sm leading-relaxed text-slate-500", children: connectFlow.detail })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2 text-xs leading-relaxed text-slate-500 md:grid-cols-3", children: steps.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "font-semibold text-brand-dark", children: [
          index + 1,
          ". ",
          step.title
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5", children: step.body })
      ] }, step.title)) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-x-4 gap-y-1 text-xs leading-relaxed text-slate-500", children: [
        localRecoveryHint !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: localRecoveryHint }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: "Guard changes routing only after this machine receives signed cloud access." })
      ] }),
      connectError !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs leading-relaxed text-brand-attention", children: connectError }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: onStartConnect, disabled: primaryBusy, children: [
          primaryBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-3.5 w-3.5 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mr-1.5 h-3.5 w-3.5", "aria-hidden": "true" }),
          primaryLabel
        ] }),
        showManualLink && /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: manualHref, variant: "outline", children: [
          "Open sign-in page",
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "ml-1.5 h-3.5 w-3.5", "aria-hidden": "true" })
        ] })
      ] })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "space-y-4", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 lg:grid-cols-[minmax(0,1fr)_260px] lg:items-start", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-2.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-brand-blue", children: "HOL Guard Cloud" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: statusTone, children: statusLabel })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-1", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-base font-semibold tracking-[-0.02em] text-brand-dark", children: connectFlow.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "max-w-3xl text-sm leading-relaxed text-slate-500", children: connectFlow.detail })
        ] })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-slate-50/80 px-3.5 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Security" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: "Guard does not change package-manager routing until this machine receives signed cloud access." })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-2.5 md:grid-cols-3", children: steps.map((step, index) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConnectStep,
      {
        index: index + 1,
        title: step.title,
        body: step.body,
        current: step.current,
        done: step.done
      },
      step.title
    )) }),
    localRecoveryHint != null && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-200 bg-slate-50/80 px-3.5 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.14em] text-slate-400", children: "Available now" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: localRecoveryHint })
    ] }),
    connectError !== null && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-[18px] border border-brand-attention/25 bg-brand-attention/[0.05] px-3.5 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Guard could not start local connect" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs leading-relaxed text-slate-600", children: connectError })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant: "primary", onClick: onStartConnect, disabled: primaryBusy, children: [
        primaryBusy ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-3.5 w-3.5 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mr-1.5 h-3.5 w-3.5", "aria-hidden": "true" }),
        primaryLabel
      ] }),
      showManualLink && /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { href: manualHref, variant: "outline", children: [
        "Open sign-in page",
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "ml-1.5 h-3.5 w-3.5", "aria-hidden": "true" })
      ] })
    ] })
  ] }) });
}
function CliFallback({ commands }) {
  const items = Object.entries(commands);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("details", { className: "rounded-xl border border-slate-200 bg-slate-50/80 px-4 py-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("summary", { className: "cursor-pointer list-none text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: "CLI fallback" }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 space-y-1.5", children: items.map(([label, command]) => /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mr-2 text-[10px] font-semibold uppercase tracking-wide text-slate-400", children: label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: "break-all font-mono text-xs text-brand-dark", children: command })
    ] }, label)) })
  ] });
}
function EntitlementNotice({
  connectError,
  connectStarting,
  data,
  onStartConnect
}) {
  const connectRequired = data.entitlement.reason === "guard_cloud_connect_required" || data.entitlement.reason === "guard_cloud_reconnect_required";
  const reconnectLikeState = data.entitlement.reason === "guard_cloud_reconnect_required" || data.entitlement.reason === "guard_cloud_connect_required" && (data.entitlement.tier !== "unknown" || data.package_shims.some((shim) => shim.installed));
  const connectMode = reconnectLikeState ? "repair" : "connect";
  const localRecoveryHint = data.package_shims.some((shim) => shim.installed) ? connectRequired ? "Existing shims on this machine can still be fixed or removed locally. Connect is only needed for new installs and cloud-gated verification." : null : null;
  const compactConnectNotice = data.package_shims.some((shim) => shim.installed) || data.protection?.path_status === "restart_required";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 px-4 py-4", children: [
    connectRequired && data.connect_flow !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConnectFlowCard,
      {
        compact: compactConnectNotice,
        connectError,
        connectStarting,
        connectFlow: data.connect_flow,
        localRecoveryHint,
        mode: connectMode,
        onStartConnect
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx(UpgradeCta, { entitlement: data.entitlement }),
    data.cli_fallback !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(CliFallback, { commands: data.cli_fallback })
  ] });
}
function activationHeadline(protection) {
  if (protection === null) return "Activation status unavailable";
  if (protection.path_status === "in_path") return "Protection live now";
  if (protection.path_status === "restart_required") return "Restart shell or apps to finish activation";
  return "Fix PATH to finish activation";
}
function ActivationSummary({
  activationAssistError,
  openingShell,
  onOpenShell,
  onRefreshStatus,
  protection
}) {
  if (protection === null) {
    return null;
  }
  const copy = resolvePackageManagerProtectionCopy(protection);
  const Icon = protection.path_status === "in_path" ? HiMiniCheckCircle : protection.path_status === "restart_required" ? HiMiniArrowPath : HiMiniExclamationTriangle;
  const toneClass = protection.path_status === "in_path" ? "border-brand-green/20 bg-brand-green/[0.04]" : protection.path_status === "restart_required" ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-brand-attention/20 bg-brand-attention/[0.04]";
  const iconClass = protection.path_status === "in_path" ? "text-brand-green" : protection.path_status === "restart_required" ? "text-brand-blue" : "text-brand-attention";
  const canOpenShell = protection.path_status === "restart_required" && protection.shell_profile_configured && isMacClient();
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `rounded-xl border px-4 py-3 ${toneClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `mt-0.5 h-4 w-4 shrink-0 ${iconClass}`, "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: activationHeadline(protection) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-600", children: copy.pathDetail }),
      protection.path_status === "restart_required" && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 flex flex-wrap items-center gap-2", children: [
        canOpenShell && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "primary", onClick: onOpenShell, disabled: openingShell, children: openingShell ? "Opening shell…" : "Open new shell" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onRefreshStatus, disabled: openingShell, children: "Refresh after restart" })
      ] }),
      activationAssistError !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 text-xs text-brand-attention", children: activationAssistError })
    ] })
  ] }) });
}
function ReceiptProofCard({ receipt }) {
  if (receipt === null) {
    return null;
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 rounded-lg border border-slate-100 bg-slate-50 px-3 py-2.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mb-1.5 text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", children: "Proof receipt" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-1 gap-1 sm:grid-cols-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-medium uppercase tracking-wide text-slate-400", children: "ID" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-xs text-brand-dark", children: receipt.id })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-medium uppercase tracking-wide text-slate-400", children: "Operation" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-mono text-xs text-brand-dark", children: receipt.operation })
      ] })
    ] })
  ] });
}
function DismissButton({ onDismiss }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "button",
    {
      type: "button",
      onClick: onDismiss,
      "aria-label": "Dismiss result",
      className: "shrink-0 rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 focus:outline-none focus:ring-2 focus:ring-brand-blue/30",
      children: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4", "aria-hidden": "true" })
    }
  );
}
function ActionResultPanel({ completed, onDismiss }) {
  const { response } = completed;
  const isOk = ["completed", "ok", "success", "succeeded"].includes(response.status);
  const detail = response.result_detail;
  const resultMessage = detail["activation_state"] === "restart_required" ? "Guard installed the shim and updated your shell profile. Open a new shell or restart AI apps to route package-manager commands through Guard." : detail["activation_state"] === "in_path" ? "Guard installed the shim and protection is live in this session." : response.result;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: `rounded-xl border px-4 py-3 ${isOk ? "border-brand-green/20 bg-brand-green/[0.04]" : "border-brand-attention/20 bg-brand-attention/[0.04]"}`,
      role: "status",
      "aria-live": "polite",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start justify-between gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-2", children: [
            isOk ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              HiMiniCheckCircle,
              {
                className: "mt-0.5 h-4 w-4 shrink-0 text-brand-green",
                "aria-hidden": "true"
              }
            ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
              HiMiniExclamationTriangle,
              {
                className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention",
                "aria-hidden": "true"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium capitalize text-brand-dark", children: [
                completed.op,
                completed.manager !== null ? ` — ${completed.manager}` : ""
              ] }),
              /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-600", children: resultMessage })
            ] })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(DismissButton, { onDismiss })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(ReceiptProofCard, { receipt: response.receipt })
      ]
    }
  );
}
function resolveShimStatus(shim) {
  if (!shim || !shim.installed) {
    return { label: "Unprotected", tone: "attention", icon: "warning" };
  }
  if (shim.activation_state === "protected") {
    return { label: "Protected", tone: "green", icon: "check" };
  }
  if (shim.activation_state === "restart_required") {
    return { label: "Restart required", tone: "blue", icon: "restart" };
  }
  if (shim.activation_state === "repair_required") {
    return { label: "Needs PATH repair", tone: "attention", icon: "warning" };
  }
  return { label: "Unprotected", tone: "attention", icon: "warning" };
}
function actionIsAvailable(state) {
  return state === "available";
}
function actionLabel(op) {
  return op.charAt(0).toUpperCase() + op.slice(1);
}
function ManagerRow({
  manager,
  shim,
  actions,
  anyPending,
  isMine,
  isConfirmingRemove,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel
}) {
  const status = resolveShimStatus(shim);
  const installState = actions.install ?? "disabled";
  const repairState = actions.repair ?? "disabled";
  const testState = actions.test ?? "disabled";
  const removeState = actions.remove ?? "disabled";
  const installAvailable = actionIsAvailable(installState);
  const repairAvailable = actionIsAvailable(repairState);
  const testAvailable = actionIsAvailable(testState);
  const removeAvailable = actionIsAvailable(removeState);
  const showInstall = (!shim || !shim.installed) && installAvailable;
  const showRepair = shim?.installed && shim.activation_state === "repair_required" && repairAvailable;
  const showTest = shim?.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim?.installed && removeAvailable;
  const handleInstall = reactExports.useCallback(() => onInstall(manager), [onInstall, manager]);
  const handleRepair = reactExports.useCallback(() => onRepair(manager), [onRepair, manager]);
  const handleTest = reactExports.useCallback(() => onTest(manager), [onTest, manager]);
  const handleRemoveRequest = reactExports.useCallback(() => onRemoveRequest(manager), [onRemoveRequest, manager]);
  const handleRemoveConfirm = reactExports.useCallback(() => onRemoveConfirm(manager), [onRemoveConfirm, manager]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 last:border-b-0", role: "row", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 px-4 py-3 sm:flex-row sm:items-center sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2", role: "cell", children: [
        status.icon === "check" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }) : status.icon === "restart" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate font-mono text-sm font-semibold text-brand-dark", children: manager }),
        isMine && /* @__PURE__ */ jsxRuntimeExports.jsx(
          HiMiniArrowPath,
          {
            className: "h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue",
            "aria-label": "Running…"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2 sm:gap-3", role: "cell", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: status.tone, children: status.label }) }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: isConfirmingRemove ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "ghost",
              label: "Cancel",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4" }),
              onClick: onRemoveCancel,
              disabled: anyPending
            }
          ),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "danger",
              label: "Confirm",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4" }),
              onClick: handleRemoveConfirm,
              disabled: anyPending
            }
          )
        ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-1.5", children: [
          showInstall && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "primary",
              label: "Protect",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4" }),
              onClick: handleInstall,
              disabled: anyPending
            }
          ),
          showRepair && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "primary",
              label: "Fix PATH",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "h-4 w-4" }),
              onClick: handleRepair,
              disabled: anyPending
            }
          ),
          showTest && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "outline",
              label: "Test",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBeaker, { className: "h-4 w-4" }),
              onClick: handleTest,
              disabled: anyPending
            }
          ),
          showRemove && /* @__PURE__ */ jsxRuntimeExports.jsx(
            IconActionButton,
            {
              variant: "danger",
              label: "Remove",
              icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "h-4 w-4" }),
              onClick: handleRemoveRequest,
              disabled: anyPending
            }
          )
        ] }) })
      ] })
    ] }),
    shim?.activation_state === "restart_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim." }) }),
    shim?.activation_state === "repair_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart." }) }),
    shim?.shim_path !== null && shim?.shim_path !== void 0 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 pb-2", children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-[10px] text-slate-400", children: shim.shim_path }) })
  ] });
}
function LoadingRow({ width }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `h-4 animate-pulse rounded-md bg-slate-100 ${width}`, "aria-hidden": "true" });
}
function LoadingSkeleton() {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "space-y-3 px-4 py-5",
      "aria-label": "Loading package firewall status",
      "aria-busy": "true",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingRow, { width: "w-1/3" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingRow, { width: "w-2/3" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingRow, { width: "w-1/2" })
      ]
    }
  );
}
function ErrorBanner({ message, onRetry }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-3 px-4 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationTriangle,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-brand-attention", children: message })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "outline", onClick: onRetry, children: "Retry" })
  ] });
}
function GlobalActionsBar({ anyPending, pendingOp, onAudit, onSync }) {
  const auditRunning = pendingOp?.op === "audit";
  const syncRunning = pendingOp?.op === "sync";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      ActionButton,
      {
        variant: "outline",
        onClick: onAudit,
        disabled: anyPending,
        "aria-busy": auditRunning,
        children: [
          auditRunning ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-1.5 h-3.5 w-3.5 animate-spin", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "mr-1.5 h-3.5 w-3.5", "aria-hidden": "true" }),
          "Audit"
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      ActionButton,
      {
        variant: "outline",
        onClick: onSync,
        disabled: anyPending,
        "aria-busy": syncRunning,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            HiMiniArrowPath,
            {
              className: `mr-1.5 h-3.5 w-3.5 ${syncRunning ? "animate-spin" : ""}`,
              "aria-hidden": "true"
            }
          ),
          "Sync"
        ]
      }
    )
  ] });
}
function FailureBanner({ failed }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "flex items-start gap-2 rounded-xl border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2.5",
      role: "alert",
      "aria-live": "assertive",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          HiMiniExclamationTriangle,
          {
            className: "mt-0.5 h-4 w-4 shrink-0 text-brand-attention",
            "aria-hidden": "true"
          }
        ),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm font-medium text-brand-dark", children: [
            failed.op,
            " failed",
            failed.manager !== null ? ` for ${failed.manager}` : ""
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-600", children: failed.message })
        ] })
      ]
    }
  );
}
function FirewallControlsView({
  activationAssistError,
  openingShell,
  data,
  pendingOp,
  lastCompleted,
  lastFailed,
  confirmRemoveManager,
  showGlobalActions,
  statusFilter,
  managerFilter,
  onStatusFilterChange,
  onManagerFilterChange,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onAudit,
  onSync,
  onDismissResult,
  onOpenShell,
  onRefreshStatus
}) {
  const anyPending = pendingOp !== null;
  const filteredManagers = reactExports.useMemo(() => {
    const shimsByManager = new Map(data.package_shims.map((s) => [s.manager, s]));
    let managers = data.supported_managers;
    if (managerFilter) {
      const q = managerFilter.toLowerCase();
      managers = managers.filter((m) => m.toLowerCase().includes(q));
    }
    if (statusFilter !== "all") {
      managers = managers.filter((m) => {
        const shim = shimsByManager.get(m);
        const status = resolveShimStatus(shim);
        if (statusFilter === "protected") return status.tone === "green";
        if (statusFilter === "actionable") return status.tone === "attention";
        if (statusFilter === "unprotected") return status.tone !== "green";
        return true;
      });
    }
    return managers;
  }, [data, managerFilter, statusFilter]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 px-4 py-4", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: "Per-manager controls" }),
      showGlobalActions && /* @__PURE__ */ jsxRuntimeExports.jsx(
        GlobalActionsBar,
        {
          anyPending,
          pendingOp,
          onAudit,
          onSync
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActivationSummary,
      {
        activationAssistError,
        openingShell,
        onOpenShell,
        onRefreshStatus,
        protection: data.protection
      }
    ),
    lastFailed !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(FailureBanner, { failed: lastFailed }),
    lastCompleted !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionResultPanel, { completed: lastCompleted, onDismiss: onDismissResult }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniMagnifyingGlass, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(
          "input",
          {
            type: "search",
            placeholder: "Filter by manager…",
            value: managerFilter,
            onChange: onManagerFilterChange,
            "aria-label": "Filter package managers",
            className: "bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
          }
        )
      ] }),
      ["all", "protected", "actionable", "unprotected"].map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        "button",
        {
          type: "button",
          onClick: () => onStatusFilterChange(s),
          "aria-pressed": statusFilter === s,
          className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${statusFilter === s ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
          children: s === "all" ? "All" : s === "protected" ? "Protected" : s === "actionable" ? "Needs action" : "Unprotected"
        },
        s
      ))
    ] }),
    filteredManagers.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No package managers found",
        body: "No package managers match the current filter, or Guard has not detected any on this machine.",
        tone: "teach"
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "table", "aria-label": "Package manager firewall status", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "div",
        {
          className: "hidden sm:flex sm:items-center sm:justify-between border-b border-slate-100 bg-slate-50 px-4 py-2",
          role: "row",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              "span",
              {
                className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400",
                role: "columnheader",
                children: "Manager"
              }
            ),
            /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-3", children: [
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "span",
                {
                  className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400",
                  role: "columnheader",
                  children: "Status"
                }
              ),
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                "span",
                {
                  className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400",
                  role: "columnheader",
                  children: "Actions"
                }
              )
            ] })
          ]
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "rowgroup", children: filteredManagers.map((manager) => {
        const shim = data.package_shims.find((s) => s.manager === manager);
        return /* @__PURE__ */ jsxRuntimeExports.jsx(
          ManagerRow,
          {
            manager,
            shim,
            actions: data.actions,
            anyPending,
            isMine: pendingOp?.manager === manager,
            isConfirmingRemove: confirmRemoveManager === manager,
            onInstall,
            onRepair,
            onTest,
            onRemoveRequest,
            onRemoveConfirm,
            onRemoveCancel
          },
          manager
        );
      }) })
    ] })
  ] });
}
function RefreshButton({ disabled, spinning, onRefresh }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    ActionButton,
    {
      variant: "ghost",
      onClick: onRefresh,
      disabled,
      "aria-label": "Refresh status",
      children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: `h-4 w-4 ${spinning ? "animate-spin" : ""}`,
          "aria-hidden": "true"
        }
      )
    }
  );
}
function PackageFirewallPanel(props) {
  const { approvalGate, onStateChanged } = props;
  const [panelLoad, setPanelLoad] = reactExports.useState({ phase: "loading" });
  const [pendingOp, setPendingOp] = reactExports.useState(null);
  const [lastCompleted, setLastCompleted] = reactExports.useState(null);
  const [lastFailed, setLastFailed] = reactExports.useState(null);
  const [connectError, setConnectError] = reactExports.useState(null);
  const [activationAssistError, setActivationAssistError] = reactExports.useState(null);
  const [startingConnect, setStartingConnect] = reactExports.useState(false);
  const [openingShell, setOpeningShell] = reactExports.useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = reactExports.useState(null);
  const [pendingApprovalOp, setPendingApprovalOp] = reactExports.useState(null);
  const [statusFilter, setStatusFilter] = reactExports.useState("all");
  const [managerFilter, setManagerFilter] = reactExports.useState("");
  const { resolvedApprovalGate, resolveApprovalGate } = useResolvedApprovalGate(approvalGate);
  const load = reactExports.useCallback(async () => {
    setPanelLoad({ phase: "loading" });
    try {
      const data = await fetchPackageFirewallStatus();
      setPanelLoad({ phase: "loaded", data });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to load package firewall status.";
      setPanelLoad({ phase: "error", message });
    }
  }, []);
  reactExports.useEffect(() => {
    void load();
  }, [load]);
  const refreshAfterOp = reactExports.useCallback(async () => {
    try {
      const data = await fetchPackageFirewallStatus();
      setPanelLoad({ phase: "loaded", data });
    } catch (err) {
      const message = err instanceof Error ? err.message : "Failed to refresh package firewall status.";
      setPanelLoad({ phase: "error", message });
    }
  }, []);
  reactExports.useEffect(() => {
    if (panelLoad.phase !== "loaded") {
      return;
    }
    const flow = panelLoad.data.connect_flow;
    if (flow === null || flow.state !== "running") {
      return;
    }
    const handle = window.setTimeout(() => {
      void refreshAfterOp();
    }, flow.poll_after_ms ?? 1500);
    return () => window.clearTimeout(handle);
  }, [panelLoad, refreshAfterOp]);
  const handleAction = reactExports.useCallback(
    async (op, manager, credentials) => {
      setPendingOp({ op, manager });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      try {
        const response = await runPackageFirewallAction(op, manager, credentials);
        setLastCompleted({ op, manager, response });
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        if (credentials === void 0 && manager !== null && err instanceof GuardHarnessActionError && err.payload?.error === "approval_gate_required") {
          await resolveApprovalGate();
          setPendingApprovalOp({ op, manager });
          return;
        }
        const message = err instanceof Error ? err.message : "Action failed.";
        setLastFailed({ op, manager, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, refreshAfterOp, resolveApprovalGate]
  );
  const handleGlobalOp = reactExports.useCallback(
    async (op) => {
      setPendingOp({ op, manager: null });
      setLastFailed(null);
      setConnectError(null);
      setActivationAssistError(null);
      try {
        const response = op === "audit" ? await runPackageAudit() : await runPackageSync();
        setLastCompleted({ op, manager: null, response });
        await refreshAfterOp();
        await onStateChanged?.();
      } catch (err) {
        const message = err instanceof Error ? err.message : "Operation failed.";
        setLastFailed({ op, manager: null, message });
      } finally {
        setPendingOp(null);
      }
    },
    [onStateChanged, refreshAfterOp]
  );
  const handleInstall = reactExports.useCallback(
    (manager) => void handleAction("install", manager),
    [handleAction]
  );
  const handleRepair = reactExports.useCallback(
    (manager) => void handleAction("repair", manager),
    [handleAction]
  );
  const handleTest = reactExports.useCallback(
    (manager) => void handleAction("test", manager),
    [handleAction]
  );
  const handleRemoveRequest = reactExports.useCallback(
    (manager) => setConfirmRemoveManager(manager),
    []
  );
  const handleRemoveConfirm = reactExports.useCallback(
    (manager) => {
      setConfirmRemoveManager(null);
      void handleAction("remove", manager);
    },
    [handleAction]
  );
  const handleRemoveCancel = reactExports.useCallback(() => setConfirmRemoveManager(null), []);
  const handleAudit = reactExports.useCallback(() => void handleGlobalOp("audit"), [handleGlobalOp]);
  const handleSync = reactExports.useCallback(() => void handleGlobalOp("sync"), [handleGlobalOp]);
  const handleDismissResult = reactExports.useCallback(() => setLastCompleted(null), []);
  const handleRetry = reactExports.useCallback(() => void load(), [load]);
  const handleStartConnect = reactExports.useCallback(async () => {
    setStartingConnect(true);
    setConnectError(null);
    setActivationAssistError(null);
    try {
      await startPackageFirewallConnect();
      await refreshAfterOp();
      await onStateChanged?.();
    } catch (error) {
      setConnectError(
        error instanceof Error ? error.message : "Unable to start Guard Cloud connect."
      );
    } finally {
      setStartingConnect(false);
    }
  }, [onStateChanged, refreshAfterOp]);
  const handleOpenShell = reactExports.useCallback(async () => {
    setOpeningShell(true);
    setActivationAssistError(null);
    try {
      await openPackageFirewallShell();
    } catch (error) {
      setActivationAssistError(error instanceof Error ? error.message : "Unable to open a new shell.");
    } finally {
      setOpeningShell(false);
    }
  }, []);
  const handleApprovalCancel = reactExports.useCallback(() => setPendingApprovalOp(null), []);
  const handleApprovalConfirm = reactExports.useCallback(
    (credentials) => {
      const pendingApproval = pendingApprovalOp;
      if (pendingApproval === null) return;
      setPendingApprovalOp(null);
      void handleAction(pendingApproval.op, pendingApproval.manager, credentials);
    },
    [handleAction, pendingApprovalOp]
  );
  const handleStatusFilterChange = reactExports.useCallback((filter) => {
    setStatusFilter(filter);
  }, []);
  const handleManagerFilterChange = reactExports.useCallback((e) => {
    setManagerFilter(e.target.value);
  }, []);
  const anyPending = pendingOp !== null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-4 py-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Package manager firewall" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-500", children: "Install Guard shims, activate PATH routing, and verify protection on this machine." })
      ] }),
      panelLoad.phase === "loaded" && /* @__PURE__ */ jsxRuntimeExports.jsx(RefreshButton, { disabled: anyPending, spinning: anyPending, onRefresh: handleRetry })
    ] }),
    panelLoad.phase === "loading" && /* @__PURE__ */ jsxRuntimeExports.jsx(LoadingSkeleton, {}),
    panelLoad.phase === "error" && /* @__PURE__ */ jsxRuntimeExports.jsx(ErrorBanner, { message: panelLoad.message, onRetry: handleRetry }),
    panelLoad.phase === "loaded" && /* @__PURE__ */ jsxRuntimeExports.jsxs(jsxRuntimeExports.Fragment, { children: [
      !panelLoad.data.entitlement.allowed && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EntitlementNotice,
        {
          connectError,
          connectStarting: startingConnect,
          data: panelLoad.data,
          onStartConnect: handleStartConnect
        }
      ) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        FirewallControlsView,
        {
          data: panelLoad.data,
          pendingOp,
          lastCompleted,
          lastFailed,
          confirmRemoveManager,
          showGlobalActions: panelLoad.data.entitlement.allowed,
          statusFilter,
          managerFilter,
          onStatusFilterChange: handleStatusFilterChange,
          onManagerFilterChange: handleManagerFilterChange,
          onInstall: handleInstall,
          onRepair: handleRepair,
          onTest: handleTest,
          onRemoveRequest: handleRemoveRequest,
          onRemoveConfirm: handleRemoveConfirm,
          onRemoveCancel: handleRemoveCancel,
          onAudit: handleAudit,
          onSync: handleSync,
          onDismissResult: handleDismissResult,
          onOpenShell: handleOpenShell,
          onRefreshStatus: handleRetry,
          openingShell,
          activationAssistError
        }
      )
    ] }),
    pendingApprovalOp !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ApprovalProofModal,
      {
        title: `${actionLabel(pendingApprovalOp.op)} ${pendingApprovalOp.manager}`,
        detail: "Enter local approval proof before Guard changes package-manager protection on this device.",
        confirmLabel: actionLabel(pendingApprovalOp.op),
        approvalGate: resolvedApprovalGate,
        onCancel: handleApprovalCancel,
        onConfirm: handleApprovalConfirm
      }
    )
  ] });
}
function SeverityBadge({ severity }) {
  const tone = severity === "critical" || severity === "high" ? "destructive" : severity === "medium" ? "attention" : "default";
  return /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone, children: severity });
}
function AdvisoryRow({ advisory }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-3 px-4 py-3 border-b border-slate-100 last:border-b-0 hover:bg-slate-50/40 transition-colors", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-0.5 shrink-0", children: advisory.knownExploited ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-4 w-4 text-red-500", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBugAnt, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0 flex-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: advisory.advisoryId }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(SeverityBadge, { severity: advisory.normalizedSeverity }),
        advisory.knownExploited && /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: "destructive", children: "Known exploited" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-sm text-slate-600", children: advisory.title }),
      advisory.summary && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xs text-slate-500 line-clamp-2", children: advisory.summary }),
      advisory.recommendedFixVersion && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-1 text-xs text-brand-green", children: [
        "Fix: ",
        advisory.recommendedFixVersion
      ] })
    ] })
  ] });
}
function SupplyChainBundlePanel() {
  const [bundle, setBundle] = reactExports.useState(null);
  const [loading, setLoading] = reactExports.useState(true);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    setLoading(true);
    fetchSupplyChainBundle().then((data) => {
      if (cancelled) return;
      setBundle(data);
      setError(null);
    }).catch((err) => {
      if (cancelled) return;
      setError(err instanceof Error ? err.message : "Failed to load");
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const severityCounts = reactExports.useMemo(() => {
    if (!bundle) return null;
    const counts = {};
    for (const a of bundle.advisories) {
      counts[a.normalizedSeverity] = (counts[a.normalizedSeverity] ?? 0) + 1;
    }
    return counts;
  }, [bundle]);
  const topAdvisories = reactExports.useMemo(() => {
    if (!bundle) return [];
    const severityOrder = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
      unknown: 4
    };
    return [...bundle.advisories].sort((a, b) => {
      const sevA = severityOrder[a.normalizedSeverity] ?? 99;
      const sevB = severityOrder[b.normalizedSeverity] ?? 99;
      if (sevA !== sevB) return sevA - sevB;
      return b.confidence - a.confidence;
    }).slice(0, 10);
  }, [bundle]);
  const handleOpenCloud = reactExports.useCallback(() => {
    window.open("https://hol.org/guard", "_blank", "noopener,noreferrer");
  }, []);
  if (loading) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain intel" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-8", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-32 mb-3" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-48 mb-2" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-4 w-40" })
      ] })
    ] });
  }
  if (error) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain intel" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "Could not load intel",
          body: error,
          tone: "error"
        }
      ) })
    ] });
  }
  if (!bundle) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain intel" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-6", children: /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No intel available",
          body: "Guard has not synced a supply chain bundle yet. Connect to Guard Cloud for live advisory data.",
          tone: "teach"
        }
      ) })
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center justify-between", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Supply chain bundle" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "button",
            {
              type: "button",
              onClick: handleOpenCloud,
              className: "inline-flex items-center gap-1 text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1.5 py-0.5",
              children: [
                "View in cloud",
                /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowTopRightOnSquare, { className: "h-3 w-3", "aria-hidden": "true" })
              ]
            }
          )
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Signed advisory feed and package risk data." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4 space-y-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Version:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "blue", children: bundle.bundleVersion })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Advisories:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: bundle.advisories.length })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Packages:" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: bundle.packages.length })
          ] })
        ] }),
        bundle.expiresAt && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-400", children: [
          "Expires ",
          formatRelativeTime(bundle.expiresAt)
        ] })
      ] })
    ] }),
    severityCounts && Object.keys(severityCounts).length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Severity breakdown" }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "px-4 py-4", children: /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid grid-cols-2 sm:grid-cols-4 gap-3", children: ["critical", "high", "medium", "low"].map((sev) => {
        const count = severityCounts[sev] ?? 0;
        const tone = sev === "critical" || sev === "high" ? "destructive" : sev === "medium" ? "attention" : "default";
        return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-lg border border-slate-100 bg-slate-50/60 px-3 py-2.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.15em] text-slate-400", children: sev }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-xl font-bold tabular-nums", children: /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone, children: count }) })
        ] }, sev);
      }) }) })
    ] }),
    topAdvisories.length > 0 && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Top advisories" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Highest severity and confidence advisories in this bundle." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: topAdvisories.map((advisory) => /* @__PURE__ */ jsxRuntimeExports.jsx(AdvisoryRow, { advisory }, advisory.advisoryId)) }),
      bundle.advisories.length > 10 && /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-t border-slate-100 px-4 py-2.5", children: /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: handleOpenCloud,
          className: "text-xs font-medium text-brand-blue hover:text-brand-blue-dark focus:outline-none focus:ring-2 focus:ring-brand-blue/30 rounded px-1.5 py-0.5",
          children: [
            "View all ",
            bundle.advisories.length,
            " advisories in Guard Cloud"
          ]
        }
      ) })
    ] })
  ] });
}
function resolveManagerCoverageStatus(protection, manager) {
  if (!protection) return "unprotected";
  if (protection.protected_managers.includes(manager)) return "protected";
  if (protection.installed_managers.includes(manager)) {
    if (protection.path_status === "restart_required") return "restart_required";
    return "path_repair";
  }
  return "unprotected";
}
function buildSupplyChainStats(snapshot) {
  const managedInstalls = snapshot.managed_installs ?? [];
  const protection = snapshot.supply_chain?.package_manager_protection;
  const supportedManagers = protection?.supported_managers ?? [];
  const protectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "protected"
  ).length;
  const stagedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "restart_required"
  ).length;
  const repairRequiredManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "path_repair"
  ).length;
  const unprotectedManagers = supportedManagers.filter(
    (manager) => resolveManagerCoverageStatus(protection, manager) === "unprotected"
  ).length;
  return {
    totalApps: managedInstalls.length,
    activeApps: managedInstalls.filter((i) => i.active).length,
    preventedInstalls: managedInstalls.filter((i) => !i.active).length,
    protectedManagers,
    stagedManagers,
    repairRequiredManagers,
    unprotectedManagers
  };
}
function StatCard({ label, value, tone = "slate" }) {
  const toneClass = tone === "green" ? "text-brand-green" : tone === "attention" ? "text-brand-attention" : tone === "blue" ? "text-brand-blue" : "text-brand-dark";
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-xl border border-slate-100 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.18em] text-slate-400", children: label }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: `mt-1.5 text-2xl font-bold tabular-nums ${toneClass}`, children: value })
  ] });
}
function AppFirewallRow({ install, protection }) {
  const [open, setOpen] = reactExports.useState(false);
  const toggle = reactExports.useCallback(() => setOpen((p) => !p), []);
  const protectedManagers = protection?.protected_managers ?? [];
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 last:border-b-0", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "button",
      {
        type: "button",
        onClick: toggle,
        "aria-expanded": open,
        className: "flex w-full items-center justify-between gap-3 px-4 py-3 text-left hover:bg-slate-50/60 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-brand-blue/30",
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2.5", children: [
            install.active ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-4 w-4 shrink-0 text-brand-green", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniXCircle, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-medium text-brand-dark", children: harnessDisplayName(install.harness) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2 shrink-0", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(Badge, { tone: install.active ? "success" : "attention", children: install.active ? "Active" : "Inactive" }),
            open ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronUp, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniChevronDown, { className: "h-4 w-4 text-slate-400", "aria-hidden": "true" })
          ] })
        ]
      }
    ),
    open && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 pb-3 pt-1", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs font-semibold uppercase tracking-[0.15em] text-slate-400 mb-2", children: "Shim coverage" }),
      protectedManagers.length > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "flex flex-wrap gap-1.5", children: protectedManagers.map((mgr) => /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "span",
        {
          className: "inline-flex items-center gap-1 rounded-full border border-brand-green/25 bg-brand-green/[0.06] px-2.5 py-0.5 text-xs font-medium text-brand-green-text",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3 w-3", "aria-hidden": "true" }),
            mgr
          ]
        },
        mgr
      )) }) : /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "No package manager shims active for this app." }),
      install.updated_at && /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2 text-xs text-slate-400", children: [
        "Updated ",
        formatRelativeTime(install.updated_at)
      ] })
    ] })
  ] });
}
function SupplyChainWorkspace({
  snapshot,
  approvalGate,
  onGoHome,
  onRuntimeRefresh
}) {
  const stats = reactExports.useMemo(() => buildSupplyChainStats(snapshot), [snapshot]);
  const protection = snapshot.supply_chain?.package_manager_protection;
  const managedInstalls = reactExports.useMemo(
    () => snapshot.managed_installs ?? [],
    [snapshot.managed_installs]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-start justify-between gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm text-slate-500", children: "Package manager firewall status, prevented installs, and feed health." }) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onGoHome, children: "Back to Home" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-4 sm:grid-cols-2 lg:grid-cols-4", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Active apps", value: stats.activeApps, tone: "green" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Prevented installs", value: stats.preventedInstalls, tone: stats.preventedInstalls > 0 ? "attention" : "slate" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        StatCard,
        {
          label: stats.stagedManagers > 0 ? "Ready after restart" : stats.repairRequiredManagers > 0 ? "Needs PATH repair" : "Protected managers",
          value: stats.stagedManagers > 0 ? stats.stagedManagers : stats.repairRequiredManagers > 0 ? stats.repairRequiredManagers : stats.protectedManagers,
          tone: stats.stagedManagers > 0 ? "blue" : stats.repairRequiredManagers > 0 ? "attention" : "green"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatCard, { label: "Unprotected managers", value: stats.unprotectedManagers, tone: stats.unprotectedManagers > 0 ? "attention" : "slate" })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx(SupplyChainBundlePanel, {}),
    /* @__PURE__ */ jsxRuntimeExports.jsx(PackageFirewallPanel, { approvalGate, onStateChanged: onRuntimeRefresh }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "App shim coverage" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Package manager hooks active per connected app." })
      ] }),
      managedInstalls.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No apps connected",
          body: "Connect an AI app to see per-app package manager coverage here.",
          tone: "teach"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { children: managedInstalls.map((install) => /* @__PURE__ */ jsxRuntimeExports.jsx(
        AppFirewallRow,
        {
          install,
          protection
        },
        `${install.harness}-${install.workspace ?? "global"}`
      )) })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Feed health" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Intel feed source mode and freshness." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(FeedHealthPanel, { snapshot })
    ] })
  ] });
}
function FeedHealthPanel({ snapshot }) {
  const cloudState = snapshot.cloud_state;
  const isSample = cloudState === "local_only";
  const isStale = snapshot.latest_receipts.length > 0 && Date.now() - new Date(snapshot.latest_receipts[0].timestamp).getTime() > 7 * 24 * 60 * 60 * 1e3;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "px-4 py-4 space-y-3", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Source mode:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isSample ? "attention" : "green", children: isSample ? "Local-only (sample intel)" : "Live cloud feed" })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs font-semibold text-slate-500 uppercase tracking-[0.15em]", children: "Freshness:" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: isStale ? "attention" : "green", children: isStale ? "Stale (7+ days)" : "Fresh" })
      ] })
    ] }),
    isSample && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniExclamationTriangle,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-800", children: "Running on local-only (sample) intel. Connect this machine to Guard Cloud for live feed data and cross-device protection." })
    ] }),
    isStale && !isSample && /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 rounded-xl border border-amber-200 bg-amber-50/60 px-3 py-2.5", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        HiMiniArrowPath,
        {
          className: "mt-0.5 h-4 w-4 shrink-0 text-amber-600",
          "aria-hidden": "true"
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-amber-800", children: "Feed data is stale. Guard has not processed new actions recently. Check that the daemon is running." })
    ] })
  ] });
}
export {
  SupplyChainWorkspace,
  buildSupplyChainStats
};
