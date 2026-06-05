import { j as jsxRuntimeExports, T as Tag, A as ActionButton, ab as HiMiniArrowPath, H as HiMiniShieldCheck, ai as HiMiniArrowTopRightOnSquare, g as HiMiniCheckCircle, b as HiMiniExclamationTriangle, h as HiMiniXCircle, r as reactExports, v as HiMiniWrenchScrewdriver, aj as HiMiniBeaker, ac as HiMiniTrash, ak as fetchPackageFirewallStatus, al as runPackageFirewallAction, a9 as GuardHarnessActionError, am as runPackageAudit, an as runPackageSync, ao as startPackageFirewallConnect, S as SectionLabel, E as EmptyState, ap as HiMiniBugAnt, a as HiMiniInformationCircle, i as harnessDisplayName, B as Badge, d as HiMiniChevronUp, e as HiMiniChevronDown, f as formatRelativeTime } from "../guard-dashboard.js";
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
function ConnectFlowCard({
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
  const statusTone = mode === "repair" ? "attention" : "blue";
  const statusLabel = mode === "repair" ? "Repair required" : "Connection required";
  const showManualLink = connectFlow.authorize_url !== null || running || failed;
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
  const connectMode = data.entitlement.reason === "guard_cloud_reconnect_required" ? "repair" : "connect";
  const localRecoveryHint = data.package_shims.some((shim) => shim.installed) ? connectRequired ? "Existing shims on this machine can still be fixed or removed locally. Connect is only needed for new installs and cloud-gated verification." : null : null;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-4 px-4 py-4", children: [
    connectRequired && data.connect_flow !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      ConnectFlowCard,
      {
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
function ActivationSummary({ protection }) {
  if (protection === null) {
    return null;
  }
  const copy = resolvePackageManagerProtectionCopy(protection);
  const Icon = protection.path_status === "in_path" ? HiMiniCheckCircle : protection.path_status === "restart_required" ? HiMiniArrowPath : HiMiniExclamationTriangle;
  const toneClass = protection.path_status === "in_path" ? "border-brand-green/20 bg-brand-green/[0.04]" : protection.path_status === "restart_required" ? "border-brand-blue/20 bg-brand-blue/[0.04]" : "border-brand-attention/20 bg-brand-attention/[0.04]";
  const iconClass = protection.path_status === "in_path" ? "text-brand-green" : protection.path_status === "restart_required" ? "text-brand-blue" : "text-brand-attention";
  return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: `rounded-xl border px-4 py-3 ${toneClass}`, children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2.5", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(Icon, { className: `mt-0.5 h-4 w-4 shrink-0 ${iconClass}`, "aria-hidden": "true" }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-sm font-medium text-brand-dark", children: activationHeadline(protection) }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs text-slate-600", children: copy.pathDetail })
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
function ShimStatusDot({ active }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    "span",
    {
      className: `inline-block h-2 w-2 shrink-0 rounded-full ${active ? "bg-brand-green" : "bg-slate-300"}`,
      "aria-hidden": "true"
    }
  );
}
function RemoveConfirmRow({ manager, onConfirm, onCancel, anyPending }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "div",
    {
      className: "flex flex-wrap items-center gap-2 rounded-lg border border-brand-attention/30 bg-brand-attention/[0.04] px-3 py-2",
      role: "alert",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs font-medium text-brand-dark", children: [
          "Remove shim for ",
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-mono", children: manager }),
          "?"
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "ml-auto flex items-center gap-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { variant: "ghost", onClick: onCancel, disabled: anyPending, children: "Cancel" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            ActionButton,
            {
              variant: "danger",
              onClick: onConfirm,
              disabled: anyPending,
              "aria-busy": anyPending,
              children: anyPending ? "Removing…" : "Confirm Remove"
            }
          )
        ] })
      ]
    }
  );
}
function ActionBtn({ label, icon, variant, onClick, disabled }) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { variant, onClick, disabled, children: [
    icon,
    label
  ] });
}
function actionIsAvailable(state) {
  return state === "available";
}
function ActionButtonRow({
  shim,
  actions,
  anyPending,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest
}) {
  const installState = actions.install ?? "disabled";
  const repairState = actions.repair ?? "disabled";
  const testState = actions.test ?? "disabled";
  const removeState = actions.remove ?? "disabled";
  const installAvailable = actionIsAvailable(installState);
  const repairAvailable = actionIsAvailable(repairState);
  const testAvailable = actionIsAvailable(testState);
  const removeAvailable = actionIsAvailable(removeState);
  const showInstall = !shim.installed && installAvailable;
  const showRepair = shim.installed && shim.activation_state === "repair_required" && repairAvailable;
  const showTest = shim.installed && shim.activation_state === "protected" && testAvailable;
  const showRemove = shim.installed && removeAvailable;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-1.5", children: [
    showInstall && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActionBtn,
      {
        label: "Protect",
        icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "mr-1 h-3.5 w-3.5", "aria-hidden": "true" }),
        variant: "primary",
        onClick: onInstall,
        disabled: anyPending
      }
    ),
    showRepair && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActionBtn,
      {
        label: "Fix PATH",
        icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniWrenchScrewdriver, { className: "mr-1 h-3.5 w-3.5", "aria-hidden": "true" }),
        variant: "primary",
        onClick: onRepair,
        disabled: anyPending
      }
    ),
    showTest && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActionBtn,
      {
        label: "Test",
        icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniBeaker, { className: "mr-1 h-3.5 w-3.5", "aria-hidden": "true" }),
        variant: "outline",
        onClick: onTest,
        disabled: anyPending
      }
    ),
    showRemove && /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActionBtn,
      {
        label: "Remove",
        icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniTrash, { className: "mr-1 h-3.5 w-3.5", "aria-hidden": "true" }),
        variant: "danger",
        onClick: onRemoveRequest,
        disabled: anyPending
      }
    )
  ] });
}
function ManagerActionCard({
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
  const handleInstall = reactExports.useCallback(() => onInstall(shim.manager), [onInstall, shim.manager]);
  const handleRepair = reactExports.useCallback(() => onRepair(shim.manager), [onRepair, shim.manager]);
  const handleTest = reactExports.useCallback(() => onTest(shim.manager), [onTest, shim.manager]);
  const handleRemoveRequest = reactExports.useCallback(
    () => onRemoveRequest(shim.manager),
    [onRemoveRequest, shim.manager]
  );
  const handleRemoveConfirm = reactExports.useCallback(
    () => onRemoveConfirm(shim.manager),
    [onRemoveConfirm, shim.manager]
  );
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "space-y-3 rounded-xl border border-slate-100 bg-white p-4 shadow-sm", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center justify-between gap-2", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(ShimStatusDot, { active: shim.active }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate font-mono text-sm font-semibold text-brand-dark", children: shim.manager }),
        isMine && /* @__PURE__ */ jsxRuntimeExports.jsx(
          HiMiniArrowPath,
          {
            className: "h-3.5 w-3.5 shrink-0 animate-spin text-brand-blue",
            "aria-label": "Running…"
          }
        )
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "shrink-0", children: shim.activation_state === "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "green", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "mr-0.5 inline h-3 w-3", "aria-hidden": "true" }),
        "Protected"
      ] }) : shim.activation_state === "restart_required" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "blue", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "mr-0.5 inline h-3 w-3", "aria-hidden": "true" }),
        "Restart required"
      ] }) : shim.activation_state === "repair_required" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "attention", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "mr-0.5 inline h-3 w-3", "aria-hidden": "true" }),
        "Needs PATH repair"
      ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(Tag, { tone: "slate", children: "Uninstalled" }) })
    ] }),
    isConfirmingRemove ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      RemoveConfirmRow,
      {
        manager: shim.manager,
        onConfirm: handleRemoveConfirm,
        onCancel: onRemoveCancel,
        anyPending
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx(
      ActionButtonRow,
      {
        shim,
        actions,
        anyPending,
        onInstall: handleInstall,
        onRepair: handleRepair,
        onTest: handleTest,
        onRemoveRequest: handleRemoveRequest
      }
    ),
    shim.activation_state === "restart_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard updated your shell profile. Open a new shell or restart AI apps to activate this shim." }),
    shim.activation_state === "repair_required" && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "text-xs text-slate-500", children: "Guard can add the shim directory to your shell profile automatically, then this manager will be ready after a restart." }),
    shim.shim_path !== null && /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "break-all font-mono text-[10px] text-slate-400", children: shim.shim_path })
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
  data,
  pendingOp,
  lastCompleted,
  lastFailed,
  confirmRemoveManager,
  showGlobalActions,
  onInstall,
  onRepair,
  onTest,
  onRemoveRequest,
  onRemoveConfirm,
  onRemoveCancel,
  onAudit,
  onSync,
  onDismissResult
}) {
  const anyPending = pendingOp !== null;
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
    /* @__PURE__ */ jsxRuntimeExports.jsx(ActivationSummary, { protection: data.protection }),
    lastFailed !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(FailureBanner, { failed: lastFailed }),
    lastCompleted !== null && /* @__PURE__ */ jsxRuntimeExports.jsx(ActionResultPanel, { completed: lastCompleted, onDismiss: onDismissResult }),
    data.package_shims.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      EmptyState,
      {
        title: "No package managers detected",
        body: "Guard has not detected any package managers on this machine.",
        tone: "teach"
      }
    ) : /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "grid gap-3 sm:grid-cols-2", children: data.package_shims.map((shim) => /* @__PURE__ */ jsxRuntimeExports.jsx(
      ManagerActionCard,
      {
        shim,
        actions: data.actions,
        anyPending,
        isMine: pendingOp?.manager === shim.manager,
        isConfirmingRemove: confirmRemoveManager === shim.manager,
        onInstall,
        onRepair,
        onTest,
        onRemoveRequest,
        onRemoveConfirm,
        onRemoveCancel
      },
      shim.manager
    )) })
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
  const [startingConnect, setStartingConnect] = reactExports.useState(false);
  const [confirmRemoveManager, setConfirmRemoveManager] = reactExports.useState(null);
  const [pendingApprovalOp, setPendingApprovalOp] = reactExports.useState(null);
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
          onInstall: handleInstall,
          onRepair: handleRepair,
          onTest: handleTest,
          onRemoveRequest: handleRemoveRequest,
          onRemoveConfirm: handleRemoveConfirm,
          onRemoveCancel: handleRemoveCancel,
          onAudit: handleAudit,
          onSync: handleSync,
          onDismissResult: handleDismissResult
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
function actionLabel(op) {
  return op.charAt(0).toUpperCase() + op.slice(1);
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
  const [filter, setFilter] = reactExports.useState({
    statusFilter: "all",
    managerFilter: ""
  });
  const handleManagerFilterChange = reactExports.useCallback((e) => {
    setFilter((f) => ({ ...f, managerFilter: e.target.value }));
  }, []);
  const handleStatusFilterChange = reactExports.useCallback((status) => {
    setFilter((f) => ({ ...f, statusFilter: status }));
  }, []);
  const stats = reactExports.useMemo(() => buildSupplyChainStats(snapshot), [snapshot]);
  const protection = snapshot.supply_chain?.package_manager_protection;
  const allManagers = reactExports.useMemo(() => {
    if (!protection) return [];
    const all = /* @__PURE__ */ new Set([...protection.protected_managers, ...protection.unprotected_managers]);
    return Array.from(all).sort();
  }, [protection]);
  const filteredManagers = reactExports.useMemo(() => {
    return allManagers.filter((mgr) => {
      const matchesText = filter.managerFilter === "" || mgr.toLowerCase().includes(filter.managerFilter.toLowerCase());
      const isProtected = resolveManagerCoverageStatus(protection, mgr) === "protected";
      const matchesStatus = filter.statusFilter === "all" || filter.statusFilter === "protected" && isProtected || filter.statusFilter === "unprotected" && !isProtected;
      return matchesText && matchesStatus;
    });
  }, [allManagers, filter, protection]);
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
    /* @__PURE__ */ jsxRuntimeExports.jsx(PackageFirewallPanel, { approvalGate, onStateChanged: onRuntimeRefresh }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "rounded-2xl border border-slate-100 bg-white shadow-sm", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "border-b border-slate-100 px-4 py-3", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Coverage by manager" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-500", children: "Live protection state and next activation step for each supported package manager." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "border-b border-slate-100 px-4 py-3", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-center gap-2", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-center gap-1.5 rounded-lg border border-slate-200 bg-slate-50 px-3 py-1.5", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniInformationCircle, { className: "h-3.5 w-3.5 text-slate-400", "aria-hidden": "true" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(
            "input",
            {
              type: "search",
              placeholder: "Filter by manager...",
              value: filter.managerFilter,
              onChange: handleManagerFilterChange,
              "aria-label": "Filter package managers",
              className: "bg-transparent text-sm text-brand-dark placeholder:text-slate-400 focus:outline-none w-40"
            }
          )
        ] }),
        ["all", "protected", "unprotected"].map((s) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          "button",
          {
            type: "button",
            onClick: () => handleStatusFilterChange(s),
            "aria-pressed": filter.statusFilter === s,
            className: `rounded-full px-3 py-1 text-xs font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-brand-blue/30 ${filter.statusFilter === s ? "bg-brand-blue text-white" : "border border-slate-200 bg-white text-slate-600 hover:bg-slate-50"}`,
            children: s.charAt(0).toUpperCase() + s.slice(1)
          },
          s
        ))
      ] }) }),
      filteredManagers.length === 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx(
        EmptyState,
        {
          title: "No package managers found",
          body: "No package managers match the current filter, or Guard has not detected any on this machine.",
          tone: "teach"
        }
      ) : /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { role: "table", "aria-label": "Package manager firewall status", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid grid-cols-[1fr_auto] gap-2 border-b border-slate-100 bg-slate-50 px-4 py-2", role: "row", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Manager" }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400", role: "columnheader", children: "Status" })
        ] }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { role: "rowgroup", children: filteredManagers.map((mgr) => {
          const status = resolveManagerCoverageStatus(protection, mgr);
          return /* @__PURE__ */ jsxRuntimeExports.jsxs(
            "div",
            {
              role: "row",
              className: "grid grid-cols-[1fr_auto] gap-2 border-b border-slate-100 px-4 py-2.5 last:border-b-0",
              children: [
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-sm font-mono text-brand-dark", role: "cell", children: mgr }),
                /* @__PURE__ */ jsxRuntimeExports.jsx("span", { role: "cell", children: status === "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "green", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "h-3.5 w-3.5 mr-1 inline", "aria-hidden": "true" }),
                  "Protected"
                ] }) : status === "restart_required" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "blue", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "h-3.5 w-3.5 mr-1 inline", "aria-hidden": "true" }),
                  "Restart required"
                ] }) : status === "path_repair" ? /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "attention", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-3.5 w-3.5 mr-1 inline", "aria-hidden": "true" }),
                  "Needs PATH repair"
                ] }) : /* @__PURE__ */ jsxRuntimeExports.jsxs(Tag, { tone: "attention", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "h-3.5 w-3.5 mr-1 inline", "aria-hidden": "true" }),
                  "Unprotected"
                ] }) })
              ]
            },
            mgr
          );
        }) })
      ] })
    ] }),
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
