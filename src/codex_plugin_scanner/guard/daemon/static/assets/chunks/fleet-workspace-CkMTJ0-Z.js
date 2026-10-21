import { a8 as isUnsupportedPlatformCheck, h as harnessDisplayName, j as jsxRuntimeExports, a9 as RECHECK_UNAVAILABLE_SIGNATURE, aa as protectionReasonText, r as reactExports, A as ActionButton, ab as HiMiniExclamationCircle, ac as hasRepairableProtectionGap, ad as remainingProtectionRepairParts, ae as protectionGapSignature, af as repairOutcomeIsStalled, ag as ProtectionRepairFlowError, ah as nextProtectionRepairOutcome, ai as waitForAuthorizeUrl, aj as startOrRecoverCloudConnect, ak as safeCloudConnectUrl, al as openPackageFirewallAuthorizeFallback, am as waitForCloudConnection, an as activeFailedHarnesses, ao as resetRepairOutcomeTracker, ap as HiMiniWrenchScrewdriver, s as HiMiniCheckCircle, c as HiMiniChevronDown, aq as fetchSettings, ar as harnessPostureRows, as as selectHarnessPosture, at as harnessPosturePatch, I as updateSettings, au as harnessRowTone, S as SectionLabel, av as harnessPostureOptions, aw as HiMiniEye, R as HiMiniShieldCheck, ax as harnessRowStatus, ay as PROTECTION_POSTURE_COPY, az as globalPosture, u as isConnectableAppHarness, L as protectionHealthFor, K as useProtectionPresentationState, aA as GuardHero, aB as ProofStrip, N as EmptyState, H as HiMiniChevronRight, aC as HiMiniXCircle, aD as HiMiniClipboardDocumentCheck, aE as HiMiniClipboard } from "../guard-dashboard.js";
import { a as SUPPORTED_APPS_BRIEF, d as defaultConnectHarness, A as APP_STATUS_LABELS } from "./app-catalog-BU3dzTBu.js";
import { u as useHarnessDetection, d as detectedHarnesses, v as visibleHarnessesFor, r as resolveDetectedAppStatus, a as versionCompatibilityFor, H as HarnessVersionLabel } from "./harness-version-label-0p6P70WE.js";
import { C as ConnectGuardCloudButton } from "./connect-guard-cloud-button-COC8NKLs.js";
import { G as GuardRepairControl, H as HarnessPostureChoiceLabel, S as SettingsSaveProofModal } from "./settings-save-proof-modal-DSJONzDi.js";
const SUPPORTED_APPS_COPY = SUPPORTED_APPS_BRIEF;
function resolveFleetHeroCopy(cloudState, activeInstallCount, protectionState, urls) {
  const hasApps = activeInstallCount > 0;
  if (hasApps && protectionState === "checking") {
    return {
      status: "checking",
      headline: "Checking app protection",
      subheadline: "Guard is confirming local protection. This takes a moment.",
      primaryCtaLabel: "Open Protect",
      primaryCtaHref: urls.fleet_url,
      primaryCtaStartsCloudConnect: false,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
      secondaryCtaStartsCloudConnect: false
    };
  }
  if (hasApps && protectionState !== "protected") {
    return {
      status: protectionState,
      headline: protectionState === "partial" ? "Apps are partially protected" : "App protection is degraded",
      subheadline: protectionState === "partial" ? "Core protection passes. Finish the remaining proofs below to reach full protection." : "Some protection checks failed or remain unproven. Use the steps below to restore full protection.",
      primaryCtaLabel: "Restore full protection",
      primaryCtaHref: "#protection-recovery",
      primaryCtaStartsCloudConnect: false,
      // The hero CTAs are hidden while protection is degraded; the recovery
      // panel below owns the connect action for that state.
      secondaryCtaLabel: cloudState === "local_only" ? "Connect this machine" : "Open Cloud Devices",
      secondaryCtaHref: cloudState === "local_only" ? urls.connect_url : urls.fleet_url,
      secondaryCtaStartsCloudConnect: false
    };
  }
  if (cloudState === "local_only") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Your apps are covered" : "Connect an app to start",
      subheadline: hasApps ? "Guard is protecting your local AI apps." : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Connect this machine",
      primaryCtaHref: urls.connect_url,
      primaryCtaStartsCloudConnect: true,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
      secondaryCtaStartsCloudConnect: false
    };
  }
  if (cloudState === "paired_waiting") {
    return {
      status: hasApps ? "clear" : "setup_gap",
      headline: hasApps ? "Apps covered, first proof pending" : "Connect an app to start",
      subheadline: hasApps ? "Guard is running. First cloud proof is on its way." : SUPPORTED_APPS_COPY,
      primaryCtaLabel: "Open Cloud Devices",
      primaryCtaHref: urls.fleet_url,
      primaryCtaStartsCloudConnect: false,
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url,
      secondaryCtaStartsCloudConnect: false
    };
  }
  return {
    status: hasApps ? "clear" : "setup_gap",
    headline: hasApps ? "Your apps are covered" : "Connect an app to start",
    subheadline: hasApps ? "Confirm that Guard is running and protecting your local AI apps." : SUPPORTED_APPS_COPY,
    primaryCtaLabel: "Open Cloud Devices",
    primaryCtaHref: urls.fleet_url,
    primaryCtaStartsCloudConnect: false,
    secondaryCtaLabel: "Open Home",
    secondaryCtaHref: urls.dashboard_url,
    secondaryCtaStartsCloudConnect: false
  };
}
function recoverySummary(failCount, unknownCount, needsConnectedApp, failedLabels = [], unsupportedCount = 0) {
  const unsupportedNote = unsupportedCount > 0 ? " Containment remains unavailable on this platform, so full protection cannot be reached here." : "";
  const protectionScope = unsupportedCount > 0 ? "supported" : "local";
  if (needsConnectedApp) {
    return `Connect an AI app to start local protection. Repair cannot finish until at least one app is connected.${unsupportedNote}`;
  }
  if (failCount === 0) {
    return `Complete the remaining ${protectionScope} proof here. Guard repairs and rechecks every ${unsupportedCount > 0 ? "repairable" : "local"} protection layer in one pass.${unsupportedNote}`;
  }
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  const namedFail = failedLabels[0]?.trim() ?? "";
  if (failCount === 1 && namedFail) {
    return `Repair ${namedFail} here${remainingProofs}. Guard repairs and rechecks every ${protectionScope} protection layer in one pass.${unsupportedNote}`;
  }
  const failedNoun = failCount === 1 ? "check" : "checks";
  return `Repair the ${failCount} failed ${failedNoun} here${remainingProofs}. Guard repairs and rechecks every ${protectionScope} protection layer in one pass.${unsupportedNote}`;
}
function repairButtonLabel(repairState, needsConnectedApp, hasUnsupportedGaps = false) {
  if (repairState?.status === "working") return "Repairing…";
  if (needsConnectedApp) return "Connect an app";
  if (repairState?.status === "error") return "Retry repair";
  return hasUnsupportedGaps ? "Repair supported protection" : "Repair protection";
}
const STALLED_REPAIR_SUMMARY = "Repair stopped after two attempts ended the same way.";
const STALLED_RECHECK_SUMMARY = "Repair stopped after two attempts could not recheck protection.";
const RUNTIME_STOP_COMMAND = "hol-guard daemon stop";
const RUNTIME_START_COMMAND = "hol-guard bootstrap";
const INLINE_COMMAND_CLASS = "rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px]";
const PROTECTION_CHECK_ACTIONS = {
  harness_hooks: {
    label: "App hooks",
    detail: "One or more app hooks need setup or repair."
  },
  daemon: {
    label: "Local runtime",
    detail: "The local Guard runtime needs attention before protection can finish."
  },
  policy_engine: {
    label: "Local policy engine",
    detail: "Guard could not confirm the local policy engine is ready."
  },
  rule_packs: {
    label: "Local rule packs",
    detail: "Guard cannot confirm the active local rule-pack proof yet."
  },
  decision_plane_compatibility: {
    label: "Decision plane",
    detail: "Guard reruns the decision-plane compatibility probe during repair. Retry here if it remains unproven."
  },
  containment_compatibility: {
    label: "Containment",
    detail: "Guard reruns the containment compatibility probe during repair. Retry here if it remains unproven."
  },
  sandbox: {
    label: "Sandbox",
    detail: "Guard reruns the sandbox enforcement probe during repair. Retry here if it remains unproven."
  },
  decision_stream: {
    label: "Command evidence",
    detail: "Guard attempts evidence-store recovery during repair. Run a protected command only if fresh proof is still needed."
  },
  tamper_checks: {
    label: "Local integrity checks",
    detail: "Managed Guard files or hooks did not pass integrity checks."
  }
};
function actionForCheck(check, repairHarness) {
  if (isUnsupportedPlatformCheck(check)) {
    return {
      label: "Unsupported on this platform",
      detail: "Containment controls are unavailable on this platform. Guard remains fail-closed; no repair is available."
    };
  }
  if (check.check_id === "harness_hooks" && repairHarness) {
    return {
      label: "App hooks",
      detail: `${harnessDisplayName(repairHarness)} hooks need setup or repair.`
    };
  }
  const action = PROTECTION_CHECK_ACTIONS[check.check_id];
  return action ? action : {
    label: check.check_id.replace(/_/g, " "),
    detail: "Guard could not confirm this protection proof."
  };
}
function ProtectionGapReason({ check }) {
  const reasonText = protectionReasonText(check.reason_code);
  if (reasonText === null) {
    return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "mt-0.5 block font-mono text-[10px] text-slate-400", children: [
      "Reason code: ",
      check.reason_code
    ] });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block text-slate-500", children: reasonText });
}
function ProtectionGapItem({
  action,
  check
}) {
  const unsupported = isUnsupportedPlatformCheck(check);
  let statusLabel = "Unproven";
  if (unsupported) {
    statusLabel = "Unsupported";
  } else if (check.status === "fail") {
    statusLabel = "Failed";
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx("li", { className: "flex items-start gap-2 border-t border-brand-attention/10 py-3 first:border-t-0", children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex items-start gap-2 text-xs text-slate-600", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      HiMiniExclamationCircle,
      {
        className: `mt-0.5 h-3.5 w-3.5 shrink-0 ${check.status === "fail" ? "text-brand-attention" : "text-slate-400"}`,
        "aria-hidden": "true"
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("strong", { className: "font-semibold text-brand-dark", children: action.label }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1 text-[10px] font-medium uppercase tracking-wide text-slate-400", children: statusLabel }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block", children: action.detail }),
      /* @__PURE__ */ jsxRuntimeExports.jsx(ProtectionGapReason, { check })
    ] })
  ] }) });
}
function StalledRepairPanel({
  tracker,
  repairableGaps,
  repairHarness
}) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 text-sm text-slate-600", "aria-live": "polite", role: "status", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: tracker?.signature === RECHECK_UNAVAILABLE_SIGNATURE ? STALLED_RECHECK_SUMMARY : STALLED_REPAIR_SUMMARY }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-1 list-disc space-y-0.5 pl-4", children: repairableGaps.map((check) => /* @__PURE__ */ jsxRuntimeExports.jsxs("li", { children: [
      actionForCheck(check, repairHarness).label,
      " — ",
      protectionReasonText(check.reason_code) ?? /* @__PURE__ */ jsxRuntimeExports.jsxs("code", { className: "font-mono text-[11px]", children: [
        "Reason code: ",
        check.reason_code
      ] })
    ] }, check.check_id)) }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "mt-2", children: [
      "Quit and reopen HOL Guard to restart the local runtime. Without the desktop app, run",
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: INLINE_COMMAND_CLASS, children: RUNTIME_STOP_COMMAND }),
      ", then",
      " ",
      /* @__PURE__ */ jsxRuntimeExports.jsx("code", { className: INLINE_COMMAND_CLASS, children: RUNTIME_START_COMMAND }),
      "."
    ] })
  ] });
}
function TargetedRepairButton({
  harness,
  onRepair
}) {
  const handleRepair = reactExports.useCallback(() => onRepair(harness), [harness, onRepair]);
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(ActionButton, { onClick: handleRepair, variant: "outline", children: [
    "Open ",
    harnessDisplayName(harness),
    " repair"
  ] });
}
function cloudPolicyRecoveryHint(input) {
  const cloudFailed = input.cloudSyncState === "failed" || Boolean(input.cloudPolicySyncError);
  if (input.cloudState !== "local_only" && (!cloudFailed || !input.dashboardUrl)) return null;
  return {
    actionLabel: input.cloudState === "local_only" ? "Connect Guard Cloud" : "Open Guard Cloud",
    detail: "Local Guard remains active. Guard Cloud policy proof is separate from local repair and is not changed here.",
    href: input.cloudState === "local_only" ? input.connectUrl : input.dashboardUrl,
    startsOAuth: input.cloudState === "local_only",
    title: "Guard Cloud policy proof"
  };
}
function cloudConnectPendingMessage(hasAuthorizeUrl, opened) {
  if (opened) {
    return "Complete sign-in in the opened window. This page will update automatically.";
  }
  return "Your browser blocked the sign-in window. Open the secure sign-in link below.";
}
function cloudConnectButtonLabel(state, defaultLabel) {
  if (state?.status === "working") return "Starting sign-in…";
  if (state?.status === "success") return "Guard Cloud connected";
  return defaultLabel;
}
function FleetProtectionRecovery(props) {
  const [repairState, setRepairState] = reactExports.useState(null);
  const [cloudConnectState, setCloudConnectState] = reactExports.useState(null);
  const [detailsOpen, setDetailsOpen] = reactExports.useState(false);
  const [repairOutcomeTracker, setRepairOutcomeTracker] = reactExports.useState(null);
  const cloudConnectControllerRef = reactExports.useRef(null);
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const hasRepairableGaps = hasRepairableProtectionGap(gaps);
  const unsupportedGaps = gaps.filter(isUnsupportedPlatformCheck);
  const hasUnsupportedGaps = unsupportedGaps.length > 0;
  const unsupportedOnly = gaps.length > 0 && !hasRepairableGaps;
  const repairableGaps = gaps.filter((check) => !isUnsupportedPlatformCheck(check));
  const failCount = repairableGaps.filter((check) => check.status === "fail").length;
  const unknownCount = repairableGaps.length - failCount;
  const needsConnectedApp = remainingProtectionRepairParts(props.health).needsConnectedApp;
  const currentGapSignature = protectionGapSignature(props.health.checks);
  const repairStalled = repairOutcomeIsStalled(repairOutcomeTracker, currentGapSignature);
  const cloudPolicyHint = cloudPolicyRecoveryHint(props.cloudPolicy);
  const repairHarnessKey = props.repairHarnesses.join("\0");
  const repairHarnessList = reactExports.useMemo(
    () => repairHarnessKey ? repairHarnessKey.split("\0") : [],
    [repairHarnessKey]
  );
  const isActiveCloudConnect = reactExports.useCallback(
    (controller) => cloudConnectControllerRef.current === controller && !controller.signal.aborted,
    []
  );
  const handleRepair = reactExports.useCallback(async () => {
    if (!hasRepairableGaps) return;
    setRepairState({
      status: "working",
      message: hasUnsupportedGaps ? "Repairing supported local protection. Containment remains unavailable on this platform…" : "Repairing app hooks, local runtime, local rule packs, and local integrity…"
    });
    try {
      const message = await props.onRepairProtection(props.repairHarnesses);
      setRepairState({ status: "success", message });
      setRepairOutcomeTracker(null);
      setDetailsOpen(true);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Repair paused before every protection step completed. Retry to continue safely.";
      const outcomeSignature = error instanceof ProtectionRepairFlowError && error.signature ? error.signature : protectionGapSignature(props.health.checks);
      const outcomeHealthSignature = outcomeSignature === RECHECK_UNAVAILABLE_SIGNATURE ? protectionGapSignature(props.health.checks) : outcomeSignature;
      setRepairOutcomeTracker(
        (tracker) => nextProtectionRepairOutcome(tracker, outcomeSignature, outcomeHealthSignature)
      );
      setRepairState({
        status: "error",
        message,
        failedHarnesses: error instanceof ProtectionRepairFlowError ? error.failedHarnesses : void 0
      });
      setDetailsOpen(true);
    }
  }, [
    hasRepairableGaps,
    hasUnsupportedGaps,
    props.health.checks,
    props.onRepairProtection,
    props.repairHarnesses
  ]);
  const connectHarness = props.connectHarness ?? defaultConnectHarness(props.repairHarness, props.repairHarnesses);
  const handleRepairClick = reactExports.useCallback(() => {
    if (needsConnectedApp && props.onRepairHarness) {
      props.onRepairHarness(connectHarness);
      return;
    }
    void handleRepair();
  }, [connectHarness, handleRepair, needsConnectedApp, props.onRepairHarness]);
  const handleDetailsToggle = reactExports.useCallback(() => {
    setDetailsOpen((open) => !open);
  }, []);
  const handleCloudConnect = reactExports.useCallback(async () => {
    cloudConnectControllerRef.current?.abort();
    const controller = new AbortController();
    cloudConnectControllerRef.current = controller;
    setCloudConnectState({
      authorizeUrl: null,
      message: "Starting secure Guard Cloud sign-in…",
      status: "working"
    });
    try {
      const status = await waitForAuthorizeUrl(
        await startOrRecoverCloudConnect(controller.signal),
        controller.signal
      );
      if (!isActiveCloudConnect(controller)) return;
      if (!status.connect_required) {
        setCloudConnectState({
          authorizeUrl: null,
          message: "Guard Cloud is connected.",
          status: "success"
        });
        return;
      }
      const flow = status.connect_flow;
      const authorizeUrl = safeCloudConnectUrl(flow?.authorize_url);
      if (!flow || !authorizeUrl) {
        throw new Error(
          flow?.detail || "Guard could not generate a secure sign-in link. Try again."
        );
      }
      const opened = openPackageFirewallAuthorizeFallback(authorizeUrl, flow.browser_opened);
      if (!isActiveCloudConnect(controller)) return;
      setCloudConnectState({
        authorizeUrl,
        message: cloudConnectPendingMessage(true, opened),
        status: "pending"
      });
      const connectedStatus = await waitForCloudConnection(status, {
        signal: controller.signal
      });
      if (!isActiveCloudConnect(controller)) return;
      if (!connectedStatus.connect_required) {
        setCloudConnectState({
          authorizeUrl: null,
          message: "Guard Cloud is connected.",
          status: "success"
        });
        return;
      }
      const detail = connectedStatus.connect_flow?.detail;
      const nextAuthorizeUrl = safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url);
      setCloudConnectState({
        authorizeUrl: nextAuthorizeUrl ?? authorizeUrl,
        message: connectedStatus.connect_flow?.state === "failed" ? detail || "Guard Cloud sign-in could not finish. Try again." : "Automatic checking stopped before sign-in finished. Complete sign-in, then try again.",
        status: connectedStatus.connect_flow?.state === "failed" ? "error" : "pending"
      });
    } catch (error) {
      if (!isActiveCloudConnect(controller)) return;
      setCloudConnectState({
        authorizeUrl: null,
        message: error instanceof Error ? error.message : "Guard could not start sign-in. Try again.",
        status: "error"
      });
    }
  }, [isActiveCloudConnect]);
  const handleCloudConnectClick = reactExports.useCallback(() => {
    void handleCloudConnect();
  }, [handleCloudConnect]);
  reactExports.useEffect(() => {
    cloudConnectControllerRef.current?.abort();
    cloudConnectControllerRef.current = null;
    setCloudConnectState(null);
  }, [props.cloudPolicy.cloudState, props.cloudPolicy.connectUrl]);
  reactExports.useEffect(() => () => cloudConnectControllerRef.current?.abort(), []);
  reactExports.useEffect(() => {
    setRepairState((state) => {
      if (state?.status !== "error" || !state.failedHarnesses) return state;
      const activeFailures = activeFailedHarnesses(state.failedHarnesses, repairHarnessList);
      if (activeFailures.length === state.failedHarnesses.length) return state;
      return { ...state, failedHarnesses: activeFailures };
    });
  }, [repairHarnessList]);
  reactExports.useEffect(() => {
    setRepairOutcomeTracker((tracker) => resetRepairOutcomeTracker(tracker, currentGapSignature));
  }, [currentGapSignature]);
  if (gaps.length === 0) return null;
  const working = repairState?.status === "working";
  const cloudConnectDisabled = ["working", "success"].includes(
    cloudConnectState?.status ?? ""
  );
  const cloudConnectMessageClassName = cloudConnectState?.status === "error" ? "text-sm text-red-600" : "text-sm text-slate-600";
  let targetedRepairHarnesses = [];
  if (repairState?.status === "error") {
    targetedRepairHarnesses = repairState.failedHarnesses ?? [];
  } else if (hasRepairableGaps) {
    targetedRepairHarnesses = repairHarnessList;
  }
  const showTargetedRepairActions = !repairStalled && hasRepairableGaps && targetedRepairHarnesses.length > 0 && Boolean(props.onRepairHarness);
  const onRepairHarness = props.onRepairHarness;
  let recoveryHeading = "Restore local protection";
  if (unsupportedOnly) {
    recoveryHeading = "Containment unavailable on this platform";
  } else if (hasUnsupportedGaps) {
    recoveryHeading = "Repair supported protection";
  }
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
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-semibold text-brand-dark", children: recoveryHeading })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: unsupportedOnly ? "Containment controls are unavailable on this platform. Guard remains fail-closed; no repair is available." : recoverySummary(
              failCount,
              unknownCount,
              needsConnectedApp,
              repairableGaps.filter((check) => check.status === "fail").map((check) => actionForCheck(check, props.repairHarness).label),
              unsupportedGaps.length
            ) })
          ] }),
          hasRepairableGaps && !repairStalled ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairClick, disabled: working, children: repairButtonLabel(repairState, needsConnectedApp, hasUnsupportedGaps) }) : null
        ] }),
        cloudPolicyHint ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 border-t border-slate-200 pt-3 text-sm text-slate-600", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "font-medium text-brand-dark", children: cloudPolicyHint.title }),
          /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1", children: cloudPolicyHint.detail }),
          cloudPolicyHint.startsOAuth ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-2 flex flex-wrap items-center gap-3", children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(
              ActionButton,
              {
                onClick: handleCloudConnectClick,
                disabled: cloudConnectDisabled,
                variant: "outline",
                children: cloudConnectButtonLabel(cloudConnectState, cloudPolicyHint.actionLabel)
              }
            ),
            cloudConnectState?.authorizeUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: cloudConnectState.authorizeUrl, variant: "quiet", children: "Open secure sign-in" }) : null,
            cloudConnectState ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: cloudConnectMessageClassName, role: "status", children: cloudConnectState.message }) : null
          ] }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: cloudPolicyHint.href, variant: "outline", className: "mt-2", children: cloudPolicyHint.actionLabel })
        ] }) : null,
        repairStalled ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          StalledRepairPanel,
          {
            tracker: repairOutcomeTracker,
            repairableGaps,
            repairHarness: props.repairHarness
          }
        ) : null,
        !repairStalled && repairState && hasRepairableGaps ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "p",
          {
            className: `mt-3 flex items-start gap-2 text-sm ${repairState.status === "error" ? "text-red-600" : "text-slate-600"}`,
            "aria-live": "polite",
            children: [
              repairState.status === "success" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniCheckCircle,
                {
                  className: "mt-0.5 h-4 w-4 shrink-0 text-emerald-500",
                  "aria-hidden": "true"
                }
              ) : null,
              repairState.message
            ]
          }
        ) : null,
        showTargetedRepairActions && onRepairHarness ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", children: Array.from(new Set(targetedRepairHarnesses)).map((harness) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          TargetedRepairButton,
          {
            harness,
            onRepair: onRepairHarness
          },
          harness
        )) }) : null,
        hasRepairableGaps && repairableGaps.some((check) => check.check_id === "harness_hooks") ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 border-t border-slate-200 pt-3", id: "guard-repair-banner", children: /* @__PURE__ */ jsxRuntimeExports.jsx(GuardRepairControl, { description: "Hooks timing out or an app stuck blocked? Repair Guard restarts what is stuck, clears stale state, and reinstalls broken hooks." }) }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: handleDetailsToggle,
            "aria-expanded": detailsOpen,
            className: "mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
            children: [
              hasRepairableGaps ? "View repair details" : "View protection details",
              /* @__PURE__ */ jsxRuntimeExports.jsx(
                HiMiniChevronDown,
                {
                  className: `h-4 w-4 transition-transform ${detailsOpen ? "rotate-180" : ""}`,
                  "aria-hidden": "true"
                }
              )
            ]
          }
        ),
        detailsOpen ? /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "mt-2 border-t border-brand-attention/10", children: gaps.map((check) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          ProtectionGapItem,
          {
            action: actionForCheck(check, props.repairHarness),
            check
          },
          check.check_id
        )) }) : null
      ]
    }
  );
}
function fleetMachinePosture(settings) {
  return globalPosture(settings);
}
function fleetMachinePostureLabel(settings) {
  return PROTECTION_POSTURE_COPY[fleetMachinePosture(settings)].label;
}
function fleetManagedCapabilities(capabilities, apps) {
  const managed = new Set(apps.filter((app) => app.active).map((app) => app.harness));
  const kept = capabilities.filter((capability) => managed.has(capability.harness));
  const known = new Set(kept.map((capability) => capability.harness));
  const synthesized = [...managed].filter((harness) => !known.has(harness)).map((harness) => ({
    harness,
    display_name: harnessDisplayName(harness),
    can_pre_block: false,
    can_ask_inline: false,
    has_native_remember: false,
    fail_open_on_hook_failure: true,
    can_pre_block_limited: false,
    honesty_sentence: "",
    limited: false
  }));
  return [...kept, ...synthesized];
}
function fleetManagedRows(rows, apps) {
  const managed = new Set(apps.filter((app) => app.active).map((app) => app.harness));
  const byName = (a, b) => a.displayName.localeCompare(b.displayName);
  const watching = rows.filter((row) => managed.has(row.harness) && row.effective === "watch").sort(byName);
  const rest = rows.filter((row) => managed.has(row.harness) && row.effective !== "watch").sort(byName);
  return [...watching, ...rest];
}
function fleetInactiveAppCount(apps) {
  return apps.filter((app) => !app.active).length;
}
function fleetPostureStatusMessage(choice, displayName) {
  return choice === "watch" ? `Guard is only recording in ${displayName}.` : `Protection restored in ${displayName}.`;
}
function gateProofUpdate(gate, proof) {
  return {
    enabled: gate?.enabled ?? false,
    configured: gate?.configured ?? false,
    cooldown_seconds: gate?.cooldown_seconds ?? 0,
    cooldown_active: gate?.cooldown_active ?? false,
    cooldown_expires_at: gate?.cooldown_expires_at ?? null,
    locked_until: gate?.locked_until ?? null,
    fail_closed: gate?.fail_closed ?? false,
    strict_all_decisions: gate?.strict_all_decisions ?? false,
    totp_enabled: gate?.totp_enabled ?? false,
    totp_pending: gate?.totp_pending ?? false,
    ...proof?.currentPassword ? { current_password: proof.currentPassword } : {},
    ...proof?.totpCode ? { totp_code: proof.totpCode } : {}
  };
}
function FleetAppProtection(props) {
  const { onChanged } = props;
  const [state, setState] = reactExports.useState({ kind: "loading" });
  const [pendingWatch, setPendingWatch] = reactExports.useState(null);
  const [savingHarness, setSavingHarness] = reactExports.useState(null);
  const [proofRequest, setProofRequest] = reactExports.useState(null);
  const [proofPending, setProofPending] = reactExports.useState(false);
  const [proofError, setProofError] = reactExports.useState(null);
  const [statusMessage, setStatusMessage] = reactExports.useState(null);
  const [error, setError] = reactExports.useState(null);
  reactExports.useEffect(() => {
    let cancelled = false;
    fetchSettings().then((payload) => {
      if (cancelled) return;
      setState({
        kind: "ready",
        settings: payload.settings,
        capabilities: payload.protection_capabilities ?? []
      });
    }).catch((cause) => {
      if (cancelled) return;
      setState({ kind: "error", message: cause instanceof Error ? cause.message : "Unable to load app protection." });
    });
    return () => {
      cancelled = true;
    };
  }, []);
  const gate = state.kind === "ready" ? state.settings.approval_gate ?? null : null;
  const gateEnabled = gate?.enabled === true;
  const rows = reactExports.useMemo(() => {
    if (state.kind !== "ready") return [];
    return fleetManagedRows(
      harnessPostureRows(state.settings, fleetManagedCapabilities(state.capabilities, props.apps)),
      props.apps
    );
  }, [state, props.apps]);
  const commit = reactExports.useCallback(async (harness, choice, proof) => {
    if (state.kind !== "ready") return "App protection is still loading.";
    const saved = state.settings;
    const next = selectHarnessPosture(saved, harness, choice);
    const patch = harnessPosturePatch(next, saved);
    if (patch === null) {
      setPendingWatch(null);
      return null;
    }
    const update = { harness_postures: patch };
    if (gateEnabled) {
      update.approval_gate = gateProofUpdate(saved.approval_gate, proof);
    }
    setSavingHarness(harness);
    setError(null);
    try {
      const payload = await updateSettings(update);
      setState((current) => current.kind === "ready" ? { ...current, settings: payload.settings } : current);
      const name = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setStatusMessage(fleetPostureStatusMessage(choice, name));
      setPendingWatch(null);
      onChanged?.();
      return null;
    } catch (cause) {
      return cause instanceof Error ? cause.message : "Unable to change protection for this app.";
    } finally {
      setSavingHarness(null);
    }
  }, [state, gateEnabled, rows, onChanged]);
  const handleChoice = reactExports.useCallback((harness, choice) => {
    if (state.kind !== "ready" || state.settings.harness_postures_locked === true) return;
    setError(null);
    setStatusMessage(null);
    if (choice === "watch") {
      setPendingWatch(harness);
      return;
    }
    setPendingWatch(null);
    if (gateEnabled) {
      const displayName = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setProofError(null);
      setProofRequest({ harness, displayName, choice });
      return;
    }
    void commit(harness, choice).then((failure) => {
      if (failure !== null) setError(failure);
    });
  }, [state, gateEnabled, rows, commit]);
  const handleConfirmWatch = reactExports.useCallback((harness) => {
    setPendingWatch(null);
    if (gateEnabled) {
      const displayName = rows.find((row) => row.harness === harness)?.displayName ?? harness;
      setProofError(null);
      setProofRequest({ harness, displayName, choice: "watch" });
      return;
    }
    void commit(harness, "watch").then((failure) => {
      if (failure !== null) setError(failure);
    });
  }, [gateEnabled, rows, commit]);
  const handleProofConfirm = reactExports.useCallback(async (proof) => {
    if (proofRequest === null) return;
    setProofPending(true);
    setProofError(null);
    const failure = await commit(proofRequest.harness, proofRequest.choice, proof);
    setProofPending(false);
    if (failure === null) {
      setProofRequest(null);
    } else {
      setProofError(failure);
    }
  }, [proofRequest, commit]);
  const handleCancelWatch = reactExports.useCallback(() => setPendingWatch(null), []);
  if (state.kind === "loading") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "guard-skeleton h-14 w-full", "aria-hidden": "true" });
  }
  if (state.kind === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "rounded-xl border border-slate-100 bg-white px-4 py-2.5 text-xs text-slate-500", children: "App protection settings are unavailable right now." });
  }
  if (rows.length === 0) return null;
  const locked = state.settings.harness_postures_locked === true;
  const watchingCount = rows.filter((row) => harnessRowTone(row) === "watch").length;
  const inactiveCount = fleetInactiveAppCount(props.apps);
  const pendingRow = pendingWatch !== null ? rows.find((row) => row.harness === pendingWatch) : void 0;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs(
    "section",
    {
      className: "overflow-hidden rounded-2xl border border-slate-100 bg-white",
      "data-testid": "fleet-app-protection",
      children: [
        /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1 px-4 pb-2 pt-3", children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Protection by app" }),
          /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-xs text-slate-500", children: [
            "Machine:",
            " ",
            /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "font-semibold text-brand-dark", children: fleetMachinePostureLabel(state.settings) }),
            watchingCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "font-semibold text-brand-attention", children: [
              " · ",
              watchingCount,
              " in Watch"
            ] }) : null
          ] })
        ] }),
        error !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { role: "alert", className: "border-t border-brand-attention/20 bg-brand-attention/[0.05] px-4 py-2 text-xs text-brand-dark", children: error }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("ul", { className: "divide-y divide-slate-100 border-t border-slate-100", children: rows.map((row) => {
          const tone = harnessRowTone(row);
          const saving = savingHarness === row.harness;
          const options = harnessPostureOptions(state.settings, row.harness);
          return /* @__PURE__ */ jsxRuntimeExports.jsxs(reactExports.Fragment, { children: [
            /* @__PURE__ */ jsxRuntimeExports.jsxs(
              "li",
              {
                className: `flex flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between ${tone === "watch" ? "bg-brand-attention/[0.05]" : ""}`,
                "data-harness": row.harness,
                children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-center gap-2", children: [
                    tone === "watch" ? /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniEye, { className: "h-4 w-4 shrink-0 text-brand-attention", "aria-hidden": "true" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldCheck, { className: "h-4 w-4 shrink-0 text-brand-blue", "aria-hidden": "true" }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "truncate text-sm font-semibold text-brand-dark", children: row.displayName }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "hidden truncate text-xs text-slate-400 lg:inline", children: harnessRowStatus(row) }),
                    saving ? /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "text-xs text-slate-400", children: "Saving…" }) : null
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("fieldset", { className: "border-0 p-0", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx("legend", { className: "sr-only", children: `Protection for ${row.displayName}` }),
                    /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "inline-flex gap-1 rounded-xl bg-slate-100 p-1", children: options.map((option) => /* @__PURE__ */ jsxRuntimeExports.jsx(
                      HarnessPostureChoiceLabel,
                      {
                        groupName: `fleet-posture-${row.harness}`,
                        choice: option.choice,
                        label: option.label,
                        selected: row.selected === option.choice,
                        disabled: locked || saving,
                        harness: row.harness,
                        onChoose: handleChoice,
                        compact: true
                      },
                      option.choice
                    )) })
                  ] })
                ]
              }
            ),
            pendingRow?.harness === row.harness ? /* @__PURE__ */ jsxRuntimeExports.jsx(
              "li",
              {
                className: "bg-brand-attention/[0.06]",
                role: "alertdialog",
                "aria-label": `Switch ${pendingRow.displayName} to Watch`,
                children: /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-2 px-4 py-2.5 sm:flex-row sm:items-center sm:justify-between", children: [
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("p", { className: "text-sm text-brand-dark", children: [
                    "Guard will only record in ",
                    pendingRow.displayName,
                    " until you switch it back."
                  ] }),
                  /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-wrap gap-2", children: [
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "button",
                      {
                        type: "button",
                        onClick: () => handleConfirmWatch(pendingRow.harness),
                        className: "inline-flex min-h-11 items-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white",
                        children: "Switch to Watch"
                      }
                    ),
                    /* @__PURE__ */ jsxRuntimeExports.jsx(
                      "button",
                      {
                        type: "button",
                        onClick: handleCancelWatch,
                        className: "inline-flex min-h-11 items-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark",
                        children: "Keep protection on"
                      }
                    )
                  ] })
                ] })
              }
            ) : null
          ] }, row.harness);
        }) }),
        inactiveCount > 0 ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "border-t border-slate-100 px-4 py-2 text-xs text-slate-400", children: inactiveCount === 1 ? "1 more app isn't connected yet — see App coverage below." : `${inactiveCount} more apps aren't connected yet — see App coverage below.` }) : null,
        locked ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "border-t border-slate-100 px-4 py-2 text-xs text-slate-400", children: "Your organization manages protection for each app, so these choices can't be changed here." }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsx("div", { "aria-live": "polite", "aria-atomic": "true", className: "sr-only", children: statusMessage ?? "" }),
        proofRequest !== null ? /* @__PURE__ */ jsxRuntimeExports.jsx(
          SettingsSaveProofModal,
          {
            open: true,
            mode: "verify-save",
            gate,
            title: "Confirm before changing protection",
            detail: `Enter your approval proof to switch ${proofRequest.displayName}.`,
            confirmLabel: "Save change",
            error: proofError,
            pending: proofPending,
            onCancel: () => {
              if (proofPending) return;
              setProofRequest(null);
              setProofError(null);
            },
            onConfirm: handleProofConfirm
          }
        ) : null
      ]
    }
  );
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
function repairHarnessesFor(installs, health) {
  return Array.from(new Set(
    installs.filter((install) => install.active !== true || health.apps.find(
      (app) => app.harness === install.harness
    )?.checks.find((check) => check.check_id === "harness_hooks")?.status !== "pass").map((install) => install.harness)
  ));
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
function AppRow({ harness, status, inventoryCount, policyCount, versionCompatibility, onOpenAppDetail }) {
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
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx(HarnessVersionLabel, { compatibility: versionCompatibility ?? null })
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
  const harnessDetection = useHarnessDetection();
  const harnesses = collectHarnesses(props.runtime);
  const managedInstalls = (props.runtime.managed_installs ?? []).filter((i) => isConnectableAppHarness(i.harness));
  const activeInstalls = managedInstalls.filter((i) => i.active);
  const inventory = props.inventory.kind === "ready" ? props.inventory.items.filter((i) => isConnectableAppHarness(i.harness)) : [];
  const detected = detectedHarnesses(harnessDetection);
  const visibleHarnesses = visibleHarnessesFor({
    managed: managedInstalls.map((item) => item.harness),
    observed: harnesses,
    inventory: inventory.map((item) => item.harness),
    detected,
    policies: props.policies.map((item) => item.harness)
  });
  const watchedHarnesses = visibleHarnessesFor({
    managed: managedInstalls.map((item) => item.harness),
    observed: harnesses,
    inventory: inventory.map((item) => item.harness),
    detected,
    policies: []
  });
  const runtimeState = props.runtime.runtime_state;
  const protectionHealth = protectionHealthFor(props.runtime);
  const protectionState = useProtectionPresentationState(protectionHealth);
  const receiptHarnesses = new Set(props.runtime.latest_receipts.map((r) => r.harness).filter(isConnectableAppHarness));
  const repairHarness = managedInstalls.find((install) => !install.active)?.harness ?? visibleHarnesses.find((harness) => protectionHealthFor(props.runtime, harness).checks.some(
    (check) => check.check_id === "harness_hooks" && check.status === "fail"
  )) ?? visibleHarnesses[0];
  const repairHarnesses = repairHarnessesFor(managedInstalls, protectionHealth);
  const postureApps = (() => {
    const activeSet = new Set(activeInstalls.map((install) => install.harness));
    const known = /* @__PURE__ */ new Set([...managedInstalls.map((install) => install.harness), ...visibleHarnesses]);
    return Array.from(known, (harness) => ({ harness, active: activeSet.has(harness) })).sort((a, b) => a.harness.localeCompare(b.harness));
  })();
  const heroCopy = resolveFleetHeroCopy(
    props.runtime.cloud_state,
    activeInstalls.length,
    protectionState,
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
        cta: protectionHealth.state !== "protected" ? null : heroCopy.primaryCtaStartsCloudConnect ? /* @__PURE__ */ jsxRuntimeExports.jsx(ConnectGuardCloudButton, { label: heroCopy.primaryCtaLabel, variant: "primary" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.primaryCtaHref, children: heroCopy.primaryCtaLabel }),
        secondaryCta: protectionHealth.state !== "protected" ? null : heroCopy.secondaryCtaStartsCloudConnect ? /* @__PURE__ */ jsxRuntimeExports.jsx(ConnectGuardCloudButton, { label: heroCopy.secondaryCtaLabel, variant: "outline" }) : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.secondaryCtaHref, variant: "outline", children: heroCopy.secondaryCtaLabel })
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(
      ProofStrip,
      {
        items: [
          { label: "Needs review", value: formatCount(props.runtime.pending_count), tone: props.runtime.pending_count > 0 ? "blue" : "slate" },
          { label: "History", value: formatCount(props.runtime.receipt_count), tone: "purple" },
          { label: "Watched apps", value: formatCount(watchedHarnesses.length), tone: protectionHealth.state === "protected" ? "green" : "slate" },
          { label: "Runtime", value: runtimeState ? "active" : "offline", tone: runtimeState ? "green" : "slate" }
        ]
      }
    ),
    protectionState !== "checking" && protectionHealth.state !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      FleetProtectionRecovery,
      {
        cloudPolicy: {
          cloudState: props.runtime.cloud_state,
          cloudSyncState: props.runtime.cloud_sync_health.state,
          cloudPolicySyncError: props.runtime.cloud_policy_sync_error,
          connectUrl: props.runtime.connect_url,
          dashboardUrl: props.runtime.dashboard_url
        },
        health: protectionHealth,
        repairHarness,
        repairHarnesses,
        onRepairProtection: props.onRepairProtection,
        onRepairHarness: props.onRepairHarness ?? props.onConnectHarness
      }
    ) : null,
    /* @__PURE__ */ jsxRuntimeExports.jsx(FleetAppProtection, { apps: postureApps, onChanged: props.onRuntimeRefresh }),
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
          const isDetected = detected.includes(harness);
          const appProtection = protectionHealthFor(props.runtime, harness);
          const status = resolveDetectedAppStatus(install, appProtection, harnessInventory.length > 0, hasReceipts, isDetected);
          return /* @__PURE__ */ jsxRuntimeExports.jsx(
            AppRow,
            {
              harness,
              status,
              inventoryCount: harnessInventory.length,
              policyCount: harnessPolicies.length,
              versionCompatibility: versionCompatibilityFor(harnessDetection, harness),
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
        props.inventory.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-500", children: props.inventory.message }) : null,
        harnessDetection.kind === "error" ? /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs text-slate-500", children: harnessDetection.message }) : null
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
  repairHarnessesFor
};
