import { R as startGuardCloudConnect, T as fetchGuardCloudConnectStatus, r as reactExports, U as ProtectionRepairFlowError, V as openPackageFirewallAuthorizeFallback, X as activeFailedHarnesses, j as jsxRuntimeExports, Y as HiMiniWrenchScrewdriver, A as ActionButton, o as HiMiniCheckCircle, C as HiMiniChevronDown, i as harnessDisplayName, Z as HiMiniExclamationCircle, p as protectionHealthFor, k as useProtectionPresentationState, q as GuardHero, _ as ProofStrip, S as SectionLabel, m as EmptyState, c as HiMiniChevronRight, $ as HiMiniEye, a0 as HiMiniXCircle, a1 as HiMiniClipboardDocumentCheck, a2 as HiMiniClipboard } from "../guard-dashboard.js";
import { S as SUPPORTED_APPS_BRIEF, A as APP_STATUS_LABELS } from "./app-catalog.js";
import { i as isConnectableAppHarness } from "./harness-setup-target.js";
class CloudRequestTimeoutError extends Error {
  constructor() {
    super("Guard Cloud did not respond within 5 seconds. Try again.");
    this.name = "CloudRequestTimeoutError";
  }
}
async function withCloudRequestTimeout(request, parentSignal) {
  if (parentSignal?.aborted) {
    throw new DOMException("Cloud connection request stopped", "AbortError");
  }
  const controller = new AbortController();
  const abort = () => controller.abort();
  parentSignal?.addEventListener("abort", abort, { once: true });
  let timedOut = false;
  const timeout = globalThis.setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, 5e3);
  try {
    return await request(controller.signal);
  } catch (error) {
    if (timedOut && !parentSignal?.aborted && error instanceof DOMException && error.name === "AbortError") {
      throw new CloudRequestTimeoutError();
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
    parentSignal?.removeEventListener("abort", abort);
  }
}
async function startOrRecoverCloudConnect(signal) {
  try {
    return await withCloudRequestTimeout(startGuardCloudConnect, signal);
  } catch (error) {
    if (!(error instanceof CloudRequestTimeoutError)) throw error;
    return await withCloudRequestTimeout(fetchGuardCloudConnectStatus, signal);
  }
}
function waitForPoll(delayMs, signal) {
  if (signal.aborted) {
    return Promise.reject(new DOMException("Cloud connection polling stopped", "AbortError"));
  }
  return new Promise((resolve, reject) => {
    const finish = () => {
      signal.removeEventListener("abort", abort);
      resolve();
    };
    const timeout = globalThis.setTimeout(finish, delayMs);
    const abort = () => {
      globalThis.clearTimeout(timeout);
      reject(new DOMException("Cloud connection polling stopped", "AbortError"));
    };
    signal.addEventListener("abort", abort, { once: true });
  });
}
async function waitForAuthorizeUrl(initialStatus, signal) {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < 10; attempt += 1) {
    const flow = status.connect_flow;
    if (!status.connect_required || flow?.authorize_url || !flow || !["starting", "running"].includes(flow.state)) {
      return status;
    }
    const pollDelayMs = Math.max(100, Math.min(5e3, flow.poll_after_ms ?? 1e3));
    await waitForPoll(pollDelayMs, signal);
    status = await withCloudRequestTimeout(fetchGuardCloudConnectStatus, signal);
  }
  return status;
}
async function waitForCloudConnection(initialStatus, {
  signal,
  fetchStatus = fetchGuardCloudConnectStatus,
  wait = waitForPoll,
  maxAttempts = 300
}) {
  if (signal.aborted) {
    throw new DOMException("Cloud connection polling stopped", "AbortError");
  }
  let status = initialStatus;
  for (let attempt = 0; attempt < maxAttempts && status.connect_required; attempt += 1) {
    if (status.connect_flow?.state === "failed") return status;
    const pollDelayMs = Math.max(250, Math.min(5e3, status.connect_flow?.poll_after_ms ?? 1e3));
    await wait(pollDelayMs, signal);
    status = await withCloudRequestTimeout(fetchStatus, signal);
  }
  return status;
}
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
function cloudPolicyRecoveryHint(input) {
  const cloudProofUnavailable = input.cloudState !== "paired_active" || input.cloudSyncState !== "healthy" || Boolean(input.cloudPolicySyncError);
  if (!cloudProofUnavailable) return null;
  return {
    actionLabel: input.cloudState === "local_only" ? "Connect Guard Cloud" : "Open Guard Cloud",
    detail: "Local Guard remains active. Guard Cloud policy proof is separate from local repair and is not changed here.",
    href: input.connectUrl,
    startsOAuth: input.cloudState === "local_only",
    title: "Guard Cloud policy proof"
  };
}
function actionForCheck(check, repairHarness) {
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
function ProtectionGapItem({
  action,
  check
}) {
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
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "ml-1 text-[10px] font-medium uppercase tracking-wide text-slate-400", children: check.status === "fail" ? "Failed" : "Unproven" }),
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 block", children: action.detail })
    ] })
  ] }) });
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
function recoverySummary(failCount, unknownCount) {
  if (failCount === 0) {
    return "Complete the remaining local proof here. Guard repairs and rechecks every local protection layer in one pass.";
  }
  const failedChecks = `${failCount} failed check${failCount === 1 ? "" : "s"}`;
  let remainingProofs = "";
  if (unknownCount > 0) {
    remainingProofs = `, then confirm the remaining ${unknownCount} proof${unknownCount === 1 ? "" : "s"}`;
  }
  return `Repair the ${failedChecks} here${remainingProofs}. Guard repairs and rechecks every local protection layer in one pass.`;
}
function repairButtonLabel(repairState) {
  if (repairState?.status === "working") return "Repairing…";
  if (repairState?.status === "error") return "Retry repair";
  return "Repair protection";
}
function cloudConnectPendingMessage(hasAuthorizeUrl, opened) {
  if (!hasAuthorizeUrl) {
    return "Open the secure sign-in link below. This page will update automatically.";
  }
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
function safeCloudConnectUrl(value) {
  if (!value) return null;
  try {
    const url = new URL(value);
    if (!url.hostname || url.username || url.password) return null;
    const loopbackHosts = ["localhost", "127.0.0.1", "[::1]"];
    const secureRemote = url.protocol === "https:";
    const localHttp = url.protocol === "http:" && loopbackHosts.includes(url.hostname);
    if (!secureRemote && !localHttp) return null;
    return url.toString();
  } catch {
    return null;
  }
}
function FleetProtectionRecovery(props) {
  const [repairState, setRepairState] = reactExports.useState(null);
  const [cloudConnectState, setCloudConnectState] = reactExports.useState(null);
  const [detailsOpen, setDetailsOpen] = reactExports.useState(false);
  const cloudConnectControllerRef = reactExports.useRef(null);
  const gaps = props.health.checks.filter((check) => check.status !== "pass");
  const failCount = gaps.filter((check) => check.status === "fail").length;
  const unknownCount = gaps.length - failCount;
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
    setRepairState({
      status: "working",
      message: "Repairing app hooks, local runtime, local rule packs, and local integrity…"
    });
    try {
      const message = await props.onRepairProtection(props.repairHarnesses);
      setRepairState({ status: "success", message });
      setDetailsOpen(true);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Repair paused before every protection step completed. Retry to continue safely.";
      setRepairState({
        status: "error",
        message,
        failedHarnesses: error instanceof ProtectionRepairFlowError ? error.failedHarnesses : void 0
      });
      setDetailsOpen(true);
    }
  }, [props.onRepairProtection, props.repairHarnesses]);
  const handleRepairClick = reactExports.useCallback(() => {
    void handleRepair();
  }, [handleRepair]);
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
      const signInUrl = authorizeUrl ?? safeCloudConnectUrl(flow?.connect_url);
      if (!flow || !signInUrl) {
        throw new Error(
          flow?.detail || "Guard could not generate a secure sign-in link. Try again."
        );
      }
      const opened = authorizeUrl ? openPackageFirewallAuthorizeFallback(authorizeUrl, flow.browser_opened) : false;
      if (!isActiveCloudConnect(controller)) return;
      setCloudConnectState({
        authorizeUrl: signInUrl,
        message: cloudConnectPendingMessage(Boolean(authorizeUrl), opened),
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
      setCloudConnectState({
        authorizeUrl: safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url) ?? safeCloudConnectUrl(connectedStatus.connect_flow?.connect_url) ?? signInUrl,
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
  if (gaps.length === 0) return null;
  const working = repairState?.status === "working";
  const cloudConnectDisabled = ["working", "success"].includes(
    cloudConnectState?.status ?? ""
  );
  const cloudConnectMessageClassName = cloudConnectState?.status === "error" ? "text-sm text-red-600" : "text-sm text-slate-600";
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
              /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { className: "text-sm font-semibold text-brand-dark", children: "Restore local protection" })
            ] }),
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: recoverySummary(failCount, unknownCount) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairClick, disabled: working, children: repairButtonLabel(repairState) })
        ] }),
        cloudPolicyHint ? /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-3 border-t border-brand-attention/10 pt-3 text-sm text-slate-600", children: [
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
        repairState ? /* @__PURE__ */ jsxRuntimeExports.jsxs(
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
        repairState?.status === "error" && repairState.failedHarnesses?.length && props.onRepairHarness ? /* @__PURE__ */ jsxRuntimeExports.jsx("div", { className: "mt-3 flex flex-wrap gap-2", children: Array.from(new Set(repairState.failedHarnesses)).map((harness) => /* @__PURE__ */ jsxRuntimeExports.jsx(
          TargetedRepairButton,
          {
            harness,
            onRepair: props.onRepairHarness
          },
          harness
        )) }) : null,
        /* @__PURE__ */ jsxRuntimeExports.jsxs(
          "button",
          {
            type: "button",
            onClick: handleDetailsToggle,
            "aria-expanded": detailsOpen,
            className: "mt-3 inline-flex items-center gap-1 text-xs font-medium text-brand-primary hover:underline focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2",
            children: [
              "View repair details",
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
      secondaryCtaLabel: "Open Home",
      secondaryCtaHref: urls.dashboard_url
    };
  }
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
function repairHarnessesFor(installs, health) {
  return Array.from(new Set(
    installs.filter((install) => install.active !== true || health.apps.find(
      (app) => app.harness === install.harness
    )?.checks.some((check) => check.check_id === "harness_hooks" && check.status === "fail") === true).map((install) => install.harness)
  ));
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
  const protectionState = useProtectionPresentationState(protectionHealth);
  const receiptHarnesses = new Set(props.runtime.latest_receipts.map((r) => r.harness).filter(isConnectableAppHarness));
  const repairHarness = managedInstalls.find((install) => !install.active)?.harness ?? visibleHarnesses.find((harness) => protectionHealthFor(props.runtime, harness).checks.some(
    (check) => check.check_id === "harness_hooks" && check.status === "fail"
  ));
  const repairHarnesses = repairHarnessesFor(managedInstalls, protectionHealth);
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
        cta: protectionHealth.state !== "protected" ? null : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.primaryCtaHref, children: heroCopy.primaryCtaLabel }),
        secondaryCta: protectionHealth.state !== "protected" ? null : /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { href: heroCopy.secondaryCtaHref, variant: "outline", children: heroCopy.secondaryCtaLabel })
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
    protectionState !== "checking" && protectionHealth.state !== "protected" ? /* @__PURE__ */ jsxRuntimeExports.jsx(
      FleetProtectionRecovery,
      {
        cloudPolicy: {
          cloudState: props.runtime.cloud_state,
          cloudSyncState: props.runtime.cloud_sync_health.state,
          cloudPolicySyncError: props.runtime.cloud_policy_sync_error,
          connectUrl: props.runtime.connect_url
        },
        health: protectionHealth,
        repairHarness,
        repairHarnesses,
        onRepairProtection: props.onRepairProtection,
        onRepairHarness: props.onRepairHarness
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
  repairHarnessesFor,
  resolveFleetHeroCopy
};
