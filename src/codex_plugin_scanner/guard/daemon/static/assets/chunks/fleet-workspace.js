import { R as startGuardCloudConnect, T as fetchGuardCloudConnectStatus, r as reactExports, U as remainingProtectionRepairParts, V as ProtectionRepairFlowError, X as openPackageFirewallAuthorizeFallback, Y as activeFailedHarnesses, j as jsxRuntimeExports, Z as HiMiniWrenchScrewdriver, A as ActionButton, o as HiMiniCheckCircle, C as HiMiniChevronDown, i as harnessDisplayName, _ as HiMiniExclamationCircle, $ as readJson, S as SectionLabel, a0 as HiMiniArrowPath, a1 as HiMiniGlobeAlt, a2 as HiMiniShieldExclamation, M as HiMiniExclamationTriangle, p as protectionHealthFor, k as useProtectionPresentationState, q as GuardHero, a3 as ProofStrip, m as EmptyState, c as HiMiniChevronRight, a4 as HiMiniEye, a5 as HiMiniXCircle, a6 as HiMiniClipboardDocumentCheck, a7 as HiMiniClipboard } from "../guard-dashboard.js";
import { d as defaultConnectHarness, S as SUPPORTED_APPS_BRIEF, A as APP_STATUS_LABELS } from "./app-catalog.js";
import { i as isConnectableAppHarness } from "./harness-setup-target.js";
import { u as useHarnessDetection, d as detectedHarnesses, v as visibleHarnessesFor, r as resolveDetectedAppStatus } from "./harness-detection.js";
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
function recoverySummary(failCount, unknownCount, needsConnectedApp) {
  if (needsConnectedApp) {
    return "Connect an AI app to start local protection. Repair cannot finish until at least one app is connected.";
  }
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
function repairButtonLabel(repairState, needsConnectedApp) {
  if (repairState?.status === "working") return "Repairing…";
  if (needsConnectedApp) return "Connect an app";
  if (repairState?.status === "error") return "Retry repair";
  return "Repair protection";
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
  const needsConnectedApp = remainingProtectionRepairParts(props.health).needsConnectedApp;
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
            /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 text-sm text-slate-600", children: recoverySummary(failCount, unknownCount, needsConnectedApp) })
          ] }),
          /* @__PURE__ */ jsxRuntimeExports.jsx(ActionButton, { onClick: handleRepairClick, disabled: working, children: repairButtonLabel(repairState, needsConnectedApp) })
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
function fetchProof(path, signal) {
  return readJson(path, { cache: "no-store", method: "GET", signal });
}
function fetchGuardNetworkStatus(signal) {
  return fetchProof("/v1/network/status", signal);
}
function fetchGuardContainmentHealth(signal) {
  return fetchProof("/v1/runtime/containment-health", signal);
}
const NETWORK_GRADES = [
  "unavailable",
  "observe",
  "deny-all",
  "proxy-only",
  "tcp-ip-destination-enforced",
  "udp-dns-destination-enforced",
  "destination-enforced"
];
const NETWORK_PHASES = ["healthy", "degraded", "recovering", "unavailable"];
const HOST_PLATFORMS = ["linux", "macos", "windows", "unsupported"];
const BACKEND_PLATFORMS = ["linux", "macos", "windows"];
const CONTAINMENT_BACKENDS = ["unsupported", "macos-sandbox", "linux-bwrap"];
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_IDENTIFIER = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const CONTAINMENT_POLICY_CONTRACT_DIGEST = "8861db0285235c9f06ca2c8443b0899928890cd63ba5d0f9873c9514e4614ee4";
const STATUS_REQUEST_TIMEOUT_MS = 8e3;
const DEFAULT_STATUS_LOADERS = {
  network: fetchGuardNetworkStatus,
  containment: fetchGuardContainmentHealth
};
const EMPTY_RESOURCE = {
  value: null,
  loadState: "idle",
  refreshing: false
};
const INITIAL_NETWORK_SANDBOX_STATUS = {
  network: EMPTY_RESOURCE,
  containment: EMPTY_RESOURCE
};
function isRecord(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function exactBoolean(value) {
  return typeof value === "boolean" ? value : null;
}
function enumValue(value, choices) {
  if (typeof value !== "string") return null;
  return choices.find((choice) => choice === value) ?? null;
}
function finiteTimestamp(value) {
  if (value === null) return null;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}
function gradeRank(grade) {
  return NETWORK_GRADES.indexOf(grade);
}
function validIdentifier(value) {
  return typeof value === "string" && value.length <= 128 && SAFE_IDENTIFIER.test(value);
}
function normalizeNetworkBackend(value, hostPlatform) {
  if (!isRecord(value) || !validIdentifier(value["backend_id"])) return null;
  const platform = enumValue(value["platform"], BACKEND_PLATFORMS);
  const advertisedGrade = enumValue(value["advertised_maximum_grade"], NETWORK_GRADES);
  const effectiveGrade = enumValue(value["effective_grade"], NETWORK_GRADES);
  const booleanFields = [
    "supported",
    "installed",
    "verified",
    "active",
    "observed",
    "production_ready",
    "requires_privilege"
  ];
  if (platform === null || advertisedGrade === null || effectiveGrade === null || booleanFields.some((field) => exactBoolean(value[field]) === null) || !validIdentifier(value["reason_code"]) || !validIdentifier(value["reference_reason_code"])) {
    return null;
  }
  const installed = value["installed"] === true;
  const verified = value["verified"] === true;
  const active = value["active"] === true;
  if (verified && !installed) return null;
  if (gradeRank(effectiveGrade) > gradeRank(advertisedGrade)) return null;
  if (active && (value["supported"] !== true || !verified || value["production_ready"] !== true || platform !== hostPlatform || gradeRank(effectiveGrade) < gradeRank("deny-all"))) {
    return null;
  }
  if (!active && gradeRank(effectiveGrade) >= gradeRank("deny-all")) return null;
  return {
    backendId: value["backend_id"],
    effectiveGrade,
    active,
    observed: value["observed"] === true
  };
}
function normalizeNetworkBackends(value, hostPlatform) {
  if (!Array.isArray(value)) return null;
  const backends = [];
  const backendIds = /* @__PURE__ */ new Set();
  for (const candidate of value) {
    const backend = normalizeNetworkBackend(candidate, hostPlatform);
    if (backend === null || backendIds.has(backend.backendId)) return null;
    backendIds.add(backend.backendId);
    backends.push(backend);
  }
  return backends;
}
function normalizeGuardNetworkStatus(value) {
  if (!isRecord(value) || value["schema"] !== "guard.network-status.v1") return null;
  const hostPlatform = enumValue(value["host_platform"], HOST_PLATFORMS);
  const effectiveGrade = enumValue(value["effective_grade"], NETWORK_GRADES);
  const independentlyObservedGrade = enumValue(value["independently_observed_grade"], NETWORK_GRADES);
  const protectionActive = exactBoolean(value["protection_active"]);
  const independentlyObserved = exactBoolean(value["independently_observed"]);
  const rawSupervisor = value["supervisor"];
  if (hostPlatform === null || effectiveGrade === null || independentlyObservedGrade === null || protectionActive === null || independentlyObserved === null || !validIdentifier(value["reason_code"])) {
    return null;
  }
  const backends = normalizeNetworkBackends(value["backends"], hostPlatform);
  if (backends === null) return null;
  const activeBackends = backends.filter((backend) => backend.active);
  const observedBackends = backends.filter((backend) => backend.observed);
  const maximumObservedGrade = observedBackends.reduce(
    (maximum, backend) => gradeRank(backend.effectiveGrade) > gradeRank(maximum) ? backend.effectiveGrade : maximum,
    "unavailable"
  );
  let supervisorValue = null;
  if (isRecord(rawSupervisor)) {
    supervisorValue = rawSupervisor;
  } else if (rawSupervisor == null && !protectionActive && !independentlyObserved) {
    supervisorValue = {
      phase: "unavailable",
      effective_grade: "unavailable",
      healthy_until_epoch_ms: null,
      permits_enforcement: false,
      independently_observed: false,
      backend_id: null,
      backend_digest: null,
      retry_attempt: 0,
      next_retry_seconds: 0
    };
  }
  if (supervisorValue === null) return null;
  const phase = enumValue(supervisorValue["phase"], NETWORK_PHASES);
  const supervisorGrade = enumValue(supervisorValue["effective_grade"], NETWORK_GRADES);
  const healthyUntilEpochMs = finiteTimestamp(supervisorValue["healthy_until_epoch_ms"]);
  const permitsEnforcement = exactBoolean(supervisorValue["permits_enforcement"]);
  const supervisorObserved = exactBoolean(supervisorValue["independently_observed"]);
  const supervisorBackendId = supervisorValue["backend_id"];
  const supervisorDigest = supervisorValue["backend_digest"];
  const retryAttempt = supervisorValue["retry_attempt"];
  const nextRetrySeconds = supervisorValue["next_retry_seconds"];
  if (phase === null || supervisorGrade === null || permitsEnforcement === null || supervisorObserved === null || supervisorBackendId !== null && !validIdentifier(supervisorBackendId) || supervisorDigest !== null && (typeof supervisorDigest !== "string" || !SHA256.test(supervisorDigest)) || typeof retryAttempt !== "number" || !Number.isInteger(retryAttempt) || retryAttempt < 0 || typeof nextRetrySeconds !== "number" || !Number.isFinite(nextRetrySeconds) || nextRetrySeconds < 0) {
    return null;
  }
  if (supervisorValue["healthy_until_epoch_ms"] !== null && healthyUntilEpochMs === null) return null;
  const expectedPermits = phase === "healthy" && gradeRank(supervisorGrade) >= gradeRank("deny-all");
  if (protectionActive !== activeBackends.length > 0 || protectionActive && activeBackends.length !== 1 || !protectionActive && effectiveGrade !== "unavailable" || protectionActive && activeBackends[0]?.effectiveGrade !== effectiveGrade || independentlyObserved !== (independentlyObservedGrade !== "unavailable") || independentlyObserved !== observedBackends.length > 0 || independentlyObservedGrade !== maximumObservedGrade || permitsEnforcement !== expectedPermits || protectionActive !== permitsEnforcement || independentlyObserved !== supervisorObserved || effectiveGrade !== supervisorGrade || protectionActive && phase !== "healthy" || protectionActive && healthyUntilEpochMs === null || protectionActive && supervisorDigest === null || protectionActive && activeBackends[0]?.backendId !== supervisorBackendId || protectionActive && (effectiveGrade === "unavailable" || effectiveGrade === "observe") || hostPlatform === "unsupported" && protectionActive) {
    return null;
  }
  return {
    hostPlatform,
    effectiveGrade,
    protectionActive,
    independentlyObserved,
    supervisor: {
      phase,
      effectiveGrade: supervisorGrade,
      healthyUntilEpochMs,
      permitsEnforcement,
      independentlyObserved: supervisorObserved
    }
  };
}
function normalizeGuardContainmentHealth(value) {
  if (!isRecord(value) || !isRecord(value["containment_health"])) return null;
  const evidence = value["containment_health"];
  if (evidence["schema_version"] !== "guard.containment-health.v1" || evidence["containment_schema_version"] !== "guard.containment.v1" || evidence["policy_version"] !== "guard.containment-policy.v1" || evidence["effect_contract_schema_version"] !== "1.0.0" || evidence["effect_decision_schema_version"] !== "1.1.0") {
    return null;
  }
  const backend = enumValue(evidence["backend"], CONTAINMENT_BACKENDS);
  const probeEnforced = exactBoolean(evidence["probe_enforced"]);
  const probeAt = evidence["probe_at"];
  const timestampHasTimezone = typeof probeAt === "string" && /(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(probeAt);
  const probeAtEpochMs = timestampHasTimezone ? Date.parse(probeAt) : Number.NaN;
  const backendDigest = evidence["backend_digest"];
  const policyDigest = evidence["policy_contract_digest"];
  const daemonFingerprint = evidence["daemon_fingerprint"];
  const runtimeFingerprint = evidence["runtime_fingerprint"];
  if (backend === null || probeEnforced === null || !Number.isFinite(probeAtEpochMs) || typeof backendDigest !== "string" || !SHA256.test(backendDigest) || policyDigest !== CONTAINMENT_POLICY_CONTRACT_DIGEST || typeof daemonFingerprint !== "string" || !SHA256.test(daemonFingerprint) || runtimeFingerprint !== daemonFingerprint) {
    return null;
  }
  if (backend === "unsupported" && probeEnforced) return null;
  return { backend, probeAtEpochMs, probeEnforced };
}
function beginNetworkSandboxRefresh(state) {
  const begin = (resource) => ({
    ...resource,
    loadState: resource.value === null ? "loading" : resource.loadState,
    refreshing: true
  });
  return {
    network: begin(state.network),
    containment: begin(state.containment)
  };
}
function settleResource(previous, result, normalize) {
  const normalized = result.status === "fulfilled" ? normalize(result.value) : null;
  if (normalized !== null) return { value: normalized, loadState: "ready", refreshing: false };
  if (previous.value !== null) return { value: previous.value, loadState: "stale", refreshing: false };
  return { value: null, loadState: "error", refreshing: false };
}
function settleNetworkSandboxStatus(previous, networkResult, containmentResult) {
  return {
    network: settleResource(previous.network, networkResult, normalizeGuardNetworkStatus),
    containment: settleResource(previous.containment, containmentResult, normalizeGuardContainmentHealth)
  };
}
function loadWithTimeout(loader, parentSignal, timeoutMs) {
  return new Promise((resolve, reject) => {
    const requestController = new AbortController();
    let settled = false;
    const finish = (callback) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timer);
      parentSignal.removeEventListener("abort", handleParentAbort);
      callback();
    };
    const handleParentAbort = () => {
      requestController.abort();
      finish(() => reject(new Error("guard_status_request_aborted")));
    };
    const timer = globalThis.setTimeout(() => {
      requestController.abort();
      finish(() => reject(new Error("guard_status_request_timed_out")));
    }, timeoutMs);
    parentSignal.addEventListener("abort", handleParentAbort, { once: true });
    if (parentSignal.aborted) {
      handleParentAbort();
      return;
    }
    void Promise.resolve().then(() => loader(requestController.signal)).then(
      (value) => finish(() => resolve(value)),
      (error) => finish(() => reject(error))
    );
  });
}
async function loadNetworkSandboxStatus(parentSignal, timeoutMs = STATUS_REQUEST_TIMEOUT_MS, loaders = DEFAULT_STATUS_LOADERS) {
  return Promise.allSettled([
    loadWithTimeout(loaders.network, parentSignal, timeoutMs),
    loadWithTimeout(loaders.containment, parentSignal, timeoutMs)
  ]);
}
function networkPresentationState(resource, nowEpochMs) {
  if (resource.value === null) return resource.loadState === "error" ? "error" : "checking";
  const status = resource.value;
  if (status.hostPlatform === "unsupported") return "unsupported";
  if (resource.loadState === "stale") return "stale";
  if (status.supervisor.healthyUntilEpochMs !== null && status.supervisor.healthyUntilEpochMs <= nowEpochMs) {
    return "stale";
  }
  const independentlyVerified = status.independentlyObserved && status.supervisor.independentlyObserved;
  const activelyEnforcing = status.protectionActive && status.supervisor.permitsEnforcement;
  return independentlyVerified && activelyEnforcing ? "ready" : "unavailable";
}
function containmentPresentationState(resource, nowEpochMs) {
  if (resource.value === null) return resource.loadState === "error" ? "error" : "checking";
  if (resource.value.backend === "unsupported") return "unsupported";
  if (resource.loadState === "stale") return "stale";
  if (nowEpochMs - resource.value.probeAtEpochMs > 5 * 60 * 1e3 || resource.value.probeAtEpochMs > nowEpochMs + 5e3) {
    return "stale";
  }
  return resource.value.probeEnforced ? "ready" : "unavailable";
}
function useNetworkSandboxStatus() {
  const [state, setState] = reactExports.useState(INITIAL_NETWORK_SANDBOX_STATUS);
  const controllerRef = reactExports.useRef(null);
  const refresh = reactExports.useCallback(async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState(beginNetworkSandboxRefresh);
    const [networkResult, containmentResult] = await loadNetworkSandboxStatus(controller.signal);
    if (controller.signal.aborted) return;
    setState((previous) => settleNetworkSandboxStatus(previous, networkResult, containmentResult));
  }, []);
  reactExports.useEffect(() => {
    void refresh();
    return () => controllerRef.current?.abort();
  }, [refresh]);
  return { state, refresh };
}
function qualifyLastKnownUnsupported(copy, loadState) {
  if (loadState !== "stale") return copy;
  return {
    label: "Unsupported · last checked",
    detail: `${copy.detail} The latest status check did not complete.`
  };
}
const STATUS_STYLE = {
  checking: "bg-slate-100 text-slate-600",
  ready: "bg-emerald-50 text-emerald-700",
  unsupported: "bg-slate-100 text-slate-600",
  unavailable: "bg-amber-50 text-amber-700",
  stale: "bg-amber-50 text-amber-700",
  error: "bg-red-50 text-red-700"
};
function networkStatusCopy(state) {
  if (state === "ready") {
    return {
      label: "Active",
      detail: "Guard has current, independently observed proof that a local provider is enforcing network boundaries."
    };
  }
  if (state === "unsupported") {
    return {
      label: "Unsupported",
      detail: "Selective network isolation is not available on this operating system."
    };
  }
  if (state === "stale") {
    return {
      label: "Proof needs refresh",
      detail: "The last provider proof is no longer current. Guard is not treating selective network isolation as active."
    };
  }
  if (state === "error") {
    return {
      label: "Couldn’t check",
      detail: "Guard could not read network provider status. No network-isolation claim is being made."
    };
  }
  if (state === "unavailable") {
    return {
      label: "Not active",
      detail: "No independently verified network provider is active. Other Guard protections continue separately."
    };
  }
  return {
    label: "Checking",
    detail: "Guard is checking for current, independently observed network enforcement."
  };
}
function containmentStatusCopy(state) {
  if (state === "ready") {
    return {
      label: "Available",
      detail: "A current local probe confirms supported actions can run inside a bounded sandbox."
    };
  }
  if (state === "unsupported") {
    return {
      label: "Unsupported",
      detail: "Bounded local execution is not available on this operating system."
    };
  }
  if (state === "stale") {
    return {
      label: "Proof needs refresh",
      detail: "The last sandbox probe is no longer current. Guard will not rely on it as positive proof."
    };
  }
  if (state === "error") {
    return {
      label: "Couldn’t check",
      detail: "Guard could not read sandbox health. It is not claiming contained execution is available."
    };
  }
  if (state === "unavailable") {
    return {
      label: "Not available",
      detail: "The local sandbox probe did not confirm enforcement. Guard will not rely on it as positive proof."
    };
  }
  return {
    label: "Checking",
    detail: "Guard is running a local sandbox compatibility check."
  };
}
function StatusIcon$1(props) {
  if (props.state === "ready") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCheckCircle, { className: "size-5 text-emerald-600", "aria-hidden": "true" });
  }
  if (props.state === "checking") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: "size-5 animate-spin text-slate-500 motion-reduce:animate-none", "aria-hidden": "true" });
  }
  if (props.state === "error") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldExclamation, { className: "size-5 text-red-600", "aria-hidden": "true" });
  }
  if (props.state === "unsupported") {
    return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldExclamation, { className: "size-5 text-slate-500", "aria-hidden": "true" });
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniExclamationTriangle, { className: "size-5 text-amber-600", "aria-hidden": "true" });
}
function StatusRow(props) {
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "grid gap-3 py-4 sm:grid-cols-[minmax(0,0.85fr)_minmax(0,1.25fr)] sm:items-start sm:gap-6", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-3", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: "mt-0.5 flex size-9 shrink-0 items-center justify-center rounded-xl bg-slate-50 text-slate-500", "aria-hidden": "true", children: props.icon }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("h3", { className: "text-sm font-semibold text-brand-dark", children: props.title }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-0.5 text-xs leading-5 text-slate-500", children: props.description })
      ] })
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex min-w-0 items-start gap-3 sm:justify-self-stretch", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(StatusIcon$1, { state: props.state }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "min-w-0", children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx("span", { className: `inline-flex rounded-full px-2.5 py-1 text-xs font-semibold ${STATUS_STYLE[props.state]}`, children: props.copy.label }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-2 max-w-[70ch] text-sm leading-6 text-slate-600", children: props.copy.detail })
      ] })
    ] })
  ] });
}
function NetworkSandboxStatusPanelView(props) {
  const { state } = props;
  const nowEpochMs = props.nowEpochMs;
  const networkState = networkPresentationState(state.network, nowEpochMs);
  const containmentState = containmentPresentationState(state.containment, nowEpochMs);
  const networkCopy = networkState === "unsupported" ? qualifyLastKnownUnsupported(networkStatusCopy(networkState), state.network.loadState) : networkStatusCopy(networkState);
  const containmentCopy = containmentState === "unsupported" ? qualifyLastKnownUnsupported(containmentStatusCopy(containmentState), state.containment.loadState) : containmentStatusCopy(containmentState);
  const refreshing = state.network.refreshing || state.containment.refreshing;
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("section", { className: "rounded-2xl border border-slate-200 bg-white px-4 py-5 sm:px-6", "aria-labelledby": "network-sandbox-heading", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "flex flex-col gap-4 sm:flex-row sm:items-start sm:justify-between", children: [
      /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { children: [
        /* @__PURE__ */ jsxRuntimeExports.jsx(SectionLabel, { children: "Execution boundaries" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("h2", { id: "network-sandbox-heading", className: "mt-1 text-lg font-semibold text-brand-dark", children: "Network & sandboxing" }),
        /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-1 max-w-[70ch] text-sm leading-6 text-slate-500", children: "Live proof from this machine. Each boundary is checked independently and may have a different status." })
      ] }),
      /* @__PURE__ */ jsxRuntimeExports.jsxs(
        "button",
        {
          type: "button",
          onClick: props.onRefresh,
          disabled: refreshing,
          className: "inline-flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-xl border border-slate-200 bg-white px-4 text-sm font-semibold text-brand-dark transition-colors hover:bg-slate-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue focus-visible:ring-offset-2 disabled:cursor-wait disabled:opacity-60",
          children: [
            /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniArrowPath, { className: `size-4 ${refreshing ? "animate-spin motion-reduce:animate-none" : ""}`, "aria-hidden": "true" }),
            refreshing ? "Refreshing…" : "Refresh status"
          ]
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsxs("div", { className: "mt-4 divide-y divide-slate-100 border-y border-slate-100", "aria-live": "polite", "aria-busy": refreshing, children: [
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        StatusRow,
        {
          title: "Selective network isolation",
          description: "When available, limits where supported processes may connect.",
          state: networkState,
          copy: networkCopy,
          icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniGlobeAlt, { className: "size-5" })
        }
      ),
      /* @__PURE__ */ jsxRuntimeExports.jsx(
        StatusRow,
        {
          title: "Contained-action sandboxing",
          description: "When available, runs supported actions with bounded file and network access.",
          state: containmentState,
          copy: containmentCopy,
          icon: /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniShieldExclamation, { className: "size-5" })
        }
      )
    ] }),
    /* @__PURE__ */ jsxRuntimeExports.jsx("p", { className: "mt-3 text-xs leading-5 text-slate-500", children: "These checks report verified local capability. They do not mean every app action is isolated." })
  ] });
}
function NetworkSandboxStatusPanel() {
  const { state, refresh } = useNetworkSandboxStatus();
  const [nowEpochMs, setNowEpochMs] = reactExports.useState(() => Date.now());
  const handleRefresh = reactExports.useCallback(() => {
    void refresh().finally(() => setNowEpochMs(Date.now()));
  }, [refresh]);
  reactExports.useEffect(() => {
    const timer = window.setInterval(() => setNowEpochMs(Date.now()), 3e4);
    return () => window.clearInterval(timer);
  }, []);
  return /* @__PURE__ */ jsxRuntimeExports.jsx(
    NetworkSandboxStatusPanelView,
    {
      state,
      onRefresh: handleRefresh,
      nowEpochMs
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
          { label: "Watched apps", value: formatCount(watchedHarnesses.length), tone: protectionHealth.state === "protected" ? "green" : "slate" },
          { label: "Runtime", value: runtimeState ? "active" : "offline", tone: runtimeState ? "green" : "slate" }
        ]
      }
    ),
    /* @__PURE__ */ jsxRuntimeExports.jsx(NetworkSandboxStatusPanel, {}),
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
        onRepairHarness: props.onRepairHarness ?? props.onConnectHarness
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
  repairHarnessesFor,
  resolveFleetHeroCopy
};
