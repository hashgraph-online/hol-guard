import { Y as openPackageFirewallAuthorizeFallback, Z as waitForCloudConnection, U as waitForAuthorizeUrl, V as startOrRecoverCloudConnect, j as jsxRuntimeExports, A as ActionButton, bN as HiMiniCloudArrowUp, r as reactExports, X as safeCloudConnectUrl, bC as PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE } from "../guard-dashboard.js";
const SIGN_IN_PENDING_MESSAGE = "Sign-in is still pending. Complete it in the opened window, or open sign-in again.";
function cloudConnectPendingMessage(opened) {
  return opened ? "Complete sign-in in the opened window. This page will update automatically." : PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE;
}
function connectOnlyPendingMessage() {
  return "Open sign-in to continue. This page will update automatically.";
}
const defaultGuardCloudConnectFlowDeps = {
  start: startOrRecoverCloudConnect,
  waitAuthorize: waitForAuthorizeUrl,
  waitConnection: waitForCloudConnection,
  openAuthorize: openPackageFirewallAuthorizeFallback
};
async function runGuardCloudConnectFlow(signal, emit, deps = defaultGuardCloudConnectFlowDeps) {
  const emitIfLive = (state) => {
    if (!signal.aborted) emit(state);
  };
  emitIfLive({ status: "working" });
  try {
    const status = await deps.waitAuthorize(await deps.start(signal), signal);
    if (signal.aborted) return;
    if (!status.connect_required) {
      emitIfLive({ status: "connected" });
      return;
    }
    const flow = status.connect_flow;
    const authorizeUrl = safeCloudConnectUrl(flow?.authorize_url);
    if (flow && authorizeUrl) {
      const opened = deps.openAuthorize(authorizeUrl, flow.browser_opened);
      emitIfLive({
        status: "pending",
        message: cloudConnectPendingMessage(opened),
        manualUrl: authorizeUrl
      });
      const connectedStatus = await deps.waitConnection(status, { signal });
      if (signal.aborted) return;
      if (!connectedStatus.connect_required) {
        emitIfLive({ status: "connected" });
        return;
      }
      const failed = connectedStatus.connect_flow?.state === "failed";
      emitIfLive({
        status: failed ? "error" : "pending",
        message: failed ? connectedStatus.connect_flow?.detail || "Guard Cloud sign-in could not finish. Try again." : SIGN_IN_PENDING_MESSAGE,
        manualUrl: safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url) ?? authorizeUrl
      });
      return;
    }
    const connectUrl = safeCloudConnectUrl(flow?.connect_url);
    if (flow && connectUrl) {
      emitIfLive({
        status: "pending",
        message: connectOnlyPendingMessage(),
        manualUrl: connectUrl
      });
      const connectedStatus = await deps.waitConnection(status, { signal });
      if (signal.aborted) return;
      if (!connectedStatus.connect_required) {
        emitIfLive({ status: "connected" });
        return;
      }
      emitIfLive({
        status: "pending",
        message: SIGN_IN_PENDING_MESSAGE,
        manualUrl: safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url) ?? connectUrl
      });
      return;
    }
    emitIfLive({
      status: "error",
      message: flow?.detail || "Guard could not start sign-in. Try again.",
      manualUrl: null
    });
  } catch (error) {
    if (signal.aborted) return;
    emitIfLive({
      status: "error",
      message: error instanceof Error ? error.message : "Guard could not start sign-in. Try again.",
      manualUrl: null
    });
  }
}
function useGuardCloudConnect(deps = defaultGuardCloudConnectFlowDeps) {
  const [state, setState] = reactExports.useState({ status: "idle" });
  const controllerRef = reactExports.useRef(null);
  reactExports.useEffect(() => {
    return () => {
      controllerRef.current?.abort();
    };
  }, []);
  const startConnect = reactExports.useCallback(() => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    void runGuardCloudConnectFlow(controller.signal, setState, deps);
  }, [deps]);
  return { state, startConnect };
}
function ConnectGuardCloudButton({
  label = "Connect Guard Cloud",
  variant = "secondary",
  workingLabel = "Starting sign-in…",
  connectedLabel = "Guard Cloud connected",
  className
}) {
  const { state, startConnect } = useGuardCloudConnect();
  let buttonLabel = label;
  if (state.status === "working") {
    buttonLabel = workingLabel;
  } else if (state.status === "connected") {
    buttonLabel = connectedLabel;
  }
  let statusLine = null;
  if (state.status === "pending" || state.status === "error") {
    statusLine = /* @__PURE__ */ jsxRuntimeExports.jsxs(
      "span",
      {
        role: "status",
        className: `flex flex-wrap items-center justify-end gap-1.5 text-xs leading-relaxed ${state.status === "error" ? "text-red-600" : "text-slate-500"}`,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx("span", { children: state.message }),
          state.manualUrl ? /* @__PURE__ */ jsxRuntimeExports.jsx(
            "a",
            {
              href: state.manualUrl,
              target: "_blank",
              rel: "noreferrer",
              className: "font-semibold text-brand-blue underline",
              children: "Open sign-in"
            }
          ) : null
        ]
      }
    );
  }
  return /* @__PURE__ */ jsxRuntimeExports.jsxs("span", { className: "inline-flex flex-col items-end gap-1", children: [
    /* @__PURE__ */ jsxRuntimeExports.jsxs(
      ActionButton,
      {
        variant,
        onClick: startConnect,
        disabled: state.status === "working",
        className,
        children: [
          /* @__PURE__ */ jsxRuntimeExports.jsx(HiMiniCloudArrowUp, { className: "mr-1.5 h-4 w-4", "aria-hidden": "true" }),
          buttonLabel
        ]
      }
    ),
    statusLine
  ] });
}
export {
  ConnectGuardCloudButton as C
};
