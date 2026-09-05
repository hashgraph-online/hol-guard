import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniCloudArrowUp } from "react-icons/hi2";

import { ActionButton } from "./approval-center-primitives";
import {
  safeCloudConnectUrl,
  startOrRecoverCloudConnect,
  waitForAuthorizeUrl,
  waitForCloudConnection,
  type GuardCloudOpenStatus,
} from "./guard-cloud-connect-flow";
import {
  openPackageFirewallAuthorizeFallback,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
} from "./package-firewall-connect-browser";

export type GuardCloudConnectUiState =
  | { status: "idle" }
  | { status: "working" }
  | { status: "pending"; message: string; manualUrl: string | null }
  | { status: "connected" }
  | { status: "error"; message: string; manualUrl: string | null };

const SIGN_IN_PENDING_MESSAGE =
  "Sign-in is still pending. Complete it in the opened window, or open sign-in again.";

function cloudConnectPendingMessage(opened: boolean): string {
  return opened
    ? "Complete sign-in in the opened window. This page will update automatically."
    : PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE;
}

function connectOnlyPendingMessage(): string {
  return "Open sign-in to continue. This page will update automatically.";
}

export type GuardCloudConnectFlowDeps = {
  start: (signal: AbortSignal) => Promise<GuardCloudOpenStatus>;
  waitAuthorize: (
    status: GuardCloudOpenStatus,
    signal: AbortSignal,
  ) => Promise<GuardCloudOpenStatus>;
  waitConnection: typeof waitForCloudConnection;
  openAuthorize: typeof openPackageFirewallAuthorizeFallback;
};

const defaultGuardCloudConnectFlowDeps: GuardCloudConnectFlowDeps = {
  start: startOrRecoverCloudConnect,
  waitAuthorize: waitForAuthorizeUrl,
  waitConnection: waitForCloudConnection,
  openAuthorize: openPackageFirewallAuthorizeFallback,
};

/**
 * Runs the daemon-mediated Guard Cloud OAuth flow: start (or recover) the
 * connect request, wait for the daemon's authorize URL, open it, then poll
 * until the daemon reports the connection landed. Emits UI states as the flow
 * progresses; never rejects — failures arrive as an "error" state.
 */
export async function runGuardCloudConnectFlow(
  signal: AbortSignal,
  emit: (state: GuardCloudConnectUiState) => void,
  deps: GuardCloudConnectFlowDeps = defaultGuardCloudConnectFlowDeps,
): Promise<void> {
  const emitIfLive = (state: GuardCloudConnectUiState): void => {
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
        manualUrl: authorizeUrl,
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
        message: failed
          ? connectedStatus.connect_flow?.detail || "Guard Cloud sign-in could not finish. Try again."
          : SIGN_IN_PENDING_MESSAGE,
        manualUrl: safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url) ?? authorizeUrl,
      });
      return;
    }
    const connectUrl = safeCloudConnectUrl(flow?.connect_url);
    if (flow && connectUrl) {
      emitIfLive({
        status: "pending",
        message: connectOnlyPendingMessage(),
        manualUrl: connectUrl,
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
        manualUrl: safeCloudConnectUrl(connectedStatus.connect_flow?.authorize_url) ?? connectUrl,
      });
      return;
    }
    emitIfLive({
      status: "error",
      message: flow?.detail || "Guard could not start sign-in. Try again.",
      manualUrl: null,
    });
  } catch (error: unknown) {
    if (signal.aborted) return;
    emitIfLive({
      status: "error",
      message:
        error instanceof Error ? error.message : "Guard could not start sign-in. Try again.",
      manualUrl: null,
    });
  }
}

export function useGuardCloudConnect(
  deps: GuardCloudConnectFlowDeps = defaultGuardCloudConnectFlowDeps,
): { state: GuardCloudConnectUiState; startConnect: () => void } {
  const [state, setState] = useState<GuardCloudConnectUiState>({ status: "idle" });
  const controllerRef = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => {
      controllerRef.current?.abort();
    };
  }, []);

  const startConnect = useCallback(() => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    void runGuardCloudConnectFlow(controller.signal, setState, deps);
  }, [deps]);

  return { state, startConnect };
}

type ConnectGuardCloudButtonProps = {
  label?: string;
  variant?: "primary" | "secondary" | "outline" | "ghost" | "quiet";
  workingLabel?: string;
  connectedLabel?: string;
  className?: string;
};

/**
 * Guard Cloud connect action that starts the daemon-mediated OAuth sign-in
 * flow instead of linking straight to the hol.org connect page.
 */
export function ConnectGuardCloudButton({
  label = "Connect Guard Cloud",
  variant = "secondary",
  workingLabel = "Starting sign-in…",
  connectedLabel = "Guard Cloud connected",
  className,
}: ConnectGuardCloudButtonProps) {
  const { state, startConnect } = useGuardCloudConnect();

  let buttonLabel = label;
  if (state.status === "working") {
    buttonLabel = workingLabel;
  } else if (state.status === "connected") {
    buttonLabel = connectedLabel;
  }

  let statusLine: ReactNode = null;
  if (state.status === "pending" || state.status === "error") {
    statusLine = (
      <span
        role="status"
        className={`flex flex-wrap items-center justify-end gap-1.5 text-xs leading-relaxed ${
          state.status === "error" ? "text-red-600" : "text-slate-500"
        }`}
      >
        <span>{state.message}</span>
        {state.manualUrl ? (
          <a
            href={state.manualUrl}
            target="_blank"
            rel="noreferrer"
            className="font-semibold text-brand-blue underline"
          >
            Open sign-in
          </a>
        ) : null}
      </span>
    );
  }

  return (
    <span className="inline-flex flex-col items-end gap-1">
      <ActionButton
        variant={variant}
        onClick={startConnect}
        disabled={state.status === "working"}
        className={className}
      >
        <HiMiniCloudArrowUp className="mr-1.5 h-4 w-4" aria-hidden="true" />
        {buttonLabel}
      </ActionButton>
      {statusLine}
    </span>
  );
}
