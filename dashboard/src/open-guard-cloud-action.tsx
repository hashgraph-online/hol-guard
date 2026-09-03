import { useCallback, useEffect, useRef, useState } from "react";
import {
  HiMiniArrowTopRightOnSquare,
  HiMiniCloud,
} from "react-icons/hi2";

import {
  startOrRecoverCloudConnect,
  waitForAuthorizeUrl,
  type GuardCloudOpenStatus,
} from "./guard-cloud-connect-flow";
import {
  openPackageFirewallAuthorizeFallback,
  PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE,
} from "./package-firewall-connect-browser";

type OpenGuardCloudActionState =
  | { status: "idle" }
  | { status: "working" }
  | { status: "error"; message: string; manualUrl?: string };

export type OpenGuardCloudActionVariant = "sidebar" | "drawer" | "approval-sidebar";

export type OpenGuardCloudActionProps = {
  variant: OpenGuardCloudActionVariant;
  collapsed?: boolean;
};

export class GuardCloudPopupBlockedError extends Error {
  readonly manualUrl: string;

  constructor(manualUrl: string) {
    super(PACKAGE_FIREWALL_CONNECT_POPUP_BLOCKED_MESSAGE);
    this.name = "GuardCloudPopupBlockedError";
    this.manualUrl = manualUrl;
  }
}

export function safeCloudConnectUrl(value: string | null | undefined): string | null {
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

function openGuardCloudUrl(url: string): boolean {
  if (typeof window === "undefined") return false;
  const popup = window.open(url, "_blank", "noopener,noreferrer");
  if (popup) {
    popup.opener = null;
    return true;
  }
  return false;
}

function buttonLabel(state: OpenGuardCloudActionState): string {
  if (state.status === "working") return "Starting sign-in…";
  return "Open Guard Cloud";
}

export async function runOpenGuardCloudConnect(
  signal: AbortSignal,
  openAuthorize: typeof openPackageFirewallAuthorizeFallback = openPackageFirewallAuthorizeFallback,
  openUrl: (url: string) => boolean = openGuardCloudUrl,
  connect: {
    start: (signal: AbortSignal) => ReturnType<typeof startOrRecoverCloudConnect>;
    wait: (
      status: GuardCloudOpenStatus,
      signal: AbortSignal,
    ) => ReturnType<typeof waitForAuthorizeUrl>;
  } = {
    start: startOrRecoverCloudConnect,
    wait: waitForAuthorizeUrl,
  },
): Promise<void> {
  const status = await connect.wait(
    await connect.start(signal),
    signal,
  );
  if (signal.aborted) return;
  if (!status.connect_required) {
    const dashboardUrl = safeCloudConnectUrl(status.dashboard_url);
    if (!dashboardUrl) {
      throw new Error("Guard Cloud is connected, but no dashboard link was returned.");
    }
    if (!openUrl(dashboardUrl)) {
      throw new GuardCloudPopupBlockedError(dashboardUrl);
    }
    return;
  }
  const flow = status.connect_flow;
  const authorizeUrl = safeCloudConnectUrl(flow?.authorize_url);
  if (!flow || !authorizeUrl) {
    throw new Error(
      flow?.detail || "Guard could not generate a secure sign-in link. Try again.",
    );
  }
  if (!openAuthorize(authorizeUrl, flow.browser_opened)) {
    throw new GuardCloudPopupBlockedError(authorizeUrl);
  }
}

function ActionError(props: { message: string; manualUrl?: string; compact?: boolean }) {
  return (
    <>
      <p className={props.compact ? "px-3 text-xs text-brand-purple" : "guard-open-guard-cloud-action__error"}>
        {props.message}
      </p>
      {props.manualUrl ? (
        <a
          className={props.compact ? "px-3 text-xs font-semibold text-brand-purple underline" : "guard-open-guard-cloud-action__manual"}
          href={props.manualUrl}
          rel="noreferrer"
          target="_blank"
        >
          Open sign-in
        </a>
      ) : null}
    </>
  );
}

function QuickActionButton(props: {
  label: string;
  disabled: boolean;
  errorMessage: string | null;
  manualUrl?: string;
  onClick: () => void;
}) {
  return (
    <>
      <button type="button" onClick={props.onClick} disabled={props.disabled}>
        <HiMiniCloud aria-hidden="true" />
        <span>{props.label}</span>
        <HiMiniArrowTopRightOnSquare aria-hidden="true" />
      </button>
      {props.errorMessage ? (
        <ActionError message={props.errorMessage} manualUrl={props.manualUrl} />
      ) : null}
    </>
  );
}

export function OpenGuardCloudAction(props: OpenGuardCloudActionProps) {
  const [state, setState] = useState<OpenGuardCloudActionState>({ status: "idle" });
  const controllerRef = useRef<AbortController | null>(null);
  const collapsed = props.collapsed ?? false;

  useEffect(() => {
    return () => {
      controllerRef.current?.abort();
    };
  }, []);

  const handleClick = useCallback(() => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState({ status: "working" });
    void runOpenGuardCloudConnect(controller.signal)
      .then(() => {
        if (controller.signal.aborted) return;
        setState({ status: "idle" });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (error instanceof GuardCloudPopupBlockedError) {
          setState({
            status: "error",
            message: error.message,
            manualUrl: error.manualUrl,
          });
          return;
        }
        setState({
          status: "error",
          message:
            error instanceof Error
              ? error.message
              : "Could not open Guard Cloud. Try again.",
        });
      });
  }, []);

  const label = buttonLabel(state);
  const errorMessage = state.status === "error" ? state.message : null;
  const manualUrl = state.status === "error" ? state.manualUrl : undefined;
  const disabled = state.status === "working";

  if (props.variant === "approval-sidebar") {
    return (
      <div className="space-y-1">
        <button
          type="button"
          onClick={handleClick}
          disabled={disabled}
          title={collapsed ? "Open Guard Cloud" : undefined}
          className={`flex min-h-10 w-full items-center rounded-lg border border-slate-200 bg-white text-left transition-colors duration-150 hover:border-brand-blue/30 hover:text-brand-dark disabled:cursor-wait disabled:opacity-70 ${collapsed ? "justify-center px-2 py-2" : "gap-2.5 px-3 py-2 text-sm font-medium text-slate-700"}`}
        >
          <span className="shrink-0 text-slate-400">
            <HiMiniCloud className="h-4 w-4" aria-hidden="true" />
          </span>
          {!collapsed ? <span className="flex-1 truncate">{label}</span> : null}
          {!collapsed ? (
            <HiMiniArrowTopRightOnSquare className="h-3.5 w-3.5 shrink-0 text-slate-300" aria-hidden="true" />
          ) : null}
        </button>
        {!collapsed && errorMessage ? (
          <ActionError compact message={errorMessage} manualUrl={manualUrl} />
        ) : null}
      </div>
    );
  }

  return (
    <QuickActionButton
      label={label}
      disabled={disabled}
      errorMessage={errorMessage}
      manualUrl={manualUrl}
      onClick={handleClick}
    />
  );
}
