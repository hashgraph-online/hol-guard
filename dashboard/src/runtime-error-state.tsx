import type { ReactNode } from "react";
import { ActionButton, EmptyState } from "./approval-center-primitives";
import { buildHomeRuntimeErrorCopy } from "./home-runtime-error";
import type { GuardRuntimeSnapshot } from "./guard-types";

type RuntimeErrorActions = {
  onReconnectSession?: () => Promise<void> | void;
  onRefreshRuntime?: () => Promise<void> | void;
  onOpenInbox: () => void;
  onOpenSettings: () => void;
};

/**
 * What a page shows in place of its content when the dashboard cannot read
 * Guard's local state: either this window lost its signed session, or the
 * local service stopped answering.
 */
export function RuntimeErrorState(props: RuntimeErrorActions & { message: string }) {
  const errorCopy = buildHomeRuntimeErrorCopy(props.message);
  const handlePrimary = () => {
    if (errorCopy.kind === "session") {
      void props.onReconnectSession?.();
      return;
    }
    void props.onRefreshRuntime?.();
  };
  const handleSecondary = errorCopy.kind === "session" ? props.onOpenInbox : props.onOpenSettings;
  return (
    <EmptyState
      title={errorCopy.title}
      body={errorCopy.body}
      action={
        <div className="flex flex-col gap-2 sm:flex-row">
          <ActionButton onClick={handlePrimary}>{errorCopy.primaryCta}</ActionButton>
          <ActionButton variant="outline" onClick={handleSecondary}>{errorCopy.secondaryCta}</ActionButton>
        </div>
      }
      tone="teach"
    />
  );
}

/**
 * Renders a page that needs the runtime snapshot, and says why when there is
 * none, so losing the local service never leaves a blank page.
 */
export function RuntimeGate(
  props: RuntimeErrorActions & {
    runtime:
      | { kind: "loading" }
      | { kind: "error"; message: string }
      | { kind: "ready"; snapshot: GuardRuntimeSnapshot };
    loading: ReactNode;
    children: (snapshot: GuardRuntimeSnapshot) => ReactNode;
  },
) {
  if (props.runtime.kind === "ready") return <>{props.children(props.runtime.snapshot)}</>;
  if (props.runtime.kind === "loading") return <>{props.loading}</>;
  return (
    <RuntimeErrorState
      message={props.runtime.message}
      onReconnectSession={props.onReconnectSession}
      onRefreshRuntime={props.onRefreshRuntime}
      onOpenInbox={props.onOpenInbox}
      onOpenSettings={props.onOpenSettings}
    />
  );
}
