import { useMemo, useState } from "react";
import { HiMiniArrowPath, HiMiniClipboardDocument, HiMiniShieldExclamation } from "react-icons/hi2";

import { ActionButton } from "./approval-center-primitives";
import {
  getRecoveryCapabilities,
  openRecoveryView,
  resolveRecoveryInstructions,
  type RecoveryCapabilityState,
  type RecoveryHandoffResult,
  type RecoveryInstallMode,
} from "./service-recovery";

export type ServiceRecoveryPanelProps = {
  title?: string;
  body?: string;
  bridge?: unknown;
  installMode?: RecoveryInstallMode;
  onOpenRecovery?: () => RecoveryHandoffResult | void | Promise<RecoveryHandoffResult | void>;
  onRetryConnection?: () => void | Promise<void>;
};

function fallbackMessage(capability: Extract<RecoveryCapabilityState, { kind: "fallback" }>): string {
  if (capability.reason === "unsupported_protocol") {
    return "This Desktop version does not expose the recovery handoff. Use the local recovery steps below.";
  }
  if (capability.reason === "invalid_bridge") {
    return "The recovery handoff could not be verified. Use the local recovery steps below.";
  }
  return "This browser tab cannot control the local service. Use the local recovery steps below.";
}

export function ServiceRecoveryPanel(props: ServiceRecoveryPanelProps) {
  const capability = useMemo(
    () => getRecoveryCapabilities({ bridge: props.bridge, installMode: props.installMode }),
    [props.bridge, props.installMode],
  );
  const instructions = useMemo(
    () => resolveRecoveryInstructions(capability.installMode),
    [capability.installMode],
  );
  const [showInstructions, setShowInstructions] = useState(capability.kind === "fallback");
  const [opening, setOpening] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const [handoffError, setHandoffError] = useState<string | null>(null);
  const [handoffStatus, setHandoffStatus] = useState<string | null>(null);
  const [copyState, setCopyState] = useState<"idle" | "copied" | "failed">("idle");

  const handleOpenRecovery = async () => {
    if (opening) return;
    setOpening(true);
    setHandoffError(null);
    setHandoffStatus(null);
    try {
      const result = props.onOpenRecovery
        ? await props.onOpenRecovery()
        : await openRecoveryView({ bridge: capability.kind === "native" ? capability.bridge : props.bridge, installMode: capability.installMode });
      if (result && result.kind !== "opened") {
        setHandoffError(
          result.kind === "failed"
            ? result.message
            : result.capability.kind === "fallback"
              ? fallbackMessage(result.capability)
              : "The trusted Recovery view is unavailable. Use the local recovery steps below.",
        );
        setShowInstructions(true);
        return;
      }
      setHandoffStatus("Recovery opened in the trusted native view. Confirm Restart Guard there; this tab did not restart the service.");
    } catch {
      setHandoffError("The trusted Recovery view could not be opened. Use the local recovery steps below.");
      setShowInstructions(true);
    } finally {
      setOpening(false);
    }
  };

  const handleRetry = async () => {
    if (!props.onRetryConnection || retrying) return;
    setRetrying(true);
    try {
      await props.onRetryConnection();
    } catch {
      setHandoffError("The connection retry did not complete. Use the local recovery steps below.");
    } finally {
      setRetrying(false);
    }
  };

  const handleCopyCommand = async () => {
    if (!instructions.command) return;
    if (typeof navigator === "undefined" || !navigator.clipboard?.writeText) {
      setCopyState("failed");
      return;
    }
    try {
      await navigator.clipboard.writeText(instructions.command);
      setCopyState("copied");
    } catch {
      setCopyState("failed");
    }
  };

  return (
    <section
      className="rounded-2xl border border-brand-blue/15 bg-brand-blue/[0.03] p-5 shadow-sm sm:p-6"
      aria-labelledby="service-recovery-title"
      data-testid="service-recovery-panel"
    >
      <div className="flex items-start gap-3">
        <span className="mt-0.5 flex h-10 w-10 shrink-0 items-center justify-center rounded-xl bg-brand-blue/10 text-brand-blue" aria-hidden="true">
          <HiMiniShieldExclamation className="h-5 w-5" />
        </span>
        <div className="min-w-0">
          <p className="text-xs font-semibold uppercase tracking-[0.12em] text-brand-blue">Troubleshoot Guard</p>
          <h2 id="service-recovery-title" className="mt-1 text-lg font-semibold tracking-tight text-brand-dark">
            {props.title ?? "We can't connect to Guard."}
          </h2>
          <p className="mt-2 max-w-2xl text-sm leading-relaxed text-muted-foreground">
            {props.body ?? "Retry the connection, or use a trusted local recovery path."}
          </p>
        </div>
      </div>

      <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:flex-wrap">
        {capability.kind === "native" ? (
          <ActionButton onClick={() => void handleOpenRecovery()} disabled={opening} data-testid="service-recovery-open">
            {opening ? "Opening recovery..." : "Open recovery"}
          </ActionButton>
        ) : null}
        {props.onRetryConnection ? (
          <ActionButton
            variant="outline"
            onClick={() => void handleRetry()}
            disabled={retrying}
            data-testid="service-recovery-retry"
          >
            <HiMiniArrowPath className={`mr-1.5 inline h-4 w-4 ${retrying ? "animate-spin" : ""}`} aria-hidden="true" />
            {retrying ? "Retrying..." : "Retry connection"}
          </ActionButton>
        ) : null}
        <ActionButton
          variant="outline"
          onClick={() => setShowInstructions((visible) => !visible)}
          data-testid="service-recovery-steps-toggle"
          aria-expanded={showInstructions}
        >
          {showInstructions ? "Hide restart steps" : "Show restart steps"}
        </ActionButton>
      </div>

      {capability.kind === "fallback" ? (
        <p className="mt-4 text-sm text-slate-600" role="status" data-testid="service-recovery-fallback">
          {fallbackMessage(capability)}
        </p>
      ) : null}
      {handoffStatus ? (
        <p className="mt-4 rounded-xl border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900" role="status" aria-live="polite">
          {handoffStatus}
        </p>
      ) : null}
      {handoffError ? (
        <p className="mt-4 rounded-xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-950" role="alert" aria-live="assertive">
          {handoffError}
        </p>
      ) : null}

      {showInstructions ? (
        <div className="mt-5 rounded-xl border border-slate-200 bg-white p-4" data-testid="service-recovery-instructions">
          <h3 className="text-sm font-semibold text-brand-dark">{instructions.title}</h3>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">{instructions.body}</p>
          <ol className="mt-3 list-decimal space-y-2 pl-5 text-sm text-slate-700">
            {instructions.steps.map((step) => <li key={step}>{step}</li>)}
          </ol>
          {instructions.command ? (
            <div className="mt-4 flex flex-col gap-2 sm:flex-row sm:items-center">
              <code className="min-w-0 flex-1 overflow-x-auto rounded-lg bg-slate-950 px-3 py-2 text-xs text-slate-100" data-testid="service-recovery-command">
                {instructions.command}
              </code>
              <ActionButton variant="outline" onClick={() => void handleCopyCommand()}>
                <HiMiniClipboardDocument className="mr-1.5 inline h-4 w-4" aria-hidden="true" />
                Copy command
              </ActionButton>
            </div>
          ) : null}
          {copyState === "copied" ? <p className="mt-2 text-xs text-emerald-700" role="status">Recovery command copied.</p> : null}
          {copyState === "failed" ? <p className="mt-2 text-xs text-amber-800" role="status">Copy was unavailable. Select the command above instead.</p> : null}
        </div>
      ) : null}
    </section>
  );
}
