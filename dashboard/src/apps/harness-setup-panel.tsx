import { useCallback, useEffect, useState } from "react";
import {
  HiMiniAdjustmentsHorizontal,
  HiMiniArrowPath,
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniRocketLaunch,
  HiMiniShieldCheck,
  HiMiniTrash,
} from "react-icons/hi2";
import { ActionButton, SectionLabel } from "../approval-center-primitives";
import { formatRelativeTime, harnessDisplayName } from "../approval-center-utils";
import { ApprovalProofModal } from "../approval-proof-modal";
import { isGuardDemoMode } from "../guard-demo";
import {
  fetchSettings,
  fetchGuardApi,
  formatHarnessCommand,
  GuardHarnessActionError,
  runHarnessAction,
} from "../guard-api";
import type {
  GuardApprovalGatePublicConfig,
  GuardHarnessAction,
  GuardHarnessActionErrorPayload,
  GuardHarnessActionResult,
  GuardHarnessSetupStep,
  GuardManagedInstall,
} from "../guard-types";

type HarnessSetupState =
  | { kind: "idle" }
  | { kind: "loading"; action: GuardHarnessAction }
  | { kind: "ready"; plan: GuardHarnessActionResult }
  | { kind: "success"; action: GuardHarnessAction; result: GuardHarnessActionResult }
  | { kind: "error"; action: GuardHarnessAction; message: string; confirmationPhrase?: string; confirmCommand?: string };

export function HarnessSetupPanel(props: {
  harness: string;
  install: GuardManagedInstall | undefined;
  status: "active" | "needs_setup" | "observed" | "unknown";
  onManagedInstallChanged?: () => Promise<void>;
}) {
  const [setupState, setSetupState] = useState<HarnessSetupState>({ kind: "idle" });
  const [disconnectArmed, setDisconnectArmed] = useState(false);
  const [approvalGate, setApprovalGate] = useState<GuardApprovalGatePublicConfig | null | undefined>(undefined);
  const [gateLoadFailed, setGateLoadFailed] = useState(false);
  const active = props.install?.active === true;
  const displayName = harnessDisplayName(props.harness);
  const gateLoaded = approvalGate !== undefined;
  const disconnectRequiresProof = approvalGate?.enabled === true;

  useEffect(() => {
    let cancelled = false;
    void fetchSettings()
      .then((payload) => {
        if (!cancelled) {
          setApprovalGate(payload.settings.approval_gate ?? null);
          setGateLoadFailed(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setApprovalGate(undefined);
          setGateLoadFailed(true);
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const refreshAfterMutation = useCallback(async () => {
    await props.onManagedInstallChanged?.();
  }, [props.onManagedInstallChanged]);

  const loadPlan = useCallback(async () => {
    setSetupState({ kind: "loading", action: active ? "verify" : "install" });
    try {
      const result = active
        ? await runHarnessAction({ harness: props.harness, action: "verify" })
        : await runHarnessAction({ harness: props.harness, action: "install", dryRun: true });
      setSetupState({ kind: "ready", plan: result });
    } catch (error) {
      setSetupState({
        kind: "error",
        action: active ? "verify" : "install",
        message: error instanceof Error ? error.message : "Unable to load setup plan.",
      });
    }
  }, [active, props.harness]);

  useEffect(() => {
    void loadPlan();
  }, [loadPlan]);

  const runAction = useCallback(
    async (action: GuardHarnessAction, options: {
      dryRun?: boolean;
      confirmationPhrase?: string;
      approval_password?: string;
      approval_totp_code?: string;
    } = {}) => {
      setSetupState({ kind: "loading", action });
      try {
        const result = action === "uninstall" && options.dryRun !== true
          ? await runDisconnectWithProof({
              harness: props.harness,
              confirmationPhrase: options.confirmationPhrase ?? `disconnect-${props.harness}`,
              approval_password: options.approval_password,
              approval_totp_code: options.approval_totp_code,
            })
          : await runHarnessAction({
              harness: props.harness,
              action,
              dryRun: options.dryRun,
              confirmationPhrase: options.confirmationPhrase,
            });
        if (!(action === "uninstall" && options.dryRun === true)) {
          setDisconnectArmed(false);
        }
        setSetupState({ kind: "success", action, result });
        if (action !== "verify" && options.dryRun !== true) {
          await refreshAfterMutation();
        }
      } catch (error) {
        if (error instanceof GuardHarnessActionError) {
          setSetupState({
            kind: "error",
            action,
            message: setupActionErrorMessage(error),
            confirmationPhrase: error.payload?.confirmation_phrase,
            confirmCommand: error.payload?.confirm_command,
          });
        } else {
          setSetupState({
            kind: "error",
            action,
            message: error instanceof Error ? error.message : "Harness action failed.",
          });
        }
      }
    },
    [props.harness, refreshAfterMutation]
  );

  const handleConnect = useCallback(() => {
    void runAction("install", { dryRun: false });
  }, [runAction]);

  const handleVerify = useCallback(() => {
    void runAction("verify");
  }, [runAction]);

  const handleRepair = useCallback(() => {
    void runAction("repair", { dryRun: false });
  }, [runAction]);

  const handleRequestDisconnect = useCallback(() => {
    setDisconnectArmed(true);
    void runAction("uninstall", { dryRun: true });
  }, [runAction]);

  const disconnectPhrase = useCallback(() => {
    if (setupState.kind === "error" && setupState.confirmationPhrase) {
      return setupState.confirmationPhrase;
    }
    if (setupState.kind === "success" && setupState.result.confirmation_phrase) {
      return setupState.result.confirmation_phrase;
    }
    return `disconnect-${props.harness}`;
  }, [props.harness, setupState]);

  const handleConfirmDisconnect = useCallback((
    credentials?: { approval_password?: string; approval_totp_code?: string },
  ) => {
    void runAction("uninstall", {
      dryRun: false,
      confirmationPhrase: disconnectPhrase(),
      approval_password: credentials?.approval_password,
      approval_totp_code: credentials?.approval_totp_code,
    });
  }, [disconnectPhrase, runAction]);

  const handleCancelDisconnect = useCallback(() => {
    setDisconnectArmed(false);
    void loadPlan();
  }, [loadPlan]);

  const busy = setupState.kind === "loading";
  let currentPlan: GuardHarnessActionResult | null = null;
  if (setupState.kind === "ready") {
    currentPlan = setupState.plan;
  } else if (setupState.kind === "success") {
    currentPlan = setupState.result;
  }
  const steps = setupStepsFor(currentPlan, active);
  const notes = setupNotesFor(currentPlan);
  const showSimpleConfirm = active && disconnectArmed && gateLoaded && !disconnectRequiresProof && !gateLoadFailed;
  const showProofModal = active && disconnectArmed && disconnectRequiresProof && approvalGate != null;

  return (
    <div className="rounded-2xl border border-brand-blue/15 bg-gradient-to-br from-brand-blue/[0.055] via-white to-brand-dark/[0.025] p-4 shadow-sm sm:p-5">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between">
        <div className="min-w-0">
          <SectionLabel>Local harness install</SectionLabel>
          <h3 className="mt-2 text-lg font-semibold text-brand-dark">
            {active ? `${displayName} is managed by Guard` : `Connect ${displayName} from this dashboard`}
          </h3>
          <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
            {active
              ? "Run safe checks, repair managed hooks, or disconnect this app without leaving the dashboard."
              : "Guard will install the local managed hooks through the daemon. No copied shell command required."}
          </p>
        </div>
        <div className="flex shrink-0 flex-wrap gap-2 max-xl:w-full max-xl:justify-start">
          {!active && (
            <ActionButton onClick={handleConnect} disabled={busy} data-primary="true">
              <HiMiniRocketLaunch className="h-4 w-4" aria-hidden="true" />
              {busy && setupState.kind === "loading" && setupState.action === "install" ? "Connecting..." : "Connect app"}
            </ActionButton>
          )}
          {active && (
            <>
              <ActionButton onClick={handleVerify} disabled={busy} variant="outline">
                <HiMiniShieldCheck className="h-4 w-4" aria-hidden="true" />
                Test
              </ActionButton>
              <ActionButton onClick={handleRepair} disabled={busy} variant="outline">
                <HiMiniArrowPath className="h-4 w-4" aria-hidden="true" />
                Repair
              </ActionButton>
            </>
          )}
        </div>
      </div>

      <div className="mt-5 grid gap-3 md:grid-cols-3">
        <SetupMetric label="Install state" value={installStateLabel(active, props.status)} active={active} />
        <SetupMetric label="Config source" value={props.install?.workspace ?? "Local machine"} />
        <SetupMetric label="Last changed" value={props.install ? formatRelativeTime(props.install.updated_at) : "Not yet"} />
      </div>

      {setupState.kind === "error" && (
        <div className="mt-4 rounded-xl border border-brand-attention/15 bg-brand-attention/[0.04] p-4">
          <div className="flex items-start gap-3">
            <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-brand-dark">Could not finish {setupActionLabel(setupState.action)}</p>
              <p className="mt-1 break-words text-sm text-muted-foreground">{setupState.message}</p>
              {setupState.confirmCommand && (
                <code className="mt-3 block overflow-x-auto rounded-lg bg-white/80 px-3 py-2 font-mono text-xs text-brand-dark">
                  {setupState.confirmCommand}
                </code>
              )}
            </div>
          </div>
        </div>
      )}

      {setupState.kind === "success" && (
        <div className="mt-4 rounded-xl border border-brand-green/20 bg-brand-green/[0.045] p-4">
          <div className="flex items-start gap-3">
            <HiMiniCheckCircle className="mt-0.5 h-5 w-5 shrink-0 text-brand-green" aria-hidden="true" />
            <div className="min-w-0">
              <p className="text-sm font-semibold text-brand-dark">{setupSuccessTitle(setupState.action, displayName)}</p>
              <p className="mt-1 text-sm text-muted-foreground">
                {setupState.action === "verify"
                  ? "Safe local check completed. No app config was changed."
                  : "Dashboard action completed through the local Guard daemon."}
              </p>
            </div>
          </div>
        </div>
      )}

      {steps.length > 0 && (
        <div className="mt-5 space-y-2">
          {steps.map((step) => (
            <HarnessSetupStepRow key={step.step_id} step={step} />
          ))}
        </div>
      )}

      {notes.length > 0 && (
        <div className="mt-4 rounded-xl border border-slate-200/70 bg-white/80 p-4">
          <p className="text-xs font-semibold uppercase tracking-widest text-slate-400">What changed</p>
          <ul className="mt-2 space-y-1.5">
            {notes.slice(0, 4).map((note) => (
              <li key={note} className="break-words text-xs leading-relaxed text-muted-foreground">
                {note}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="mt-5 flex flex-wrap items-center gap-2 border-t border-slate-200/70 pt-4">
        <button
          onClick={() => void loadPlan()}
          disabled={busy}
          className="inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
        >
          Refresh setup
        </button>
        {active && !disconnectArmed && (
          <button
            onClick={handleRequestDisconnect}
            disabled={busy}
            className="inline-flex min-h-10 items-center gap-1.5 rounded-lg border border-brand-attention/20 bg-white px-3 text-sm font-medium text-brand-attention transition-colors hover:bg-brand-attention/[0.04] disabled:opacity-50"
          >
            <HiMiniTrash className="h-4 w-4" aria-hidden="true" />
            Disconnect
          </button>
        )}
        {showSimpleConfirm && (
          <>
            <button
              onClick={() => handleConfirmDisconnect()}
              disabled={busy}
              className="inline-flex min-h-10 items-center rounded-lg bg-brand-attention px-3 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-50"
            >
              {busy && setupState.kind === "loading" && setupState.action === "uninstall" ? "Disconnecting..." : "Confirm disconnect"}
            </button>
            <button
              onClick={handleCancelDisconnect}
              disabled={busy}
              className="inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
            >
              Keep connected
            </button>
          </>
        )}
        {active && disconnectArmed && !showSimpleConfirm && (
          <button
            onClick={handleCancelDisconnect}
            disabled={busy}
            className="inline-flex min-h-10 items-center rounded-lg border border-slate-200 bg-white px-3 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50 disabled:opacity-50"
          >
            Keep connected
          </button>
        )}
      </div>
      {active && disconnectArmed && !gateLoaded && !gateLoadFailed ? (
        <p className="mt-3 text-sm text-muted-foreground">Checking approval requirements before disconnect.</p>
      ) : null}
      {active && disconnectArmed && gateLoadFailed ? (
        <p className="mt-3 text-sm text-brand-attention" role="alert">
          Guard could not load approval settings. Keep the app connected and retry disconnect.
        </p>
      ) : null}
      {showProofModal ? (
        <ApprovalProofModal
          title={`Disconnect ${displayName}`}
          detail={
            approvalGate.totp_enabled === true
              ? "Enter a fresh authenticator code to remove Guard protection from this app."
              : "Enter your approval password to remove Guard protection from this app."
          }
          confirmLabel="Disconnect app"
          busyLabel="Disconnecting..."
          approvalGate={approvalGate}
          requireFreshTotp={approvalGate.totp_enabled === true}
          busy={busy && setupState.kind === "loading" && setupState.action === "uninstall"}
          error={setupState.kind === "error" && setupState.action === "uninstall" ? setupState.message : null}
          onCancel={handleCancelDisconnect}
          onConfirm={handleConfirmDisconnect}
        />
      ) : null}
    </div>
  );
}

async function runDisconnectWithProof(input: {
  harness: string;
  confirmationPhrase: string;
  approval_password?: string;
  approval_totp_code?: string;
}): Promise<GuardHarnessActionResult> {
  if (isGuardDemoMode()) {
    return {
      harness: input.harness,
      action: "uninstall",
      dry_run: false,
      steps: [],
    };
  }
  const response = await fetchGuardApi(
    `/v1/harnesses/${encodeURIComponent(input.harness)}/uninstall`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        dry_run: false,
        confirmation_phrase: input.confirmationPhrase,
        ...(input.approval_password ? { approval_password: input.approval_password } : {}),
        ...(input.approval_totp_code ? { approval_totp_code: input.approval_totp_code } : {}),
      }),
    },
  );
  const payload = (await response.json().catch(() => null)) as unknown;
  if (!response.ok) {
    throw new GuardHarnessActionError(
      response.status,
      isHarnessActionErrorPayload(payload) ? payload : null,
    );
  }
  return payload as GuardHarnessActionResult;
}

function isHarnessActionErrorPayload(value: unknown): value is GuardHarnessActionErrorPayload {
  return typeof value === "object" && value !== null && typeof (value as { error?: unknown }).error === "string";
}

function HarnessSetupStepRow({ step }: { step: GuardHarnessSetupStep }) {
  const commandText = formatHarnessCommand(step.command);
  return (
    <div className="rounded-xl border border-slate-200/70 bg-white/80 p-3">
      <div className="flex items-start gap-3">
        <span className="mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-brand-blue">
          {step.writes_config ? <HiMiniAdjustmentsHorizontal className="h-3.5 w-3.5" aria-hidden="true" /> : <HiMiniCheckCircle className="h-3.5 w-3.5" aria-hidden="true" />}
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-brand-dark">{step.title}</p>
          <p className="mt-0.5 text-xs leading-relaxed text-muted-foreground">{step.body}</p>
          {commandText && (
            <code className="mt-2 block overflow-x-auto rounded-lg bg-slate-50 px-3 py-2 font-mono text-xs text-brand-dark">
              {commandText}
            </code>
          )}
        </div>
      </div>
    </div>
  );
}

function SetupMetric(props: { label: string; value: string; active?: boolean }) {
  return (
    <div className="min-w-0 rounded-xl border border-slate-200/70 bg-white/80 p-3">
      <p className="text-[10px] font-semibold uppercase tracking-widest text-slate-400">{props.label}</p>
      <p className={`mt-1 truncate text-sm font-semibold ${props.active ? "text-brand-green" : "text-brand-dark"}`}>
        {props.value}
      </p>
    </div>
  );
}
function installStateLabel(
  active: boolean,
  status: "active" | "needs_setup" | "observed" | "unknown",
): string {
  if (active) return "Installed";
  if (status === "observed") return "Observed";
  return "Not connected";
}

function setupStepsFor(result: GuardHarnessActionResult | null, active: boolean): GuardHarnessSetupStep[] {
  if (!result) return [];
  if (Array.isArray(result.steps) && result.steps.length > 0) return result.steps;
  if (result.verification?.steps) return result.verification.steps;
  if (!active && result.contract?.setup_steps) return result.contract.setup_steps;
  if (active && result.contract?.verify_steps) return result.contract.verify_steps;
  return [];
}
function setupNotesFor(result: GuardHarnessActionResult | null): string[] {
  const manifest = result?.managed_install?.manifest;
  const notes = manifest?.["notes"];
  return Array.isArray(notes) ? notes.filter((note): note is string => typeof note === "string") : [];
}

function setupActionLabel(action: GuardHarnessAction): string {
  if (action === "install") return "connect";
  if (action === "verify") return "test";
  if (action === "repair") return "repair";
  return "disconnect";
}

function setupActionErrorMessage(error: GuardHarnessActionError): string {
  if (error.payload?.error === "confirmation_required") {
    return "Disconnect requires confirmation so accidental clicks cannot remove local protection.";
  }
  if (error.payload?.error === "approval_gate_totp_required") {
    return "Enter a fresh authenticator code to disconnect this app.";
  }
  if (
    error.payload?.error === "approval_gate_required"
    || error.payload?.error === "approval_gate_password_required"
  ) {
    return "Enter your approval password to disconnect this app.";
  }
  return error.payload?.error ?? error.message;
}
function setupSuccessTitle(action: GuardHarnessAction, displayName: string): string {
  if (action === "install") return `${displayName} connected`;
  if (action === "verify") return `${displayName} test complete`;
  if (action === "repair") return `${displayName} repaired`;
  return `${displayName} disconnected`;
}
