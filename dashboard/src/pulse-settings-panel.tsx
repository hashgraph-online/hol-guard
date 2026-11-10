import { useCallback, useEffect, useId, useRef, useState, type ChangeEvent } from "react";
import { ActionButton, SectionLabel, Tag } from "./approval-center-primitives";
import { disableApprovalGatePulse, recoverApprovalGatePulse } from "./guard-api";
import type { GuardApprovalGatePublicConfig, GuardSettingsPayload } from "./guard-types";
import { PulseSetupModal, pulseCooldownLabel } from "./pulse-setup-modal";

export { PULSE_SITE_URL, pulseCooldownLabel } from "./pulse-setup-modal";

type Step = "closed" | "setup" | "recover";

type PulseSettingsPanelProps = {
  gateConfig: GuardApprovalGatePublicConfig | null;
  savedGateConfig: GuardApprovalGatePublicConfig | null;
  onSettingsPayload: (payload: GuardSettingsPayload) => void;
};

const INPUT_CLASS =
  "mt-1 min-h-9 w-full rounded-lg border border-slate-200 bg-white px-2.5 py-1.5 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20";

/** Settings > Approval gate > Yanez Pulse: the third factor beside the password and the authenticator. */
export function PulseSettingsPanel({ gateConfig, savedGateConfig, onSettingsPayload }: PulseSettingsPanelProps) {
  const id = useId();
  const pulseEnabled = gateConfig?.pulse_enabled === true;
  const wasConfigured = savedGateConfig?.configured === true;
  const gateActive = savedGateConfig?.enabled === true;
  const totpEnabled = gateConfig?.totp_enabled === true;
  const [step, setStep] = useState<Step>("closed");
  const [password, setPassword] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelDisable = useRef<AbortController | null>(null);

  // Leaving the page stops waiting for the YID app.
  useEffect(() => () => cancelDisable.current?.abort(), []);

  const reset = useCallback(() => {
    setStep("closed");
    setPassword("");
    setRecoveryCode("");
    setError(null);
  }, []);

  const run = useCallback(async (action: () => Promise<void>) => {
    setPending(true);
    setError(null);
    try {
      await action();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Pulse request failed.");
    } finally {
      setPending(false);
    }
  }, []);

  const handleDisable = useCallback(() => run(async () => {
    const controller = new AbortController();
    cancelDisable.current = controller;
    try {
      onSettingsPayload(await disableApprovalGatePulse(controller.signal));
      reset();
    } finally {
      cancelDisable.current = null;
    }
  }), [onSettingsPayload, reset, run]);

  const handleRecover = useCallback(() => run(async () => {
    onSettingsPayload(await recoverApprovalGatePulse({ approval_password: password, pulse_recovery_code: recoveryCode.trim() }));
    reset();
  }), [onSettingsPayload, password, recoveryCode, reset, run]);

  const field = (label: string, value: string, onChange: (value: string) => void) => (
    <label className="block" htmlFor={`${id}-${label}`}>
      <span className="text-xs font-medium text-slate-500">{label}</span>
      <input
        id={`${id}-${label}`}
        type="password"
        autoComplete="off"
        spellCheck={false}
        value={value}
        onChange={(event: ChangeEvent<HTMLInputElement>) => onChange(event.target.value)}
        className={INPUT_CLASS}
      />
    </label>
  );

  return (
    <div className="overflow-hidden rounded-xl border border-brand-blue/15 bg-white">
      <div className="flex items-center justify-between gap-2">
        <div className="px-4 py-3">
          <SectionLabel>Yanez Pulse</SectionLabel>
          <p className="mt-1 max-w-xl text-xs leading-5 text-slate-500">
            Approve in the YID app with a face scan instead of a password or authenticator code.
          </p>
        </div>
        <div className="px-4">
          <Tag tone={pulseEnabled ? "green" : "slate"}>{pulseEnabled ? "Enabled" : "Not connected"}</Tag>
        </div>
      </div>
      <div className="space-y-3 border-t border-slate-100 bg-slate-50/50 px-4 py-3">
        {!gateActive ? (
          <p className="text-xs leading-5 text-slate-500">
            {wasConfigured
              ? "Turn on Ask for proof to manage Yanez Pulse."
              : "Set an approval password first, then connect Yanez Pulse to approve with a face scan."}
          </p>
        ) : pulseEnabled && step === "closed" ? (
          <>
            <p className="text-xs leading-5 text-slate-600">
              Cooldown:{" "}
              {pulseCooldownLabel(gateConfig?.pulse_cooldown_seconds ?? 0)}. Changes to Guard itself always ask again.
            </p>
            <div className="flex flex-wrap gap-2">
              <ActionButton variant="outline" disabled={pending} onClick={handleDisable}>
                {pending ? "Waiting for the YID app…" : "Turn off Pulse"}
              </ActionButton>
              {pending ? (
                <ActionButton variant="outline" onClick={() => cancelDisable.current?.abort()}>Cancel</ActionButton>
              ) : (
                <ActionButton variant="outline" onClick={() => setStep("recover")}>Lost the YID app?</ActionButton>
              )}
            </div>
          </>
        ) : !pulseEnabled ? (
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="max-w-xl space-y-1">
              <p className="text-sm font-medium text-brand-dark">Approve from your phone without typing a password or code.</p>
              <p className="text-xs text-slate-500">
                Setup opens a guided flow for password confirmation, then asks for an agent key from the YID app.
              </p>
            </div>
            <ActionButton variant="outline" onClick={() => setStep("setup")}>Set up Pulse</ActionButton>
          </div>
        ) : null}

        {/* Stays open after Pulse turns on, to show the recovery code. */}
        {step === "setup" ? (
          <PulseSetupModal totpEnabled={totpEnabled} onSettingsPayload={onSettingsPayload} onClose={reset} />
        ) : null}

        {step === "recover" ? (
          <div className="space-y-3">
            <p className="text-xs leading-5 text-slate-600">Enter your approval password and the recovery code you saved when you set up Pulse.</p>
            {field("Approval password", password, setPassword)}
            {field("Recovery code", recoveryCode, setRecoveryCode)}
            <div className="flex gap-2">
              <ActionButton disabled={pending || !password || !recoveryCode.trim()} onClick={handleRecover}>Turn off Pulse</ActionButton>
              <ActionButton variant="outline" disabled={pending} onClick={reset}>Cancel</ActionButton>
            </div>
          </div>
        ) : null}

        {error ? (
          <p role="alert" className="rounded-lg border border-brand-attention/20 bg-brand-attention/[0.06] px-3 py-2 text-sm text-brand-attention">{error}</p>
        ) : null}
      </div>
    </div>
  );
}
