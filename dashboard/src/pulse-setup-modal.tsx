import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { HiMiniXMark } from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import {
  authorizeApprovalGatePulseSetup,
  beginApprovalGatePulseEnrollment,
  confirmApprovalGatePulseEnrollment,
  fetchWithGuardAuth,
  type GuardPulseEnrollment,
} from "./guard-api";
import type { GuardSettingsPayload } from "./guard-types";
import { waitForPulseApproval } from "./pulse-approval";
import { GuardModalLayer } from "./guard-modal-layer";

export const PULSE_SITE_URL = "https://pulse.yanez.ai";

const ENROLLMENT_OUTCOME_MESSAGES = {
  rejected: "The enrollment was rejected in the YID app.",
  expired: "The enrollment was not approved within 15 minutes. Try again.",
  error: "Guard couldn't reach Yanez Pulse. Check your internet connection and try again.",
  cancelled: "Pulse setup was cancelled.",
} as const;

type SetupStep = "confirm" | "connect" | "approve" | "verifying" | "recovery";

const STEP_TEXT: Record<SetupStep, { label: string; title: string; description: string }> = {
  confirm: {
    label: "Step 1 of 3",
    title: "Confirm your approval password",
    description: "Guard needs your approval password before you connect the YID app.",
  },
  connect: {
    label: "Step 2 of 3",
    title: "Connect the YID app",
    description: "Create an agent key for HOL Guard in the YID app and paste it here.",
  },
  approve: {
    label: "Step 3 of 3",
    title: "Approve in the YID app",
    description: "Open the YID app, check the match code and approve with a face scan.",
  },
  verifying: {
    label: "Step 3 of 3",
    title: "Approve in the YID app",
    description: "Open the YID app, check the match code and approve with a face scan.",
  },
  recovery: {
    label: "Done",
    title: "Save your recovery code",
    description: "Pulse is now your approval factor. Keep this code offline: with your approval password it turns Pulse off if you lose the YID app.",
  },
};

const LABEL_CLASS = "text-xs font-semibold uppercase tracking-[0.18em] text-slate-500";
const INPUT_CLASS =
  "mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20";

export function pulseCooldownLabel(seconds: number): string {
  if (seconds === 900) return "15 minutes, same kind of action";
  if (seconds === 3600) return "1 hour, same kind of action";
  return "Every action (recommended)";
}

function ErrorNote({ message }: { message: string | null }) {
  if (message === null) return null;
  return (
    <p role="alert" className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
      {message}
    </p>
  );
}

function Field(props: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="block">
      <span className={LABEL_CLASS}>{props.label}</span>
      {props.children}
      {props.hint ? <p className="mt-1 text-xs text-slate-500">{props.hint}</p> : null}
    </label>
  );
}

/** Pulse setup in the same three-step window as the authenticator setup. */
export function PulseSetupModal(props: {
  totpEnabled: boolean;
  onSettingsPayload: (payload: GuardSettingsPayload) => void;
  onClose: () => void;
}) {
  const [step, setStep] = useState<SetupStep>("confirm");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [agentKey, setAgentKey] = useState("");
  const [cooldown, setCooldown] = useState<0 | 900 | 3600>(0);
  const [enrollment, setEnrollment] = useState<GuardPulseEnrollment | null>(null);
  const [recoveryCode, setRecoveryCode] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cancelWait = useRef<AbortController | null>(null);

  // Closing the window stops the wait for the YID app.
  useEffect(() => () => cancelWait.current?.abort(), []);

  const run = useCallback(async (action: () => Promise<void>) => {
    setPending(true);
    setError(null);
    try {
      await action();
    } catch (failure) {
      setError(failure instanceof Error ? failure.message : "Pulse setup failed.");
    } finally {
      setPending(false);
    }
  }, []);

  const handleConfirm = useCallback(() => run(async () => {
    await authorizeApprovalGatePulseSetup({
      approval_password: password,
      approval_totp_code: props.totpEnabled ? totpCode.trim() : undefined,
    });
    setPassword("");
    setTotpCode("");
    setStep("connect");
  }), [password, props.totpEnabled, run, totpCode]);

  const handleConnect = useCallback(() => run(async () => {
    const response = await beginApprovalGatePulseEnrollment({ pulse_agent_key: agentKey.trim() });
    // The key is now in Guard's secret store; drop it from page memory.
    setAgentKey("");
    const started = response.pulse_enrollment;
    setEnrollment(started);
    setStep("approve");
    const controller = new AbortController();
    cancelWait.current = controller;
    try {
      const outcome = await waitForPulseApproval(
        fetchWithGuardAuth,
        { requestId: started.request_id, matchCode: started.match_code, decideBy: started.decide_by },
        controller.signal,
      );
      if (outcome !== "approved") throw new Error(ENROLLMENT_OUTCOME_MESSAGES[outcome]);
      setStep("verifying");
      const { pulse_recovery_code: code, ...settings } = await confirmApprovalGatePulseEnrollment({
        request_id: started.request_id,
        cooldown_seconds: cooldown,
      });
      props.onSettingsPayload(settings);
      setRecoveryCode(code);
      setStep("recovery");
    } catch (failure) {
      // Back to step 2: for 15 minutes after step 1, trying again needs only the key.
      setEnrollment(null);
      setStep("connect");
      throw failure;
    } finally {
      cancelWait.current = null;
    }
  }), [agentKey, cooldown, props, run]);

  const text = STEP_TEXT[step];
  const onEnter = (ready: boolean, action: () => void) => (event: { key: string }) => {
    if (event.key === "Enter" && ready && !pending) action();
  };
  const confirmReady = password.trim().length > 0 && (!props.totpEnabled || totpCode.trim().length > 0);
  const connectReady = agentKey.trim().length > 0;

  // The recovery code is shown once: only "I saved it" closes the window then.
  const closeUnlessShowingCode = () => {
    if (step !== "recovery") props.onClose();
  };

  return (
    <GuardModalLayer ariaLabel="Set up Yanez Pulse" onClose={closeUnlessShowingCode} panelClassName="w-full max-w-3xl">
      <div className="max-h-[90vh] overflow-y-auto rounded-3xl border border-brand-blue/15 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-6 py-5">
          <div>
            <SectionLabel>Yanez Pulse setup</SectionLabel>
            <p className="mt-2 text-xs font-medium uppercase tracking-[0.16em] text-slate-500">{text.label}</p>
            <h3 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">{text.title}</h3>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
              {step === "confirm" && props.totpEnabled
                ? "Guard needs your approval password and a current authenticator code before you connect the YID app."
                : text.description}
            </p>
          </div>
          <button
            type="button"
            onClick={closeUnlessShowingCode}
            hidden={step === "recovery"}
            className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-brand-dark"
            aria-label="Close Pulse setup"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        {step === "confirm" ? (
          <div className="space-y-4 p-6">
            <Field label="Approval password">
              <input
                type="password"
                autoComplete="current-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                onKeyDown={onEnter(confirmReady, handleConfirm)}
                className={INPUT_CLASS}
              />
            </Field>
            {props.totpEnabled ? (
              <Field label="Authenticator code">
                <input
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  autoComplete="one-time-code"
                  value={totpCode}
                  onChange={(event) => setTotpCode(event.target.value)}
                  onKeyDown={onEnter(confirmReady, handleConfirm)}
                  placeholder="123456"
                  className="mt-2 min-h-12 w-full rounded-xl border border-slate-200 bg-white px-3 text-center text-lg font-semibold tracking-[0.35em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                />
              </Field>
            ) : null}
            <ErrorNote message={error} />
            <ActionButton onClick={handleConfirm} disabled={pending || !confirmReady}>
              {pending ? "Checking..." : "Continue"}
            </ActionButton>
          </div>
        ) : null}

        {step === "connect" ? (
          <div className="grid gap-5 p-6 lg:grid-cols-[minmax(0,1fr)_300px]">
            <ol className="list-decimal space-y-3 pl-5 text-sm leading-6 text-slate-600">
              <li>
                Scan the QR code on{" "}
                <a className="text-brand-blue underline" href={PULSE_SITE_URL} target="_blank" rel="noreferrer noopener">pulse.yanez.ai</a>{" "}
                with your phone camera. It installs the YanezYID app if needed, then registers your Yanez identity.
              </li>
              <li>
                In the YID app, go to <span className="font-medium text-brand-dark">Settings → Agent Keys</span>, create a key
                named HOL Guard, and paste it here. It starts with <code className="font-mono text-xs">yak_</code>.
              </li>
              <li>If a face scan isn't accepted, just scan again.</li>
            </ol>
            <div className="space-y-4 rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
              <Field label="YID agent key" hint="Hidden as you type. Guard stores it in its secret store.">
                <input
                  type="password"
                  autoComplete="off"
                  spellCheck={false}
                  value={agentKey}
                  onChange={(event) => setAgentKey(event.target.value)}
                  onKeyDown={onEnter(connectReady, handleConnect)}
                  className={INPUT_CLASS}
                />
              </Field>
              <Field label="Cooldown" hint="A cooldown only covers the same kind of action and scope from the same session. Guard changes always ask again.">
                <select
                  value={String(cooldown)}
                  onChange={(event) => {
                    const seconds = Number(event.target.value);
                    setCooldown(seconds === 900 ? 900 : seconds === 3600 ? 3600 : 0);
                  }}
                  className={INPUT_CLASS}
                >
                  {([0, 900, 3600] as const).map((seconds) => (
                    <option key={seconds} value={seconds}>{pulseCooldownLabel(seconds)}</option>
                  ))}
                </select>
              </Field>
              <ErrorNote message={error} />
              <div className="flex flex-wrap gap-2">
                <ActionButton onClick={handleConnect} disabled={pending || !connectReady}>
                  {pending ? "Contacting Pulse..." : "Continue"}
                </ActionButton>
                <ActionButton variant="outline" disabled={pending} onClick={() => { setError(null); setStep("confirm"); }}>
                  Back
                </ActionButton>
              </div>
            </div>
          </div>
        ) : null}

        {(step === "approve" || step === "verifying") && enrollment !== null ? (
          <div className="space-y-4 p-6">
            <div className="rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
              <p className={LABEL_CLASS}>Match code</p>
              <p className="mt-2 font-mono text-3xl font-semibold tracking-[0.35em] text-brand-dark">{enrollment.match_code}</p>
              <p className="mt-2 text-xs text-slate-500">
                The YID app shows the same code for identity {enrollment.yid_hint}. Approve only if they match.
              </p>
            </div>
            <p role="status" className="text-sm text-brand-dark">
              {step === "verifying"
                ? "Approved in the YID app. Checking the approval..."
                : "Waiting for your approval. Guard checks every 10 seconds, for up to 15 minutes."}
            </p>
            {step === "approve" ? (
              <ActionButton variant="outline" onClick={() => cancelWait.current?.abort()}>Cancel</ActionButton>
            ) : null}
          </div>
        ) : null}

        {step === "recovery" && recoveryCode !== null ? (
          <div className="space-y-4 p-6">
            <div role="alert" className="rounded-2xl border border-brand-attention/20 bg-brand-attention/[0.06] p-4">
              <p className={LABEL_CLASS}>Recovery code</p>
              <p className="mt-2 font-mono text-lg tracking-wider text-brand-dark">{recoveryCode}</p>
              <p className="mt-2 text-xs text-slate-600">Guard will not show it again.</p>
            </div>
            <ActionButton onClick={props.onClose}>I saved it</ActionButton>
          </div>
        ) : null}
      </div>
    </GuardModalLayer>
  );
}
