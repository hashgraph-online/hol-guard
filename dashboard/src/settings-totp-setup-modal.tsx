import { useRef, type ChangeEvent } from "react";
import { HiMiniXMark } from "react-icons/hi2";
import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { type GuardApprovalGateTotpEnrollment } from "./guard-api";
import { useFocusTrap } from "./use-focus-trap";
import { TotpEnrollmentQrPanel } from "./totp-enrollment-qr-panel";
import { TotpSetupStep, resolveTotpSetupModalTitle, resolveTotpSetupModalDescription } from "./settings-workspace-model";

export function TotpSetupConfirmStep(props: {
  actionPassword: string;
  pending: "enroll" | "verify" | "disable" | null;
  error: string | null;
  onActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmPassword: () => void;
}) {
  return (
    <div className="space-y-4 p-6">
      <label className="block">
        <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Approval password</span>
        <input
          type="password"
          autoComplete="current-password"
          value={props.actionPassword}
          onChange={props.onActionPasswordChange}
          onKeyDown={(event) => {
            if (
              event.key === "Enter"
              && props.actionPassword.trim().length > 0
              && props.pending === null
            ) {
              props.onConfirmPassword();
            }
          }}
          className="mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
        />
      </label>
      {props.error !== null && (
        <p className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
          {props.error}
        </p>
      )}
      <ActionButton onClick={props.onConfirmPassword} disabled={props.pending !== null}>
        {props.pending === "enroll" ? "Continuing..." : "Continue"}
      </ActionButton>
    </div>
  );
}

export function TotpSetupScanStep(props: {
  enrollment: GuardApprovalGateTotpEnrollment;
  deviceLabel: string;
  actionPassword: string;
  totpCode: string;
  pending: "enroll" | "verify" | "disable" | null;
  error: string | null;
  onActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onDeviceLabelChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onVerify: () => void;
}) {
  return (
    <div className="grid gap-5 p-6 lg:grid-cols-[minmax(0,1fr)_260px]">
      <TotpEnrollmentQrPanel enrollment={props.enrollment} />
      <div className="space-y-4 rounded-2xl border border-slate-100 bg-slate-50/70 p-4">
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Approval password</span>
          <input
            type="password"
            autoComplete="current-password"
            value={props.actionPassword}
            onChange={props.onActionPasswordChange}
            className="mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
          <p className="mt-1 text-xs text-slate-500">
            Update this if you changed your approval password after starting setup.
          </p>
        </label>
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Device label</span>
          <input
            type="text"
            value={props.deviceLabel}
            onChange={props.onDeviceLabelChange}
            className="mt-2 min-h-11 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        <label className="block">
          <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Six-digit code</span>
          <input
            type="text"
            inputMode="numeric"
            pattern="[0-9]*"
            maxLength={6}
            value={props.totpCode}
            onChange={props.onTotpCodeChange}
            onKeyDown={(event) => {
              if (
                event.key === "Enter"
                && props.totpCode.trim().length > 0
                && props.pending === null
              ) {
                props.onVerify();
              }
            }}
            placeholder="123456"
            className="mt-2 min-h-12 w-full rounded-xl border border-slate-200 bg-white px-3 text-center text-lg font-semibold tracking-[0.35em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
          />
        </label>
        {props.error !== null && (
          <p className="rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-xs text-brand-dark">
            {props.error}
          </p>
        )}
        <ActionButton onClick={props.onVerify} disabled={props.pending !== null}>
          {props.pending === "verify" ? "Verifying..." : "Finish setup"}
        </ActionButton>
      </div>
    </div>
  );
}

export function TotpSetupModal(props: {
  step: TotpSetupStep;
  enrollment: GuardApprovalGateTotpEnrollment | null;
  deviceLabel: string;
  actionPassword: string;
  totpCode: string;
  pending: "enroll" | "verify" | "disable" | null;
  error: string | null;
  onActionPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onDeviceLabelChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onConfirmPassword: () => void;
  onVerify: () => void;
  onClose: () => void;
}) {
  const modalRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, modalRef);
  const isConfirmStep = props.step === "confirm" || props.enrollment === null;
  const stepLabel = isConfirmStep ? "1" : "2";

  return (
    <div
      className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-brand-dark/45 p-4 backdrop-blur-sm"
      role="dialog"
      aria-modal="true"
      aria-label="Set up authenticator app"
    >
      <div ref={modalRef} className="w-full max-w-3xl overflow-hidden rounded-3xl border border-brand-blue/15 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-4 border-b border-slate-100 px-6 py-5">
          <div>
            <SectionLabel>Authenticator setup</SectionLabel>
            <p className="mt-2 text-xs font-medium uppercase tracking-[0.16em] text-slate-500">
              Step {stepLabel} of 2
            </p>
            <h3 className="mt-2 text-2xl font-semibold tracking-tight text-brand-dark">
              {resolveTotpSetupModalTitle(isConfirmStep)}
            </h3>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-600">
              {resolveTotpSetupModalDescription(isConfirmStep)}
            </p>
          </div>
          <button
            type="button"
            onClick={props.onClose}
            className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-500 transition-colors hover:bg-slate-50 hover:text-brand-dark"
            aria-label="Close authenticator setup"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>
        {isConfirmStep ? (
          <TotpSetupConfirmStep
            actionPassword={props.actionPassword}
            pending={props.pending}
            error={props.error}
            onActionPasswordChange={props.onActionPasswordChange}
            onConfirmPassword={props.onConfirmPassword}
          />
        ) : null}
        {!isConfirmStep && props.enrollment !== null ? (
          <TotpSetupScanStep
            enrollment={props.enrollment}
            deviceLabel={props.deviceLabel}
            actionPassword={props.actionPassword}
            totpCode={props.totpCode}
            pending={props.pending}
            error={props.error}
            onActionPasswordChange={props.onActionPasswordChange}
            onDeviceLabelChange={props.onDeviceLabelChange}
            onTotpCodeChange={props.onTotpCodeChange}
            onVerify={props.onVerify}
          />
        ) : null}
      </div>
    </div>
  );
}
