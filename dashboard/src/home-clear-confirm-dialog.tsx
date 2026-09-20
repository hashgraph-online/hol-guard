import { useRef, type ChangeEvent } from "react";
import { HiMiniExclamationTriangle } from "react-icons/hi2";
import { useFocusTrap } from "./use-focus-trap";
import { approvalProofRequiresPassword } from "./approval-proof-inline";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

export function ClearConfirmDialog(props: {
  clearConfirm: { harness?: string; all?: boolean };
  approvalGate: GuardApprovalGatePublicConfig | null;
  clearPassword: string;
  clearTotpCode: string;
  clearError: string | null;
  clearSubmitting: boolean;
  onClearPasswordChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onClearTotpCodeChange: (event: ChangeEvent<HTMLInputElement>) => void;
  onCancelClear: () => void;
  onConfirmClear: () => Promise<void>;
}) {
  const dialogRef = useRef<HTMLDivElement>(null);
  useFocusTrap(true, dialogRef);
  const needsProof = props.approvalGate?.enabled === true && props.approvalGate.configured === true;
  const needsPassword = approvalProofRequiresPassword(props.approvalGate);
  const proofIncomplete = needsProof
    && (needsPassword ? props.clearPassword.trim() === "" : props.clearTotpCode.trim() === "");

  return (
    <div className="guard-fade-in fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm" role="dialog" aria-modal="true" aria-label="Confirm clear decisions">
      <div ref={dialogRef} className="guard-fade-in w-full max-w-md rounded-2xl border border-brand-attention/20 bg-white p-6 shadow-2xl">
            <div className="flex items-start gap-3">
              <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention" aria-hidden="true" />
              <div>
                <h3 className="text-lg font-semibold tracking-tight text-brand-dark">
                  Clear remembered decisions?
                </h3>
                <p className="mt-2 text-sm text-muted-foreground">
                  This will remove {props.clearConfirm.all ? "all saved approvals" : `decisions for ${props.clearConfirm.harness ?? "this app"}`}. Guard will ask again next time matching actions run.
                </p>
                {needsProof && (
                  <div className="mt-4 grid gap-3">
                    {needsPassword ? (
                      <label className="block">
                      <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Approval password</span>
                      <input
                        type="password"
                        autoComplete="current-password"
                        value={props.clearPassword}
                        onChange={props.onClearPasswordChange}
                        className="mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                      />
                      </label>
                    ) : (
                      <label className="block">
                        <span className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-500">Authenticator code</span>
                        <input
                          type="text"
                          inputMode="numeric"
                          pattern="[0-9]*"
                          maxLength={6}
                          value={props.clearTotpCode}
                          onChange={props.onClearTotpCodeChange}
                          placeholder="123456"
                          autoComplete="one-time-code"
                          className="mt-1 min-h-10 w-full rounded-xl border border-slate-200 bg-white px-3 text-sm tracking-[0.28em] text-brand-dark focus:border-brand-blue focus:outline-none focus:ring-2 focus:ring-brand-blue/20"
                        />
                      </label>
                    )}
                  </div>
                )}
                {props.clearError !== null && (
                  <p className="mt-3 rounded-xl border border-brand-attention/20 bg-brand-attention/[0.04] px-3 py-2 text-sm text-brand-dark">
                    {props.clearError}
                  </p>
                )}
              </div>
            </div>
            <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end">
              <button
                type="button"
                onClick={props.onCancelClear}
                className="inline-flex min-h-11 items-center justify-center rounded-lg border border-slate-200 bg-white px-4 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
              >
                Keep decisions
              </button>
              <button
                type="button"
                onClick={props.onConfirmClear}
                disabled={props.clearSubmitting || proofIncomplete}
                className="inline-flex min-h-11 items-center justify-center rounded-lg bg-brand-attention px-4 text-sm font-semibold text-white transition-colors hover:bg-brand-attention/90 disabled:opacity-60"
              >
                {props.clearSubmitting ? "Clearing..." : "Clear decisions"}
              </button>
            </div>
          </div>
        </div>
  );
}
