import { HiMiniExclamationTriangle } from "react-icons/hi2";
import { describeSupplyChainRecoveryFailure, type SupplyChainRecoveryOperation } from "./supply-chain-audit-failure";

/**
 * Failure state for the workspace audit setup modal. It stays in the brand
 * palette: attention indigo on its pale surface for the frame, brand dark for
 * the words, and the accessible attention text tone for the next step. The
 * pale attention hue alone is not readable as text, so it only draws the icon
 * and border.
 */
export function SupplyChainAuditFailureNotice(props: {
  message: string;
  approvalStep?: boolean;
  operation?: SupplyChainRecoveryOperation;
}) {
  const failure = describeSupplyChainRecoveryFailure(props.message, {
    approvalStep: props.approvalStep,
    operation: props.operation,
  });
  return (
    <div
      role="alert"
      className="flex items-start gap-3 rounded-xl border border-brand-attention/30 bg-brand-attention-bg px-4 py-3.5"
    >
      <HiMiniExclamationTriangle className="mt-0.5 h-5 w-5 shrink-0 text-brand-attention-text" aria-hidden="true" />
      <div className="min-w-0 space-y-1.5">
        <p className="text-sm font-semibold text-brand-dark">{failure.title}</p>
        <p className="text-sm leading-relaxed text-brand-dark/75">{failure.summary}</p>
        <p className="text-sm font-semibold leading-relaxed text-brand-attention-text">{failure.nextStep}</p>
        {failure.technicalDetail !== "" ? (
          <p className="break-words font-mono text-xs leading-5 text-brand-dark/75">{failure.technicalDetail}</p>
        ) : null}
      </div>
    </div>
  );
}
