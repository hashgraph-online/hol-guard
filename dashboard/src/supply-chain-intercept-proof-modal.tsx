import {
  HiMiniCheckCircle,
  HiMiniExclamationTriangle,
  HiMiniXMark,
} from "react-icons/hi2";
import { ActionButton, Tag } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import type { InterceptProofSnapshot } from "./supply-chain-intercept-proof";

type InterceptProofModalProps = {
  proof: InterceptProofSnapshot;
  onClose: () => void;
};

function ManagerProofRow({
  manager,
  detail,
  interceptRan,
}: {
  manager: string;
  detail: string;
  interceptRan: boolean;
}) {
  return (
    <div className="rounded-xl border border-slate-100 bg-slate-50/80 px-3 py-2.5">
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono text-sm font-semibold text-brand-dark">{manager}</span>
        <Tag tone={interceptRan ? "green" : "attention"}>
          {interceptRan ? "Proof recorded" : "Needs attention"}
        </Tag>
      </div>
      <p className="mt-1.5 text-xs leading-relaxed text-slate-600">{detail}</p>
    </div>
  );
}

export function InterceptProofModal({ proof, onClose }: InterceptProofModalProps) {
  const toneClass = proof.interceptProved
    ? "border-brand-green/20 bg-brand-green/[0.04]"
    : "border-brand-attention/20 bg-brand-attention/[0.04]";
  const Icon = proof.interceptProved ? HiMiniCheckCircle : HiMiniExclamationTriangle;
  const iconClass = proof.interceptProved ? "text-brand-green" : "text-brand-attention";

  return (
    <div
      role="dialog"
      aria-label="Intercept proof details"
      aria-modal="true"
      className="fixed inset-0 z-50 flex items-end sm:items-center justify-center p-4"
      data-testid="intercept-proof-modal"
    >
      <div className="absolute inset-0 bg-black/30 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <div className="relative flex max-h-[85vh] w-full max-w-lg flex-col overflow-hidden rounded-2xl bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-100 px-5 py-4">
          <div>
            <p className="text-base font-semibold text-brand-dark">Intercept proof</p>
            <p className="mt-1 text-sm text-slate-500">
              Guard ran a controlled package-manager call to verify shim interception.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close intercept proof modal"
            className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full text-slate-400 hover:bg-slate-100 hover:text-slate-600"
          >
            <HiMiniXMark className="h-5 w-5" aria-hidden="true" />
          </button>
        </div>

        <div className="space-y-4 overflow-y-auto px-5 py-4">
          <div className={`rounded-xl border px-4 py-3 ${toneClass}`}>
            <div className="flex items-start gap-2.5">
              <Icon className={`mt-0.5 h-4 w-4 shrink-0 ${iconClass}`} aria-hidden="true" />
              <div>
                <p className="text-sm font-medium text-brand-dark">{proof.summary}</p>
                {proof.timestamp !== null && (
                  <p className="mt-1 text-xs text-slate-500">
                    Recorded {formatRelativeTime(proof.timestamp)}
                  </p>
                )}
              </div>
            </div>
          </div>

          {proof.managerResults.length > 0 ? (
            <div className="space-y-2">
              <p className="text-[11px] font-semibold uppercase tracking-[0.16em] text-slate-400">
                Manager results
              </p>
              {proof.managerResults.map((entry) => (
                <ManagerProofRow
                  key={entry.manager}
                  manager={entry.manager}
                  detail={entry.detail}
                  interceptRan={entry.interceptRan}
                />
              ))}
            </div>
          ) : null}

          {proof.pathRepairRequired.length > 0 ? (
            <div className="rounded-xl border border-amber-200 bg-amber-50/70 px-3 py-2.5">
              <p className="text-xs font-medium text-amber-950">PATH repair still required</p>
              <p className="mt-1 text-xs text-amber-900/90">
                {proof.pathRepairRequired.join(", ")} need repair before intercept proof can complete.
              </p>
            </div>
          ) : null}

          {proof.receiptId !== null ? (
            <div className="rounded-xl border border-slate-100 bg-slate-50 px-3 py-2.5">
              <p className="text-[10px] font-semibold uppercase tracking-[0.18em] text-slate-400">
                Proof receipt
              </p>
              <p className="mt-1 break-all font-mono text-xs text-brand-dark">{proof.receiptId}</p>
            </div>
          ) : null}
        </div>

        <div className="border-t border-slate-100 px-5 py-4">
          <ActionButton variant="primary" onClick={onClose}>
            Done
          </ActionButton>
        </div>
      </div>
    </div>
  );
}
