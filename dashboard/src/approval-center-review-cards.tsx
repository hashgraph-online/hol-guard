import { HiMiniCheck, HiMiniXMark } from "react-icons/hi2";
import type { GuardApprovalRequest } from "./guard-types";

type WhyThisPausedProps = {
  item: GuardApprovalRequest;
};

export function WhyThisPaused(props: WhyThisPausedProps) {
  const signals = props.item.decision_v2_json?.signals ?? [];
  const plainReasons = signals
    .filter((s) => s.plain_reason.trim().length > 0)
    .map((s) => s.plain_reason);

  const reasons: string[] =
    plainReasons.length > 0
      ? plainReasons
      : props.item.why_now
        ? [props.item.why_now]
        : [];

  if (reasons.length === 0) return null;

  return (
    <div className="mt-3 space-y-1">
      <p className="font-mono text-[11px] font-semibold uppercase tracking-[0.2em] text-muted-foreground">
        Why this was paused
      </p>
      <ul className="space-y-1">
        {reasons.map((reason) => (
          <li key={reason} className="flex items-start gap-2 text-sm text-brand-dark/80">
            <span className="mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full bg-brand-purple/60" />
            {reason}
          </li>
        ))}
      </ul>
    </div>
  );
}

type ApproveConsequenceProps = {
  retryInstruction: string | null;
};

export function ApproveConsequence(props: ApproveConsequenceProps) {
  const text =
    props.retryInstruction !== null
      ? `If you approve: ${props.retryInstruction}`
      : "If you approve: HOL Guard will let this action run and remember your choice within the selected scope.";
  return (
    <div className="flex items-start gap-2">
      <HiMiniCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-green" aria-hidden="true" />
      <p className="text-xs leading-5 text-muted-foreground">{text}</p>
    </div>
  );
}

export function BlockConsequence() {
  return (
    <div className="flex items-start gap-2">
      <HiMiniXMark className="mt-0.5 h-3.5 w-3.5 shrink-0 text-brand-purple" aria-hidden="true" />
      <p className="text-xs leading-5 text-muted-foreground">
        If you block: HOL Guard will stop this action and you can allow it again any time from the
        Review Queue.
      </p>
    </div>
  );
}

export function KeyboardHints() {
  return (
    <div className="mt-4 hidden items-center gap-4 text-xs text-muted-foreground md:flex">
      <span className="flex items-center gap-1.5">
        <kbd className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px]">
          A
        </kbd>
        Approve
      </span>
      <span className="flex items-center gap-1.5">
        <kbd className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 font-mono text-[11px]">
          B
        </kbd>
        Block
      </span>
      <span className="text-slate-400">·</span>
      <span>Keyboard shortcuts available after reviewing above</span>
    </div>
  );
}

type ConfirmModalProps = {
  action: "allow" | "block";
  scopeLabel: string;
  onConfirm: () => void;
  onCancel: () => void;
};

export function ConfirmModal(props: ConfirmModalProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/30 p-4 backdrop-blur-sm">
      <div className="w-full max-w-md rounded-2xl border border-slate-200 bg-white p-6 shadow-2xl">
        <h2 className="text-lg font-semibold tracking-tight text-brand-dark">
          Broad approval — are you sure?
        </h2>
        <p className="mt-3 text-sm leading-6 text-brand-dark/70">
          This will remember your choice for {props.scopeLabel}. This is harder to undo.
        </p>
        <div className="mt-5 flex flex-col gap-2 sm:flex-row sm:justify-end">
          <button
            type="button"
            onClick={props.onCancel}
            className="rounded-full border border-slate-200 bg-white px-4 py-2 text-sm font-medium text-brand-dark transition-colors hover:bg-slate-50"
          >
            Go back
          </button>
          <button
            type="button"
            onClick={props.onConfirm}
            className="rounded-full bg-brand-blue px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-brand-blue/90"
          >
            Confirm {props.scopeLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
