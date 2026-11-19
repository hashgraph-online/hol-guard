import { useEffect, useState } from "react";
import {
  PULSE_APPROVAL_EVENT,
  dropFinishedPulseToast,
  nextPulseToasts,
  type PulseApprovalDetail,
} from "./pulse-approval";

const STATUS_COPY: Record<PulseApprovalDetail["status"], string> = {
  pending: "Approve this in the YID app with your face scan.",
  approved: "Approved in the YID app. Verifying the receipt…",
  rejected: "Rejected in the YID app. The action stays blocked.",
  expired: "The Pulse request expired. The action stays blocked.",
  error: "Yanez Pulse is unreachable. The action stays blocked.",
  cancelled: "Pulse approval cancelled.",
};

/**
 * Shows the match code while a gated request waits on the YID app. Each
 * request has its own entry, so one that finishes never hides the match code
 * of another that is still waiting.
 */
export function PulseApprovalOverlay() {
  const [toasts, setToasts] = useState<PulseApprovalDetail[]>([]);

  useEffect(() => {
    const timers = new Set<ReturnType<typeof setTimeout>>();
    const onEvent = (event: Event) => {
      const detail = (event as CustomEvent<PulseApprovalDetail>).detail;
      setToasts((current) => nextPulseToasts(current, detail));
      if (detail.status !== "pending") {
        const timer = setTimeout(() => {
          timers.delete(timer);
          setToasts((current) => dropFinishedPulseToast(current, detail.requestId));
        }, 4000);
        timers.add(timer);
      }
    };
    window.addEventListener(PULSE_APPROVAL_EVENT, onEvent);
    return () => {
      window.removeEventListener(PULSE_APPROVAL_EVENT, onEvent);
      for (const timer of timers) clearTimeout(timer);
    };
  }, []);

  if (toasts.length === 0) return null;
  return (
    <div className="fixed bottom-4 right-4 z-50 w-full max-w-sm space-y-2">
      {toasts.map((detail) => (
        <div
          key={detail.requestId}
          role="status"
          aria-live="polite"
          className="rounded-xl border border-brand-blue/20 bg-white p-4 shadow-xl"
        >
          <p className="text-xs font-semibold uppercase tracking-wide text-brand-blue">Yanez Pulse</p>
          <p className="mt-1 text-sm text-brand-dark">{STATUS_COPY[detail.status]}</p>
          {detail.status === "pending" && detail.matchCode ? (
            <p className="mt-2 text-sm text-slate-600">
              Match code <strong className="font-mono text-base tracking-widest text-brand-dark">{detail.matchCode}</strong>
            </p>
          ) : null}
        </div>
      ))}
    </div>
  );
}
