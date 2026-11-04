import { useEffect, useState } from "react";
import { PULSE_APPROVAL_EVENT, type PulseApprovalDetail } from "./pulse-approval";

const STATUS_COPY: Record<PulseApprovalDetail["status"], string> = {
  pending: "Approve this in the YID app with your face scan.",
  approved: "Approved in the YID app. Verifying the receipt…",
  rejected: "Rejected in the YID app. The action stays blocked.",
  expired: "The Pulse request expired. The action stays blocked.",
  error: "Yanez Pulse is unreachable. The action stays blocked.",
  cancelled: "Pulse approval cancelled.",
};

/** Shows the match code while a gated request waits on the YID app. */
export function PulseApprovalOverlay() {
  const [detail, setDetail] = useState<PulseApprovalDetail | null>(null);

  useEffect(() => {
    const onEvent = (event: Event) => {
      setDetail((event as CustomEvent<PulseApprovalDetail>).detail);
    };
    window.addEventListener(PULSE_APPROVAL_EVENT, onEvent);
    return () => window.removeEventListener(PULSE_APPROVAL_EVENT, onEvent);
  }, []);

  useEffect(() => {
    if (detail === null || detail.status === "pending") return;
    const timer = setTimeout(() => setDetail(null), 4000);
    return () => clearTimeout(timer);
  }, [detail]);

  if (detail === null) return null;
  return (
    <div
      role="status"
      aria-live="polite"
      className="fixed bottom-4 right-4 z-50 w-full max-w-sm rounded-xl border border-brand-blue/20 bg-white p-4 shadow-xl"
    >
      <p className="text-xs font-semibold uppercase tracking-wide text-brand-blue">Yanez Pulse</p>
      <p className="mt-1 text-sm text-brand-dark">{STATUS_COPY[detail.status]}</p>
      {detail.status === "pending" && detail.matchCode ? (
        <p className="mt-2 text-sm text-slate-600">
          Match code <strong className="font-mono text-base tracking-widest text-brand-dark">{detail.matchCode}</strong>
        </p>
      ) : null}
    </div>
  );
}
