import { HiMiniCheckCircle } from "react-icons/hi2";
import { SectionLabel } from "./approval-center-primitives";
import { formatRelativeTime } from "./approval-center-utils";
import { receiptDescribesRequest } from "./approval-retry-guidance";
import { approvalLeftActionStopped } from "./evidence/approval-outcome";
import { pastDecisionVerb } from "./review-states";
import type { ReviewViewModel } from "./review-workspace";

export function ReviewLastTimeCard({ detail }: { detail: ReviewViewModel }) {
  const { item, receipt, diff } = detail;
  if (!receipt || !receiptDescribesRequest(item, receipt)) return null;
  return <div className="rounded-xl border border-slate-100 p-4 sm:p-5">
    <SectionLabel>Last time</SectionLabel>
    <p className="mt-2 text-sm text-muted-foreground">
      {approvalLeftActionStopped(receipt) ? <>
        You approved a similar action once {formatRelativeTime(receipt.timestamp)}, but it stayed stopped.
      </> : <>
        You previously {pastDecisionVerb(receipt.policy_decision)} a similar action{" "}{formatRelativeTime(receipt.timestamp)}.
      </>}
    </p>
    {diff && diff.changed_fields.length > 0 && <div className="mt-3 rounded-xl border border-slate-200/70 bg-slate-50 p-4">
      <p className="text-sm font-medium text-brand-dark">What changed since then:</p>
      <ul className="mt-2 space-y-1">{diff.changed_fields.map((field) => <li key={field} className="flex items-center gap-2 text-sm text-brand-dark">
        <HiMiniCheckCircle className="h-3.5 w-3.5 shrink-0 text-brand-blue" aria-hidden="true" />{field}
      </li>)}</ul>
    </div>}
  </div>;
}
