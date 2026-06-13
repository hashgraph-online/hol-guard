import { scopeLabel } from "./approval-center-utils";

const REVIEW_SCOPE_LADDER = [
  { scope: "artifact", detail: "Guard remembers only the next matching retry." },
  { scope: "workspace", detail: "Guard remembers the same action in this project folder." },
  { scope: "publisher", detail: "Guard remembers actions from the same source in this app." },
  { scope: "harness", detail: "Guard remembers the action across this app." },
  { scope: "global", detail: "Guard remembers the action on every project on this device." },
] as const;

type PolicyRememberedRulesRightRailProps = {
  onOpenCloudExceptions: () => void;
};

export function PolicyRememberedRulesRightRail({
  onOpenCloudExceptions,
}: PolicyRememberedRulesRightRailProps) {
  return (
    <aside className="space-y-4 lg:sticky lg:top-4">
      <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-4 text-sm text-slate-600">
        <p className="font-medium text-brand-dark">Remembered rules vs Cloud exceptions</p>
        <ul className="mt-2 list-disc space-y-1 pl-5">
          <li>Review and Inbox keep fast allow/block decisions for the work in front of you.</li>
          <li>Remembered rules on this tab explain what Guard will do next time for matching actions.</li>
          <li>Cloud exceptions are separate governed risk acceptances managed in Guard Cloud.</li>
        </ul>
        <button
          type="button"
          onClick={onOpenCloudExceptions}
          className="mt-3 text-sm font-medium text-brand-blue hover:underline"
        >
          Open Cloud exceptions tab
        </button>
      </div>

      <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-600 shadow-sm">
        <p className="font-medium text-brand-dark">Review scope ladder</p>
        <p className="mt-1 text-xs leading-relaxed text-slate-500">
          When you approve in Inbox, you pick how broadly Guard should remember the decision. Wider
          scopes apply to more future actions.
        </p>
        <ol className="mt-3 space-y-2.5">
          {REVIEW_SCOPE_LADDER.map((step, index) => (
            <li key={step.scope} className="flex gap-2.5">
              <span className="flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-brand-blue/10 text-[11px] font-semibold text-brand-blue">
                {index + 1}
              </span>
              <div>
                <p className="text-sm font-medium text-brand-dark">{scopeLabel(step.scope)}</p>
                <p className="text-xs leading-relaxed text-slate-500">{step.detail}</p>
              </div>
            </li>
          ))}
        </ol>
      </div>
    </aside>
  );
}
