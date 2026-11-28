import { useBrowserBurst } from "./browser-burst";

/** PRD 5.8 item 8: the step list on a card that covers a burst. */
export function BrowserBurstSteps({ requestId }: { requestId: string }) {
  const burst = useBrowserBurst(requestId);
  if (burst === null) return null;
  return (
    <div data-browser-burst={burst.count} className="border-t border-slate-100 px-4 py-2.5 sm:px-5">
      <p className="text-sm font-medium text-brand-dark">{burst.count} steps on this site</p>
      <ol className="mt-1.5 list-decimal space-y-0.5 pl-5 text-sm text-brand-dark/80">
        {burst.steps.map((step) => (
          <li key={step.requestId} className="break-words">
            {step.text}
          </li>
        ))}
      </ol>
      <p className="mt-1.5 text-xs text-muted-foreground">
        Your choice answers the first step. A grant also clears the steps it covers; the others stay
        waiting.
      </p>
    </div>
  );
}
