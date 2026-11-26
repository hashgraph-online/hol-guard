import { useId } from "react";
import type { GuardBrowserSurfaceV1 } from "../guard-types";
import { browserSurfaceLabel } from "../mcp-call/browser-card";

/** The sensitive parts of the browser the step can reach. Each chip names itself in text. */
export function BrowserRiskChips({ chips }: { chips: GuardBrowserSurfaceV1[] }) {
  const labelId = useId();
  const unique = [...new Set(chips)];
  if (unique.length === 0) return null;
  return (
    <div className="pt-2">
      <p id={labelId} className="text-xs font-medium text-brand-dark/60">
        Can reach
      </p>
      <ul aria-labelledby={labelId} className="mt-1.5 flex flex-wrap gap-1.5">
        {unique.map((chip) => (
          <li
            key={chip}
            data-browser-surface={chip}
            className="inline-flex max-w-full items-center break-words rounded-full border border-brand-attention/30 bg-brand-attention/[0.08] px-2.5 py-0.5 text-xs font-medium text-brand-dark"
          >
            {browserSurfaceLabel(chip)}
          </li>
        ))}
      </ul>
    </div>
  );
}
