import { HiMiniCursorArrowRays, HiMiniLockClosed, HiMiniPencilSquare } from "react-icons/hi2";
import type { GuardBrowserCardV1 } from "../guard-types";
import { browserInputSummary } from "../mcp-call/browser-card";
import { CardRow } from "./browser-call-parts";

const INPUT_LABELS = { text: "Types", key: "Presses", file: "Sends", script: "Runs" } as const;

/**
 * The element the step acts on and what it enters there. Core's card never
 * carries typed text, so this shows the kind and length of the input only.
 */
export function BrowserInputPreview({ card }: { card: GuardBrowserCardV1 }) {
  const { element_preview: element, input_kind: kind, input_masked: masked } = card.detail;
  const summary = browserInputSummary(card);
  if (element === null && summary === null) return null;
  return (
    <>
      {element !== null && (
        <CardRow icon={HiMiniCursorArrowRays} label="On">
          <span className="break-words text-brand-dark">{element}</span>
        </CardRow>
      )}
      {kind !== null && summary !== null && (
        <CardRow icon={masked ? HiMiniLockClosed : HiMiniPencilSquare} label={INPUT_LABELS[kind]}>
          <span className="text-brand-dark">{summary}</span>
          {masked && (
            <span className="mt-0.5 text-xs text-muted-foreground">Guard does not show what it types here.</span>
          )}
        </CardRow>
      )}
    </>
  );
}
