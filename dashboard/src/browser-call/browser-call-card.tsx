import { isWatchOnlyObservation } from "../approval-center-utils";
import type { GuardApprovalRequest, GuardBrowserCardV1 } from "../guard-types";
import { McpAppMark } from "../mcp-call/mcp-app-mark";
import { actingApp, mcpMarkName } from "../mcp-call/mcp-brand";
import { CodePanel, McpCallFooter, mcpCallReason, subtitleOf } from "../mcp-call/mcp-call-card";
import { ConsequenceNote, EffectPill } from "../mcp-call/mcp-call-parts";
import type { McpCallExplanation } from "../mcp-call/mcp-call-types";
import { BrowserInputPreview } from "./browser-input-preview";
import { BrowserProfileLine } from "./browser-profile-line";
import { BrowserRiskChips } from "./browser-risk-chips";
import { BrowserSiteLine } from "./browser-site-line";

/** A masked step's typed text stays off the whole card, the exact input included. */
const MASKED_INPUT_NOTE = "This step types into a hidden field, so Guard does not show its input.";

/**
 * A browser step, drawn from Core's native card (PRD 5.8 items 1 to 5 and 7).
 * The page heading already says Core's headline, so the card names the step and
 * then the site, the browser, the element and input, and what the
 * step can reach. The decision choices sit below the card, unchanged.
 */
export function BrowserCallCard(props: {
  item: GuardApprovalRequest;
  card: GuardBrowserCardV1;
  explanation: McpCallExplanation;
}) {
  const { item, card, explanation } = props;
  return (
    <section
      aria-label="What the agent is asking to do"
      data-browser-card={card.verb}
      className="mt-5 rounded-2xl border border-slate-200 bg-white"
    >
      <div className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-2 p-4 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:p-5">
        <McpAppMark name={mcpMarkName(explanation)} size="md" />
        <div className="min-w-0">
          <h3 className="break-words text-base font-semibold leading-snug text-brand-dark">{explanation.title}</h3>
          <p className="mt-0.5 break-words text-sm text-brand-dark/70">
            {subtitleOf(explanation, actingApp(explanation))}
          </p>
        </div>
        <div className="col-start-2 row-start-2 sm:col-start-3 sm:row-start-1">
          <EffectPill effect={explanation.effect} />
        </div>
      </div>

      {isWatchOnlyObservation(item) && (
        <p className="mx-4 mb-3 text-sm font-medium text-brand-dark sm:mx-5">
          Watch let this call through. Guard would have stopped it.
        </p>
      )}
      <ConsequenceNote explanation={explanation} />

      <div className="border-t border-slate-100 px-4 py-2.5 sm:px-5">
        <BrowserSiteLine site={card.site} />
        <BrowserProfileLine profile={card.profile_line} />
        <BrowserInputPreview card={card} />
        <BrowserRiskChips chips={card.risk_chips} />
      </div>

      {explanation.code !== null && explanation.code.collapsed !== true && (
        <div className="mx-4 mb-4 sm:mx-5">
          <CodePanel requestId={item.request_id} code={explanation.code} />
        </div>
      )}
      {explanation.code !== null && explanation.code.collapsed === true && (
        <details className="border-t border-slate-100 px-4 py-3 sm:px-5">
          <summary className="cursor-pointer select-none text-sm font-medium text-brand-dark/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30">
            See the code it runs
          </summary>
          <div className="mt-3">
            <CodePanel requestId={item.request_id} code={explanation.code} />
          </div>
        </details>
      )}

      <McpCallFooter
        item={item}
        explanation={explanation}
        reason={mcpCallReason(item, explanation)}
        withheldInput={card.detail.input_masked ? MASKED_INPUT_NOTE : undefined}
      />
    </section>
  );
}
