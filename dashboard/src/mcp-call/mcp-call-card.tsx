import { buildPrimaryReviewAction, isWatchOnlyObservation, resolveRequestWorkingDirectory } from "../approval-center-utils";
import type { GuardApprovalRequest } from "../guard-types";
import { LoggedActionPanel } from "../logged-action-panel";
import { plainMcpReason } from "./explain-mcp-call";
import type { McpCallExplanation, McpCodeBlock, McpFact } from "./mcp-call-types";
import { McpAppMark } from "./mcp-app-mark";
import { BrowserReportPrompt } from "./browser-report-prompt";
import { actingApp, mcpMarkName } from "./mcp-brand";
import { ConsequenceNote, EffectPill, FactList, StepRow } from "./mcp-call-parts";

/** A lone action is already in the heading, so its row appears only when it has details to show. */
function showsSteps(explanation: McpCallExplanation): boolean {
  if (explanation.steps.length > 1 || (explanation.hiddenSteps ?? 0) > 0) return true;
  return explanation.steps.some((step) => step.details.length > 0 || step.hiddenDetails > 0);
}

function subtitleOf(explanation: McpCallExplanation, app: string): string {
  if (explanation.builtIn === true) return `Built into ${explanation.connector}`;
  return app === explanation.connector ? `Tool from ${explanation.connector}` : `${app}, through ${explanation.connector}`;
}

// Core's catch-all sentence. It says nothing the page does not, so the card gives its own reason instead.
const GENERIC_REASON = /needs your approval before this action can run/i;

/** What approving covers. When Guard cannot confirm the account, it can only allow the call once, and says why. */
function scopeNote(item: GuardApprovalRequest, connector: string): string {
  if (item.scope_restrictions?.includes("provider_account_unverified_once_only") === true) {
    return `You can allow this once, for these exact inputs. Guard cannot save it for next time, because it cannot confirm which ${connector} account it uses.`;
  }
  return "Allow once and Always allow both cover only these exact inputs. If the inputs change, Guard asks again.";
}

function CodePanel({ requestId, code }: { requestId: string; code: McpCodeBlock }) {
  return (
    <LoggedActionPanel
      key={`${requestId}-code`}
      label={code.collapsed === true ? "Code" : code.label}
      text={code.text}
      copyAriaLabel="Copy the code to clipboard"
    />
  );
}

/** What an MCP tool call is, in plain words, instead of the call's raw JSON. */
export function McpCallCard({ item, explanation }: { item: GuardApprovalRequest; explanation: McpCallExplanation }) {
  const watchOnly = isWatchOnlyObservation(item);
  const workingDirectory = resolveRequestWorkingDirectory(item);
  // Why Guard asked is said here, once. The alerts above the card leave this sentence out.
  const coreReason = plainMcpReason(item, buildPrimaryReviewAction(item).detail);
  const reason = coreReason !== null && !GENERIC_REASON.test(coreReason) ? coreReason : explanation.whyAsked;
  const app = actingApp(explanation);
  const facts: McpFact[] = [
    ...explanation.facts,
    ...(workingDirectory !== null ? [{ label: "Working directory", value: workingDirectory, mono: true }] : []),
  ];

  return (
    <section aria-label="What the agent is asking to do" className="mt-5 rounded-2xl border border-slate-200 bg-white">
      <div className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-2 p-4 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:p-5">
        <McpAppMark name={mcpMarkName(explanation)} size="md" />
        <div className="min-w-0">
          <h3 className="text-base font-semibold leading-snug text-brand-dark">{explanation.title}</h3>
          <p className="mt-0.5 break-words text-sm text-brand-dark/70">{subtitleOf(explanation, app)}</p>
        </div>
        <div className="col-start-2 row-start-2 sm:col-start-3 sm:row-start-1">
          <EffectPill effect={explanation.effect} />
        </div>
      </div>

      {watchOnly && (
        <p className="mx-4 mb-3 text-sm font-medium text-brand-dark sm:mx-5">
          Watch let this call through. Guard would have stopped it.
        </p>
      )}
      <ConsequenceNote explanation={explanation} />

      {showsSteps(explanation) && explanation.stepsCaption !== undefined && (
        <p className="border-t border-slate-100 px-4 pt-3 text-xs font-medium uppercase tracking-wide text-brand-dark/60 sm:px-5">
          {explanation.stepsCaption}
        </p>
      )}
      {showsSteps(explanation) && (
        <ol
          className={explanation.stepsCaption !== undefined ? "" : "border-t border-slate-100"}
          aria-label={explanation.stepsCaption ?? "Actions in this call"}
        >
          {explanation.steps.map((step, index) => (
            <StepRow key={step.id} step={step} position={index + 1} total={explanation.steps.length} />
          ))}
          {(explanation.hiddenSteps ?? 0) > 0 && (
            <li className="border-t border-slate-100 px-4 py-3 text-xs text-muted-foreground sm:px-5">
              {explanation.hiddenSteps} more {explanation.hiddenSteps === 1 ? "action" : "actions"} in the exact input
            </li>
          )}
        </ol>
      )}

      {facts.length > 0 && (
        <div className="border-t border-slate-100 px-4 py-3.5 sm:px-5">
          <FactList facts={facts} />
        </div>
      )}

      {explanation.quotes !== null && (
        <figure className="mx-4 mb-4 rounded-xl border border-dashed border-slate-300 bg-slate-50/70 px-3 py-2 sm:mx-5">
          <figcaption className="text-xs font-medium text-brand-dark/70">{explanation.quotes.caption}</figcaption>
          {explanation.quotes.items.map((text) => (
            <blockquote key={text} className="mt-1 break-words text-sm text-brand-dark">
              “{text}”
            </blockquote>
          ))}
          <p className="mt-1 text-[11px] leading-snug text-muted-foreground">
            In the agent's own words. Guard has not checked this, so decide from what the call does.
          </p>
        </figure>
      )}

      {explanation.code !== null && explanation.code.collapsed !== true && (
        <div className="mx-4 mb-4 sm:mx-5">
          <CodePanel requestId={item.request_id} code={explanation.code} />
        </div>
      )}
      {explanation.code !== null && explanation.code.collapsed === true && (
        <details className="border-t border-slate-100 px-4 py-3 sm:px-5">
          <summary className="cursor-pointer select-none text-sm font-medium text-brand-dark/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30">
            See {explanation.code.label.charAt(0).toLowerCase()}
            {explanation.code.label.slice(1)}
          </summary>
          <div className="mt-3">
            <CodePanel requestId={item.request_id} code={explanation.code} />
          </div>
        </details>
      )}

      <details className="border-t border-slate-100 px-4 py-3 sm:px-5">
        <summary className="cursor-pointer select-none text-sm font-medium text-brand-dark/80 focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30">
          See the exact input
        </summary>
        {explanation.rawInput !== null ? (
          <div className="mt-3">
            <LoggedActionPanel
              key={`${item.request_id}-input`}
              label="Input"
              text={explanation.rawInput}
              copyAriaLabel="Copy the exact input to clipboard"
              expandAriaLabel="Expand the exact input"
              collapseAriaLabel="Collapse the exact input"
            />
          </div>
        ) : (
          <p className="mt-2 text-sm text-muted-foreground">This call sent no input.</p>
        )}
        <p className="mt-2 break-all text-xs text-muted-foreground">
          Tool <code className="font-mono text-brand-dark/80">{explanation.toolId}</code>
        </p>
      </details>

      <div className="space-y-1 border-t border-slate-100 px-4 py-3 text-xs leading-snug text-muted-foreground sm:px-5">
        <p>{reason}</p>
        <p>
          {scopeNote(item, explanation.connector)}
          {explanation.truncated ? " Long text is shown shortened here." : ""}
        </p>
      </div>
      {item.browser_card ? <BrowserReportPrompt requestId={item.request_id} /> : null}
    </section>
  );
}
