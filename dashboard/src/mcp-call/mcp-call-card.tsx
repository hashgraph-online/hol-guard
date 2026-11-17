import { buildPrimaryReviewAction, isWatchOnlyObservation, resolveRequestWorkingDirectory } from "../approval-center-utils";
import type { GuardApprovalRequest } from "../guard-types";
import { LoggedActionPanel } from "../logged-action-panel";
import { plainMcpReason } from "./explain-mcp-call";
import type { McpCallExplanation, McpFact } from "./mcp-call-types";
import { ConnectorMark, ConsequenceNote, EffectPill, FactList, StepRow } from "./mcp-call-parts";
import { unique } from "./mcp-input";

/**
 * Where the call acts: the one app its actions name when there is just one
 * (Gmail through Composio), else the connector it goes through.
 */
function actingApp(explanation: McpCallExplanation): string {
  const apps = unique(explanation.steps.map((step) => step.app).filter((app): app is string => app !== null));
  return apps.length === 1 ? apps[0] : explanation.connector;
}

/** A lone action is already in the heading, so its row appears only when it has details to show. */
function showsSteps(explanation: McpCallExplanation): boolean {
  if (explanation.steps.length > 1 || (explanation.hiddenSteps ?? 0) > 0) return true;
  return explanation.steps.some((step) => step.details.length > 0 || step.hiddenDetails > 0);
}

function subtitleOf(explanation: McpCallExplanation, app: string): string {
  if (explanation.builtIn === true) return `Built into ${explanation.connector}`;
  return app === explanation.connector ? `Tool from ${explanation.connector}` : `${app}, through ${explanation.connector}`;
}

/** What an MCP tool call is, in plain words, instead of the call's raw JSON. */
export function McpCallCard({ item, explanation }: { item: GuardApprovalRequest; explanation: McpCallExplanation }) {
  const watchOnly = isWatchOnlyObservation(item);
  const workingDirectory = resolveRequestWorkingDirectory(item);
  // Why Guard asked is said here, once. The alerts above the card leave this sentence out.
  const reason = plainMcpReason(item, buildPrimaryReviewAction(item).detail) ?? explanation.whyAsked;
  const app = actingApp(explanation);
  const facts: McpFact[] = [
    ...explanation.facts,
    ...(workingDirectory !== null ? [{ label: "Working directory", value: workingDirectory, mono: true }] : []),
  ];

  return (
    <section aria-label="What the agent is asking to do" className="mt-5 rounded-2xl border border-slate-200 bg-white">
      <div className="grid grid-cols-[auto_minmax(0,1fr)] items-start gap-x-3 gap-y-2 p-4 sm:grid-cols-[auto_minmax(0,1fr)_auto] sm:p-5">
        <ConnectorMark name={explanation.builtIn === true ? (explanation.requester ?? app) : app} />
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

      {showsSteps(explanation) && (
        <ol className="border-t border-slate-100" aria-label="Actions in this call">
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

      {explanation.code !== null && (
        <div className="mx-4 mb-4 sm:mx-5">
          <LoggedActionPanel
            key={`${item.request_id}-code`}
            label={explanation.code.label}
            text={explanation.code.text}
            copyAriaLabel={`Copy ${explanation.code.label.toLowerCase()} to clipboard`}
          />
        </div>
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
          Allow once and Always allow both match these exact inputs. If the agent asks again with different inputs,
          Guard asks again.
          {explanation.truncated ? " Long text is shown shortened here." : ""}
        </p>
      </div>
    </section>
  );
}
