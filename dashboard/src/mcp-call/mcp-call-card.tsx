import type { IconType } from "react-icons";
import {
  HiMiniCommandLine,
  HiMiniLink,
  HiMiniMagnifyingGlass,
  HiMiniPaperAirplane,
  HiMiniPencilSquare,
  HiMiniQuestionMarkCircle,
  HiMiniTrash,
} from "react-icons/hi2";
import { buildPrimaryReviewAction, isWatchOnlyObservation, resolveRequestWorkingDirectory } from "../approval-center-utils";
import type { GuardApprovalRequest } from "../guard-types";
import { LoggedActionPanel } from "../logged-action-panel";
import { plainMcpReason } from "./explain-mcp-call";
import type { McpCallExplanation, McpFact } from "./mcp-call-types";
import { MCP_EFFECT_COPY, type McpEffectKind } from "./mcp-effects";

const EFFECT_ICONS: Record<McpEffectKind, IconType> = {
  read: HiMiniMagnifyingGlass,
  write: HiMiniPencilSquare,
  send: HiMiniPaperAirplane,
  delete: HiMiniTrash,
  "run-code": HiMiniCommandLine,
  connect: HiMiniLink,
  unknown: HiMiniQuestionMarkCircle,
};

/** What an MCP tool call is, in plain words, instead of the call's raw JSON. */
export function McpCallCard({ item, explanation }: { item: GuardApprovalRequest; explanation: McpCallExplanation }) {
  const watchOnly = isWatchOnlyObservation(item);
  const workingDirectory = resolveRequestWorkingDirectory(item);
  const reason = plainMcpReason(item, buildPrimaryReviewAction(item).detail);
  const facts: McpFact[] = [
    ...explanation.facts,
    ...(workingDirectory !== null ? [{ label: "Working directory", value: workingDirectory, mono: true }] : []),
  ];

  return (
    <section aria-label="What the agent is asking to do" className="mt-5 rounded-2xl border border-slate-200 bg-white">
      <div className="flex items-start gap-3 p-4 sm:p-5">
        <ConnectorMark name={explanation.connector} />
        <div className="min-w-0 flex-1">
          <h3 className="text-base font-semibold leading-snug text-brand-dark">{explanation.title}</h3>
          <p className="mt-0.5 text-sm text-brand-dark/70">Tool from {explanation.connector}</p>
        </div>
        <EffectPill effect={explanation.effect} />
      </div>

      <div className="px-4 pb-4 sm:px-5">
        {watchOnly && (
          <p className="mb-2 text-sm font-medium text-brand-dark">
            Watch let this call through. Guard would have stopped it.
          </p>
        )}
        <p className="max-w-[68ch] text-sm leading-relaxed text-brand-dark">{explanation.summary}</p>
        <p className="mt-1 max-w-[68ch] text-xs leading-snug text-muted-foreground">{explanation.effectBasis}</p>
        {reason !== null && <p className="mt-2 max-w-[68ch] text-sm leading-snug text-brand-dark/80">{reason}</p>}
      </div>

      {explanation.steps.length > 0 && (
        <ol className="border-t border-slate-100" aria-label="Actions in this call">
          {explanation.steps.map((step) => (
            <StepRow key={step.id} step={step} />
          ))}
        </ol>
      )}

      {facts.length > 0 && (
        <div className="border-t border-slate-100 px-4 py-3 sm:px-5">
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

      <p className="border-t border-slate-100 px-4 py-3 text-xs leading-snug text-muted-foreground sm:px-5">
        Allow once and Always allow both match these exact inputs. If the agent asks again with different inputs,
        Guard asks again.
        {explanation.truncated ? " Long text is shown shortened here." : ""}
      </p>
    </section>
  );
}

function ConnectorMark({ name }: { name: string }) {
  const letter = name.trim().charAt(0).toUpperCase() || "?";
  return (
    <span
      aria-hidden="true"
      className="flex h-10 w-10 shrink-0 items-center justify-center rounded-xl border border-slate-200 bg-slate-50 text-base font-semibold text-brand-dark"
    >
      {letter}
    </span>
  );
}

function EffectPill({ effect }: { effect: McpEffectKind }) {
  const Icon = EFFECT_ICONS[effect];
  const tone =
    effect === "read"
      ? "border-slate-200 bg-slate-50 text-brand-dark/80"
      : "border-brand-attention/30 bg-brand-attention/[0.08] text-brand-dark";
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`}>
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {MCP_EFFECT_COPY[effect].label}
    </span>
  );
}

function StepRow({ step }: { step: McpCallExplanation["steps"][number] }) {
  const Icon = EFFECT_ICONS[step.effect];
  return (
    <li className="flex items-start gap-3 border-b border-slate-100 px-4 py-3 last:border-b-0 sm:px-5">
      <Icon className="mt-0.5 h-4 w-4 shrink-0 text-brand-dark/60" aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
          <p className="min-w-0 break-words text-sm font-medium text-brand-dark">
            {step.action}
            {step.app !== null && <span className="font-normal text-brand-dark/70"> in {step.app}</span>}
          </p>
          <span className="shrink-0 text-xs text-brand-dark/60">{MCP_EFFECT_COPY[step.effect].label}</span>
        </div>
        {step.details.length > 0 && (
          <div className="mt-1.5">
            <FactList facts={step.details} />
          </div>
        )}
        {step.hiddenDetails > 0 && (
          <p className="mt-1 text-xs text-muted-foreground">
            {step.hiddenDetails} more {step.hiddenDetails === 1 ? "field" : "fields"} in the exact input
          </p>
        )}
      </div>
    </li>
  );
}

function FactList({ facts }: { facts: McpFact[] }) {
  return (
    <dl className="grid grid-cols-[minmax(5.5rem,auto)_minmax(0,1fr)] gap-x-3 gap-y-1 text-sm">
      {facts.map((fact) => (
        <div key={`${fact.label}-${fact.value}`} className="contents">
          <dt className="text-brand-dark/60">{fact.label}</dt>
          <dd className={`min-w-0 break-words text-brand-dark ${fact.mono === true ? "font-mono text-xs" : ""}`}>
            {fact.value}
          </dd>
        </div>
      ))}
    </dl>
  );
}
