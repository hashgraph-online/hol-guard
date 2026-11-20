import { useCallback, useState } from "react";
import type { IconType } from "react-icons";
import {
  HiMiniCommandLine,
  HiMiniComputerDesktop,
  HiMiniCursorArrowRays,
  HiMiniExclamationTriangle,
  HiMiniInformationCircle,
  HiMiniLink,
  HiMiniMagnifyingGlass,
  HiMiniPaperAirplane,
  HiMiniPencilSquare,
  HiMiniQuestionMarkCircle,
  HiMiniTrash,
} from "react-icons/hi2";
import type { McpCallExplanation, McpConsequence, McpFact, McpStep } from "./mcp-call-types";
import { MCP_EFFECT_COPY, type McpEffectKind } from "./mcp-effects";
import { emailAddresses, linkParts } from "./mcp-values";

const EFFECT_ICONS: Record<McpEffectKind, IconType> = {
  "in-app": HiMiniComputerDesktop,
  read: HiMiniMagnifyingGlass,
  write: HiMiniPencilSquare,
  send: HiMiniPaperAirplane,
  delete: HiMiniTrash,
  "run-code": HiMiniCommandLine,
  connect: HiMiniLink,
  "act-as-you": HiMiniCursorArrowRays,
  unknown: HiMiniQuestionMarkCircle,
};

const CONSEQUENCE_TONES: Record<McpConsequence["tone"], string> = {
  calm: "border-slate-200 bg-slate-50",
  care: "border-brand-attention/30 bg-brand-attention/[0.07]",
  danger: "border-red-200 bg-red-50",
};

const LONG_VALUE_CHARS = 140;

export function EffectPill({ effect }: { effect: McpEffectKind }) {
  const Icon = EFFECT_ICONS[effect];
  const tone =
    effect === "read" || effect === "in-app"
      ? "border-slate-200 bg-slate-50 text-brand-dark/80"
      : "border-brand-attention/30 bg-brand-attention/[0.08] text-brand-dark";
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-semibold ${tone}`}>
      <Icon className="h-3.5 w-3.5" aria-hidden="true" />
      {MCP_EFFECT_COPY[effect].label}
    </span>
  );
}

/** What approving lets happen, first thing under the heading, coloured by how much care it asks for. */
export function ConsequenceNote({ explanation }: { explanation: McpCallExplanation }) {
  const { consequence, aside, effect, effectBasis } = explanation;
  const Icon = consequence.tone === "danger" ? HiMiniExclamationTriangle : EFFECT_ICONS[effect];
  return (
    <div role="note" className={`mx-4 mb-4 rounded-xl border px-3.5 py-3 sm:mx-5 ${CONSEQUENCE_TONES[consequence.tone]}`}>
      <div className="flex items-start gap-2.5">
        <Icon className="mt-0.5 h-4 w-4 shrink-0 text-brand-dark/70" aria-hidden="true" />
        <div className="min-w-0">
          <p className="text-sm font-medium leading-snug text-brand-dark">{consequence.text}</p>
          {aside !== null && <p className="mt-1 text-sm leading-snug text-brand-dark/75">{aside}</p>}
          {effectBasis.length > 0 && (
            <p className="mt-1.5 flex items-center gap-1 text-xs leading-snug text-muted-foreground">
              <HiMiniInformationCircle className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
              {effectBasis}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * One action in a call. A call with a single action has already named it in the
 * card's heading, so its row shows only the action's own details.
 */
export function StepRow({ step, position, total }: { step: McpStep; position: number; total: number }) {
  const Icon = EFFECT_ICONS[step.effect];
  const lone = total === 1;
  return (
    <li className="flex items-start gap-3 border-b border-slate-100 px-4 py-3 last:border-b-0 sm:px-5">
      {!lone && (
        <span
          aria-hidden="true"
          className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-slate-100 text-[11px] font-semibold text-brand-dark/70"
        >
          {position}
        </span>
      )}
      <div className="min-w-0 flex-1">
        {!lone && (
          <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
            <p className="flex min-w-0 items-center gap-1.5 break-words text-sm font-medium text-brand-dark">
              <Icon className="h-4 w-4 shrink-0 text-brand-dark/60" aria-hidden="true" />
              <span>
                {step.action}
                {step.app !== null && <span className="font-normal text-brand-dark/70"> in {step.app}</span>}
              </span>
            </p>
            <span className="shrink-0 text-xs text-brand-dark/60">{MCP_EFFECT_COPY[step.effect].label}</span>
          </div>
        )}
        {step.details.length > 0 && (
          <div className={lone ? "" : "mt-1.5"}>
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

export function FactList({ facts }: { facts: McpFact[] }) {
  return (
    <dl className="grid grid-cols-[minmax(5.5rem,auto)_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-sm">
      {facts.map((fact) => (
        <div key={`${fact.label}-${fact.value}`} className="contents">
          <dt className="pt-0.5 text-brand-dark/60">{fact.label}</dt>
          <dd className="min-w-0 break-words text-brand-dark">
            <FactValue fact={fact} />
          </dd>
        </div>
      ))}
    </dl>
  );
}

function FactValue({ fact }: { fact: McpFact }) {
  switch (fact.kind) {
    case "email":
      return <AddressChips value={fact.value} />;
    case "url":
      return <LinkValue value={fact.value} />;
    case "long":
      return <LongText value={fact.value} />;
    case "code":
      return (
        <code className="block whitespace-pre-wrap break-words rounded-md bg-slate-50 px-2 py-1 font-mono text-xs">
          {fact.value}
        </code>
      );
    default:
      return <span className={fact.mono === true ? "font-mono text-xs" : ""}>{fact.value}</span>;
  }
}

function AddressChips({ value }: { value: string }) {
  const addresses = emailAddresses(value) ?? [value];
  return (
    <ul className="flex flex-wrap gap-1.5" aria-label="Addresses">
      {addresses.map((address) => (
        <li key={address} className="rounded-full border border-slate-200 bg-slate-50 px-2.5 py-0.5 text-xs font-medium">
          {address}
        </li>
      ))}
    </ul>
  );
}

/** A web address as text, host first. It is never a link: the agent chose it, so the card does not make it one-click. */
function LinkValue({ value }: { value: string }) {
  const parts = linkParts(value);
  if (parts === null) return <span>{value}</span>;
  return (
    <span className="break-all">
      <span className="font-semibold">{parts.host}</span>
      <span className="text-brand-dark/60">{parts.rest}</span>
    </span>
  );
}

function LongText({ value }: { value: string }) {
  const [open, setOpen] = useState(false);
  const toggle = useCallback(() => setOpen((current) => !current), []);
  const needsToggle = value.length > LONG_VALUE_CHARS || value.includes("\n");
  return (
    <div>
      <p className={`whitespace-pre-wrap break-words ${open || !needsToggle ? "" : "line-clamp-3"}`}>{value}</p>
      {needsToggle && (
        <button
          type="button"
          onClick={toggle}
          aria-expanded={open}
          className="mt-0.5 text-xs font-medium text-brand-blue hover:underline focus:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/30"
        >
          {open ? "Show less" : "Show more"}
        </button>
      )}
    </div>
  );
}
