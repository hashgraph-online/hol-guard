import {
  HiMiniChevronRight,
  HiMiniEye,
  HiMiniPencilSquare,
  HiMiniPuzzlePiece,
  HiMiniQuestionMarkCircle,
} from "react-icons/hi2";
import { LoggedActionPanel } from "./logged-action-panel";
import type { McpToolCallEffect, McpToolCallView } from "./mcp-tool-call-view";

const EFFECT_COPY: Record<McpToolCallEffect, { badge: string; note: string; className: string }> = {
  reads: {
    badge: "Looks up information",
    note: "The tool's name says it only reads. Its server decides what it really does.",
    className: "bg-brand-green-bg/60 text-brand-green-text",
  },
  changes: {
    badge: "Can make changes",
    note: "The tool's name says it creates, changes, sends or removes something.",
    className: "bg-amber-50 text-amber-700",
  },
  unknown: {
    badge: "Not sure what it changes",
    note: "Guard can't tell from the tool's name whether it changes anything.",
    className: "bg-gray-100 text-gray-600",
  },
};

const EFFECT_ICON: Record<McpToolCallEffect, typeof HiMiniEye> = {
  reads: HiMiniEye,
  changes: HiMiniPencilSquare,
  unknown: HiMiniQuestionMarkCircle,
};

/** Technical text for the collapsed panel: the exact tool name, then its input. */
export function mcpToolCallTechnicalText(view: McpToolCallView): string {
  return view.rawInput === null ? view.technicalName : `${view.technicalName}\n\n${view.rawInput}`;
}

export function McpToolCallPanel({
  view,
  appName,
  observed,
}: {
  view: McpToolCallView;
  appName: string;
  observed: boolean;
}) {
  const effect = EFFECT_COPY[view.effect];
  const EffectIcon = EFFECT_ICON[view.effect];
  const verb = observed ? "asked to" : "wants to";

  return (
    <section aria-label="Tool call" className="rounded-xl border border-slate-200 bg-slate-50/60 p-4">
      <div className="flex flex-wrap items-start gap-3">
        <span className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-slate-200 bg-white text-brand-blue">
          <HiMiniPuzzlePiece className="h-5 w-5" aria-hidden="true" />
        </span>
        <div className="min-w-0 flex-1">
          <p className="text-xs font-medium text-muted-foreground">
            {view.server === null ? "Connected tool" : `Tool from ${view.server}`}
          </p>
          <p className="mt-0.5 break-words text-base font-semibold text-brand-dark">{view.tool}</p>
        </div>
        <span
          className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-semibold ${effect.className}`}
        >
          <EffectIcon className="h-3.5 w-3.5" aria-hidden="true" />
          {effect.badge}
        </span>
      </div>

      <p className="mt-3 text-sm leading-relaxed text-brand-dark">
        <span className="font-semibold">{appName}</span> {verb} {view.sentence}.
      </p>
      <p className="mt-1 text-xs leading-snug text-muted-foreground">{effect.note}</p>

      <div className="mt-4">
        <h4 className="text-xs font-semibold text-brand-dark/70">
          {view.fields.length > 0 ? "Details it sent to the tool" : "Details"}
        </h4>
        {view.fields.length > 0 ? (
          <dl className="mt-2 divide-y divide-slate-200 overflow-hidden rounded-lg border border-slate-200 bg-white">
            {view.fields.map((field, index) => (
              <div
                key={`${field.label}-${index}`}
                className="grid gap-1 px-3 py-2 sm:grid-cols-[minmax(8rem,12rem)_1fr] sm:gap-4"
              >
                <dt className="text-xs font-medium text-muted-foreground sm:text-sm">{field.label}</dt>
                <dd
                  className={`min-w-0 break-words text-sm text-brand-dark ${field.mono ? "font-mono text-[13px]" : ""}`}
                >
                  {field.value}
                </dd>
              </div>
            ))}
          </dl>
        ) : (
          <p className="mt-1 text-sm text-muted-foreground">The agent sent no details with this call.</p>
        )}
        {view.hiddenFieldCount > 0 && (
          <p className="mt-2 text-xs text-muted-foreground">
            {view.hiddenFieldCount} more {view.hiddenFieldCount === 1 ? "detail is" : "details are"} in the
            technical details below.
          </p>
        )}
      </div>

      <details className="group mt-4">
        <summary className="inline-flex min-h-11 cursor-pointer list-none items-center gap-1.5 rounded-md text-sm font-medium text-brand-blue focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-brand-blue/40 [&::-webkit-details-marker]:hidden">
          <HiMiniChevronRight className="h-4 w-4 transition-transform group-open:rotate-90" aria-hidden="true" />
          Technical details
        </summary>
        <div className="mt-2">
          <LoggedActionPanel
            label="Tool name and input"
            text={mcpToolCallTechnicalText(view)}
            copyAriaLabel="Copy the tool name and input to clipboard"
            expandAriaLabel="Expand the tool name and input"
            collapseAriaLabel="Collapse the tool name and input"
          />
        </div>
      </details>
    </section>
  );
}
