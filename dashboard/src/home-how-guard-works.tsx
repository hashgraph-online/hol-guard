import { useCallback, useEffect, useReducer, useRef, useState, type ComponentType } from "react";
import {
  HiMiniArrowPath,
  HiMiniArrowUpTray,
  HiMiniCheck,
  HiMiniChevronDown,
  HiMiniChevronUp,
  HiMiniCommandLine,
  HiMiniCube,
  HiMiniDocumentText,
  HiMiniHandRaised,
  HiMiniMagnifyingGlass,
  HiMiniNoSymbol,
  HiMiniPencilSquare,
} from "react-icons/hi2";

import { ActionButton, SectionLabel } from "./approval-center-primitives";
import { brandMarkSvg } from "./brand-mark-geometry";
import {
  decisionOutcome,
  guardVerdict,
  INITIAL_SESSION_STATE,
  ROW_STATUS_LABELS,
  rowStatus,
  SAMPLE_SESSION,
  SAMPLE_TIMING_MS,
  sampleAppName,
  sessionCounts,
  sessionPhase,
  sessionReducer,
  sessionStatusLine,
  type RowStatus,
  type SampleDecision,
  type SampleRow,
  type SampleRowKind,
  type SessionEvent,
  type SessionState,
} from "./home-sample-flow";
import { useReducedMotion } from "./use-reduced-motion";

type IconType = ComponentType<{ className?: string; "aria-hidden"?: boolean | "true" }>;

const KIND_ICONS: Record<SampleRowKind, IconType> = {
  read: HiMiniDocumentText,
  search: HiMiniMagnifyingGlass,
  command: HiMiniCommandLine,
  edit: HiMiniPencilSquare,
  install: HiMiniCube,
  upload: HiMiniArrowUpTray,
};

export const HOW_GUARD_WORKS_OUTCOMES = [
  {
    key: "ran",
    title: "Ran without asking",
    short: "Ran",
    body: "Reading, searching, editing and everyday commands.",
    icon: HiMiniCheck,
  },
  {
    key: "stopped",
    title: "Stopped without asking",
    short: "Stopped",
    body: "Clearly harmful, like sending your keys off this computer.",
    icon: HiMiniNoSymbol,
  },
  {
    key: "asked",
    title: "Asked you",
    short: "Asked you",
    body: "Only when Guard can’t tell, like a package it hasn’t seen.",
    icon: HiMiniHandRaised,
  },
] as const;

const COLLAPSE_STORAGE_KEY = "guard-collapsed-how-guard-works";

/** New installs see the walkthrough open; once Guard has a history, it starts collapsed. */
export function resolveHowGuardWorksDefaultOpen(receiptCount: number): boolean {
  return receiptCount < 20;
}

function readStoredOpen(): boolean | null {
  try {
    const stored = typeof window !== "undefined" ? window.localStorage.getItem(COLLAPSE_STORAGE_KEY) : null;
    return stored === null ? null : stored === "1";
  } catch {
    return null;
  }
}

function writeStoredOpen(open: boolean): void {
  try {
    window.localStorage.setItem(COLLAPSE_STORAGE_KEY, open ? "1" : "0");
  } catch {
    return;
  }
}

/** Lets another part of Home open the walkthrough and scroll to it (the hero's "How Guard works" button). */
export function useHowGuardWorksReveal(): { openSignal: number; reveal: () => void } {
  const [openSignal, setOpenSignal] = useState(0);
  const reducedMotion = useReducedMotion();
  const reveal = useCallback(() => {
    setOpenSignal((value) => value + 1);
    window.setTimeout(() => {
      document.getElementById("guard-how-it-works")?.scrollIntoView({ behavior: reducedMotion ? "auto" : "smooth", block: "start" });
    }, 0);
  }, [reducedMotion]);
  return { openSignal, reveal };
}

function reduceSession(state: SessionState, event: SessionEvent): SessionState {
  return sessionReducer(state, event);
}

/** Plays the sample session once it is on screen, one row at a time (all at once under reduced motion). */
function useSampleSession(reducedMotion: boolean) {
  const [state, dispatch] = useReducer(reduceSession, INITIAL_SESSION_STATE);
  const [visible, setVisible] = useState(false);
  const observedRef = useRef<HTMLDivElement | null>(null);
  const phase = sessionPhase(state);

  useEffect(() => {
    const element = observedRef.current;
    if (!element || typeof IntersectionObserver === "undefined") {
      setVisible(true);
      return;
    }
    const observer = new IntersectionObserver(([entry]) => setVisible(entry.isIntersecting), { threshold: 0.3 });
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!visible || phase === "waiting" || phase === "finished") return;
    if (reducedMotion) {
      dispatch({ type: "skip" });
      return;
    }
    const delay = phase === "ready" ? 0 : state.checking ? SAMPLE_TIMING_MS.check : SAMPLE_TIMING_MS.gap;
    const timer = window.setTimeout(() => dispatch({ type: "tick" }), delay);
    return () => window.clearTimeout(timer);
  }, [visible, phase, state.shown, state.checking, state.decision, reducedMotion]);

  return { state, dispatch, phase, observedRef };
}

export function HomeHowGuardWorks(props: { receiptCount: number; connectedHarnesses: string[]; openSignal?: number }) {
  const [open, setOpen] = useState<boolean>(() => readStoredOpen() ?? resolveHowGuardWorksDefaultOpen(props.receiptCount));
  useEffect(() => {
    if (props.openSignal) {
      setOpen(true);
      writeStoredOpen(true);
    }
  }, [props.openSignal]);
  const toggle = useCallback(() => {
    setOpen((previous) => {
      writeStoredOpen(!previous);
      return !previous;
    });
  }, []);

  return (
    <section id="guard-how-it-works" className="overflow-hidden rounded-2xl border border-slate-200/80 bg-white shadow-sm" aria-label="How Guard protects you">
      <button
        type="button"
        onClick={toggle}
        className="flex w-full items-start gap-3 px-5 py-4 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-blue/60"
        aria-expanded={open}
        aria-controls="guard-how-it-works-body"
      >
        <div className="min-w-0 flex-1">
          <SectionLabel>How Guard protects you</SectionLabel>
          <h2 className="mt-1.5 text-lg font-semibold tracking-tight text-brand-dark">Guard stays quiet until it matters</h2>
          <p className="mt-1 max-w-2xl text-sm text-slate-500">
            Everyday work runs, harmful actions are stopped, and you’re asked only when Guard can’t tell. Here’s a sample session.
          </p>
        </div>
        <span className="mt-0.5 inline-flex shrink-0 items-center gap-1 text-xs font-medium text-slate-500">
          {open ? "Hide" : "Show"}
          {open ? <HiMiniChevronUp className="h-4 w-4" aria-hidden="true" /> : <HiMiniChevronDown className="h-4 w-4" aria-hidden="true" />}
        </span>
      </button>
      {open ? <HowGuardWorksBody appName={sampleAppName(props.connectedHarnesses)} /> : null}
    </section>
  );
}

function HowGuardWorksBody(props: { appName: string }) {
  const reducedMotion = useReducedMotion();
  const { state, dispatch, phase, observedRef } = useSampleSession(reducedMotion);
  const [inspected, setInspected] = useState<number | null>(null);
  const decide = useCallback((decision: SampleDecision) => dispatch({ type: "decide", decision }), [dispatch]);
  const replay = useCallback(() => {
    setInspected(null);
    dispatch({ type: "replay" });
  }, [dispatch]);
  const toggleInspect = useCallback((index: number) => setInspected((current) => (current === index ? null : index)), []);
  const rows = SAMPLE_SESSION.slice(0, state.shown);

  return (
    <div
      id="guard-how-it-works-body"
      ref={observedRef}
      className="grid gap-4 border-t border-slate-100 bg-surface-1 p-4 sm:p-5 lg:grid-cols-[minmax(0,1fr)_300px]"
    >
      <GuardPanel state={state} inspected={inspected} />

      <div className="flex min-w-0 flex-col overflow-hidden rounded-2xl border border-slate-200 bg-white lg:order-first">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-100 px-4 py-3">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-lg bg-surface-2 font-mono text-[11px] font-bold text-brand-dark" aria-hidden="true">
              {props.appName.slice(0, 2)}
            </span>
            <p className="truncate text-sm font-semibold text-brand-dark">
              {props.appName} <span className="font-normal text-slate-500">· sample session</span>
            </p>
          </div>
          <p className="guard-session-status text-xs text-slate-500" data-phase={phase}>
            {sessionStatusLine(state)}
          </p>
        </div>
        <ol className="guard-session-feed flex-1" aria-label="Sample session">
          {rows.map((row, index) => (
            <SessionRow
              key={`${state.runs}-${row.id}`}
              index={index}
              row={row}
              status={rowStatus(state, index)}
              inspected={inspected === index}
              appName={props.appName}
              onInspect={toggleInspect}
              onDecide={decide}
            />
          ))}
        </ol>
        <div className="flex min-h-14 flex-wrap items-center justify-between gap-2 border-t border-slate-100 px-4 py-2">
          <p className="text-xs text-slate-500">{phase === "finished" ? "Pick any action to see why Guard let it run or not." : "A demonstration. Nothing runs on your computer."}</p>
          {phase === "finished" ? (
            <ActionButton variant="outline" onClick={replay}>
              <HiMiniArrowPath className="mr-2 h-4 w-4" aria-hidden="true" />
              Play again
            </ActionButton>
          ) : null}
        </div>
      </div>
    </div>
  );
}

const OUTCOME_TONES: Record<(typeof HOW_GUARD_WORKS_OUTCOMES)[number]["key"], string> = {
  ran: "bg-brand-green-bg text-brand-green-text",
  stopped: "bg-amber-50 text-amber-700",
  asked: "bg-brand-blue/10 text-brand-blue",
};

/** Guard's side of the session: the live mark, what it just decided and why, and the running totals. */
function GuardPanel(props: { state: SessionState; inspected: number | null }) {
  const verdict = guardVerdict(props.state, props.inspected);
  const counts = sessionCounts(props.state);
  const pulseKey = `${props.state.runs}-${props.state.shown}-${props.state.checking ? 1 : 0}-${props.state.decision ?? ""}-${props.inspected ?? ""}`;
  return (
    <aside aria-label="Guard" className="flex flex-col rounded-2xl border border-slate-200 bg-white p-4 sm:p-5">
      <div className="flex items-start gap-4 lg:flex-col lg:items-center lg:text-center">
        <div className="guard-checkpoint" data-state={verdict.mark} aria-hidden="true">
          <span key={pulseKey} className="guard-checkpoint-ripple" />
          <span className="guard-checkpoint-mark" dangerouslySetInnerHTML={{ __html: brandMarkSvg("#3f4174") }} />
        </div>
        <div className="min-w-0 flex-1 lg:w-full" aria-live="polite">
          <SectionLabel>Guard</SectionLabel>
          <p className="guard-checkpoint-title mt-1 text-base font-semibold text-brand-dark" data-state={verdict.mark}>
            {verdict.title}
          </p>
          <p className="mt-1 text-sm leading-relaxed text-slate-600">{verdict.detail}</p>
          {verdict.target ? (
            <p className="mt-2 hidden truncate rounded-lg bg-surface-1 px-2 py-1 font-mono text-[11px] text-slate-600 lg:block" title={verdict.target}>
              {verdict.target}
            </p>
          ) : null}
        </div>
      </div>
      <ul className="mt-4 grid grid-cols-3 gap-2 border-t border-slate-100 pt-4 lg:mt-5 lg:grid-cols-1" aria-label="This session so far">
        {HOW_GUARD_WORKS_OUTCOMES.map((outcome) => {
          const Icon = outcome.icon;
          return (
            <li key={outcome.key} className="grid grid-cols-[auto_1fr] items-center gap-x-2 gap-y-1 rounded-xl bg-surface-1 p-2.5 lg:grid-cols-[auto_minmax(0,1fr)_auto] lg:gap-x-3 lg:p-3">
              <span className={`inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full ${OUTCOME_TONES[outcome.key]}`}>
                <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              </span>
              <span key={counts[outcome.key]} className="guard-session-count justify-self-end text-xl font-semibold tabular-nums text-brand-dark lg:order-last lg:text-2xl">
                {counts[outcome.key]}
              </span>
              <div className="col-span-2 min-w-0 lg:col-span-1">
                <p className="text-xs font-semibold text-brand-dark lg:hidden">{outcome.short}</p>
                <p className="hidden text-sm font-semibold text-brand-dark lg:block">{outcome.title}</p>
                <p className="mt-0.5 hidden text-xs leading-relaxed text-slate-500 lg:block">{outcome.body}</p>
              </div>
            </li>
          );
        })}
      </ul>
      <p className="mt-3 hidden text-xs leading-relaxed text-slate-500 sm:block lg:mt-auto lg:pt-3">In real use, every check is saved on this computer so you can look back at it in Evidence.</p>
    </aside>
  );
}

const STATUS_CHIP: Record<RowStatus, string> = {
  checking: "text-slate-500",
  ran: "text-brand-green-text",
  stopped: "border border-amber-200 bg-amber-50 text-amber-700",
  waiting: "border border-brand-blue/25 bg-brand-blue/10 text-brand-blue",
  once: "border border-brand-blue/20 bg-brand-blue/10 text-brand-blue",
  always: "border border-brand-blue/20 bg-brand-blue/10 text-brand-blue",
  block: "border border-amber-200 bg-amber-50 text-amber-700",
};

function StatusChip(props: { status: RowStatus }) {
  const { status } = props;
  return (
    <span
      className={`guard-session-chip inline-flex shrink-0 items-center gap-1.5 whitespace-nowrap rounded-full px-2.5 py-1 text-xs font-medium ${STATUS_CHIP[status]}`}
      data-status={status}
    >
      {status === "checking" ? <span className="guard-session-spinner" aria-hidden="true" /> : null}
      {status === "ran" ? <HiMiniCheck className="h-3.5 w-3.5" aria-hidden="true" /> : null}
      {status === "stopped" || status === "block" ? <HiMiniNoSymbol className="h-3.5 w-3.5" aria-hidden="true" /> : null}
      {status === "waiting" ? <HiMiniHandRaised className="h-3.5 w-3.5" aria-hidden="true" /> : null}
      {ROW_STATUS_LABELS[status]}
    </span>
  );
}

function SessionRow(props: {
  index: number;
  row: SampleRow;
  status: RowStatus;
  inspected: boolean;
  appName: string;
  onInspect: (index: number) => void;
  onDecide: (decision: SampleDecision) => void;
}) {
  const { row, status, index, onInspect } = props;
  const Icon = KIND_ICONS[row.kind];
  const resolved = status !== "checking";
  const tone = resolved && row.verdict !== "ran" ? row.verdict : "plain";
  const handleInspect = useCallback(() => onInspect(index), [onInspect, index]);
  // Short chips stay beside the label; longer verdicts drop under it on phones so the command keeps its width.
  const inlineChip = status === "ran" || status === "checking";
  return (
    <li className="guard-session-row border-t border-slate-100 first:border-t-0" data-tone={tone} data-inspected={props.inspected || undefined}>
      <button
        type="button"
        onClick={handleInspect}
        disabled={!resolved}
        aria-pressed={props.inspected}
        className="grid min-h-14 w-full grid-cols-[auto_minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1.5 px-4 py-2 text-left focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-brand-blue/50 enabled:hover:bg-surface-1/70"
      >
        <span className="guard-session-icon inline-flex h-7 w-7 items-center justify-center rounded-lg bg-surface-2 text-slate-500">
          <Icon className="h-3.5 w-3.5" aria-hidden="true" />
        </span>
        <span className="min-w-0">
          <span className="block text-sm text-brand-dark">{row.label}</span>
          <span className="block truncate font-mono text-[11px] text-slate-500" title={row.target}>
            {row.target}
          </span>
        </span>
        <span className={inlineChip ? "justify-self-end" : "col-span-2 col-start-2 justify-self-start sm:col-span-1 sm:col-start-auto sm:justify-self-end"}>
          <StatusChip status={status} />
        </span>
      </button>
      {resolved && row.verdict === "stopped" && row.reason ? (
        <p className="guard-session-detail pb-3 pl-14 pr-4 text-xs leading-relaxed text-amber-800">{row.reason}</p>
      ) : null}
      {resolved && row.verdict === "ask" ? <SampleReview row={row} status={status} appName={props.appName} onDecide={props.onDecide} /> : null}
    </li>
  );
}

function SampleReview(props: { row: SampleRow; status: RowStatus; appName: string; onDecide: (decision: SampleDecision) => void }) {
  const { status } = props;
  if (status !== "waiting") {
    return <p className="guard-session-detail pb-3 pl-14 pr-4 text-xs leading-relaxed text-slate-600">{decisionOutcome(status as SampleDecision)}</p>;
  }
  return (
    <div className="px-4 pb-4 sm:pl-14">
      <div className="guard-session-detail rounded-xl border border-brand-blue/20 bg-brand-blue/[0.03] p-3.5" role="group" aria-label="Sample question from Guard">
        <p className="text-sm font-semibold text-brand-dark">Should {props.appName} install this package?</p>
        <p className="mt-1 text-xs leading-relaxed text-slate-600">{props.row.reason} The app waits here until you answer. Try it:</p>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-3">
          <DecisionButton label="Allow once" decision="once" variant="success" icon={HiMiniCheck} onDecide={props.onDecide} />
          <DecisionButton label="Always allow" decision="always" variant="outline" onDecide={props.onDecide} />
          <DecisionButton label="Block" decision="block" variant="outline" icon={HiMiniNoSymbol} onDecide={props.onDecide} />
        </div>
      </div>
    </div>
  );
}

function DecisionButton(props: {
  label: string;
  decision: SampleDecision;
  variant: "success" | "outline";
  icon?: IconType;
  onDecide: (decision: SampleDecision) => void;
}) {
  const { decision, onDecide } = props;
  const handleClick = useCallback(() => onDecide(decision), [onDecide, decision]);
  const Icon = props.icon;
  return (
    <ActionButton variant={props.variant} onClick={handleClick}>
      {Icon ? <Icon className="mr-2 h-4 w-4" aria-hidden="true" /> : null}
      {props.label}
    </ActionButton>
  );
}
