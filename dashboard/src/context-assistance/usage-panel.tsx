import { useEffect, useState } from "react";
import { ActionButton } from "../approval-center-primitives";
import { isGuardDemoMode } from "../guard-demo";
import { ContextAssistanceApiError } from "./api";
import { readUsageMeter, type UsageMeter, type UsageTool, type UsageTotals } from "./usage-api";

const NAMES: Record<string, string> = {
  codex: "Codex", "claude-code": "Claude Code", copilot: "Copilot", cursor: "Cursor", gemini: "Gemini", opencode: "OpenCode", pi: "Pi",
};
const ROWS: [keyof UsageTotals, string][] = [
  ["uncached_input_tokens", "Input at full price"],
  ["cached_input_tokens", "Input read from cache"],
  ["cache_write_tokens", "Input written to cache"],
  ["output_tokens", "Output"],
  ["requests", "Model requests"],
  ["compactions", "Chat summaries"],
];
const POLL_MS = 3_000;
const exact = new Intl.NumberFormat();
const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });

/** Short form for big numbers so two columns fit a phone; the exact count stays one hover or tap away. */
export function usageNumber(value: number): string {
  return value >= 1_000_000 ? compact.format(value) : exact.format(value);
}

export function listNames(names: string[]): string {
  const shown = names.map((name) => NAMES[name] ?? name);
  return shown.length > 1 ? shown.slice(0, -1).join(", ") + " or " + shown[shown.length - 1] : shown.join("");
}

function when(stamp: string): string {
  const moment = new Date(stamp);
  return Number.isNaN(moment.getTime()) ? stamp : moment.toLocaleString(undefined, { weekday: "short", hour: "numeric", minute: "2-digit" });
}

function Cell({ value }: { value: number }) {
  return <td title={exact.format(value)}>{usageNumber(value)}</td>;
}

function ToolCard({ week, today, days }: { week: UsageTool; today: UsageTool | undefined; days: number }) {
  const name = NAMES[week.harness] ?? week.harness;
  if (!week.sessions) {
    return <article className="cigar-card cigar-usage-card"><h3>{name}</h3><p>No sessions in the last {days} days.</p></article>;
  }
  return <article className="cigar-card cigar-usage-card" aria-label={name + " usage"}>
    <h3>{name}<span>{exact.format(week.sessions)} {week.sessions === 1 ? "session" : "sessions"}</span></h3>
    <table className="cigar-usage-table">
      <thead><tr><th scope="col"><span className="sr-only">Kind</span></th><th scope="col">Today</th><th scope="col">Last {days} days</th></tr></thead>
      <tbody>{ROWS.map(([field, label]) => <tr key={field}><th scope="row">{label}</th>
        <Cell value={today?.totals[field] ?? 0} /><Cell value={week.totals[field]} /></tr>)}</tbody>
    </table>
    {week.recent.length ? <details className="cigar-usage-recent">
      <summary>Latest sessions</summary>
      <ul>{week.recent.map((session, index) => <li key={index}>
        <strong>{session.folder ?? "Unknown folder"}</strong>
        <span>{[session.model, when(session.last_active)].filter(Boolean).join(" · ")}</span>
        <span>{exact.format(session.totals.requests)} requests · {usageNumber(session.totals.uncached_input_tokens)} input at full price · {usageNumber(session.totals.output_tokens)} output</span>
      </li>)}</ul>
    </details> : null}
  </article>;
}

/** What each AI app used, read from the app's own records on this computer. */
export function CigarUsagePanel() {
  const [meter, setMeter] = useState<UsageMeter | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [attempt, setAttempt] = useState(0);
  const demo = isGuardDemoMode();

  useEffect(() => {
    if (demo) return;
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    setError(null);
    const load = () => readUsageMeter(controller.signal).then((next) => {
      setMeter(next);
      if (next.state === "counting" || next.refreshing) timer = setTimeout(load, POLL_MS);
    }, (cause: unknown) => {
      if (controller.signal.aborted) return;
      setError(cause instanceof ContextAssistanceApiError ? cause.message : "Guard could not read usage right now. Try again in a moment.");
    });
    void load();
    return () => { controller.abort(); if (timer) clearTimeout(timer); };
  }, [demo, attempt]);

  if (demo) return <div className="cigar-note"><strong>Usage is not shown in the demo</strong><p>On your computer this tab lists what each AI app used.</p></div>;
  if (error || meter?.state === "unavailable") {
    return <div className="cigar-note" role="alert"><strong>Usage could not be read</strong><p>{error ?? "Guard could not read the usage records on this computer."}</p>
      <ActionButton variant="outline" onClick={() => setAttempt((n) => n + 1)}>Try again</ActionButton></div>;
  }
  if (!meter || meter.state === "counting") {
    return <div className="cigar-note" role="status" aria-live="polite"><strong>Counting your usage…</strong>
      <p>The first count reads every session from the last week, so a long history can take a minute.</p></div>;
  }
  const today = new Map(meter.today.map((tool) => [tool.harness, tool]));
  return <div className="cigar-usage">
    <div className="cigar-usage-grid">{meter.week.map((tool) => <ToolCard key={tool.harness} week={tool} today={today.get(tool.harness)} days={meter.window_days} />)}</div>
    <p className="cigar-usage-foot">Input read from cache is billed at a fraction of the full input price. A chat summary is when the app shortens the conversation so it can keep going.</p>
    {meter.unread.length ? <p className="cigar-usage-foot">Guard does not read usage records from {listNames(meter.unread)}, so they are not shown here.</p> : null}
  </div>;
}
