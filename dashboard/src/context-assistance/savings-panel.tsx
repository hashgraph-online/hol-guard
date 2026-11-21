import type { Savings, SavingsApp } from "./usage-api";

const NAMES: Record<string, string> = { codex: "Codex", "claude-code": "Claude Code" };
const exact = new Intl.NumberFormat();
const compact = new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 });
/** An estimate keeps two meaningful digits so it never looks more exact than it is. */
const rough = new Intl.NumberFormat(undefined, { notation: "compact", maximumSignificantDigits: 2 });
/** Sentences spell the size out ("3.1 million"); tables keep the short form. */
const spoken = new Intl.NumberFormat(undefined, { notation: "compact", compactDisplay: "long", maximumSignificantDigits: 2 });

function count(value: number): string {
  return value >= 10_000 ? compact.format(value) : exact.format(value);
}

function plural(value: number, one: string, many: string): string {
  return exact.format(value) + " " + (value === 1 ? one : many);
}

function period(days: number): string {
  return days === 7 ? "this week" : "in the last " + days + " days";
}

function rates(apps: SavingsApp[]): string {
  const named = apps.filter((app) => app.measured_sessions > 0).map((app) => (NAMES[app.app] ?? app.app) + " " + app.rate_percent + "%");
  return named.length ? named.join(", ") : "about half";
}

function AppRows({ apps }: { apps: SavingsApp[] }) {
  const measured = apps.filter((app) => app.measured_sessions > 0);
  if (!measured.length) return null;
  return <table className="cigar-usage-table cigar-savings-apps">
    <caption className="sr-only">Tokens by app</caption>
    <thead><tr><th scope="col">App</th><th scope="col">Used</th><th scope="col">Saved (estimate)</th></tr></thead>
    <tbody>{measured.map((app) => <tr key={app.app}>
      <th scope="row">{NAMES[app.app] ?? app.app}</th>
      <td title={exact.format(app.used_tokens) + " tokens"}>{count(app.used_tokens)}</td>
      <td title={"About " + exact.format(app.estimated_saved_tokens) + " tokens, at " + app.rate_percent + "%"}>~{rough.format(app.estimated_saved_tokens)}</td>
    </tr>)}</tbody>
  </table>;
}

/** What CIGAR saved: the measured facts first-hand, the token estimate labeled as one. */
export function CigarSavingsPanel({ savings }: { savings: Savings | null | undefined }) {
  if (!savings) return null;
  const { total } = savings;
  const when = period(savings.window_days);
  if (!total.sessions) {
    return <section className="cigar-savings cigar-savings-quiet" aria-label="Tokens CIGAR saved">
      <h3>No savings to show yet</h3>
      <p>Once CIGAR hands project code to Codex or Claude Code, this shows how much work it saved the AI {when}.</p>
    </section>;
  }
  const used = total.used_tokens;
  const saved = total.estimated_saved_tokens;
  // Only sessions Guard could read say which files the AI opened again.
  const checked = total.files_checked;
  const skipped = Math.max(0, checked - total.files_opened_anyway);
  const facts = [
    plural(total.prompts, "prompt", "prompts") + " got project code from CIGAR",
    "About " + count(total.context_tokens) + " tokens of code handed over",
    checked ? exact.format(skipped) + " of " + plural(checked, "file", "files") + " shown, the AI didn't need to open again" : null,
  ].filter((fact): fact is string => fact !== null);
  const readable = total.measured_sessions > 0;
  const measured = readable && used > 0;
  const share = measured ? Math.max(4, Math.round((used / (used + saved)) * 100)) : 100;
  return <section className="cigar-savings" aria-labelledby="cigar-savings-title">
    <h3 id="cigar-savings-title">{measured ? <>CIGAR saved about <strong>{spoken.format(saved)}</strong> tokens {when}</> : <>CIGAR helped {plural(total.sessions, "session", "sessions")} {when}</>}</h3>
    <p className="cigar-savings-lede">{measured
      ? "That's our best estimate. In the sessions CIGAR helped, your AI apps used " + spoken.format(used) + " tokens. Without CIGAR, the same work would likely have taken about " + spoken.format(used + saved) + "."
      : readable
        ? "Guard read those sessions' records but found no tokens used, so it can't estimate the tokens saved. What it did measure is below."
        : "Guard could not read those sessions' own records, so it can't estimate the tokens saved. What it did measure is below."}</p>
    {measured ? <>
      <div className="cigar-savings-bar" role="img" aria-label={"Used " + spoken.format(used) + " tokens. Without CIGAR, about " + spoken.format(saved) + " more."} style={{ ["--used" as string]: share + "%" }}>
        <span className="cigar-savings-used" /><span className="cigar-savings-saved" />
      </div>
      <ul className="cigar-savings-key" aria-hidden="true">
        <li><span className="cigar-savings-swatch is-used" />Used (measured)</li>
        <li><span className="cigar-savings-swatch is-saved" />Saved (estimate)</li>
      </ul>
    </> : null}
    <ul className="cigar-savings-facts">{facts.map((fact) => <li key={fact}>{fact}</li>)}</ul>
    <AppRows apps={savings.apps} />
    {measured && total.measured_sessions < total.sessions
      ? <p className="cigar-usage-foot">The estimate covers {exact.format(total.measured_sessions)} of {plural(total.sessions, "session", "sessions")}. Guard could not read the rest.</p> : null}
    <details className="cigar-usage-recent cigar-savings-how">
      <summary>How we estimate</summary>
      <p>A token is a small piece of text, about ¾ of a word. AI apps read and write in tokens, and you pay for them.</p>
      <p>Guard counts the tokens each helped session really used, from the app's own records on this computer. Nothing leaves this computer.</p>
      <p>Guard can't rerun your work without CIGAR, so the saved number comes from our own tests, where CIGAR cut tokens by {rates(savings.apps)}. Your real savings may be higher or lower.</p>
    </details>
  </section>;
}
