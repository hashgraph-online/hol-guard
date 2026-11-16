import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CigarSavingsPanel } from "./savings-panel";
import { parseSavings, parseUsageMeter } from "./usage-api";

const totals = (over: Record<string, number> = {}) => ({
  sessions: 3, prompts: 12, context_tokens: 9_400, files_shown: 22, files_checked: 22, files_opened_anyway: 4,
  measured_sessions: 3, used_tokens: 1_200_000, estimated_saved_tokens: 1_400_000, ...over,
});
// Expected numbers use the same formatters as the page, so the test passes in any locale.
const spoken = (n: number) => new Intl.NumberFormat(undefined, { notation: "compact", compactDisplay: "long", maximumSignificantDigits: 2 }).format(n);
const exact = (n: number) => new Intl.NumberFormat().format(n);
const text = (value: string) => new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
const wire = (total = totals(), apps = [{ app: "codex", rate_percent: 52, ...total }]) =>
  ({ schema: "guard-cigar-savings.v1", window_days: 7, estimate: true, total, apps });

// The page only shows an estimate Guard labeled as one, and never lets a bad estimate hide the usage numbers.
assert.ok(parseSavings(wire()));
assert.equal(parseSavings({ ...wire(), estimate: false }), null);
assert.equal(parseSavings({ ...wire(), schema: "other" }), null);
assert.equal(parseSavings(wire(totals({ used_tokens: -1 }))), null);
assert.equal(parseSavings(wire(totals(), [{ app: "codex", rate_percent: 100, ...totals() }])), null);
const meter = { state: "ready", window_days: 7, today: [], week: [], unread: [] };
assert.equal(parseUsageMeter({ ...meter, savings: { broken: true } }).savings, null);
assert.equal(parseUsageMeter(meter).savings, null);

const full = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire())} />);
assert.match(full, text("CIGAR saved about <strong>" + spoken(1_400_000) + "</strong> tokens this week"));
assert.match(full, /That&#x27;s our best estimate/);
assert.match(full, text("used " + spoken(1_200_000) + " tokens. Without CIGAR, the same work would likely have taken about " + spoken(2_600_000) + "."));
assert.match(full, /Saved \(estimate\)/);
assert.match(full, /12 prompts got project code from CIGAR/);
assert.match(full, text("About " + exact(9_400) + " tokens of code handed over"));
assert.match(full, /18 of 22 files shown, the AI didn&#x27;t need to open again/);
assert.match(full, text('role="img" aria-label="Used ' + spoken(1_200_000) + " tokens. Without CIGAR, about " + spoken(1_400_000) + ' more."'));
assert.match(full, /--used:46%/);
assert.match(full, /How we estimate/);
assert.match(full, /about ¾ of a word/);
assert.match(full, /Codex 52%/);
assert.doesNotMatch(full, /Guard could not read the rest/);

// Some sessions unreadable: the estimate says what it covers, and only read sessions count reopened files.
const partial = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ measured_sessions: 1, files_checked: 5, files_opened_anyway: 1 })))} />);
assert.match(partial, /The estimate covers 1 of 3 sessions\. Guard could not read the rest\./);
assert.match(partial, /4 of 5 files shown, the AI didn&#x27;t need to open again/);

// No session readable: measured facts only, no invented number, no bar.
const blind = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ measured_sessions: 0, files_checked: 0, files_opened_anyway: 0, used_tokens: 0, estimated_saved_tokens: 0 })))} />);
assert.match(blind, /CIGAR helped 3 sessions this week/);
assert.match(blind, /can&#x27;t estimate the tokens saved/);
assert.doesNotMatch(blind, /saved about|role="img"|<table/);
assert.match(blind, /cut tokens by about half\./, "with no app measured the method still reads as a sentence");
assert.match(blind, /12 prompts got project code/);
assert.doesNotMatch(blind, /didn&#x27;t need to open again/, "unread sessions never claim files went unopened");

// Sessions read but no tokens found: say so instead of blaming unreadable records.
const zero = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ used_tokens: 0, estimated_saved_tokens: 0 })))} />);
assert.match(zero, /found no tokens used/);
assert.doesNotMatch(zero, /could not read|saved about|role="img"/);

// Nothing helped yet, or no estimate at all.
const empty = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ sessions: 0, prompts: 0, context_tokens: 0, files_shown: 0, files_checked: 0, files_opened_anyway: 0, measured_sessions: 0, used_tokens: 0, estimated_saved_tokens: 0 }), []))} />);
assert.match(empty, /No savings to show yet/);
assert.doesNotMatch(empty, /\b0 tokens|saved about/);
assert.equal(renderToStaticMarkup(<CigarSavingsPanel savings={null} />), "");

// One session, one prompt, one file: singular words.
const one = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ sessions: 1, prompts: 1, files_shown: 1, files_checked: 1, files_opened_anyway: 1, measured_sessions: 1, used_tokens: 900, estimated_saved_tokens: 970 })))} />);
assert.match(one, text("CIGAR saved about <strong>" + spoken(970) + "</strong> tokens this week"));
assert.match(one, /1 prompt got project code/);
assert.match(one, /0 of 1 file shown/);
console.log("CIGAR savings estimate panel passed.");
