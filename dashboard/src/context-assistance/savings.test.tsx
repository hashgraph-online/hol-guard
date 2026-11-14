import assert from "node:assert/strict";
import { renderToStaticMarkup } from "react-dom/server";
import { CigarSavingsPanel } from "./savings-panel";
import { parseSavings, parseUsageMeter } from "./usage-api";

const totals = (over: Record<string, number> = {}) => ({
  sessions: 3, prompts: 12, context_tokens: 9_400, files_shown: 22, files_opened_anyway: 4,
  measured_sessions: 3, used_tokens: 1_200_000, estimated_saved_tokens: 1_400_000, ...over,
});
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
assert.match(full, /CIGAR saved about <strong>1\.4 million<\/strong> tokens this week/);
assert.match(full, /That&#x27;s our best estimate/);
assert.match(full, /used 1\.2 million tokens\. Without CIGAR, the same work would likely have taken about 2\.6 million\./);
assert.match(full, /Saved \(estimate\)/);
assert.match(full, /12 prompts got project code from CIGAR/);
assert.match(full, /About 9,400 tokens of code handed over/);
assert.match(full, /18 of 22 files shown, the AI didn&#x27;t need to open again/);
assert.match(full, /role="img" aria-label="Used 1\.2 million tokens\. Without CIGAR, about 1\.4 million more\."/);
assert.match(full, /--used:46%/);
assert.match(full, /How we estimate/);
assert.match(full, /about ¾ of a word/);
assert.match(full, /Codex 52%/);
assert.doesNotMatch(full, /Guard could not read the rest/);

// Some sessions unreadable: the estimate says what it covers.
const partial = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ measured_sessions: 1 })))} />);
assert.match(partial, /The estimate covers 1 of 3 sessions\. Guard could not read the rest\./);

// No session readable: measured facts only, no invented number, no bar.
const blind = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ measured_sessions: 0, used_tokens: 0, estimated_saved_tokens: 0 })))} />);
assert.match(blind, /CIGAR helped 3 sessions this week/);
assert.match(blind, /can&#x27;t estimate the tokens saved/);
assert.doesNotMatch(blind, /saved about|role="img"|<table/);
assert.match(blind, /cut tokens by about half\./, "with no app measured the method still reads as a sentence");
assert.match(blind, /12 prompts got project code/);

// Nothing helped yet, or no estimate at all.
const empty = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ sessions: 0, prompts: 0, context_tokens: 0, files_shown: 0, files_opened_anyway: 0, measured_sessions: 0, used_tokens: 0, estimated_saved_tokens: 0 }), []))} />);
assert.match(empty, /No savings to show yet/);
assert.doesNotMatch(empty, /\b0 tokens|saved about/);
assert.equal(renderToStaticMarkup(<CigarSavingsPanel savings={null} />), "");

// One session, one prompt, one file: singular words.
const one = renderToStaticMarkup(<CigarSavingsPanel savings={parseSavings(wire(totals({ sessions: 1, prompts: 1, files_shown: 1, files_opened_anyway: 1, measured_sessions: 0, used_tokens: 0, estimated_saved_tokens: 0 })))} />);
assert.match(one, /CIGAR helped 1 session this week/);
assert.match(one, /1 prompt got project code/);
assert.match(one, /0 of 1 file shown/);
console.log("CIGAR savings estimate panel passed.");
