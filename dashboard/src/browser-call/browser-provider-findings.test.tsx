import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { parseBrowserCard } from "../mcp-call/browser-card";
import { checkedAgo, parseProviderFindings } from "./browser-provider-finding-model";
import { BrowserProviderFindings } from "./browser-provider-findings";

const row = {
  provider_id: "provider.exampleshield",
  provider_name: "ExampleShield",
  capability: "browser.origin-reputation",
  verdict: "danger",
  state: "fresh",
  reason_labels: ["Reported for phishing", "Registered recently", "Looks like another site", "Serves malware"],
  observed_at_ms: 1_000,
};

// Closed shapes only: a row with an unknown verdict, capability or state, a bad id or provider text is left off.
const rows = parseProviderFindings([
  row,
  { ...row, provider_id: "provider.second", verdict: "ok", reason_labels: [], sponsored: true },
  { ...row, provider_id: "provider.third", verdict: "safe" },
  { ...row, provider_id: "command.git" },
  { ...row, provider_id: "provider.fifth", capability: "browser.unknown" },
  { ...row, provider_id: "provider.sixth", state: "online" },
  { ...row, provider_id: "provider.seventh", provider_name: "Example‮Shield" },
  "provider.eighth",
]);
assert.deepEqual(rows.map((item) => item.provider_id), ["provider.exampleshield", "provider.second"]);
assert.equal(rows[0].reason_labels.length, 3, "at most three reason labels");
assert.equal(rows[0].sponsored, false);
assert.equal(rows[1].sponsored, true);
assert.deepEqual(parseProviderFindings("not a list"), []);
assert.deepEqual(
  parseProviderFindings([{ ...row, reason_labels: ["Fine", "Hidden​text", 7, "Fine"] }])[0].reason_labels,
  ["Fine"],
);

assert.equal(checkedAgo(1_000, 3_000), "checked just now");
assert.equal(checkedAgo(1_000, 41_000), "checked 40 s ago");
assert.equal(checkedAgo(1_000, 1_000 + 5 * 60_000), "checked 5 min ago");
assert.equal(checkedAgo(10_000, 1_000), "checked just now", "a clock behind the answer is not negative");

const html = renderToStaticMarkup(createElement(BrowserProviderFindings, { findings: rows, nowMs: 41_000 }));
assert.match(html, /Provider findings/);
assert.match(html, /ExampleShield/);
assert.match(html, /Site reputation/);
assert.match(html, /data-provider-verdict="danger"[^>]*>Flagged as dangerous</);
assert.match(html, /Reported for phishing/);
assert.doesNotMatch(html, /Serves malware/);
assert.match(html, /checked 40 s ago/);
assert.match(html, /provider\.second[\s\S]*>Sponsor</);
assert.match(html, /No problems found/);

// A row without a fresh answer names its state and never shows a verdict or reasons.
const stale = parseProviderFindings([{ ...row, state: "rate_limited" }]);
const staleHtml = renderToStaticMarkup(createElement(BrowserProviderFindings, { findings: stale, nowMs: 41_000 }));
assert.match(staleHtml, /Provider is limiting requests/);
assert.doesNotMatch(staleHtml, /Flagged as dangerous|Reported for phishing/);

assert.equal(renderToStaticMarkup(createElement(BrowserProviderFindings, { findings: [] })), "");

// The card parser keeps Guard's own facts and adds the rows Core attached.
const card = parseBrowserCard({
  headline: "Example Agent wants to open shop.example.test",
  verb: "navigate",
  site: { origin: "https://shop.example.test" },
  profile_line: "shared",
  detail: {},
  risk_chips: ["cookies"],
  provider_findings: [row],
  choices: ["allow_once", "always_allow", "deny"],
});
if (card === null) throw new Error("card parses");
assert.deepEqual(card.risk_chips, ["cookies"]);
assert.equal(card.provider_findings.length, 1);

console.log("browser provider findings tests passed");
