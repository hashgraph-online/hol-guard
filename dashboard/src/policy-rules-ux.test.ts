import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import assert from "node:assert/strict";
import { resolvePolicyViewFromHash, withPolicyViewHash } from "./policy-workspace-page";
import { resolvePolicyViewHint } from "./policy-workspace";

const here = dirname(fileURLToPath(import.meta.url));
const read = (name: string) => readFileSync(join(here, name), "utf8");

assert.equal(resolvePolicyViewFromHash("#policy-view=cloud-exceptions"), "exceptions");
assert.equal(resolvePolicyViewFromHash("#policy-view=how-guard-decides"), "strict");
assert.equal(resolvePolicyViewFromHash("#policy-view=remembered-rules"), "rules");
assert.equal(resolvePolicyViewFromHash(""), "rules");
assert.equal(resolvePolicyViewFromHash("#guard-token=tok&guardDaemon=http://127.0.0.1:9"), "rules");
// Tab writes preserve session/daemon fragment params.
const preserved = withPolicyViewHash("#guard-token=tok&guardDaemon=http://127.0.0.1:9", "exceptions");
assert.ok(preserved.includes("guard-token=tok"), "tab hash keeps the session token param");
assert.ok(preserved.includes("guardDaemon="), "tab hash keeps the daemon param");
assert.equal(resolvePolicyViewFromHash(preserved), "exceptions");
assert.match(resolvePolicyViewHint("rules"), /approved or blocked/);

const page = read("policy-workspace-page.tsx");
assert.ok(page.includes("What Guard remembers, allows, and blocks"), "non-rules views keep the task title");
assert.ok(page.includes("remembered"), "rules view leads with a compact status line, hero carries the title");
assert.ok(page.includes("counts={{ rules: ruleCounts.total }}"), "rules tab shows a live count");
assert.ok(page.includes("history.replaceState"), "tab switches update the URL hash without reload");

const chrome = read("policy-page-chrome.tsx");
assert.ok(chrome.includes("Connect Guard Cloud to request an exception."), "disabled exception action explains why");
assert.ok(chrome.includes("resolvePolicyViewHint"), "tabs carry a plain-language hint");

const tab = read("policy-remembered-rules-tab.tsx");
assert.ok(tab.includes("PolicyRulesHero"), "remembered tab leads with the light rules header");
assert.ok(tab.includes("PolicyRulesAttentionStrip"), "broad allows surface as one quiet strip, not cards");
assert.ok(!tab.includes("PolicyRulesSpotlight"), "spotlight shelf is gone");
assert.ok(!tab.includes("guard-posture-bar"), "posture bar is gone — counts live in the header facts");
assert.ok(tab.includes("PolicyRulesListSwitch"), "action filter uses the Extensions list switch");
assert.ok(tab.includes("PolicyRuleInspector"), "rules open in an inspector");
assert.ok(tab.includes("Clear search and filters"), "filtered state offers one-click recovery");
assert.ok(tab.includes("Review pending requests"), "empty rules route to Inbox");
assert.ok(tab.includes("handleRemoveSelected"), "bulk removal reuses the single-rule clear path");
assert.ok(tab.includes("PolicyRulesAbout"), "explanations live in one bottom disclosure");
const jsx = tab.slice(tab.indexOf("return ("));
assert.ok(jsx.indexOf("PolicyRulesHero") < jsx.indexOf("PolicyRuleTable"), "header precedes the single rules list");
assert.ok(jsx.indexOf("PolicyRuleTable") < jsx.indexOf("PolicyRulesAbout"), "about disclosure follows the list");

const views = read("policy-workspace-views.tsx");
assert.ok(views.includes("Remove selected"), "selected rules expose bulk removal");
assert.ok(views.includes("PolicyRuleRow"), "table renders the extracted rule row");
const row = read("policy-workspace-row.tsx");
assert.ok(row.includes("aria-label={`Select rule"), "row selection is labelled per rule");
assert.ok(row.includes("display.rememberSentence"), "rows state what Guard will do next time");
assert.ok(row.includes("Broad allow"), "broad allows are flagged in the list");
assert.ok(row.includes("onInspect"), "rows expose an Inspect action");

const about = read("policy-rules-about.tsx");
assert.ok(about.includes("<details"), "about is a single disclosure, not a rail");

const hero = read("policy-rules-hero.tsx");
assert.ok(!hero.includes("guard-hero"), "header does not copy the Home dark hero");
assert.ok(!hero.includes("HeroParticleLogo"), "header carries no particle stage");
assert.ok(hero.includes("guard-state-pill"), "header uses the native state pill");
assert.ok(!hero.includes("Lorem"), "header uses real model copy only");

const styledSelect = read("styled-select.tsx");
assert.ok(styledSelect.includes("appearance-none"), "selects suppress raw OS chrome");
assert.ok(styledSelect.includes("HiMiniChevronDown"), "selects carry the shared chevron");
const filterBar = read("evidence/evidence-filter-bar.tsx");
assert.ok(filterBar.includes("StyledSelect"), "evidence filters use the styled select");
assert.ok(!filterBar.includes("<select"), "evidence filters have no bare native selects");

const inspector = read("policy-rule-inspector.tsx");
assert.ok(inspector.includes('role="dialog"'), "inspector is a modal dialog");
assert.ok(inspector.includes("Remove rule"), "inspector reuses the remove path");
assert.ok(inspector.includes("Exact action approved"), "inspector names the exact approved action");
assert.ok(inspector.includes("resolveExactApprovedAction"), "inspector reads the exact action from the decision");
assert.ok(inspector.includes("resolvePolicyEvidenceHref"), "inspector links the approval record");

console.log("policy-rules-ux.test.ts: all assertions passed");
