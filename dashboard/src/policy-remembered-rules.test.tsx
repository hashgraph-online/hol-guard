import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PolicyRememberedRulesTab } from "./policy-remembered-rules-tab";
import { PolicyRulesAbout } from "./policy-rules-about";
import { PolicyRulesAttentionStrip } from "./policy-rules-attention-strip";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));

assert(typeof PolicyRememberedRulesTab === "function", "exports PolicyRememberedRulesTab");
assert(typeof PolicyRulesAbout === "function", "exports PolicyRulesAbout");
assert(typeof PolicyRulesAttentionStrip === "function", "exports PolicyRulesAttentionStrip");

const tabSource = readFileSync(join(here, "policy-remembered-rules-tab.tsx"), "utf8");
const aboutSource = readFileSync(join(here, "policy-rules-about.tsx"), "utf8");
const workspaceSource = readFileSync(join(here, "policy-workspace.tsx"), "utf8");
const pageSource = readFileSync(join(here, "policy-workspace-page.tsx"), "utf8");
const chromeSource = readFileSync(join(here, "policy-page-chrome.tsx"), "utf8");
const viewsSource = readFileSync(join(here, "policy-workspace-views.tsx"), "utf8");

assert(tabSource.includes('placeholder="Search remembered rules…"'), "tab uses rules-specific search");
assert(tabSource.includes('aria-label="Search remembered rules"'), "tab labels rules search");
assert(tabSource.includes('aria-label="Filter by app"'), "tab preserves app filter");
assert(tabSource.includes("All assets"), "tab uses mockup asset filter label");
assert(tabSource.includes('aria-label="Filter by action type"'), "tab preserves family filter");
assert(tabSource.includes("PolicyRuleTable"), "tab renders one unified rules table");
assert(!tabSource.includes("PolicyRememberedLocalRules"), "tab no longer splits local/cloud sections");
assert(!tabSource.includes("PolicyRememberedCloudRules"), "tab no longer splits local/cloud sections");
assert(tabSource.includes("PolicyRulesAbout"), "tab mounts the about disclosure");
assert(tabSource.includes("No remembered rules yet"), "empty state title lives in the table props");
assert(tabSource.includes("Approve or block in Inbox"), "empty state body preserved");

assert(aboutSource.includes("How Guard decides"), "about shows decision composition");
assert(aboutSource.includes('guardAwareHref("/extensions")'), "about links to canonical Extensions, token kept");
assert(aboutSource.includes("Once"), "scope ladder includes Once");
assert(aboutSource.includes("Team policy"), "scope ladder includes Team policy");
assert(aboutSource.includes("This cwd"), "scope ladder includes This cwd");
assert(aboutSource.includes("Open Cloud exceptions tab"), "about links to Cloud exceptions tab");
assert(aboutSource.includes("PolicyGuardCloudBundleCard"), "about shows Guard Cloud bundle card");

assert(workspaceSource.includes("PolicyRememberedRulesTab"), "workspace uses remembered rules tab");
assert(!workspaceSource.includes("GroupedPolicySection"), "workspace no longer mounts grouped sections directly");
assert(pageSource.includes("PolicyUnderlineTabBar"), "page hosts underline policy tabs");
assert(pageSource.includes("PolicyPageToolbar"), "page hosts policy toolbar");
assert(chromeSource.includes("Reload policy"), "policy toolbar exposes reload policy");

assert(viewsSource.includes("Source"), "rules list shows source column");
const rowSource = readFileSync(join(here, "policy-workspace-row.tsx"), "utf8");
assert(rowSource.includes('scopeLabel(policy.scope, "policy")'), "rules list uses policy scope labels");
assert(rowSource.includes("resolvePolicyRowTitle"), "rules list uses mockup row titles");
const inspectorSource = readFileSync(join(here, "policy-rule-inspector.tsx"), "utf8");
assert(inspectorSource.includes("resolvePolicyApprovalRecordLabel"), "inspector links approval record by receipt id");
assert(!rowSource.includes("Approval record"), "rules list no longer carries a separate approval column");
assert(rowSource.includes("GoverningExtensionLink"), "rules link to their governing Extension when known");
assert(rowSource.includes("display.rememberSentence"), "each rule states its plain-language consequence");
assert(rowSource.includes("View on cloud"), "cloud rules link to Guard Cloud");
assert(rowSource.includes("Remove rule"), "local rules expose remove action");
assert(rowSource.includes("!cloudManaged"), "remove action gated to non-cloud rules");

console.log("policy-remembered-rules.test.tsx: all assertions passed");
