import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { PolicyRememberedCloudRules } from "./policy-remembered-cloud-rules";
import { PolicyRememberedLocalRules } from "./policy-remembered-local-rules";
import { PolicyRememberedRulesRightRail } from "./policy-remembered-rules-right-rail";
import { PolicyRememberedRulesTab } from "./policy-remembered-rules-tab";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));

assert(typeof PolicyRememberedLocalRules === "function", "exports PolicyRememberedLocalRules");
assert(typeof PolicyRememberedCloudRules === "function", "exports PolicyRememberedCloudRules");
assert(typeof PolicyRememberedRulesTab === "function", "exports PolicyRememberedRulesTab");
assert(typeof PolicyRememberedRulesRightRail === "function", "exports PolicyRememberedRulesRightRail");

const localSource = readFileSync(join(here, "policy-remembered-local-rules.tsx"), "utf8");
const cloudSource = readFileSync(join(here, "policy-remembered-cloud-rules.tsx"), "utf8");
const tabSource = readFileSync(join(here, "policy-remembered-rules-tab.tsx"), "utf8");
const railSource = readFileSync(join(here, "policy-remembered-rules-right-rail.tsx"), "utf8");
const workspaceSource = readFileSync(join(here, "policy-workspace.tsx"), "utf8");
const pageSource = readFileSync(join(here, "policy-workspace-page.tsx"), "utf8");
const chromeSource = readFileSync(join(here, "policy-page-chrome.tsx"), "utf8");
const viewsSource = readFileSync(join(here, "policy-workspace-views.tsx"), "utf8");

assert(localSource.includes("No local remembered rules yet"), "local rules empty state title");
assert(localSource.includes("Approve or block in Inbox"), "local rules empty state body");
assert(localSource.includes("onClearPolicy"), "local rules support remove action");

assert(cloudSource.includes("No Guard Cloud rules synced"), "cloud rules empty state title");
assert(cloudSource.includes("Connect Guard Cloud"), "cloud rules empty state body");
assert(cloudSource.includes("cloudVariant"), "cloud rules use cloud table variant");
assert(!cloudSource.includes("onClearPolicy"), "cloud rules are read-only without remove");

assert(tabSource.includes('placeholder="Search command, project, path, or app…"'), "tab preserves search");
assert(tabSource.includes('aria-label="Filter by app"'), "tab preserves app filter");
assert(tabSource.includes("All assets"), "tab uses mockup asset filter label");
assert(tabSource.includes('aria-label="Filter by action type"'), "tab preserves family filter");
assert(tabSource.includes("PolicyGuardCloudBundleCard"), "tab shows Guard Cloud bundle card");
assert(tabSource.includes("PolicyRememberedLocalRules"), "tab mounts local rules section");
assert(tabSource.includes("PolicyRememberedCloudRules"), "tab mounts cloud rules section");
assert(tabSource.includes("PolicyRememberedRulesRightRail"), "tab mounts right rail helper");

assert(railSource.includes("Active mode"), "right rail shows active mode card");
assert(railSource.includes("Approvals are still fast"), "right rail explains fast approvals");
assert(railSource.includes('scope: "artifact"'), "scope ladder includes narrowest scope");
assert(railSource.includes('scope: "global"'), "scope ladder includes widest scope");
assert(railSource.includes('scopeLabel(step.scope, "policy")'), "scope ladder renders policy scope labels");
assert(railSource.includes("Open Cloud exceptions tab"), "right rail links to Cloud exceptions tab");

assert(workspaceSource.includes("PolicyRememberedRulesTab"), "workspace uses remembered rules tab");
assert(!workspaceSource.includes("GroupedPolicySection"), "workspace no longer mounts grouped sections directly");
assert(pageSource.includes("PolicyUnderlineTabBar"), "page hosts underline policy tabs");
assert(pageSource.includes("PolicyPageToolbar"), "page hosts policy toolbar");
assert(chromeSource.includes("Reload policy"), "policy toolbar exposes reload policy");

assert(viewsSource.includes("Rule"), "rules list uses rule column");
assert(viewsSource.includes("Source"), "rules list shows source column");
assert(viewsSource.includes('scopeLabel(policy.scope, "policy")'), "rules list uses policy scope labels");
assert(viewsSource.includes("display.pathLine"), "rules list shows approval path");
assert(viewsSource.includes("resolvePolicyRowTitle"), "rules list uses mockup row titles");
assert(viewsSource.includes("resolvePolicyApprovalRecordLabel"), "rules list links approval record by receipt id");
assert(!viewsSource.includes("display.rememberSentence"), "rules list omits verbose remember sentence");
assert(viewsSource.includes("View on cloud"), "cloud rules link to Guard Cloud");
assert(viewsSource.includes("Remove rule"), "local rules expose remove action");
assert(viewsSource.includes("!cloudManaged"), "remove action gated to non-cloud rules");
assert(viewsSource.includes("HiMiniLockClosed"), "cloud rules show read-only policy lock");

console.log("policy-remembered-rules.test.tsx: all assertions passed");
