import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const workspaceSource = readFileSync(join(here, "policy-workspace.tsx"), "utf8");
const tabSource = readFileSync(join(here, "policy-strict-config-tab.tsx"), "utf8");
const enforcementSource = readFileSync(join(here, "policy-strict-config-enforcement-preview.tsx"), "utf8");
const pageSource = readFileSync(join(here, "policy-workspace-page.tsx"), "utf8");

assert(workspaceSource.includes("PolicyStrictConfigTab"), "policy workspace mounts strict config tab");
assert(!workspaceSource.includes("StrictModeView"), "legacy strict mode view removed");
assert(!tabSource.includes("fetchSettings"), "policy decision view must not own a second settings editor");
assert(!tabSource.includes("updateSettings"), "policy decision view must not mutate settings");
assert(tabSource.includes("Policy explains. Settings configures."), "policy view explains ownership");
assert(tabSource.includes("Open protection rules"), "policy view links to the canonical editor");
assert(enforcementSource.includes("How Guard decides"), "policy view shows evaluation order");
assert(enforcementSource.includes("sm:grid-cols-2"), "decision order adapts for tablet and phone widths");
assert(enforcementSource.includes("xl:grid-cols-5"), "decision order uses a compact desktop grid");
assert(workspaceSource.includes("cloudControlsUrl={resolveCloudPolicyControlsUrl(snapshot)}"), "strict config receives cloud controls url");
assert(pageSource.includes("resolveProtectionRulesPath(window.location.search)"), "policy links directly to canonical protection rules");
assert(pageSource.includes('params.set("demo", "1")'), "policy keeps local demo verification isolated from the daemon");

console.log("policy-strict-config-ia.test.ts: all assertions passed");
