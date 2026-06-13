import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { supplyChainCloudTagTone } from "./supply-chain-workspace-hero-state";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));

const workspaceSource = readFileSync(join(here, "supply-chain-workspace.tsx"), "utf8");
const controlsSource = readFileSync(join(here, "supply-chain-firewall-controls.tsx"), "utf8");
const issueFocusSource = readFileSync(join(here, "supply-chain-issue-focus.tsx"), "utf8");

assert(supplyChainCloudTagTone("paired_active") === "green", "cloud tag tone for paired active");
assert(supplyChainCloudTagTone("paired_waiting") === "blue", "cloud tag tone for paired waiting");
assert(supplyChainCloudTagTone("local_only") === "attention", "cloud tag tone for local only");

assert(
  workspaceSource.includes("SupplyChainStatusHeader"),
  "workspace uses unified status header",
);
assert(
  !workspaceSource.includes("SupplyChainAuditFindingsSummary"),
  "workspace drops duplicate audit findings summary",
);
assert(
  workspaceSource.includes("PackageWorkbenchPanel"),
  "workspace keeps single audit findings workbench",
);
assert(
  !controlsSource.includes("NextActionHero"),
  "firewall controls drop duplicate next-step hero",
);
assert(
  controlsSource.includes('layout="card"'),
  "firewall controls render manager cards",
);
assert(
  !issueFocusSource.includes("amber-"),
  "issue focus avoids amber alert styling",
);

console.log("supply-chain-ux-consolidation.test.ts: all assertions passed");
