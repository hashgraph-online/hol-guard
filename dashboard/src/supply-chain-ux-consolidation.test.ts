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
const hubSource = readFileSync(join(here, "supply-chain-hub-workspace.tsx"), "utf8");
const auditSource = readFileSync(join(here, "audit-workspace.tsx"), "utf8");
const workbenchSource = readFileSync(join(here, "package-workbench-panel.tsx"), "utf8");
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
  workspaceSource.includes("SupplyChainAuditTeaser"),
  "workspace shows compact audit teaser instead of full workbench",
);
assert(
  !workspaceSource.includes("PackageWorkbenchPanel"),
  "workspace drops full audit findings workbench",
);
assert(
  auditSource.includes("PackageWorkbenchPanel"),
  "audit tab hosts package workbench",
);
assert(
  !auditSource.includes("AuditRunProgress"),
  "audit tab does not mount a separate progress card",
);
assert(
  workbenchSource.includes("AuditProgressStepList"),
  "workbench embeds progressive audit steps in one panel",
);
assert(
  workbenchSource.includes("Run audit again"),
  "workbench keeps re-run audit action after completion",
);
assert(
  workbenchSource.includes('viewMode === "all"'),
  "workbench exposes full package inventory view",
);
assert(
  hubSource.includes("useSupplyChainAuditSession"),
  "hub owns shared audit session state",
);
assert(
  hubSource.includes("onAuditStarted={auditSession.handleAuditStarted}"),
  "hub wires audit start navigation into firewall panel",
);
assert(
  workbenchSource.includes("GuardModalLayer"),
  "workbench opens finding detail in modal layer",
);
assert(
  workbenchSource.includes("max-h-[min(60vh,32rem)]"),
  "workbench table scrolls within viewport",
);
assert(
  workspaceSource.includes("supply-chain-workspace-hero-state"),
  "workspace imports supply chain hero state helpers",
);
assert(
  workspaceSource.includes("resolveSupplyChainWorkspaceHero"),
  "workspace resolves hero state for status header",
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
