import { renderToStaticMarkup } from "react-dom/server";
import { PackageWorkbenchPanel } from "./package-workbench-panel";
import { ActiveFilterChip, FilterChip, buildFilterSummary } from "./package-workbench-filter-modal";
import type { PackageWorkbenchFilters, PackageWorkbenchSortKey } from "./guard-types";
import type { SupplyChainAuditSnapshot } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const snapshot: SupplyChainAuditSnapshot = {
  generatedAt: "2026-06-09T12:00:00.000Z",
  source: "cloud",
  decision: "warn",
  inventory: {
    totalPackages: 3,
    directPackageCount: 2,
    transitivePackageCount: 1,
    sbomPackageCount: 1,
  },
  packages: [
    {
      id: "pkg-1",
      packageName: "left-pad",
      ecosystem: "npm",
      namespace: null,
      decision: "warn",
      severity: "medium",
      reasons: [{ code: "outdated", message: "Outdated dependency", severity: "medium" }],
      advisoryAliases: [],
      status: "known",
    },
    {
      id: "pkg-2",
      packageName: "minimist",
      ecosystem: "npm",
      namespace: null,
      decision: "block",
      severity: "critical",
      reasons: [{ code: "known_malware", message: "Known malware", severity: "critical" }],
      advisoryAliases: ["GHSA-vh95-rmgr-6w4w"],
      status: "known",
    },
    {
      id: "pkg-3",
      packageName: "chalk",
      ecosystem: "npm",
      namespace: null,
      decision: "monitor",
      severity: "unknown",
      reasons: [],
      advisoryAliases: [],
      status: "known",
    },
  ],
  findings: [
    {
      id: "pkg-1",
      packageName: "left-pad",
      ecosystem: "npm",
      namespace: null,
      decision: "warn",
      severity: "medium",
      reasons: [{ code: "outdated", message: "Outdated dependency", severity: "medium" }],
      advisoryAliases: [],
      status: "known",
    },
    {
      id: "pkg-2",
      packageName: "minimist",
      ecosystem: "npm",
      namespace: null,
      decision: "block",
      severity: "critical",
      reasons: [{ code: "known_malware", message: "Known malware", severity: "critical" }],
      advisoryAliases: ["GHSA-vh95-rmgr-6w4w"],
      status: "known",
    },
  ],
  manifestPaths: ["package.json"],
  lockfilePaths: ["package-lock.json"],
  receiptId: null,
};

const panelMarkup = renderToStaticMarkup(
  <PackageWorkbenchPanel auditSnapshot={snapshot} onRunAudit={() => undefined} />,
);

assert(panelMarkup.includes("Filters"), "PWP1: panel should expose a Filters button");
assert(panelMarkup.includes("All packages"), "PWP2: panel should render all-packages chip");
assert(panelMarkup.includes("Needs review"), "PWP3: panel should render needs-review chip");
assert(panelMarkup.includes("3"), "PWP3-B: panel should show all-packages count");
assert(panelMarkup.includes("2"), "PWP3-C: panel should show needs-review count");
assert(!panelMarkup.includes("All ecosystems"), "PWP4: inline ecosystem filter pills should be removed");
assert(!panelMarkup.includes("All decisions"), "PWP5: inline decision filter pills should be removed");
assert(!panelMarkup.includes("All severities"), "PWP6: inline severity filter pills should be removed");
assert(!panelMarkup.includes(">Sort</span>"), "PWP7: inline sort button row should be removed");
assert(!panelMarkup.includes("Search packages…"), "PWP8: inline search input should be removed");
assert(panelMarkup.includes('aria-pressed="true"'), "PWP9: view-mode chips use aria-pressed");
assert(!panelMarkup.includes('role="switch"'), "PWP10: view-mode chips do not use role switch");
assert(!panelMarkup.includes("aria-checked"), "PWP11: view-mode chips do not use aria-checked");

const singleFilter: PackageWorkbenchFilters = {
  ecosystem: "npm",
  decision: "all",
  severity: "all",
  search: "",
};
assert(
  buildFilterSummary(singleFilter, "severity" as PackageWorkbenchSortKey, "desc").length === 1,
  "PWP12: a single active filter produces a chip",
);
assert(
  buildFilterSummary(
    { ecosystem: "all", decision: "all", severity: "all", search: "" },
    "severity" as PackageWorkbenchSortKey,
    "desc",
  ).length === 0,
  "PWP13: default filters produce no chips",
);

const chipMarkup = renderToStaticMarkup(
  <ActiveFilterChip label="Ecosystem: npm" onRemove={() => undefined} />,
);
assert(chipMarkup.includes("Ecosystem: npm"), "PWP14: active filter chip renders its label");

console.log("package-workbench-panel.test.tsx: all assertions passed");
