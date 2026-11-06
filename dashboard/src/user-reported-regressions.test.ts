import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const feedHealthSource = readFileSync(join(__dirname, "feed-health-workspace.tsx"), "utf8");
const policyTabSource = readFileSync(join(__dirname, "policy-strict-config-tab.tsx"), "utf8");
const strictModeSource = readFileSync(join(__dirname, "policy-strict-config-strict-mode-card.tsx"), "utf8");
const sparklineSource = readFileSync(join(__dirname, "evidence/sparkline.tsx"), "utf8");
const appSource = readFileSync(join(__dirname, "app.tsx"), "utf8");
const layoutSource = readFileSync(join(__dirname, "approval-center-layout.tsx"), "utf8");

assert(
  !feedHealthSource.includes("onClick={onOpenSettings}"),
  "feed health must not forward the React click event into settings navigation",
);
assert(
  feedHealthSource.match(/onClick=\{\(\) => onOpenSettings\(\)\}/g)?.length === 2,
  "both feed health settings actions invoke the zero-argument callback",
);
assert(
  !policyTabSource.includes("onClick={onOpenSettings}"),
  "policy settings action must not forward the React click event",
);
assert(
  !strictModeSource.includes("onClick={onOpenSettings}"),
  "strict-mode settings action must not forward the React click event",
);
assert(
  sparklineSource.includes("<span className=\"text-[10px] font-semibold leading-none text-slate-500\">{count}</span>"),
  "non-empty evidence bars expose their count as visible text",
);
assert(
  sparklineSource.includes("aria-label={`Guard activity over the last ${days} days`}"),
  "evidence activity chart has an accessible label",
);
assert(
  appSource.includes('lazyWorkspace("extensions-workspace", () =>') && appSource.includes('import("./extensions-workspace")'),
  "extensions workspace loads through the retrying lazy wrapper",
);
assert(
  layoutSource.includes("<ErrorBoundary key={props.view} onReset={props.onGoHome}>"),
  "workspace chrome recovers chunk-load failures without crashing the shell",
);
assert(
  appSource.includes("<ErrorBoundary onReset={handleCloseHelp}>"),
  "help modal chunk failures stay inside the dashboard recovery UI",
);

console.log("user-reported-regressions.test.ts: all tests passed");
