import { renderToStaticMarkup } from "react-dom/server";
import { AppModesPanel, AppModesPanelView, appModesSummary } from "./app-modes-panel";
import type { FleetAppPosture } from "../fleet-app-protection";
import type { GuardContextAssistanceConfig, GuardSettings } from "../guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

const emptyStorage = { getItem: () => null, setItem: () => undefined };
(globalThis as unknown as { window: object }).window = {
  location: { origin: "http://127.0.0.1:4781", pathname: "/", search: "", hash: "" },
  localStorage: emptyStorage,
  sessionStorage: emptyStorage,
};

const cigarOn = {
  schema_version: 1,
  enabled: true,
  runtime_id: "selected",
  resource_profile: "balanced",
  features: { review_briefs: true, agent_context: true, shared_agents: false },
  sources: { native_policy_facts: true, sanitized_receipt_facts: true, workspace_documents: true, source_set_id: "s" },
  storage: { mode: "memory", retention_hours: 24 },
  limits: { context_tokens: 1, reserve_tokens: 1, max_active_workspaces: 1, idle_shutdown_seconds: 1 },
} as GuardContextAssistanceConfig;

function settings(overrides: Partial<GuardSettings> = {}): GuardSettings {
  return {
    mode: "enforce",
    protection_posture: "protected",
    security_level: "balanced",
    harness_postures: {},
    context_assistance: cigarOn,
    ...overrides,
  } as GuardSettings;
}

assert(appModesSummary(settings(), "codex") === "Guard and CIGAR are both on", "default summary");
const guardOnly = appModesSummary(settings({ harness_cigar: { codex: "off" } }), "codex");
assert(guardOnly.startsWith("Guard only"), `Guard-only summary: ${guardOnly}`);
const cigarOnly = appModesSummary(settings({ harness_postures: { codex: "watch" } }), "codex");
assert(cigarOnly.startsWith("CIGAR only"), `CIGAR-only summary: ${cigarOnly}`);
assert(
  appModesSummary(settings({ context_assistance: null }), "codex") === "Guard is on",
  "an app without CIGAR reads as Guard on"
);

const unmanaged = renderToStaticMarkup(
  <AppModesPanel harness="codex" managed={false} onSetUp={() => undefined} />
);
assert(unmanaged.includes("What runs in"), "panel has a heading");
assert(unmanaged.includes("Set up Guard for"), "an unmanaged app offers setup instead of switches");
assert(!unmanaged.includes('role="switch"'), "an unmanaged app shows no switches");

const managed = renderToStaticMarkup(
  <AppModesPanel harness="codex" managed onSetUp={() => undefined} />
);
assert(!managed.includes("Set up Guard for"), "a managed app does not offer setup");
assert(managed.includes("guard-skeleton"), "a managed app shows a skeleton while settings load");

function loaded(current: GuardSettings, hasSwitches: boolean): FleetAppPosture {
  return {
    kind: "ready",
    rowFor: () => undefined,
    control: () => (hasSwitches ? <span data-testid="app-mode-switches" /> : null),
    watchConfirm: () => null,
    summary: null,
    settings: current,
    footer: null,
  } as unknown as FleetAppPosture;
}

const ready = renderToStaticMarkup(
  <AppModesPanelView harness="codex" managed onSetUp={() => undefined} posture={loaded(settings({ harness_cigar: { codex: "off" } }), true)} />
);
assert(ready.includes('data-testid="app-mode-switches"'), "a loaded managed app shows its switches");
assert(ready.includes('data-testid="app-modes-summary"'), "a loaded managed app names what runs");
assert(ready.includes("Guard only"), "the summary follows the saved settings");
assert(!ready.includes("guard-skeleton"), "no skeleton once loaded");
assert(!ready.includes("Set up Guard for"), "a loaded managed app does not offer setup");

const notInterceptedYet = renderToStaticMarkup(
  <AppModesPanelView harness="codex" managed={false} onSetUp={() => undefined} posture={loaded(settings(), false)} />
);
assert(!notInterceptedYet.includes('data-testid="app-mode-switches"'), "a loaded unmanaged app shows no switches");
assert(!notInterceptedYet.includes('data-testid="app-modes-summary"'), "a loaded unmanaged app claims nothing runs");
assert(notInterceptedYet.includes("Set up Guard for"), "a loaded unmanaged app offers setup");

console.log("app-modes-panel tests passed");
