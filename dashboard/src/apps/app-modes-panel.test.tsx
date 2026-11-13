import { renderToStaticMarkup } from "react-dom/server";
import { AppModesPanel, appModesSummary } from "./app-modes-panel";
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

console.log("app-modes-panel tests passed");
