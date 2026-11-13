import {
  appModes,
  appModesNote,
  appModesUpdate,
  applyHarnessCigarPatch,
  cigarAvailable,
  guardOffPrompt,
  needsConfirm,
  watchIsUntimed,
} from "./fleet-app-modes";
import type { GuardContextAssistanceConfig, GuardSettings } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function same(actual: unknown, expected: unknown, message: string): void {
  assert(JSON.stringify(actual) === JSON.stringify(expected), `${message}: got ${JSON.stringify(actual)}`);
}

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

// The four states.
same(appModes(settings(), "codex"), { guard: true, cigar: true }, "Guard + CIGAR by default");
same(appModes(settings({ harness_cigar: { codex: "off" } }), "codex"), { guard: true, cigar: false }, "Guard only");
const cigarOnly = settings({ harness_postures: { codex: "watch" } });
same(appModes(cigarOnly, "codex"), { guard: false, cigar: true }, "CIGAR only");
same(
  appModes(settings({ harness_postures: { codex: "watch" }, harness_cigar: { codex: "off" } }), "codex"),
  { guard: false, cigar: false },
  "recording only",
);

// CIGAR availability.
assert(!cigarAvailable(settings(), "cursor"), "an app without a prompt context hook cannot use CIGAR");
assert(!cigarAvailable(settings({ context_assistance: { ...cigarOn, enabled: false } }), "codex"), "CIGAR off machine-wide");
assert(
  !cigarAvailable(settings({ context_assistance: { ...cigarOn, features: { ...cigarOn.features, agent_context: false } } }), "codex"),
  "CIGAR without agent context",
);
same(appModes(settings({ context_assistance: null }), "codex"), { guard: true, cigar: false }, "no CIGAR config reads as off");

// Updates.
same(
  appModesUpdate(settings(), "codex", { guard: false, cigar: true }),
  { harness_postures: { codex: "watch" }, harness_watch_untimed: true },
  "Guard off with CIGAR on is an untimed Watch",
);
same(
  appModesUpdate(settings(), "codex", { guard: true, cigar: false }),
  { harness_cigar: { codex: "off" } },
  "CIGAR off alone touches only the CIGAR table",
);
same(
  appModesUpdate(settings(), "codex", { guard: false, cigar: false }),
  { harness_postures: { codex: "watch" }, harness_cigar: { codex: "off" } },
  "both off is the timed Watch",
);
same(
  appModesUpdate(cigarOnly, "codex", { guard: false, cigar: false }),
  { harness_postures: { codex: "watch" }, harness_cigar: { codex: "off" } },
  "leaving CIGAR only restarts the Watch timer",
);
same(
  appModesUpdate(cigarOnly, "codex", { guard: true, cigar: true }),
  { harness_postures: { codex: null } },
  "Guard back on clears the Watch entry",
);
const recording = settings({
  harness_postures: { codex: "watch" },
  harness_watch_entered_at: { codex: "2026-11-12T00:00:00Z" },
  harness_cigar: { codex: "off" },
});
assert(!watchIsUntimed(recording, "codex"), "a stamped Watch is timed");
assert(watchIsUntimed(cigarOnly, "codex"), "an unstamped app Watch is untimed");
same(
  appModesUpdate(recording, "codex", { guard: false, cigar: true }),
  { harness_postures: { codex: "watch" }, harness_watch_untimed: true, harness_cigar: { codex: null } },
  "turning CIGAR on in Watch makes the Watch last",
);
same(appModesUpdate(settings(), "codex", { guard: true, cigar: true }), null, "no change sends nothing");
same(
  appModesUpdate(settings(), "cursor", { guard: false, cigar: true }),
  { harness_postures: { cursor: "watch" } },
  "an app CIGAR cannot serve falls back to the timed Watch",
);
same(
  appModesUpdate(settings({ protection_posture: "watch" }), "codex", { guard: false, cigar: true }),
  { harness_postures: { codex: "watch" }, harness_watch_untimed: true },
  "CIGAR only under a machine Watch is the app's own lasting entry",
);

// Confirmation.
assert(needsConfirm({ guard: true, cigar: true }, { guard: false, cigar: true }), "turning Guard off confirms");
assert(!needsConfirm({ guard: true, cigar: true }, { guard: true, cigar: false }), "CIGAR off alone does not confirm");
assert(needsConfirm({ guard: false, cigar: false }, { guard: false, cigar: true }), "making Watch last confirms");
assert(!needsConfirm({ guard: false, cigar: true }, { guard: false, cigar: false }), "going back to timed Watch does not confirm");

// A managed lock owns Guard: only the CIGAR choice is sent, and nothing waits on a confirmation.
const locked = settings({ protection_posture: "watch", harness_postures_locked: true });
same(
  appModesUpdate(locked, "codex", { guard: false, cigar: false }),
  { harness_cigar: { codex: "off" } },
  "CIGAR off under a lock sends no posture",
);
same(
  appModesUpdate(settings({ ...locked, harness_cigar: { codex: "off" } }), "codex", { guard: false, cigar: true }),
  { harness_cigar: { codex: null } },
  "CIGAR on under a lock sends no posture",
);
assert(!needsConfirm({ guard: false, cigar: false }, { guard: false, cigar: true }, true), "a lock skips the confirmation");
same(
  applyHarnessCigarPatch({ codex: "off", pi: "off" }, { codex: null, omp: "off" }),
  { pi: "off", omp: "off" },
  "null removes an app's CIGAR entry",
);

// Notes and prompts.
assert(appModesNote(settings(), "codex") === null, "the usual state needs no note");
assert(appModesNote(settings({ harness_cigar: { codex: "off" } }), "codex")?.startsWith("Guard only") === true, "Guard only note");
assert(appModesNote(cigarOnly, "codex")?.startsWith("CIGAR only") === true, "CIGAR only note");
assert(appModesNote(recording, "codex") === "Watch · recording only", "recording note");
assert(appModesNote(settings(), "cursor") === null, "an app without CIGAR has no CIGAR note");
assert(guardOffPrompt(settings(), "codex", { guard: false, cigar: true }, "Codex").includes("CIGAR keeps"), "CIGAR-only prompt");
assert(guardOffPrompt(settings(), "codex", { guard: false, cigar: false }, "Codex").includes("24 hours"), "timed prompt names the hours");
assert(
  guardOffPrompt(settings({ watch_auto_revert_hours: 0 }), "codex", { guard: false, cigar: false }, "Codex").includes("until you turn it back on"),
  "no timer prompt",
);
assert(
  guardOffPrompt(recording, "codex", { guard: false, cigar: true }, "Codex").startsWith("CIGAR will start"),
  "turning CIGAR on from Watch reads as an enable",
);
const machineWatchOverride = settings({ protection_posture: "watch", harness_postures: { codex: "extra_careful" } });
assert(
  guardOffPrompt(machineWatchOverride, "codex", { guard: false, cigar: false }, "Codex").includes("following this machine's Watch"),
  "an app that falls back to machine Watch is not promised a new interval",
);

console.log("fleet-app-modes.test.ts: all assertions passed");
