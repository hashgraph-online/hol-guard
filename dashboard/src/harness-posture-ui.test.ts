import type { GuardProtectionCapability, GuardSettings } from "./guard-types";
import {
  canRestartHarnessWatch,
  clearHarnessWatchOverrides,
  effectiveHarnessPosture,
  harnessPostureOptions,
  harnessPosturePatch,
  harnessPostureRows,
  harnessPostureSummary,
  harnessWatchPrompt,
  normalizeHarnessPostures,
  restartHarnessWatch,
  selectHarnessPosture,
  turnProtectionOnUpdate,
  watchBannerModel,
  withHarnessPosturePatch,
} from "./harness-posture-ui";
import { WATCH_BANNER_COPY } from "./protection-posture-copy";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function settings(overrides: Partial<GuardSettings> = {}): GuardSettings {
  return {
    mode: "enforce",
    protection_posture: "protected",
    security_level: "balanced",
    harness_postures: {},
    ...overrides,
  } as GuardSettings;
}

function capability(harness: string, displayName: string): GuardProtectionCapability {
  return { harness, display_name: displayName } as GuardProtectionCapability;
}

const capabilities = [capability("codex", "Codex"), capability("claude-code", "Claude Code")];

// Normalizer drops malformed entries.
const normalized = normalizeHarnessPostures({ codex: "watch", bad: "nope", "": "watch", other: 3 });
assert(Object.keys(normalized).length === 1 && normalized.codex === "watch", "normalizer keeps valid entries only");
assert(Object.keys(normalizeHarnessPostures(null)).length === 0, "normalizer handles non-objects");

// Selecting Watch stores only an override; Protected under a protected machine inherits.
const watched = selectHarnessPosture(settings(), "codex", "watch");
assert(watched.harness_postures?.codex === "watch", "watch stores an override for the app");
assert(effectiveHarnessPosture(watched, "codex") === "watch", "watch override is effective");
assert(effectiveHarnessPosture(watched, "claude-code") === "protected", "other apps stay protected");
const restored = selectHarnessPosture(watched, "codex", "on");
assert(restored.harness_postures?.codex === undefined, "protected under a protected machine clears the override");

// Under a Watch machine, Protected is the override and Watch inherits.
const globalWatch = settings({ protection_posture: "watch", mode: "observe" });
const protectedApp = selectHarnessPosture(globalWatch, "codex", "on");
assert(protectedApp.harness_postures?.codex === "protected", "protected under Watch stores an override");
assert(effectiveHarnessPosture(protectedApp, "codex") === "protected", "protected override is effective under Watch");
assert(
  selectHarnessPosture(protectedApp, "codex", "watch").harness_postures?.codex === undefined,
  "watch under a Watch machine inherits",
);

// A stricter machine posture is never weakened by a Protected override, and re-selecting is a no-op.
const careful = settings({ protection_posture: "extra_careful", harness_postures: { codex: "protected" } });
assert(effectiveHarnessPosture(careful, "codex") === "extra_careful", "override does not weaken extra careful");
assert(selectHarnessPosture(careful, "codex", "on") === careful, "re-selecting the protected level is a no-op");
const optionLabels = harnessPostureOptions(careful, "codex").map((option) => option.label).join("/");
assert(optionLabels === "Extra careful/Watch", "options show the stricter machine level and Watch");
const cliOverride = settings({ harness_postures: { codex: "extra_careful" } });
assert(selectHarnessPosture(cliOverride, "codex", "on") === cliOverride, "extra careful override is not silently cleared");

// Patch carries only changed entries so unrelated saves never re-stamp Watch.
const saved = settings({ harness_postures: { codex: "watch" } });
assert(harnessPosturePatch(saved, saved) === null, "no change, no patch");
const draft = settings({ harness_postures: { "claude-code": "watch" } });
const patch = harnessPosturePatch(draft, saved);
assert(patch !== null && patch.codex === null && patch["claude-code"] === "watch", "patch clears and sets only changes");
const payload = withHarnessPosturePatch(
  { ...draft, harness_postures_effective: { codex: "watch" }, harness_postures_locked: false },
  draft,
  saved,
);
assert(payload.harness_postures?.codex === null, "payload carries the patch, not the full map");
assert(!("harness_postures_effective" in payload), "read-only effective map is not sent");
assert(!("harness_postures_locked" in payload), "read-only lock flag is not sent");
assert(
  !("harness_postures" in withHarnessPosturePatch({ ...saved }, saved, saved)),
  "unchanged apps send no per-app key",
);

// Summary names the apps in Watch.
assert(harnessPostureSummary(harnessPostureRows(settings(), capabilities)) === "Every app is protected.", "all protected");
assert(
  harnessPostureSummary(harnessPostureRows(watched, capabilities)) === "1 of 2 apps in Watch: Codex.",
  "summary names the watched app",
);
assert(harnessPostureSummary(harnessPostureRows(globalWatch, capabilities)) === "Every app is in Watch.", "all watch");
assert(clearHarnessWatchOverrides(watched).harness_postures?.codex === undefined, "clear removes watch overrides");

// Banner names the apps and only appears when something is in Watch.
assert(watchBannerModel({ protection_posture: "protected", harnesses_in_watch: [] }) === null, "no banner when protected");
const appBanner = watchBannerModel({
  protection_posture: "protected",
  harness_postures: { codex: "watch", "claude-code": "watch" },
  harnesses_in_watch: ["codex", "claude-code"],
  protection_capabilities: capabilities,
});
assert(appBanner !== null && !appBanner.globalWatch, "per-app banner is not machine wide");
assert(
  appBanner !== null && appBanner.message === "Guard is only recording in Codex and Claude Code. Other apps are protected.",
  "banner names the apps in Watch",
);
const machineBanner = watchBannerModel({ protection_posture: "watch", harnesses_in_watch: ["codex"] });
assert(machineBanner !== null && machineBanner.message === WATCH_BANNER_COPY, "machine banner keeps the original copy");

// Turn protection on ends machine Watch and clears per-app Watch, leaving other overrides.
const update = turnProtectionOnUpdate({
  protection_posture: "watch",
  harness_postures: { codex: "watch", "claude-code": "extra_careful" },
});
assert(update.protection_posture === "protected", "turn on sets the machine posture");
assert(
  update.harness_postures?.codex === null && update.harness_postures?.["claude-code"] === undefined,
  "turn on clears only Watch overrides",
);
const appOnly = turnProtectionOnUpdate({ protection_posture: "protected", harness_postures: { codex: "watch" } });
assert(appOnly.protection_posture === undefined, "turn on leaves a protected machine alone");

// The Watch prompt describes what the other apps actually do.
const underGlobalWatch = settings({ protection_posture: "watch", mode: "observe", harness_postures: { codex: "protected" } });
assert(
  harnessWatchPrompt(harnessPostureRows(underGlobalWatch, capabilities), "codex") ===
    "Guard will only record in Codex. Every app will then be in Watch.",
  "prompt does not claim other apps stay protected under machine Watch",
);
assert(
  harnessWatchPrompt(harnessPostureRows(settings(), capabilities), "codex") ===
    "Guard will only record in Codex. Your other apps stay protected.",
  "prompt keeps other apps protected under a protected machine",
);

// An app already in its own Watch can restart its timer; unrelated saves leave it alone.
const appWatch = settings({ harness_postures: { codex: "watch" } });
assert(canRestartHarnessWatch(appWatch, "codex"), "own Watch entry can restart");
assert(!canRestartHarnessWatch(appWatch, "claude-code"), "inherited posture has no own timer");
assert(!canRestartHarnessWatch({ ...appWatch, watch_auto_revert_hours: 0 }, "codex"), "no timer when auto-revert is off");
assert(harnessPosturePatch(appWatch, appWatch) === null, "unchanged Watch is not re-sent");
const restarted = restartHarnessWatch(appWatch, "codex");
assert(harnessPosturePatch(restarted, appWatch)?.codex === "watch", "restart re-sends the Watch entry");
assert(
  !("harness_watch_restart" in withHarnessPosturePatch(restarted, restarted, appWatch)),
  "restart marker stays out of the payload",
);
