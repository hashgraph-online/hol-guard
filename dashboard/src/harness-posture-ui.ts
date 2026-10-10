import type {
  GuardHarnessPosturePatch,
  GuardProtectionCapability,
  GuardProtectionPostureValue,
  GuardSettings,
} from "./guard-types";
import type { GuardSettingsUpdate } from "./guard-api";
import { isProtectionPosture, WATCH_BANNER_COPY } from "./protection-posture-copy";

export type HarnessPostureChoice = "watch" | "on";

export type HarnessPostureOption = {
  choice: HarnessPostureChoice;
  label: string;
};

export type HarnessPostureRow = {
  harness: string;
  displayName: string;
  /** Posture this app actually runs under right now. */
  effective: GuardProtectionPostureValue;
  /** True when the app has its own entry rather than following the machine. */
  hasOverride: boolean;
  selected: HarnessPostureChoice;
};

const POSTURE_LABEL: Record<GuardProtectionPostureValue, string> = {
  protected: "Protected",
  extra_careful: "Extra careful",
  watch: "Watch",
};

export function normalizeHarnessPostures(value: unknown): Record<string, GuardProtectionPostureValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return {};
  const result: Record<string, GuardProtectionPostureValue> = {};
  for (const [harness, posture] of Object.entries(value)) {
    if (harness.length > 0 && typeof posture === "string" && isProtectionPosture(posture)) {
      result[harness] = posture;
    }
  }
  return result;
}

function globalPosture(settings: GuardSettings): GuardProtectionPostureValue {
  if (isProtectionPosture(settings.protection_posture)) return settings.protection_posture;
  if (settings.mode === "observe") return "watch";
  return "protected";
}

/** Level an app gets when it is not in Watch: its own level, or the machine's protected level. */
function protectedLevel(
  effective: GuardProtectionPostureValue,
  baseline: GuardProtectionPostureValue,
): GuardProtectionPostureValue {
  if (effective !== "watch") return effective;
  if (baseline !== "watch") return baseline;
  return "protected";
}

export function effectiveHarnessPosture(settings: GuardSettings, harness: string): GuardProtectionPostureValue {
  const override = settings.harness_postures?.[harness];
  const baseline = globalPosture(settings);
  if (override === undefined) return baseline;
  if (override === "watch") return "watch";
  // A non-watch override never weakens a stricter machine-wide posture.
  return baseline === "extra_careful" ? baseline : override;
}

export function harnessPostureRows(
  settings: GuardSettings,
  capabilities: GuardProtectionCapability[],
): HarnessPostureRow[] {
  return capabilities.map((capability) => {
    const effective = effectiveHarnessPosture(settings, capability.harness);
    return {
      harness: capability.harness,
      displayName: capability.display_name,
      effective,
      hasOverride: settings.harness_postures?.[capability.harness] !== undefined,
      selected: effective === "watch" ? "watch" : "on",
    };
  });
}

/** The two choices offered for one app: its protected level, and Watch. */
export function harnessPostureOptions(settings: GuardSettings, harness: string): HarnessPostureOption[] {
  const onLevel = protectedLevel(effectiveHarnessPosture(settings, harness), globalPosture(settings));
  return [
    { choice: "on", label: POSTURE_LABEL[onLevel] },
    { choice: "watch", label: POSTURE_LABEL.watch },
  ];
}

/** Draft update for one app. Watch under a Watch machine, or on under a protected one, just inherits. */
export function selectHarnessPosture(
  settings: GuardSettings,
  harness: string,
  choice: HarnessPostureChoice,
): GuardSettings {
  const baseline = globalPosture(settings);
  // Already protected: leave the app's own level (for example Extra careful) alone.
  if (choice === "on" && effectiveHarnessPosture(settings, harness) !== "watch") return settings;
  const next = { ...(settings.harness_postures ?? {}) };
  if (choice === "watch") {
    if (baseline === "watch") delete next[harness];
    else next[harness] = "watch";
  } else if (baseline === "watch") {
    next[harness] = "protected";
  } else {
    delete next[harness];
  }
  return { ...settings, harness_postures: next };
}

/** True when an app is in Watch through its own entry, so its own timer can restart. */
export function canRestartHarnessWatch(settings: GuardSettings, harness: string): boolean {
  return settings.harness_postures?.[harness] === "watch" && (settings.watch_auto_revert_hours ?? 24) > 0;
}

/** Draft that restarts one app's Watch timer on the next save. */
export function restartHarnessWatch(settings: GuardSettings, harness: string): GuardSettings {
  if (!canRestartHarnessWatch(settings, harness)) return settings;
  const restarts = new Set(settings.harness_watch_restart ?? []);
  restarts.add(harness);
  return { ...settings, harness_watch_restart: [...restarts].sort() };
}

/**
 * Only the entries that changed, plus Watch entries the user asked to restart,
 * so saving other settings never re-stamps an app that is already in Watch.
 * `null` clears an override.
 */
export function harnessPosturePatch(
  draft: GuardSettings,
  saved: GuardSettings | null,
): GuardHarnessPosturePatch | null {
  const before = saved?.harness_postures ?? {};
  const after = draft.harness_postures ?? {};
  const restarts = new Set(draft.harness_watch_restart ?? []);
  const patch: GuardHarnessPosturePatch = {};
  for (const harness of new Set([...Object.keys(before), ...Object.keys(after)])) {
    const posture = after[harness] ?? null;
    const restart = posture === "watch" && restarts.has(harness);
    if (restart || posture !== (before[harness] ?? null)) patch[harness] = posture;
  }
  return Object.keys(patch).length > 0 ? patch : null;
}

/** Draft with every per-app Watch entry cleared, so those apps follow the machine again. */
export function clearHarnessWatchOverrides(settings: GuardSettings): GuardSettings {
  const next = Object.fromEntries(
    Object.entries(settings.harness_postures ?? {}).filter(([, posture]) => posture !== "watch"),
  );
  return { ...settings, harness_postures: next };
}

/** Banner model for the settings draft, which can differ from the saved snapshot. */
export function settingsWatchBannerModel(
  settings: GuardSettings,
  capabilities: GuardProtectionCapability[],
): WatchBannerModel | null {
  const rows = harnessPostureRows(settings, capabilities);
  return watchBannerModel({
    protection_posture: globalPosture(settings),
    harness_postures: settings.harness_postures,
    harnesses_in_watch: rows.filter((row) => row.effective === "watch").map((row) => row.harness),
    protection_capabilities: capabilities,
  });
}

/** Replace the full per-app map with its patch and drop read-only per-app fields. */
export function withHarnessPosturePatch(
  payload: Partial<GuardSettings>,
  draft: GuardSettings,
  saved: GuardSettings | null,
): GuardSettingsUpdate {
  const {
    harness_postures: _postures,
    harness_postures_effective: _effective,
    harness_postures_locked: _locked,
    harness_watch_entered_at: _enteredAt,
    harness_watch_restart: _restart,
    ...rest
  } = payload;
  const patch = harnessPosturePatch(draft, saved);
  return patch === null ? rest : { ...rest, harness_postures: patch };
}

export function harnessPostureSummary(rows: HarnessPostureRow[]): string {
  if (rows.length === 0) return "";
  const watching = rows.filter((row) => row.effective === "watch");
  if (watching.length === 0) return "Every app is protected.";
  if (watching.length === rows.length) return "Every app is in Watch.";
  return `${watching.length} of ${rows.length} apps in Watch: ${joinNames(watching.map((row) => row.displayName))}.`;
}

/** Confirmation copy for putting one app in Watch, given what the other apps will do. */
export function harnessWatchPrompt(rows: HarnessPostureRow[], harness: string): string {
  const row = rows.find((candidate) => candidate.harness === harness);
  const name = row?.displayName ?? harness;
  const others = rows.filter((candidate) => candidate.harness !== harness);
  const protectedOthers = others.filter((candidate) => candidate.effective !== "watch");
  const lead = `Guard will only record in ${name}.`;
  if (others.length === 0) return lead;
  if (protectedOthers.length === 0) return `${lead} Every app will then be in Watch.`;
  if (protectedOthers.length === others.length) return `${lead} Your other apps stay protected.`;
  const verb = protectedOthers.length === 1 ? "stays" : "stay";
  return `${lead} ${joinNames(protectedOthers.map((candidate) => candidate.displayName))} ${verb} protected.`;
}

export function joinNames(names: string[]): string {
  if (names.length <= 1) return names[0] ?? "";
  if (names.length === 2) return `${names[0]} and ${names[1]}`;
  return `${names.slice(0, -1).join(", ")}, and ${names[names.length - 1]}`;
}

export type WatchBannerModel = {
  /** Whole machine is in Watch. */
  globalWatch: boolean;
  /** Apps in Watch on their own while the machine is protected. */
  appNames: string[];
  message: string;
  confirmMessage: string;
};

type WatchSnapshotFields = {
  protection_posture?: string | undefined;
  harness_postures?: Record<string, GuardProtectionPostureValue> | undefined;
  harnesses_in_watch?: string[] | undefined;
  protection_capabilities?: GuardProtectionCapability[] | undefined;
};

function displayNameFor(harness: string, capabilities: GuardProtectionCapability[] | undefined): string {
  return capabilities?.find((capability) => capability.harness === harness)?.display_name ?? harness;
}

/** Null when nothing is in Watch, so the banner stays hidden. */
export function watchBannerModel(snapshot: WatchSnapshotFields): WatchBannerModel | null {
  const globalWatch = snapshot.protection_posture === "watch";
  const watchOverrides = Object.entries(snapshot.harness_postures ?? {})
    .filter(([, posture]) => posture === "watch")
    .map(([harness]) => harness);
  const inWatch = globalWatch ? [] : (snapshot.harnesses_in_watch ?? watchOverrides);
  if (!globalWatch && inWatch.length === 0) return null;
  const appNames = inWatch.map((harness) => displayNameFor(harness, snapshot.protection_capabilities));
  if (globalWatch) {
    return {
      globalWatch,
      appNames: [],
      message: WATCH_BANNER_COPY,
      confirmMessage: "Guard will start stopping dangerous actions in every app.",
    };
  }
  const names = joinNames(appNames);
  return {
    globalWatch,
    appNames,
    message: `Guard is only recording in ${names}. Other apps are protected.`,
    confirmMessage: `Guard will start stopping dangerous actions in ${names}.`,
  };
}

/** Settings update that ends Watch: the machine posture and any per-app Watch entries. */
export function turnProtectionOnUpdate(snapshot: WatchSnapshotFields): GuardSettingsUpdate {
  const update: GuardSettingsUpdate = {};
  if (snapshot.protection_posture === "watch") update.protection_posture = "protected";
  const cleared: GuardHarnessPosturePatch = {};
  for (const [harness, posture] of Object.entries(snapshot.harness_postures ?? {})) {
    if (posture === "watch") cleared[harness] = null;
  }
  if (Object.keys(cleared).length > 0) update.harness_postures = cleared;
  return update;
}
