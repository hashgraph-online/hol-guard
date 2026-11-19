import type { GuardSettingsUpdate } from "./guard-api";
import type { GuardSettings } from "./guard-types";
import { effectiveHarnessPosture, globalPosture, harnessPosturePatch, selectHarnessPosture } from "./harness-posture-ui";

/**
 * What one app runs on the Protect screen. Guard checks the app's actions;
 * CIGAR adds project context to its prompts so the agent reads and spends less.
 */
export type AppModes = { guard: boolean; cigar: boolean };

/**
 * Apps whose prompt hook can carry CIGAR's project context. Copilot CLI and
 * Grok drop what an allowing prompt hook adds, Cursor's prompt hook can only
 * allow or block, and Guard has no prompt hook in the rest.
 */
const CIGAR_APPS = new Set(["claude-code", "codex", "pi", "omp", "devin", "muse", "zcode", "kimi", "cline"]);

/**
 * True when CIGAR adds project context on this machine: the person turned it
 * on, and the core confirms it still does after validation and managed policy.
 */
export function cigarReady(settings: GuardSettings): boolean {
  const config = settings.context_assistance;
  const requested = config?.enabled === true && config.features.agent_context && config.sources.workspace_documents;
  return requested && settings.context_assistance_effective_ready !== false;
}

/** True when managed policy owns each app's CIGAR choice. */
export function cigarLocked(settings: GuardSettings): boolean {
  return settings.managed_locked_settings?.includes("harness_cigar") === true;
}

/** True when this app's prompts can receive CIGAR's context at all. */
export function cigarSupported(harness: string): boolean {
  return CIGAR_APPS.has(harness);
}

/**
 * True when this app's Guard setup on this machine sends Guard its prompts.
 * Cline does that only through its native hooks, not through the Cline plugin.
 */
export function cigarReachesApp(settings: GuardSettings, harness: string): boolean {
  return cigarSupported(harness) && (settings.cigar_apps?.includes(harness) ?? true);
}

/** True when CIGAR runs for this app or can be switched on for it right now. */
export function cigarAvailable(settings: GuardSettings, harness: string): boolean {
  return cigarReady(settings) && cigarReachesApp(settings, harness);
}

export function appModes(settings: GuardSettings, harness: string): AppModes {
  return {
    guard: effectiveHarnessPosture(settings, harness) !== "watch",
    cigar: cigarAvailable(settings, harness) && settings.harness_cigar?.[harness] !== "off",
  };
}

/** An app in Watch through its own entry with no revert time: it keeps only CIGAR until changed. */
export function watchIsUntimed(settings: GuardSettings, harness: string): boolean {
  return settings.harness_postures?.[harness] === "watch" && settings.harness_watch_entered_at?.[harness] === undefined;
}

/**
 * The settings update that moves one app to `next`, or null when nothing
 * changes. Guard off with CIGAR on is a lasting choice, so its Watch entry
 * is sent untimed; Guard off with CIGAR off is the usual timed Watch, and
 * moving to it from a lasting choice restarts the timer.
 */
export function appModesUpdate(settings: GuardSettings, harness: string, next: AppModes): GuardSettingsUpdate | null {
  const update: GuardSettingsUpdate = {};
  const available = cigarAvailable(settings, harness);
  const cigarOnly = !next.guard && next.cigar && available;
  if (settings.harness_postures_locked === true) {
    // A managed lock owns each app's Guard setting; only CIGAR can change here.
  } else if (cigarOnly) {
    if (!watchIsUntimed(settings, harness)) {
      update.harness_postures = { [harness]: "watch" };
      update.harness_watch_untimed = true;
    }
  } else if (next.guard) {
    const patch = harnessPosturePatch(selectHarnessPosture(settings, harness, "on"), settings);
    if (patch !== null) update.harness_postures = patch;
  } else {
    const draft = selectHarnessPosture(settings, harness, "watch");
    const patch = harnessPosturePatch(draft, settings) ?? {};
    // Leaving a lasting CIGAR-only Watch starts the usual revert timer.
    if (watchIsUntimed(settings, harness) && globalPosture(settings) !== "watch") patch[harness] = "watch";
    if (Object.keys(patch).length > 0) update.harness_postures = patch;
  }
  if (available) {
    const off = settings.harness_cigar?.[harness] === "off";
    if (next.cigar === off) update.harness_cigar = { [harness]: next.cigar ? null : "off" };
  }
  return Object.keys(update).length > 0 ? update : null;
}

/**
 * Turning Guard off, or making a Guard-off app last, waits for an inline
 * confirmation. Under a managed lock Guard cannot change, so nothing does.
 */
export function needsConfirm(current: AppModes, next: AppModes, locked = false): boolean {
  if (next.guard || locked) return false;
  return current.guard || (next.cigar && !current.cigar);
}

/** Why an app's CIGAR switch cannot be used, or undefined when it can. */
export function cigarUnavailableReason(settings: GuardSettings, harness: string, displayName: string): string | undefined {
  if (cigarAvailable(settings, harness)) {
    return cigarLocked(settings) ? "Your organization manages CIGAR for each app." : undefined;
  }
  if (cigarSupported(harness) && !cigarReachesApp(settings, harness)) {
    return `Guard is set up in ${displayName} through its plugin, which doesn't send Guard your prompts. Set up ${displayName} with its native hooks to use CIGAR.`;
  }
  if (cigarSupported(harness)) return "CIGAR is off on this machine. Set it up on the CIGAR page.";
  return `${displayName} doesn't let Guard add context to its prompts yet.`;
}

/** Applies a per-app CIGAR patch, where null removes an app's entry. */
export function applyHarnessCigarPatch(
  current: GuardSettings["harness_cigar"],
  patch: Record<string, "off" | null>,
): NonNullable<GuardSettings["harness_cigar"]> {
  const next = { ...(current ?? {}) };
  for (const [harness, choice] of Object.entries(patch)) {
    if (choice === null) delete next[harness];
    else next[harness] = choice;
  }
  return next;
}

/** Short line under an app's name that says what runs there, or null for the usual Guard + CIGAR. */
export function appModesNote(settings: GuardSettings, harness: string): string | null {
  const modes = appModes(settings, harness);
  const available = cigarAvailable(settings, harness);
  if (modes.guard) return available && !modes.cigar ? "Guard only · CIGAR off for this app" : null;
  if (modes.cigar) return "CIGAR only · Guard is not checking actions";
  return globalPosture(settings) === "watch" && settings.harness_postures?.[harness] === undefined
    ? "Watch · follows the machine setting"
    : "Watch · recording only";
}

/** Plain-language confirmation for a saved change, read by screen readers. */
export function appModesStatusMessage(next: AppModes, displayName: string): string {
  if (next.guard && next.cigar) return `Guard and CIGAR are on in ${displayName}.`;
  if (next.guard) return `Guard is on in ${displayName}. CIGAR is off.`;
  if (next.cigar) return `CIGAR is on in ${displayName}. Guard is not checking actions.`;
  return `Guard is only recording in ${displayName}.`;
}

/**
 * The inline confirmation's sentence for turning Guard off. An app that ends
 * up following the machine's Watch keeps the machine's timing, so no new
 * interval is promised for it.
 */
export function guardOffPrompt(settings: GuardSettings, harness: string, next: AppModes, displayName: string): string {
  if (next.cigar && !appModes(settings, harness).guard) {
    return `CIGAR will start adding project context in ${displayName}. Guard stays off and no longer turns back on by itself.`;
  }
  if (next.cigar) {
    return `Guard will stop checking ${displayName}'s actions until you turn it back on. CIGAR keeps adding project context.`;
  }
  const ownWatch = appModesUpdate(settings, harness, next)?.harness_postures?.[harness] === "watch";
  if (globalPosture(settings) === "watch" && !ownWatch) {
    return `Guard will only record in ${displayName}, following this machine's Watch setting.`;
  }
  const revertHours = settings.watch_auto_revert_hours ?? 24;
  if (revertHours > 0) {
    const hours = revertHours === 1 ? "1 hour" : `${revertHours} hours`;
    return `Guard will only record in ${displayName}. Protection comes back on its own after ${hours}.`;
  }
  return `Guard will only record in ${displayName} until you turn it back on.`;
}
