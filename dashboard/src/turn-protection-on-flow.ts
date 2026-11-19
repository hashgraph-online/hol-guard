import { gateProofUpdate } from "./fleet-app-protection";
import { turnProtectionOnUpdate } from "./harness-posture-ui";
import type { SettingsSaveProofCredentials } from "./settings-save-proof-modal";
import type {
  GuardApprovalGatePublicConfig,
  GuardSettings,
  GuardSettingsPayload,
} from "./guard-types";
import type { GuardSettingsUpdate } from "./guard-api";

export type TurnProtectionOnDeps = {
  fetchSettings: () => Promise<GuardSettingsPayload>;
  updateSettings: (update: GuardSettingsUpdate) => Promise<GuardSettingsPayload>;
};

/**
 * Where the Watch banner's "Turn protection on" lands after one click.
 *
 * - `saved`: Guard saved the change (or nothing was left in Watch).
 * - `needs-proof`: the approval gate is on, so the banner asks for the
 *   password and authenticator code before saving.
 * - `locked`: the organization manages this setting, so it cannot change here.
 */
export type TurnProtectionOnStep =
  | { kind: "saved"; payload: GuardSettingsPayload | null }
  | { kind: "needs-proof"; settings: GuardSettings; gate: GuardApprovalGatePublicConfig }
  | { kind: "locked" };

/** True when the saved settings forbid the change the banner would make. */
export function turnProtectionOnLocked(settings: GuardSettings, update: GuardSettingsUpdate): boolean {
  const managed = settings.managed_locked_settings ?? [];
  if (update.harness_postures !== undefined && settings.harness_postures_locked === true) return true;
  if (update.protection_posture !== undefined && managed.includes("protection_posture")) return true;
  return false;
}

function isEmptyUpdate(update: GuardSettingsUpdate): boolean {
  return Object.keys(update).length === 0;
}

/**
 * First step of turning protection on from a Watch banner. Reads the saved
 * settings, never a cached snapshot, so the change and the gate check match
 * what Guard enforces right now.
 */
export async function startTurnProtectionOn(deps: TurnProtectionOnDeps): Promise<TurnProtectionOnStep> {
  const current = await deps.fetchSettings();
  const settings = current.settings;
  const update = turnProtectionOnUpdate(settings);
  if (isEmptyUpdate(update)) return { kind: "saved", payload: null };
  if (turnProtectionOnLocked(settings, update)) return { kind: "locked" };
  const gate = settings.approval_gate;
  if (gate?.enabled === true) return { kind: "needs-proof", settings, gate };
  return { kind: "saved", payload: await deps.updateSettings(update) };
}

/** Saves the change with the approval proof the user just entered. */
export async function finishTurnProtectionOn(
  deps: TurnProtectionOnDeps,
  settings: GuardSettings,
  proof: SettingsSaveProofCredentials,
): Promise<GuardSettingsPayload> {
  const update = turnProtectionOnUpdate(settings);
  update.approval_gate = gateProofUpdate(settings.approval_gate, proof);
  return deps.updateSettings(update);
}

export function turnProtectionOnErrorMessage(cause: unknown): string {
  const detail = cause instanceof Error ? cause.message.trim() : "";
  return detail.length > 0 ? detail : "Guard couldn't turn protection on. Try again.";
}
