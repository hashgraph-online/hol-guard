/** Upgrade advice for a review raised because the Node.js a command launches
 * matches a high or critical advisory.
 *
 * Guard computes this from the stored review and the executable it checked;
 * the dashboard only displays it and, for nvm with a patched version already
 * installed, asks Guard to switch nvm's default to that version.
 */
export const RUNTIME_UPGRADE_ADVICE_SCHEMA = "guard.runtime-upgrade-advice.v1";

export type GuardRuntimeUpgradeManager = "nvm" | "homebrew" | "other";

export type GuardRuntimeUpgradeAdvice = {
  readonly current_version: string;
  readonly current_path: string;
  readonly advisory_id: string;
  readonly severity: string;
  readonly known_exploited: boolean;
  readonly manager: GuardRuntimeUpgradeManager;
  /** The first release at or above the affected one that the advisories leave
   * clean. A later release is not promised to be clean. */
  readonly patched_version: string | null;
  /** A clean version nvm already has installed. */
  readonly installed_version: string | null;
  /** The version the one-click switch would make nvm's default; null when none is offered. */
  readonly switch_version: string | null;
  /** Whether nvm's default already names the installed clean version. */
  readonly switched: boolean;
  readonly command: string | null;
  readonly download_url: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.trim().length > 0 ? value : null;
}

const MANAGERS: readonly GuardRuntimeUpgradeManager[] = ["nvm", "homebrew", "other"];
const NODE_DOWNLOAD_URL = "https://nodejs.org/en/download";

export function normalizeRuntimeUpgradeAdvice(raw: unknown): GuardRuntimeUpgradeAdvice | null {
  if (!isRecord(raw) || raw.schema !== RUNTIME_UPGRADE_ADVICE_SCHEMA || raw.family !== "node") return null;
  const currentVersion = text(raw.current_version);
  const currentPath = text(raw.current_path);
  const advisoryId = text(raw.advisory_id);
  const severity = text(raw.severity);
  if (currentVersion === null || currentPath === null || advisoryId === null || severity === null) return null;
  const manager = MANAGERS.find((candidate) => candidate === raw.manager) ?? "other";
  // The link always goes to the official download page, whatever the payload says.
  return {
    current_version: currentVersion,
    current_path: currentPath,
    advisory_id: advisoryId,
    severity,
    known_exploited: raw.known_exploited === true,
    manager,
    patched_version: text(raw.patched_version),
    installed_version: text(raw.installed_version),
    switch_version: manager === "nvm" ? text(raw.switch_version) : null,
    switched: raw.switched === true,
    command: text(raw.command),
    download_url: NODE_DOWNLOAD_URL,
  };
}

/** One line naming what to move to, or null when the advisories name nothing. */
export function runtimeUpgradeTarget(advice: GuardRuntimeUpgradeAdvice): string | null {
  if (advice.installed_version !== null) {
    return `Node.js ${advice.installed_version} is already installed and is not affected.`;
  }
  if (advice.patched_version !== null) {
    return `Node.js ${advice.patched_version} fixes it.`;
  }
  return null;
}

/** The advice the card shows: the switch's own reply while the review still
 * carries the advice it answered, else the review's latest advice. */
export function currentRuntimeUpgradeAdvice(
  latest: GuardRuntimeUpgradeAdvice | undefined,
  reply: { readonly answered: GuardRuntimeUpgradeAdvice | undefined; readonly advice: GuardRuntimeUpgradeAdvice } | null,
): GuardRuntimeUpgradeAdvice | undefined {
  return reply !== null && reply.answered === latest ? reply.advice : latest;
}
