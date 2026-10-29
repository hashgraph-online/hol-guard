/**
 * Dashboard-side contract for handing recovery to an authorized native view.
 *
 * This module deliberately has no HTTP, process, filesystem, or credential
 * operations. A browser can retry the dashboard connection, but only the
 * trusted native Recovery view may start a lifecycle operation.
 */

import { dashboardEmbedsInDesktop } from "./desktop-embed";

export const SERVICE_RECOVERY_PROTOCOL = "hol-guard-recovery.v1" as const;
export const SERVICE_RECOVERY_BRIDGE_SCHEMA = "hol-guard-dashboard-recovery.v1" as const;
export const SERVICE_RECOVERY_BRIDGE_CAPABILITY = "open_recovery" as const;
/** Fixed same-origin route consumed by Desktop navigation before Core HTTP. */
export const RECOVERY_HANDOFF_PATH = "/__hol_guard_recovery__" as const;

export type RecoveryInstallMode =
  | "desktop-bundled"
  | "desktop-external"
  | "cli"
  | "browser-only"
  | "unknown";

export type RecoveryBridge = {
  schema: typeof SERVICE_RECOVERY_BRIDGE_SCHEMA;
  protocol: typeof SERVICE_RECOVERY_PROTOCOL;
  capabilities: readonly string[];
  installMode: RecoveryInstallMode;
  openRecovery: () => void | Promise<void>;
};

export type RecoveryCapabilityState =
  | {
      kind: "native";
      installMode: RecoveryInstallMode;
      bridge: RecoveryBridge;
    }
  | {
      kind: "fallback";
      installMode: RecoveryInstallMode;
      reason: "bridge_missing" | "invalid_bridge" | "unsupported_protocol";
    };

export type RecoveryHandoffResult =
  | { kind: "opened" }
  | { kind: "fallback"; capability: RecoveryCapabilityState }
  | { kind: "failed"; capability: RecoveryCapabilityState; message: string };

export type RecoveryInstructions = {
  installMode: RecoveryInstallMode;
  title: string;
  body: string;
  steps: readonly string[];
  command: string | null;
};

type UnknownRecord = Record<string, unknown>;

const RECOVERY_CAPABILITY_NAMES = new Set([
  SERVICE_RECOVERY_BRIDGE_CAPABILITY,
  "recovery_view",
  "desktop_recovery_view",
]);

function isRecord(value: unknown): value is UnknownRecord {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function hasOwn(value: UnknownRecord, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

const RECOVERY_BRIDGE_GLOBAL_NAMES = [
  "__HOL_GUARD_RECOVERY_BRIDGE__",
] as const;

function hostInjectedRecoveryBridge(): RecoveryBridge | null {
  try {
    if (typeof window === "undefined") return null;
    const globals = window as unknown as UnknownRecord;
    for (const name of RECOVERY_BRIDGE_GLOBAL_NAMES) {
      const descriptor = Object.getOwnPropertyDescriptor(globals, name);
      if (
        !descriptor
        || descriptor.configurable
        || descriptor.writable
        || !("value" in descriptor)
        || !Object.isFrozen(descriptor.value)
      ) {
        continue;
      }
      const bridge = readRecoveryBridge(descriptor.value);
      if (bridge) return bridge;
    }
    return null;
  } catch {
    return null;
  }
}

export function normalizeRecoveryInstallMode(value: unknown): RecoveryInstallMode {
  if (typeof value !== "string") return "unknown";
  const normalized = value.trim().toLowerCase();
  if (["desktop-bundled", "bundled", "desktop", "appimage"].includes(normalized)) {
    return "desktop-bundled";
  }
  if (["desktop-external", "external", "desktop-cli"].includes(normalized)) {
    return "desktop-external";
  }
  if (["cli", "local-cli", "standalone-cli"].includes(normalized)) return "cli";
  if (["browser", "browser-only", "web"].includes(normalized)) return "browser-only";
  return "unknown";
}

function defaultInstallMode(): RecoveryInstallMode {
  try {
    return dashboardEmbedsInDesktop() ? "desktop-bundled" : "browser-only";
  } catch {
    return "browser-only";
  }
}

function bridgeInstallMode(value: UnknownRecord): RecoveryInstallMode {
  const explicit = normalizeRecoveryInstallMode(value.installMode ?? value.install_mode);
  return explicit === "unknown" ? defaultInstallMode() : explicit;
}

function bridgeSchemaSupported(value: UnknownRecord): boolean {
  return value.schema === SERVICE_RECOVERY_BRIDGE_SCHEMA && value.protocol === SERVICE_RECOVERY_PROTOCOL;
}

function bridgeHasRecoveryCapability(value: UnknownRecord): boolean {
  return (
    Array.isArray(value.capabilities) &&
    value.capabilities.some((entry) => typeof entry === "string" && RECOVERY_CAPABILITY_NAMES.has(entry))
  );
}

export function readRecoveryBridge(source?: unknown): RecoveryBridge | null {
  const candidate = source;
  if (!isRecord(candidate)) return null;
  if (!bridgeSchemaSupported(candidate) || !bridgeHasRecoveryCapability(candidate)) return null;
  if (typeof candidate.openRecovery !== "function") return null;
  const capabilities = candidate.capabilities;
  if (!Array.isArray(capabilities)) return null;
  return {
    schema: SERVICE_RECOVERY_BRIDGE_SCHEMA,
    protocol: SERVICE_RECOVERY_PROTOCOL,
    capabilities: capabilities.filter((entry): entry is string => typeof entry === "string"),
    installMode: bridgeInstallMode(candidate),
    openRecovery: candidate.openRecovery as RecoveryBridge["openRecovery"],
  };
}

export function getRecoveryCapabilities(options?: {
  bridge?: unknown;
  installMode?: unknown;
} | unknown): RecoveryCapabilityState {
  const optionRecord = isRecord(options) && (hasOwn(options, "bridge") || hasOwn(options, "installMode"))
    ? options
    : null;
  const candidate = optionRecord ? optionRecord.bridge : options;
  const rawCandidate = candidate;
  const bridge = readRecoveryBridge(rawCandidate) ?? (rawCandidate === undefined ? hostInjectedRecoveryBridge() : null);
  const installMode = normalizeRecoveryInstallMode(
    optionRecord?.installMode ?? (isRecord(rawCandidate) ? rawCandidate.installMode : undefined),
  );
  const resolvedInstallMode = installMode === "unknown"
    ? (bridge?.installMode ?? defaultInstallMode())
    : installMode;

  if (bridge) {
    return {
      kind: "native",
      installMode: resolvedInstallMode,
      bridge: { ...bridge, installMode: resolvedInstallMode },
    };
  }

  let reason: "bridge_missing" | "invalid_bridge" | "unsupported_protocol" = "bridge_missing";
  if (rawCandidate !== undefined && rawCandidate !== null) {
    reason = isRecord(rawCandidate) && !bridgeSchemaSupported(rawCandidate)
      ? "unsupported_protocol"
      : "invalid_bridge";
  }
  return { kind: "fallback", installMode: resolvedInstallMode, reason };
}

export function resolveRecoveryInstructions(installMode: RecoveryInstallMode): RecoveryInstructions {
  switch (installMode) {
    case "cli":
      return {
        installMode,
        title: "Use the installed Guard CLI",
        body: "A browser tab cannot restart a local service through its unavailable HTTP connection.",
        steps: [
          "Open a terminal on the same device where Guard is installed.",
          "Run the recovery command shipped with that Guard installation.",
          "Return here and choose Retry connection after the command finishes.",
        ],
        command: "hol-guard daemon recovery restart",
      };
    case "desktop-bundled":
      return {
        installMode,
        title: "Open Guard Desktop",
        body: "This browser tab cannot restart a bundled Desktop service. Use the trusted Desktop recovery screen instead.",
        steps: [
          "Open HOL Guard Desktop from the installed application.",
          "Choose Troubleshoot Guard.",
          "Choose Restart Guard in the native recovery screen, then return here and retry the connection.",
        ],
        command: null,
      };
    case "desktop-external":
      return {
        installMode,
        title: "Open the installed Guard Desktop",
        body: "The browser cannot control the local service. Use the installed Desktop recovery screen for this device.",
        steps: [
          "Open the installed HOL Guard Desktop application.",
          "Choose Troubleshoot Guard, then Restart Guard.",
          "Return here and choose Retry connection after recovery completes.",
        ],
        command: null,
      };
    case "browser-only":
      return {
        installMode,
        title: "Use a local recovery path",
        body: "A browser tab cannot restart Guard through a service that is not responding.",
        steps: [
          "Open HOL Guard Desktop on this device if it is installed, then choose Troubleshoot Guard.",
          "If this device uses the Guard CLI, use the command shipped with that installation rather than a different runtime.",
          "Return here and choose Retry connection after the local recovery finishes.",
        ],
        command: null,
      };
    case "unknown":
    default:
      return {
        installMode: "unknown",
        title: "Use the supported local recovery path",
        body: "This browser tab cannot safely identify an installed local recovery path.",
        steps: [
          "Open the Guard Desktop or Guard CLI installation that owns this device.",
          "Use its supported Troubleshoot Guard or recovery action.",
          "Return here and choose Retry connection after recovery completes.",
        ],
        command: null,
      };
  }
}

export async function openRecoveryView(options?: {
  bridge?: unknown;
  installMode?: unknown;
}): Promise<RecoveryHandoffResult> {
  const capability = getRecoveryCapabilities(options);
  if (capability.kind !== "native") {
    return { kind: "fallback", capability };
  }
  try {
    await capability.bridge.openRecovery();
    return { kind: "opened" };
  } catch {
    return {
      kind: "failed",
      capability,
      message: "The trusted Recovery view could not be opened. Use the local recovery steps below.",
    };
  }
}
