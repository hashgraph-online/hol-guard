import { renderToStaticMarkup } from "react-dom/server";

import {
  FleetAppProtection,
  fleetInactiveAppCount,
  fleetMachinePosture,
  fleetMachinePostureLabel,
  fleetManagedCapabilities,
  fleetManagedRows,
  fleetPostureStatusMessage,
  gateProofUpdate,
} from "./fleet-app-protection";
import { harnessPostureRows } from "./harness-posture-ui";
import type { GuardApprovalGatePublicConfig, GuardProtectionCapability, GuardSettings } from "./guard-types";

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

const capabilities = [capability("codex", "Codex"), capability("claude-code", "Claude Code"), capability("cursor", "Cursor")];
const rows = harnessPostureRows(settings({ harness_postures: { codex: "watch" } }), capabilities);

// Only apps whose hooks Guard manages get a row; Watch sorts first.
const apps = [
  { harness: "claude-code", active: true },
  { harness: "codex", active: true },
  { harness: "cursor", active: false },
];
const managed = fleetManagedRows(rows, apps);
assert(
  managed.length === 2 && managed[0].harness === "codex" && managed[1].harness === "claude-code",
  "unmanaged apps are absent and Watch rows sort first",
);
assert(fleetInactiveAppCount(apps) === 1, "inactive apps are counted for the coverage note");
assert(fleetInactiveAppCount([{ harness: "codex", active: true }]) === 0, "no note when everything is managed");

// A managed app missing from the capability catalog still gets an entry.
const managedCaps = fleetManagedCapabilities(capabilities, [{ harness: "grok", active: true }]);
assert(
  managedCaps.length === 1 && managedCaps[0].harness === "grok" && managedCaps[0].display_name.length > 0,
  "managed apps outside the catalog are synthesized instead of dropped",
);
const keptCaps = fleetManagedCapabilities(capabilities, apps);
assert(
  keptCaps.length === 2 && keptCaps.every((cap) => cap.harness !== "cursor"),
  "capabilities are trimmed to the managed apps",
);

// The machine posture line derives from settings, defaulting to Protected.
assert(fleetMachinePosture(settings()) === "protected", "missing posture defaults to protected");
assert(
  fleetMachinePosture(settings({ protection_posture: "watch", mode: "observe" })) === "watch",
  "machine watch is reported",
);
assert(
  fleetMachinePostureLabel(settings({ protection_posture: "extra_careful" })) === "Extra careful",
  "machine posture uses the shared labels",
);
assert(
  fleetMachinePostureLabel(settings({ protection_posture: undefined, mode: "observe" })) === "Watch",
  "legacy observe mode without an explicit posture reads as Watch, matching the rows",
);
assert(
  fleetMachinePostureLabel(settings({ protection_posture: "protected", mode: "observe" })) === "Protected",
  "an explicit posture wins over the legacy mode, matching the rows",
);

assert(
  fleetPostureStatusMessage("watch", "Codex") === "Guard is only recording in Codex.",
  "watch status copy says Guard records only",
);
assert(
  fleetPostureStatusMessage("on", "Codex") === "Protection restored in Codex.",
  "protected status copy says protection is restored",
);

const bareGate = gateProofUpdate(null);
assert(bareGate.enabled === false && bareGate.configured === false, "missing gate config falls back to defaults");
assert(!("current_password" in bareGate), "no proof means no password key");

const gate: GuardApprovalGatePublicConfig = {
  enabled: true,
  configured: true,
  cooldown_seconds: 900,
  cooldown_active: false,
  cooldown_expires_at: null,
  locked_until: null,
  fail_closed: false,
  strict_all_decisions: false,
  totp_enabled: true,
  totp_pending: false,
};
const withProof = gateProofUpdate(gate, { currentPassword: "passphrase", totpCode: "123456" });
assert(withProof.enabled === true, "gate payload keeps the enabled flag");
assert(withProof.current_password === "passphrase", "gate payload carries the password proof");
assert(withProof.totp_code === "123456", "gate payload carries the authenticator code");

const withoutProof = gateProofUpdate(gate);
assert(withoutProof.enabled === true, "gate payload without proof keeps the gate state");
assert(!("current_password" in withoutProof) && !("totp_code" in withoutProof), "gate payload without proof omits credentials");

const loading = renderToStaticMarkup(<FleetAppProtection apps={apps} onChanged={() => undefined} />);
assert(loading.includes("guard-skeleton"), "fleet panel starts in a loading state");

console.log("fleet-app-protection.test.tsx: all assertions passed");
