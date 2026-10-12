import { renderToStaticMarkup } from "react-dom/server";

import {
  FleetAppProtection,
  fleetPostureStatusMessage,
  gateProofUpdate,
} from "./fleet-app-protection";
import type { GuardApprovalGatePublicConfig } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

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

const loading = renderToStaticMarkup(<FleetAppProtection onChanged={() => undefined} />);
assert(loading.includes("guard-skeleton"), "fleet panel starts in a loading state");

console.log("fleet-app-protection.test.tsx: all assertions passed");
