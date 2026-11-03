import assert from "node:assert/strict";

import type { PackageShimEntry } from "./guard-types";
import { rosterGroupFor } from "./supply-chain-firewall-controls";
import { managerRowNote } from "./supply-chain-firewall-manager-row";

function shim(overrides: Partial<PackageShimEntry>): PackageShimEntry {
  return {
    active: false,
    activation_state: "uninstalled",
    detected: true,
    installed: false,
    integrity: "ok",
    last_intercept_proof_at: null,
    manager: "npm",
    path_broken: false,
    path_index: null,
    path_summary: null,
    real_binary_found: true,
    real_binary_path: null,
    real_binary_path_index: null,
    shim_path: null,
    tested: false,
    ...overrides,
  };
}

// Groups: detected but not installed waits below; installed and working is done;
// anything installed but not intercepting needs a fix.
assert.equal(rosterGroupFor(undefined), "unprotected");
assert.equal(rosterGroupFor(shim({})), "unprotected");
assert.equal(rosterGroupFor(shim({ installed: true, activation_state: "protected" })), "protected");
assert.equal(rosterGroupFor(shim({ installed: true, activation_state: "repair_required", path_broken: true })), "fix");
assert.equal(rosterGroupFor(shim({ installed: true, activation_state: "restart_required" })), "fix");

// The row names t// The PATH summary does not say which copy runs first, so the row names the tool, never a path.
assert.equal(
  managerRowNote(
    shim({
      installed: true,
      activation_state: "repair_required",
      manager: "uv",
      path_broken: true,
      path_summary: "/home/alex/.local/bin/uv precedes /home/alex/.hol-guard/package-shims/bin/uv",
    }),
  ),
  "Another uv runs before Guard's shim, so installs skip Guard.",
);
// A tampered shim needs a repair, whatever PATH says.
assert.equal(
  managerRowNote(shim({ installed: true, activation_state: "repair_required", integrity: "tampered", path_broken: true })),
  "Guard's shim was changed on disk. Repair it to restore checks.",
);
assert.equal(
  managerRowNote(shim({ installed: true, activation_state: "restart_required" })),
  "Open a new shell, and restart AI apps that run it, to turn this on.",
);
assert.equal(managerRowNote(shim({ installed: true, activation_state: "repair_required" })), "Guard's shim folder is not on PATH yet.");
// Protected but never tested still points at the Test action.
assert.equal(
  managerRowNote(shim({ installed: true, activation_state: "protected" })),
  "Not tested yet. Run a test to confirm installs are checked.",
);
assert.match(
  managerRowNote(shim({ installed: true, activation_state: "protected", last_intercept_proof_at: new Date().toISOString() })) ?? "",
  /^Tested /,
);
assert.equal(managerRowNote(shim({})), null);

console.log("supply-chain-roster-groups.test.ts: all assertions passed");
