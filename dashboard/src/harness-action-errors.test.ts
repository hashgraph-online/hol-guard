import { GuardHarnessActionError } from "./guard-api";
import {
  isApprovalGateRequiredError,
  isGuardHarnessActionError,
  isSupplyChainSyncConnectError,
  isSupplyChainSyncRetryableError,
  readHarnessActionUserMessage,
  resolveApprovalGateSyncFailure,
} from "./harness-action-errors";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

function makeHarnessError(
  status: number,
  payload: ConstructorParameters<typeof GuardHarnessActionError>[1],
): GuardHarnessActionError {
  return new GuardHarnessActionError(status, payload);
}

function makeDuckTypedHarnessError(
  status: number,
  payload: ConstructorParameters<typeof GuardHarnessActionError>[1],
): GuardHarnessActionError {
  const error = makeHarnessError(status, payload);
  return Object.assign(Object.create(GuardHarnessActionError.prototype), error);
}

assert(
  isGuardHarnessActionError(makeHarnessError(403, { error: "approval_gate_required" })),
  "instanceof GuardHarnessActionError is recognized",
);
assert(
  isGuardHarnessActionError(
    makeDuckTypedHarnessError(403, {
      error: "approval_gate_required",
      message: "Approval password is required.",
    }),
  ),
  "duck-typed GuardHarnessActionError is recognized",
);
assert(
  isApprovalGateRequiredError(
    makeHarnessError(403, {
      error: "approval_gate_required",
      message: "Approval password is required.",
    }),
  ),
  "approval_gate_required code is detected",
);
assert(
  isApprovalGateRequiredError(
    makeHarnessError(403, {
      error: "Approval password is required.",
    }),
  ),
  "human-readable error field is detected",
);
assert(
  isApprovalGateRequiredError(
    makeDuckTypedHarnessError(403, {
      error: "approval_gate_required",
      message: "Approval password is required.",
    }),
  ),
  "duck-typed approval_gate_required is detected",
);
assert(
  isApprovalGateRequiredError(
    makeHarnessError(403, {
      error: "approval_gate_password_required",
      message: "Approval gate password is required.",
    }),
  ),
  "approval_gate_password_required code is detected",
);
assert(
  isApprovalGateRequiredError(
    makeHarnessError(403, {
      error: "approval_gate_totp_required",
      message: "TOTP code is required.",
    }),
  ),
  "approval_gate_totp_required code is detected",
);
assert(
  isApprovalGateRequiredError(new Error("Approval password is required.")),
  "plain Error message fallback is detected",
);
assert(
  !isApprovalGateRequiredError(makeHarnessError(403, { error: "approval_gate_locked" })),
  "locked gate is not treated as missing password",
);
assert(
  !isApprovalGateRequiredError(makeHarnessError(403, { error: "approval_gate_grant_expired" })),
  "expired proof is not treated as missing password",
);

const withoutCredentials = resolveApprovalGateSyncFailure(
  makeHarnessError(403, {
    error: "Approval password is required.",
  }),
);
assert(
  withoutCredentials.kind === "approval_required",
  "missing credentials route to approval step",
);

const withCredentials = resolveApprovalGateSyncFailure(
  makeHarnessError(403, {
    error: "approval_gate_required",
    message: "Approval password is required.",
  }),
  { hasCredentials: true },
);
assert(withCredentials.kind === "failed", "wrong password stays on approval form with error");

assert(
  isSupplyChainSyncConnectError(
    makeHarnessError(403, {
      error: "guard_cloud_connect_required",
      message: "Guard Cloud workspace is not connected.",
    }),
  ),
  "connect required sync errors are detected",
);
assert(
  isSupplyChainSyncConnectError(
    makeHarnessError(403, {
      error: "guard_cloud_reconnect_required",
      message: "Guard Cloud authorization expired.",
    }),
  ),
  "reconnect required sync errors are detected",
);
assert(
  !isSupplyChainSyncConnectError(
    makeHarnessError(502, {
      error: "supply_chain_sync_failed",
      message: "Guard supply-chain bundle sync failed.",
    }),
  ),
  "sync transport failures are not connect errors",
);

assert(
  isSupplyChainSyncRetryableError(
    makeHarnessError(503, {
      error: "supply_chain_sync_unavailable",
      message: "Guard Cloud is unavailable. Local Guard keeps protecting this machine.",
      retryable: true,
    }),
  ),
  "retryable cloud outage sync errors are detected",
);
assert(
  !isSupplyChainSyncRetryableError(
    makeHarnessError(503, {
      error: "supply_chain_sync_unavailable",
      message: "Supply-chain sync is not available on this device.",
    }),
  ),
  "non-retryable sync unavailable errors are not retryable",
);

const networkFailure = resolveApprovalGateSyncFailure(new Error("Failed to fetch"), {
  hasCredentials: true,
});
assert(
  networkFailure.kind === "failed" &&
    networkFailure.message.includes("lost connection while syncing"),
  "failed to fetch maps to daemon connection guidance",
);

console.log("harness-action-errors.test.ts: all assertions passed");
