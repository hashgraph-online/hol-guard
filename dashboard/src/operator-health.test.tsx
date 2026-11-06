import { renderToStaticMarkup } from "react-dom/server";

import { normalizeOperatorHealth } from "./guard-api";
import { formatOperatorCount, OperatorHealthCard } from "./runtime-overview";
import type { GuardOperatorHealth, GuardOperatorHealthState } from "./guard-types";

const storage = {
  getItem: () => null,
  setItem: () => undefined,
};
Object.assign(globalThis, {
  window: {
    location: {
      origin: "http://127.0.0.1:7392",
      pathname: "/",
      search: "",
      hash: "",
    },
    localStorage: storage,
    sessionStorage: storage,
  },
});

function assert(condition: boolean, message: string): void {
  if (!condition) throw new Error(message);
}

function health(state: GuardOperatorHealthState, repairable = false): GuardOperatorHealth {
  return {
    state,
    cause: state === "backlogged"
      ? "A short local backlog is waiting behind active reviews."
      : `Local processing is ${state}.`,
    automatic_recovery: "Guard drains queued work and adjusts ready workers automatically.",
    repairable,
    queue_depth: 12_345,
    queue_limit: 20_000,
    oldest_wait_ms: 1_250,
    workers_busy: 6,
    workers_ready: 2,
    workers_configured: 8,
  };
}

for (const state of ["healthy", "backlogged", "saturated", "store-contended"] as const) {
  const markup = renderToStaticMarkup(<OperatorHealthCard health={health(state)} />);
  assert(markup.includes(`data-operator-health="${state}"`), `${state} must have a stable UI state contract`);
  assert(markup.includes("Automatic recovery:"), `${state} must explain automatic recovery`);
  assert(markup.includes(formatOperatorCount(12_345)), `${state} must format counts for the active locale`);
  assert(!markup.includes("Repair local processing"), `${state} load state must not offer repair`);
  assert(!/degraded|authenticate|approve|reconnect/i.test(markup), `${state} load copy must not imply auth or approval`);
}

const repairMarkup = renderToStaticMarkup(<OperatorHealthCard health={health("saturated", true)} />);
assert(repairMarkup.includes("Repair local processing"), "an actual component fault must offer repair");
assert(
  repairMarkup.includes("/settings?section=maintenance#approval-center-repair"),
  "repair must link to the working settings action",
);

const normalized = normalizeOperatorHealth({
  ...health("backlogged"),
  queue_depth: -5,
  workers_ready: Number.NaN,
});
assert(normalized?.queue_depth === 0, "negative queue depth must fail closed to zero");
assert(normalized?.workers_ready === 0, "non-finite worker counts must fail closed to zero");
assert(normalizeOperatorHealth({ state: "unknown" }) === undefined, "unknown health states must be rejected");
