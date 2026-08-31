import { useCallback, useEffect, useRef, useState } from "react";
import { fetchGuardContainmentHealth, fetchGuardNetworkStatus } from "./guard-api";

const NETWORK_GRADES = [
  "unavailable",
  "observe",
  "deny-all",
  "proxy-only",
  "tcp-ip-destination-enforced",
  "udp-dns-destination-enforced",
  "destination-enforced",
] as const;
const NETWORK_PHASES = ["healthy", "degraded", "recovering", "unavailable"] as const;
const HOST_PLATFORMS = ["linux", "macos", "windows", "unsupported"] as const;
const CONTAINMENT_BACKENDS = ["unsupported", "macos-sandbox", "linux-bwrap"] as const;
const SHA256 = /^[0-9a-f]{64}$/;
const CONTAINMENT_POLICY_CONTRACT_DIGEST = "8861db0285235c9f06ca2c8443b0899928890cd63ba5d0f9873c9514e4614ee4";

type NetworkGrade = (typeof NETWORK_GRADES)[number];
type NetworkPhase = (typeof NETWORK_PHASES)[number];
type HostPlatform = (typeof HOST_PLATFORMS)[number];
type ContainmentBackend = (typeof CONTAINMENT_BACKENDS)[number];

export type GuardNetworkStatus = {
  hostPlatform: HostPlatform;
  effectiveGrade: NetworkGrade;
  protectionActive: boolean;
  independentlyObserved: boolean;
  supervisor: {
    phase: NetworkPhase;
    effectiveGrade: NetworkGrade;
    healthyUntilEpochMs: number | null;
    permitsEnforcement: boolean;
    independentlyObserved: boolean;
  };
};

export type GuardContainmentHealth = {
  backend: ContainmentBackend;
  probeAtEpochMs: number;
  probeEnforced: boolean;
};

export type ProofPresentationState = "checking" | "ready" | "unsupported" | "unavailable" | "stale" | "error";

export type GuardStatusResource<T> = {
  value: T | null;
  loadState: "idle" | "loading" | "ready" | "stale" | "error";
  refreshing: boolean;
};

export type NetworkSandboxStatusState = {
  network: GuardStatusResource<GuardNetworkStatus>;
  containment: GuardStatusResource<GuardContainmentHealth>;
};

export type NetworkSandboxStatusLoaders = {
  network: (signal: AbortSignal) => Promise<unknown>;
  containment: (signal: AbortSignal) => Promise<unknown>;
};

const STATUS_REQUEST_TIMEOUT_MS = 8_000;
const DEFAULT_STATUS_LOADERS: NetworkSandboxStatusLoaders = {
  network: fetchGuardNetworkStatus,
  containment: fetchGuardContainmentHealth,
};

const EMPTY_RESOURCE = {
  value: null,
  loadState: "idle",
  refreshing: false,
} as const;

export const INITIAL_NETWORK_SANDBOX_STATUS: NetworkSandboxStatusState = {
  network: EMPTY_RESOURCE,
  containment: EMPTY_RESOURCE,
};

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function exactBoolean(value: unknown): boolean | null {
  return typeof value === "boolean" ? value : null;
}

function enumValue<const T extends readonly string[]>(value: unknown, choices: T): T[number] | null {
  if (typeof value !== "string") return null;
  return choices.find((choice) => choice === value) ?? null;
}

function finiteTimestamp(value: unknown): number | null {
  if (value === null) return null;
  return typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : null;
}

export function normalizeGuardNetworkStatus(value: unknown): GuardNetworkStatus | null {
  if (!isRecord(value) || value["schema"] !== "guard.network-status.v1") return null;
  const hostPlatform = enumValue(value["host_platform"], HOST_PLATFORMS);
  const effectiveGrade = enumValue(value["effective_grade"], NETWORK_GRADES);
  const protectionActive = exactBoolean(value["protection_active"]);
  const independentlyObserved = exactBoolean(value["independently_observed"]);
  const supervisorValue = value["supervisor"];
  if (
    hostPlatform === null ||
    effectiveGrade === null ||
    protectionActive === null ||
    independentlyObserved === null ||
    !isRecord(supervisorValue)
  ) {
    return null;
  }
  const phase = enumValue(supervisorValue["phase"], NETWORK_PHASES);
  const supervisorGrade = enumValue(supervisorValue["effective_grade"], NETWORK_GRADES);
  const healthyUntilEpochMs = finiteTimestamp(supervisorValue["healthy_until_epoch_ms"]);
  const permitsEnforcement = exactBoolean(supervisorValue["permits_enforcement"]);
  const supervisorObserved = exactBoolean(supervisorValue["independently_observed"]);
  if (phase === null || supervisorGrade === null || permitsEnforcement === null || supervisorObserved === null) return null;
  if (supervisorValue["healthy_until_epoch_ms"] !== null && healthyUntilEpochMs === null) return null;
  if (
    protectionActive !== permitsEnforcement ||
    independentlyObserved !== supervisorObserved ||
    effectiveGrade !== supervisorGrade ||
    (protectionActive && phase !== "healthy") ||
    (protectionActive && healthyUntilEpochMs === null) ||
    (protectionActive && (effectiveGrade === "unavailable" || effectiveGrade === "observe")) ||
    (hostPlatform === "unsupported" && protectionActive)
  ) {
    return null;
  }
  return {
    hostPlatform,
    effectiveGrade,
    protectionActive,
    independentlyObserved,
    supervisor: {
      phase,
      effectiveGrade: supervisorGrade,
      healthyUntilEpochMs,
      permitsEnforcement,
      independentlyObserved: supervisorObserved,
    },
  };
}

export function normalizeGuardContainmentHealth(value: unknown): GuardContainmentHealth | null {
  if (!isRecord(value) || !isRecord(value["containment_health"])) return null;
  const evidence = value["containment_health"];
  if (
    evidence["schema_version"] !== "guard.containment-health.v1" ||
    evidence["containment_schema_version"] !== "guard.containment.v1" ||
    evidence["policy_version"] !== "guard.containment-policy.v1" ||
    evidence["effect_contract_schema_version"] !== "1.0.0" ||
    evidence["effect_decision_schema_version"] !== "1.1.0"
  ) {
    return null;
  }
  const backend = enumValue(evidence["backend"], CONTAINMENT_BACKENDS);
  const probeEnforced = exactBoolean(evidence["probe_enforced"]);
  const probeAt = evidence["probe_at"];
  const timestampHasTimezone = typeof probeAt === "string" && /(?:Z|[+-][0-9]{2}:[0-9]{2})$/.test(probeAt);
  const probeAtEpochMs = timestampHasTimezone ? Date.parse(probeAt) : Number.NaN;
  const backendDigest = evidence["backend_digest"];
  const policyDigest = evidence["policy_contract_digest"];
  const daemonFingerprint = evidence["daemon_fingerprint"];
  const runtimeFingerprint = evidence["runtime_fingerprint"];
  if (
    backend === null ||
    probeEnforced === null ||
    !Number.isFinite(probeAtEpochMs) ||
    typeof backendDigest !== "string" ||
    !SHA256.test(backendDigest) ||
    policyDigest !== CONTAINMENT_POLICY_CONTRACT_DIGEST ||
    typeof daemonFingerprint !== "string" ||
    !SHA256.test(daemonFingerprint) ||
    runtimeFingerprint !== daemonFingerprint
  ) {
    return null;
  }
  if (backend === "unsupported" && probeEnforced) return null;
  return { backend, probeAtEpochMs, probeEnforced };
}

export function beginNetworkSandboxRefresh(state: NetworkSandboxStatusState): NetworkSandboxStatusState {
  const begin = <T,>(resource: GuardStatusResource<T>): GuardStatusResource<T> => ({
    ...resource,
    loadState: resource.value === null ? "loading" : resource.loadState,
    refreshing: true,
  });
  return {
    network: begin(state.network),
    containment: begin(state.containment),
  };
}

function settleResource<T>(
  previous: GuardStatusResource<T>,
  result: PromiseSettledResult<unknown>,
  normalize: (value: unknown) => T | null,
): GuardStatusResource<T> {
  const normalized = result.status === "fulfilled" ? normalize(result.value) : null;
  if (normalized !== null) return { value: normalized, loadState: "ready", refreshing: false };
  if (previous.value !== null) return { value: previous.value, loadState: "stale", refreshing: false };
  return { value: null, loadState: "error", refreshing: false };
}

export function settleNetworkSandboxStatus(
  previous: NetworkSandboxStatusState,
  networkResult: PromiseSettledResult<unknown>,
  containmentResult: PromiseSettledResult<unknown>,
): NetworkSandboxStatusState {
  return {
    network: settleResource(previous.network, networkResult, normalizeGuardNetworkStatus),
    containment: settleResource(previous.containment, containmentResult, normalizeGuardContainmentHealth),
  };
}

function loadWithTimeout(
  loader: (signal: AbortSignal) => Promise<unknown>,
  parentSignal: AbortSignal,
  timeoutMs: number,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const requestController = new AbortController();
    let settled = false;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      globalThis.clearTimeout(timer);
      parentSignal.removeEventListener("abort", handleParentAbort);
      callback();
    };
    const handleParentAbort = () => {
      requestController.abort();
      finish(() => reject(new Error("guard_status_request_aborted")));
    };
    const timer = globalThis.setTimeout(() => {
      requestController.abort();
      finish(() => reject(new Error("guard_status_request_timed_out")));
    }, timeoutMs);
    parentSignal.addEventListener("abort", handleParentAbort, { once: true });
    if (parentSignal.aborted) {
      handleParentAbort();
      return;
    }
    void Promise.resolve()
      .then(() => loader(requestController.signal))
      .then(
        (value) => finish(() => resolve(value)),
        (error: unknown) => finish(() => reject(error)),
      );
  });
}

export async function loadNetworkSandboxStatus(
  parentSignal: AbortSignal,
  timeoutMs = STATUS_REQUEST_TIMEOUT_MS,
  loaders: NetworkSandboxStatusLoaders = DEFAULT_STATUS_LOADERS,
): Promise<[PromiseSettledResult<unknown>, PromiseSettledResult<unknown>]> {
  return Promise.allSettled([
    loadWithTimeout(loaders.network, parentSignal, timeoutMs),
    loadWithTimeout(loaders.containment, parentSignal, timeoutMs),
  ]);
}

export function networkPresentationState(
  resource: GuardStatusResource<GuardNetworkStatus>,
  nowEpochMs: number,
): ProofPresentationState {
  if (resource.value === null) return resource.loadState === "error" ? "error" : "checking";
  const status = resource.value;
  if (status.hostPlatform === "unsupported") return "unsupported";
  if (resource.loadState === "stale") return "stale";
  if (
    status.supervisor.healthyUntilEpochMs !== null &&
    status.supervisor.healthyUntilEpochMs <= nowEpochMs
  ) {
    return "stale";
  }
  const independentlyVerified = status.independentlyObserved && status.supervisor.independentlyObserved;
  const activelyEnforcing = status.protectionActive && status.supervisor.permitsEnforcement;
  return independentlyVerified && activelyEnforcing ? "ready" : "unavailable";
}

export function containmentPresentationState(
  resource: GuardStatusResource<GuardContainmentHealth>,
  nowEpochMs: number,
): ProofPresentationState {
  if (resource.value === null) return resource.loadState === "error" ? "error" : "checking";
  if (resource.value.backend === "unsupported") return "unsupported";
  if (resource.loadState === "stale") return "stale";
  if (nowEpochMs - resource.value.probeAtEpochMs > 5 * 60 * 1_000 || resource.value.probeAtEpochMs > nowEpochMs + 5_000) {
    return "stale";
  }
  return resource.value.probeEnforced ? "ready" : "unavailable";
}

export function useNetworkSandboxStatus(): {
  state: NetworkSandboxStatusState;
  refresh: () => Promise<void>;
} {
  const [state, setState] = useState(INITIAL_NETWORK_SANDBOX_STATUS);
  const controllerRef = useRef<AbortController | null>(null);

  const refresh = useCallback(async () => {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;
    setState(beginNetworkSandboxRefresh);
    const [networkResult, containmentResult] = await loadNetworkSandboxStatus(controller.signal);
    if (controller.signal.aborted) return;
    setState((previous) => settleNetworkSandboxStatus(previous, networkResult, containmentResult));
  }, []);

  useEffect(() => {
    void refresh();
    return () => controllerRef.current?.abort();
  }, [refresh]);

  return { state, refresh };
}
