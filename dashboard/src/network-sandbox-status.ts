import { useCallback, useEffect, useRef, useState } from "react";
import { fetchGuardContainmentHealth, fetchGuardNetworkStatus } from "./network-sandbox-api";

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
const BACKEND_PLATFORMS = ["linux", "macos", "windows"] as const;
const CONTAINMENT_BACKENDS = ["unsupported", "macos-sandbox", "linux-bwrap"] as const;
const SHA256 = /^[0-9a-f]{64}$/;
const SAFE_IDENTIFIER = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
const CONTAINMENT_POLICY_CONTRACT_DIGEST = "157eb473c61c87e71483d1064db862b58e979864b486c693d39d54c6429b03f2";

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

type ValidatedNetworkBackend = {
  backendId: string;
  effectiveGrade: NetworkGrade;
  active: boolean;
  observed: boolean;
};

function gradeRank(grade: NetworkGrade): number {
  return NETWORK_GRADES.indexOf(grade);
}

function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length <= 128 && SAFE_IDENTIFIER.test(value);
}

function normalizeNetworkBackend(value: unknown, hostPlatform: HostPlatform): ValidatedNetworkBackend | null {
  if (!isRecord(value) || !validIdentifier(value["backend_id"])) return null;
  const platform = enumValue(value["platform"], BACKEND_PLATFORMS);
  const advertisedGrade = enumValue(value["advertised_maximum_grade"], NETWORK_GRADES);
  const effectiveGrade = enumValue(value["effective_grade"], NETWORK_GRADES);
  const booleanFields = [
    "supported",
    "installed",
    "verified",
    "active",
    "observed",
    "production_ready",
    "requires_privilege",
  ] as const;
  if (
    platform === null ||
    advertisedGrade === null ||
    effectiveGrade === null ||
    booleanFields.some((field) => exactBoolean(value[field]) === null) ||
    !validIdentifier(value["reason_code"]) ||
    !validIdentifier(value["reference_reason_code"])
  ) {
    return null;
  }
  const installed = value["installed"] === true;
  const verified = value["verified"] === true;
  const active = value["active"] === true;
  if (verified && !installed) return null;
  if (gradeRank(effectiveGrade) > gradeRank(advertisedGrade)) return null;
  if (
    active &&
    (value["supported"] !== true ||
      !verified ||
      value["production_ready"] !== true ||
      platform !== hostPlatform ||
      gradeRank(effectiveGrade) < gradeRank("deny-all"))
  ) {
    return null;
  }
  if (!active && gradeRank(effectiveGrade) >= gradeRank("deny-all")) return null;
  return {
    backendId: value["backend_id"],
    effectiveGrade,
    active,
    observed: value["observed"] === true,
  };
}

function normalizeNetworkBackends(value: unknown, hostPlatform: HostPlatform): ValidatedNetworkBackend[] | null {
  if (!Array.isArray(value)) return null;
  const backends: ValidatedNetworkBackend[] = [];
  const backendIds = new Set<string>();
  for (const candidate of value) {
    const backend = normalizeNetworkBackend(candidate, hostPlatform);
    if (backend === null || backendIds.has(backend.backendId)) return null;
    backendIds.add(backend.backendId);
    backends.push(backend);
  }
  return backends;
}

export function normalizeGuardNetworkStatus(value: unknown): GuardNetworkStatus | null {
  if (!isRecord(value) || value["schema"] !== "guard.network-status.v1") return null;
  const hostPlatform = enumValue(value["host_platform"], HOST_PLATFORMS);
  const effectiveGrade = enumValue(value["effective_grade"], NETWORK_GRADES);
  const independentlyObservedGrade = enumValue(value["independently_observed_grade"], NETWORK_GRADES);
  const protectionActive = exactBoolean(value["protection_active"]);
  const independentlyObserved = exactBoolean(value["independently_observed"]);
  const rawSupervisor = value["supervisor"];
  if (
    hostPlatform === null ||
    effectiveGrade === null ||
    independentlyObservedGrade === null ||
    protectionActive === null ||
    independentlyObserved === null ||
    !validIdentifier(value["reason_code"])
  ) {
    return null;
  }
  const backends = normalizeNetworkBackends(value["backends"], hostPlatform);
  if (backends === null) return null;
  const activeBackends = backends.filter((backend) => backend.active);
  const observedBackends = backends.filter((backend) => backend.observed);
  const maximumObservedGrade = observedBackends.reduce<NetworkGrade>(
    (maximum, backend) => (gradeRank(backend.effectiveGrade) > gradeRank(maximum) ? backend.effectiveGrade : maximum),
    "unavailable",
  );
  let supervisorValue: Record<string, unknown> | null = null;
  if (isRecord(rawSupervisor)) {
    supervisorValue = rawSupervisor;
  } else if (rawSupervisor == null && !protectionActive && !independentlyObserved) {
    supervisorValue = {
      phase: "unavailable",
      effective_grade: "unavailable",
      healthy_until_epoch_ms: null,
      permits_enforcement: false,
      independently_observed: false,
      backend_id: null,
      backend_digest: null,
      retry_attempt: 0,
      next_retry_seconds: 0,
    };
  }
  if (supervisorValue === null) return null;
  const phase = enumValue(supervisorValue["phase"], NETWORK_PHASES);
  const supervisorGrade = enumValue(supervisorValue["effective_grade"], NETWORK_GRADES);
  const healthyUntilEpochMs = finiteTimestamp(supervisorValue["healthy_until_epoch_ms"]);
  const permitsEnforcement = exactBoolean(supervisorValue["permits_enforcement"]);
  const supervisorObserved = exactBoolean(supervisorValue["independently_observed"]);
  const supervisorBackendId = supervisorValue["backend_id"];
  const supervisorDigest = supervisorValue["backend_digest"];
  const retryAttempt = supervisorValue["retry_attempt"];
  const nextRetrySeconds = supervisorValue["next_retry_seconds"];
  if (
    phase === null ||
    supervisorGrade === null ||
    permitsEnforcement === null ||
    supervisorObserved === null ||
    (supervisorBackendId !== null && !validIdentifier(supervisorBackendId)) ||
    (supervisorDigest !== null && (typeof supervisorDigest !== "string" || !SHA256.test(supervisorDigest))) ||
    typeof retryAttempt !== "number" ||
    !Number.isInteger(retryAttempt) ||
    retryAttempt < 0 ||
    typeof nextRetrySeconds !== "number" ||
    !Number.isFinite(nextRetrySeconds) ||
    nextRetrySeconds < 0
  ) {
    return null;
  }
  if (supervisorValue["healthy_until_epoch_ms"] !== null && healthyUntilEpochMs === null) return null;
  const expectedPermits = phase === "healthy" && gradeRank(supervisorGrade) >= gradeRank("deny-all");
  if (
    protectionActive !== (activeBackends.length > 0) ||
    (protectionActive && activeBackends.length !== 1) ||
    (!protectionActive && effectiveGrade !== "unavailable") ||
    (protectionActive && activeBackends[0]?.effectiveGrade !== effectiveGrade) ||
    independentlyObserved !== (independentlyObservedGrade !== "unavailable") ||
    independentlyObserved !== (observedBackends.length > 0) ||
    independentlyObservedGrade !== maximumObservedGrade ||
    permitsEnforcement !== expectedPermits ||
    protectionActive !== permitsEnforcement ||
    independentlyObserved !== supervisorObserved ||
    effectiveGrade !== supervisorGrade ||
    (protectionActive && phase !== "healthy") ||
    (protectionActive && healthyUntilEpochMs === null) ||
    (protectionActive && supervisorDigest === null) ||
    (protectionActive && activeBackends[0]?.backendId !== supervisorBackendId) ||
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

export function nextProofClockDelay(
  state: NetworkSandboxStatusState,
  nowEpochMs: number,
  fallbackMs = 30_000,
): number {
  const boundaries = [
    state.network.value?.supervisor.healthyUntilEpochMs,
    state.containment.value === null ? null : state.containment.value.probeAtEpochMs + 5 * 60 * 1_000,
  ];
  const futureDelays = boundaries
    .filter((boundary): boundary is number => boundary !== null && boundary > nowEpochMs)
    .map((boundary) => boundary - nowEpochMs + 1);
  return futureDelays.length === 0 ? fallbackMs : Math.min(fallbackMs, ...futureDelays);
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
