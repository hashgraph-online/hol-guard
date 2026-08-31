import { readJson } from "./guard-api";

function fetchProof(path: string, signal?: AbortSignal): Promise<unknown> {
  return readJson<unknown>(path, { cache: "no-store", method: "GET", signal });
}

export function fetchGuardNetworkStatus(signal?: AbortSignal): Promise<unknown> {
  return fetchProof("/v1/network/status", signal);
}

export function fetchGuardContainmentHealth(signal?: AbortSignal): Promise<unknown> {
  return fetchProof("/v1/runtime/containment-health", signal);
}
