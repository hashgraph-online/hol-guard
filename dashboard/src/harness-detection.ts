import { useEffect, useState } from "react";

import { fetchGuardApi } from "./guard-api";
import { isGuardDemoMode } from "./guard-demo";
import { isConnectableAppHarness } from "./apps/harness-setup-target";
import type { GuardHarnessSetupContract, GuardProtectionAppHealth } from "./guard-types";

export type DetectedAppStatus = "protected" | "partial" | "found_unprotected" | "needs_repair" | "not_found";

export type GuardHarnessSetupItem = GuardHarnessSetupContract & {
  status: "protected" | "found" | "not_found";
  observed_copy: string;
  installed: boolean;
  command_available: boolean;
  config_paths: string[];
  artifact_count: number;
};

export type HarnessDetectionState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; items: GuardHarnessSetupItem[] };

async function fetchHarnessSetupItems(): Promise<GuardHarnessSetupItem[]> {
  if (isGuardDemoMode()) return [];
  const response = await fetchGuardApi("/v1/harnesses");
  if (!response.ok) throw new Error(`Unable to detect local AI apps (${response.status}).`);
  const payload = (await response.json()) as { items?: GuardHarnessSetupItem[] };
  return Array.isArray(payload.items) ? payload.items : [];
}

export function useHarnessDetection(): HarnessDetectionState {
  const [state, setState] = useState<HarnessDetectionState>({ kind: "loading" });
  useEffect(() => {
    let cancelled = false;
    void fetchHarnessSetupItems()
      .then((items) => {
        if (!cancelled) setState({ kind: "ready", items });
      })
      .catch((error: unknown) => {
        if (!cancelled) {
          setState({ kind: "error", message: error instanceof Error ? error.message : "Unable to detect local AI apps." });
        }
      });
    return () => {
      cancelled = true;
    };
  }, []);
  return state;
}

export function detectedHarnesses(state: HarnessDetectionState): string[] {
  if (state.kind !== "ready") return [];
  return state.items
    .filter((item) => item.status !== "not_found" && isConnectableAppHarness(item.harness))
    .map((item) => item.harness);
}

export function visibleHarnessesFor(input: {
  managed: string[];
  observed: string[];
  inventory: string[];
  detected: string[];
  policies: string[];
}): string[] {
  return Array.from(new Set([
    ...input.managed,
    ...input.observed,
    ...input.inventory,
    ...input.detected,
    ...input.policies,
  ].filter(isConnectableAppHarness))).sort((a, b) => a.localeCompare(b));
}

export function isHarnessDetected(state: HarnessDetectionState, harness: string): boolean {
  return state.kind === "ready" && isHarnessDetectedItems(state.items, harness);
}

export function isHarnessDetectedItems(
  items: ReadonlyArray<Pick<GuardHarnessSetupItem, "harness" | "status">>,
  harness: string,
): boolean {
  return items.some((item) => item.harness === harness && item.status !== "not_found");
}

export function resolveDetectedAppStatus(
  install: { active?: boolean } | undefined,
  protectionHealth: GuardProtectionAppHealth,
  hasInventory: boolean,
  hasReceipts: boolean,
  detected: boolean,
): DetectedAppStatus {
  if (install !== undefined) {
    const hookCheck = protectionHealth.checks.find((check) => check.check_id === "harness_hooks");
    if (!install.active || hookCheck?.status === "fail") return "needs_repair";
    if (protectionHealth.state === "protected") return "protected";
    return "partial";
  }
  return hasInventory || hasReceipts || detected ? "found_unprotected" : "not_found";
}
