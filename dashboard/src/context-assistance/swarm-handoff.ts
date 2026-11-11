import { useSyncExternalStore } from "react";

/** Navigation intent only. A discovered process never supplies a context grant. */
export type SwarmContextTarget = { id: string; label: string; harness: string; workspace: string | null };
let target: SwarmContextTarget | null = null;
const listeners = new Set<() => void>();
const subscribe = (listener: () => void) => { listeners.add(listener); return () => { listeners.delete(listener); }; };
const snapshot = () => target;

export function setSwarmContextTarget(value: SwarmContextTarget | null) {
  // Keep project paths in this tab's memory, outside URLs and persistent storage.
  target = value ? { id: value.id, label: value.label, harness: value.harness, workspace: value.workspace } : null;
  listeners.forEach((listener) => listener());
}
export function useSwarmContextTarget() { return useSyncExternalStore(subscribe, snapshot, snapshot); }
export function usesPromptContext(harness: string) { return ["codex", "claude-code", "pi", "omp"].includes(harness); }
