import { useSyncExternalStore } from "react";

function getReducedMotion(): boolean {
  if (typeof window === "undefined") return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

function subscribe(callback: () => void): () => void {
  const mql = window.matchMedia("(prefers-reduced-motion: reduce)");
  mql.addEventListener("change", callback);
  return () => mql.removeEventListener("change", callback);
}

export function useReducedMotion(): boolean {
  return useSyncExternalStore(subscribe, getReducedMotion, () => false);
}
