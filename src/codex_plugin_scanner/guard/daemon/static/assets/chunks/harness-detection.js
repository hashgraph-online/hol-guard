import { r as reactExports, b0 as isGuardDemoMode, b1 as fetchGuardApi } from "../guard-dashboard.js";
import { i as isConnectableAppHarness } from "./harness-setup-target.js";
async function fetchHarnessSetupItems() {
  if (isGuardDemoMode()) return [];
  const response = await fetchGuardApi("/v1/harnesses");
  if (!response.ok) throw new Error(`Unable to detect local AI apps (${response.status}).`);
  const payload = await response.json();
  return Array.isArray(payload.items) ? payload.items : [];
}
function useHarnessDetection() {
  const [state, setState] = reactExports.useState({ kind: "loading" });
  reactExports.useEffect(() => {
    let cancelled = false;
    void fetchHarnessSetupItems().then((items) => {
      if (!cancelled) setState({ kind: "ready", items });
    }).catch((error) => {
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
function detectedHarnesses(state) {
  if (state.kind !== "ready") return [];
  return state.items.filter((item) => item.status !== "not_found" && isConnectableAppHarness(item.harness)).map((item) => item.harness);
}
function visibleHarnessesFor(input) {
  return Array.from(new Set([
    ...input.managed,
    ...input.observed,
    ...input.inventory,
    ...input.detected,
    ...input.policies
  ].filter(isConnectableAppHarness))).sort((a, b) => a.localeCompare(b));
}
function isHarnessDetected(state, harness) {
  return state.kind === "ready" && isHarnessDetectedItems(state.items, harness);
}
function isHarnessDetectedItems(items, harness) {
  return items.some((item) => item.harness === harness && item.status !== "not_found");
}
function resolveDetectedAppStatus(install, protectionHealth, hasInventory, hasReceipts, detected) {
  if (install !== void 0) {
    const hookCheck = protectionHealth.checks.find((check) => check.check_id === "harness_hooks");
    if (!install.active || hookCheck?.status !== "pass") return "needs_repair";
    if (protectionHealth.state === "protected") return "protected";
    return "partial";
  }
  return hasInventory || hasReceipts || detected ? "found_unprotected" : "not_found";
}
export {
  detectedHarnesses as d,
  isHarnessDetected as i,
  resolveDetectedAppStatus as r,
  useHarnessDetection as u,
  visibleHarnessesFor as v
};
