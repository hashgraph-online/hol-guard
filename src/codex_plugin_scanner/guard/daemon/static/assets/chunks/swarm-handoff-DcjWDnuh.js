import { r as reactExports } from "../guard-dashboard.js";
let target = null;
const listeners = /* @__PURE__ */ new Set();
const subscribe = (listener) => {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
};
const snapshot = () => target;
function setSwarmContextTarget(value) {
  target = value ? { id: value.id, label: value.label, harness: value.harness, workspace: value.workspace } : null;
  listeners.forEach((listener) => listener());
}
function useSwarmContextTarget() {
  return reactExports.useSyncExternalStore(subscribe, snapshot, snapshot);
}
function usesPromptContext(harness) {
  return ["codex", "claude-code", "pi", "omp"].includes(harness);
}
export {
  useSwarmContextTarget as a,
  setSwarmContextTarget as s,
  usesPromptContext as u
};
