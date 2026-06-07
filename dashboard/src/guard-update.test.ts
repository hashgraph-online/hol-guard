import { normalizeGuardUpdateStatus } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const normalized = normalizeGuardUpdateStatus({
  current_version: "1.2.3",
  latest_version: "1.2.4",
  installer: "pipx",
  version_check: {
    source: "pypi",
    status: "stale",
    current_version: "1.2.3",
    latest_version: "1.2.4",
    update_available: true,
  },
  auto_updatable: true,
  update_available: true,
  blocked_reason: null,
});

assert(normalized.current_version === "1.2.3", "current version should normalize");
assert(normalized.latest_version === "1.2.4", "latest version should normalize");
assert(normalized.installer === "pipx", "installer should normalize");
assert(normalized.update_available === true, "update_available should normalize");
assert(normalized.version_check.update_available === true, "version_check should normalize");

const blocked = normalizeGuardUpdateStatus({
  auto_updatable: false,
  update_available: false,
  blocked_reason: "Local install only",
});

assert(blocked.auto_updatable === false, "auto_updatable false should normalize");
assert(blocked.blocked_reason === "Local install only", "blocked_reason should normalize");
assert(blocked.current_version === "unknown", "missing current_version should default to unknown");

console.log("guard-update.test.ts: all tests passed");
