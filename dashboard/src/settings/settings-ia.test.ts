import { isLocalSettingsTabKey, localSettingsNavItems } from "./settings-ia";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(localSettingsNavItems.length === 5, "local settings should expose five focused sections");
assert(
  localSettingsNavItems.some((item) => item.key === "protection"),
  "protection tab should exist",
);
assert(
  localSettingsNavItems.some((item) => item.key === "approval"),
  "approval tab should exist",
);
assert(isLocalSettingsTabKey("notifications"), "notifications should be a valid tab key");
assert(isLocalSettingsTabKey("rules"), "protection rules should be a valid tab key");
assert(!isLocalSettingsTabKey("risk"), "legacy fine-tuning should not remain a separate tab");
assert(!isLocalSettingsTabKey("defaults"), "legacy fallback rules should not remain a separate tab");
assert(isLocalSettingsTabKey("maintenance"), "maintenance tab should be a valid tab key");
assert(!isLocalSettingsTabKey("billing"), "cloud-only tabs should not validate locally");
assert(!isLocalSettingsTabKey("advanced"), "legacy advanced tab key should not validate locally");

console.log("settings-ia.test.ts: all tests passed");
