import { isLocalSettingsTabKey, localSettingsNavItems } from "./settings-ia";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(localSettingsNavItems.length === 6, "local settings should expose six tabs");
assert(
  localSettingsNavItems.some((item) => item.key === "protection"),
  "protection tab should exist",
);
assert(
  localSettingsNavItems.some((item) => item.key === "approval"),
  "approval tab should exist",
);
assert(isLocalSettingsTabKey("notifications"), "notifications should be a valid tab key");
assert(isLocalSettingsTabKey("risk"), "risk tab should be a valid tab key");
assert(isLocalSettingsTabKey("defaults"), "defaults tab should be a valid tab key");
assert(isLocalSettingsTabKey("maintenance"), "maintenance tab should be a valid tab key");
assert(!isLocalSettingsTabKey("billing"), "cloud-only tabs should not validate locally");
assert(!isLocalSettingsTabKey("advanced"), "legacy advanced tab key should not validate locally");

console.log("settings-ia.test.ts: all tests passed");
