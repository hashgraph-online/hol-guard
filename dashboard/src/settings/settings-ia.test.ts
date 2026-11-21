import { isLocalSettingsTabKey, localSettingsNavGroups, localSettingsNavItems } from "./settings-ia";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(localSettingsNavItems.length === 7, "settings should expose six machine sections and one Guard Cloud section");
assert(
  localSettingsNavItems.filter((item) => item.group === "local").length === 6,
  "machine settings should keep six focused sections",
);
assert(
  localSettingsNavGroups.map((group) => group.key).join(",") === "local,cloud",
  "Guard Cloud settings should sit after the machine's own settings",
);
assert(
  localSettingsNavItems.at(-1)?.key === "cloud-actions" && localSettingsNavItems.at(-1)?.group === "cloud",
  "Cloud actions should be the Guard Cloud section",
);
assert(isLocalSettingsTabKey("cloud-actions"), "Cloud actions should be a valid tab key");
assert(
  localSettingsNavItems.some((item) => item.key === "protection"),
  "protection tab should exist",
);
assert(
  localSettingsNavItems.some((item) => item.key === "apps"),
  "per-app protection tab should exist",
);
assert(
  localSettingsNavItems.findIndex((item) => item.key === "apps")
    === localSettingsNavItems.findIndex((item) => item.key === "protection") + 1,
  "apps tab should sit next to the machine protection tab",
);
assert(
  localSettingsNavItems.some((item) => item.key === "approval"),
  "approval tab should exist",
);
assert(isLocalSettingsTabKey("notifications"), "notifications should be a valid tab key");
assert(isLocalSettingsTabKey("rules"), "protection rules should be a valid tab key");
assert(isLocalSettingsTabKey("apps"), "per-app protection should be a valid tab key");
assert(!isLocalSettingsTabKey("risk"), "legacy fine-tuning should not remain a separate tab");
assert(!isLocalSettingsTabKey("defaults"), "legacy fallback rules should not remain a separate tab");
assert(isLocalSettingsTabKey("maintenance"), "maintenance tab should be a valid tab key");
assert(!isLocalSettingsTabKey("billing"), "cloud-only tabs should not validate locally");
assert(!isLocalSettingsTabKey("advanced"), "legacy advanced tab key should not validate locally");

console.log("settings-ia.test.ts: all tests passed");
