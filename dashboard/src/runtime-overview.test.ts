import { resolveCloudIntelCopy, resolveCloudSyncHealthCopy, resolveProtectionLevelCopy } from "./runtime-overview";
import type { GuardCloudSyncHealth } from "./guard-types";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const healthDisabled: GuardCloudSyncHealth = {
  state: "disabled",
  label: "Sync disabled",
  detail: "Cloud sync is turned off on this machine.",
  pending_events: 0,
  last_synced_at: null,
  next_retry_after: null
};

const healthHealthy: GuardCloudSyncHealth = {
  state: "healthy",
  label: "Sync healthy",
  detail: "Cloud sync is running normally.",
  pending_events: 0,
  last_synced_at: new Date().toISOString(),
  next_retry_after: null
};

const localOnlyCopy = resolveCloudIntelCopy("local_only");
assert(localOnlyCopy.label === "Offline, free", "T507: local_only label should be 'Offline, free'");
assert(localOnlyCopy.detail.length > 0, "T507: local_only detail should not be empty");
assert(localOnlyCopy.detail.includes("locally"), "T507: local_only detail should mention 'locally'");

const localOnlySyncCopy = resolveCloudSyncHealthCopy(healthDisabled);
assert(localOnlySyncCopy.label === healthDisabled.label, "T507: cloud sync health label should match");
assert(localOnlySyncCopy.detail === healthDisabled.detail, "T507: cloud sync health detail should match");

const protectionBalanced = resolveProtectionLevelCopy("balanced");
assert(protectionBalanced.includes("secrets"), "T507: balanced description should mention secrets");

const pairedActiveCopy = resolveCloudIntelCopy("paired_active");
assert(pairedActiveCopy.label === "Synced, pro", "T508: paired_active label should be 'Synced, pro'");
assert(pairedActiveCopy.detail.length > 0, "T508: paired_active detail should not be empty");
assert(pairedActiveCopy.detail.includes("Guard Cloud"), "T508: paired_active detail should mention Guard Cloud");

const pairedWaitingCopy = resolveCloudIntelCopy("paired_waiting");
assert(pairedWaitingCopy.label === "Pairing…", "T508: paired_waiting label should be 'Pairing…'");

const pairedActiveSyncCopy = resolveCloudSyncHealthCopy(healthHealthy);
assert(pairedActiveSyncCopy.label === healthHealthy.label, "T508: healthy sync label should match");

const protectionStrict = resolveProtectionLevelCopy("strict");
assert(protectionStrict.includes("network"), "T508: strict description should mention network");

const protectionCustom = resolveProtectionLevelCopy("custom");
assert(protectionCustom.includes("Custom"), "T508: custom description should mention Custom");
