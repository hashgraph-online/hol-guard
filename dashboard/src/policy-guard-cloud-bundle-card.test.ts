import {
  formatCloudBundleHashDisplay,
  resolveCloudBundleStatusSubtitle,
} from "./policy-guard-cloud-bundle-helpers";
import { resolveCloudPolicyBundleCopy } from "./policy-workspace-helpers";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

assert(
  formatCloudBundleHashDisplay("sha256:abcdef1234567890") === "sha256:abcdef…7890",
  "bundle hash display uses middle truncation for sha256 hashes",
);
assert(
  formatCloudBundleHashDisplay("sha256:abc") === "sha256:abc",
  "bundle hash display preserves prefix for short hashes",
);
assert(formatCloudBundleHashDisplay(null) === "Unavailable", "missing hash shows unavailable");

const attentionCopy = resolveCloudPolicyBundleCopy({
  cloud_policy_bundle_version: "policy-1781231113830",
  cloud_policy_sync_error: "auth_expired",
  cloud_policy_bundle_hash: "sha256:abcdef1234567890",
});
assert(attentionCopy?.label === "Needs attention", "sync error surfaces attention label");
assert(
  resolveCloudBundleStatusSubtitle(attentionCopy!) === "Sync needs attention",
  "status subtitle stays short when sync needs attention",
);
assert(
  attentionCopy!.detail.includes("auth_expired"),
  "full sync detail remains available for detail row",
);

const syncedCopy = resolveCloudPolicyBundleCopy({
  cloud_policy_bundle_version: "v2026.05.23.1",
  cloud_policy_rollout_state: "active",
  cloud_policy_bundle_hash: "a1b2c3d4e5f6",
});
assert(
  resolveCloudBundleStatusSubtitle(syncedCopy!) === "All policies up to date",
  "synced subtitle matches mockup copy",
);

console.log("policy-guard-cloud-bundle-card.test.ts: all assertions passed");
