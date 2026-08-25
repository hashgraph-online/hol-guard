import assert from "node:assert/strict";

import { appliedPolicyCloudHref } from "./extension-policy-applied-toast";

const singlePermission = appliedPolicyCloudHref({
  cloudControlsUrl: "https://cloud.example.test/dashboard",
  extensionId: "command.git",
  extensionName: "Git",
  changedPermissionIds: ["command.git.permission.force-push"],
});
assert.equal(
  singlePermission,
  "https://cloud.example.test/guard/controls?extensionId=command.git&permissionId=command.git.permission.force-push",
);

const multiplePermissions = appliedPolicyCloudHref({
  cloudControlsUrl: "https://cloud.example.test/dashboard",
  extensionId: "command.git",
  extensionName: "Git",
  changedPermissionIds: ["command.git.permission.force-push", "command.git.permission.hard-reset"],
});
assert.equal(multiplePermissions, "https://cloud.example.test/guard/controls?extensionId=command.git");

console.log("extension-policy-panel.managed-controls.test.ts: all assertions passed");
