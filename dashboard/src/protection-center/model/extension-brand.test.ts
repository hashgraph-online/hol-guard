import assert from "node:assert/strict";

import {
  CATALOG_EXTENSION_IDS,
  extensionBrandTestId,
  resolveExtensionBrand,
} from "./extension-brand";

assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.git" })), "git");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.github" })), "github");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.cicd.github" })), "github-actions");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.cloud.aws" })), "aws");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.cloud.gcp" })), "gcp");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.cloud.azure" })), "azure");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.dns.aws" })), "aws");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.dns.gcp" })), "gcp");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.dns.azure" })), "azure");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.infrastructure-as-code" })), "terraform opentofu pulumi");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.kubernetes-operations" })), "kubernetes helm");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.package.node" })), "node npm");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.package.jvm" })), "maven gradle");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.payment" })), "stripe");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.feature-flags" })), "launchdarkly");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.guard-self-protection" })), "guard");
assert.equal(resolveExtensionBrand({ extension_id: "command.guard-self-protection" }).kind, "guard");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.filesystem" })), "fallback-folder");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.windows" })), "windows");
assert.equal(extensionBrandTestId(resolveExtensionBrand({ extension_id: "command.remote.ssh" })), "fallback-globe");

assert.equal(
  extensionBrandTestId(resolveExtensionBrand({
    extension_id: "command.npm",
    name: "npm",
    ecosystem_ids: ["npm"],
    executables: ["npm"],
  })),
  "npm",
);

assert.equal(resolveExtensionBrand({ extension_id: "command.unknown-tool" }).kind, "fallback");

for (const extensionId of CATALOG_EXTENSION_IDS) {
  const resolution = resolveExtensionBrand({ extension_id: extensionId });
  assert.ok(extensionBrandTestId(resolution).length > 0, `${extensionId} should resolve to a brand or fallback`);
  if (extensionId === "command.guard-self-protection") {
    assert.equal(resolution.kind, "guard");
    continue;
  }
  if (resolution.kind === "marks") {
    assert.ok(resolution.marks.length >= 1 && resolution.marks.length <= 3, `${extensionId} should show 1-3 marks`);
  }
}

const stripe = resolveExtensionBrand({ extension_id: "command.payment" });
assert.equal(stripe.kind, "marks");
if (stripe.kind === "marks") {
  assert.equal(stripe.marks[0]?.color, "635BFF");
  assert.equal(stripe.marks[0]?.label, "Stripe");
}

console.log("extension-brand.test.ts: all assertions passed");
