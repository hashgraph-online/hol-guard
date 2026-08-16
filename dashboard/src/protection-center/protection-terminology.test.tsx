import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { ProtectionModuleDetail } from "./protection-module-detail";
import { FIXED_PROTECTION_MODULE, PROTECTION_AUTHORITY_FIXTURES } from "./fixtures/protection-fixtures";

const simple = renderToStaticMarkup(createElement(ProtectionModuleDetail, {
  extension: FIXED_PROTECTION_MODULE,
  effective: PROTECTION_AUTHORITY_FIXTURES.protected,
  catalogDigest: "a".repeat(64),
  onBack: () => undefined,
  onRefresh: () => undefined,
}));

for (const legacy of [
  "Permission controls",
  "Semantic review",
  "Blast radius",
  "Global lockdown",
  ">Modules<",
]) {
  assert.equal(simple.includes(legacy), false, `Simple Extensions must not surface legacy wording: ${legacy}`);
}
assert.match(simple, />Git</);
assert.match(simple, /font-mono[^"]*">git</);
assert.match(simple, /Protection settings/);
assert.match(simple, /Extensions/);
assert.match(simple, /Test Lab/);
assert.match(simple, /Developer details/);

console.log("protection-terminology.test.tsx: all assertions passed");
