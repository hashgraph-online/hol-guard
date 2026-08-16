import assert from "node:assert/strict";

import { protectionModuleFixture } from "../fixtures/protection-fixtures";
import { protectionPresentationComplete, protectionPresentationIssues } from "./protection-author-metadata";

const complete = protectionModuleFixture({
  name: "Package downloads",
  description: "Protects package acquisition and install actions.",
  executables: ["npm"],
  ecosystem_ids: ["npm"],
  risk_classes: ["supply-chain"],
  action_classes: ["package-install"],
  safer_alternatives: ["Review the package before installing it."],
});
assert.equal(protectionPresentationComplete(complete), true);
assert.deepEqual(protectionPresentationIssues(complete), []);

const incomplete = protectionModuleFixture({
  name: "",
  description: "",
  executables: [],
  ecosystem_ids: [],
  risk_classes: [],
  action_classes: [],
  safer_alternatives: [],
});
assert.deepEqual(protectionPresentationIssues(incomplete), [
  "missing-name",
  "missing-description",
  "missing-action-example",
  "missing-risk-language",
  "missing-safer-guidance",
]);

console.log("protection-author-metadata.test.ts: all assertions passed");
