import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import { FIXED_PROTECTION_MODULE } from "./fixtures/protection-fixtures";
import { ProtectionTestLab } from "./protection-test-lab";

const lab = renderToStaticMarkup(createElement(ProtectionTestLab, { extension: FIXED_PROTECTION_MODULE }));
assert.match(lab, /aria-labelledby="protection-test-lab-heading"/);
assert.match(lab, /id="protection-test-lab-heading"/);
assert.match(lab, /Command to check/);
assert.match(lab, /type="button"/);
assert.match(lab, /Check safely/);
assert.doesNotMatch(lab, /autofocus/i);

console.log("protection-final-a11y.test.tsx: all assertions passed");
