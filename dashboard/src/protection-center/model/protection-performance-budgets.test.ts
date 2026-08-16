import assert from "node:assert/strict";

import { PROTECTION_CENTER_PERFORMANCE_BUDGETS } from "./protection-performance-budgets";

assert.equal(PROTECTION_CENTER_PERFORMANCE_BUDGETS.simpleRuleRenderCap, 500);
assert.ok(PROTECTION_CENTER_PERFORMANCE_BUDGETS.recentDecisionCap <= 20);
assert.ok(PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchCharacterCap <= 160);
assert.ok(PROTECTION_CENTER_PERFORMANCE_BUDGETS.humanSearchTermCap <= 8);
assert.ok(PROTECTION_CENTER_PERFORMANCE_BUDGETS.developerRelationshipCap <= 1024);

console.log("protection-performance-budgets.test.ts: all assertions passed");
