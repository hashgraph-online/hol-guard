import { resolveSecurityLevelDescription, buildClearPolicyPayload } from "./settings-workspace";
import { repairApprovalCenter, setupDesktopNotifications } from "./guard-api";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const balancedDesc = resolveSecurityLevelDescription("balanced");
assert(balancedDesc.length > 0, "T529: balanced description should not be empty");
assert(balancedDesc.includes("secrets") || balancedDesc.includes("destructive"), "T529: balanced description should mention secrets or destructive");

const strictDesc = resolveSecurityLevelDescription("strict");
assert(strictDesc.length > 0, "T529: strict description should not be empty");
assert(strictDesc.includes("network") || strictDesc.includes("more"), "T529: strict description should mention network or more");
assert(strictDesc !== balancedDesc, "T529: strict and balanced descriptions should differ");

const customDesc = resolveSecurityLevelDescription("custom");
assert(customDesc.length > 0, "T529: custom description should not be empty");
assert(customDesc.includes("Custom") || customDesc.includes("custom") || customDesc.includes("rules"), "T529: custom description should mention custom rules");

const clearAllPayload = buildClearPolicyPayload(true);
assert(clearAllPayload.all === true, "T530: clearPolicy payload should have all=true");
assert(!("harness" in clearAllPayload) || clearAllPayload.harness === undefined, "T530: clearPolicy payload should not have harness when clearing all");

const clearNonePayload = buildClearPolicyPayload(false);
assert(clearNonePayload.all === false, "T530: clearPolicy payload with all=false should have all=false");

assert(typeof repairApprovalCenter === "function", "T739: repairApprovalCenter should be exported as a function");
assert(typeof setupDesktopNotifications === "function", "T740: setupDesktopNotifications should be exported as a function");
