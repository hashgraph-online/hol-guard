import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(message);
  }
}

const here = dirname(fileURLToPath(import.meta.url));
const tabSource = readFileSync(join(here, "policy-cloud-exceptions-tab.tsx"), "utf8");
const panelSource = readFileSync(join(here, "policy-cloud-exception-request-panel.tsx"), "utf8");
const layoutSource = readFileSync(join(here, "policy-cloud-exception-request-layout.tsx"), "utf8");
const stepsSource = readFileSync(join(here, "policy-cloud-exception-request-steps.tsx"), "utf8");
const draftSource = readFileSync(join(here, "policy-cloud-exception-request-draft.ts"), "utf8");
const guardApiSource = readFileSync(join(here, "guard-api.ts"), "utf8");

const REQUIRED_STEPS = ["Source", "Scope", "Guardrails", "Review", "Submitted"];

assert(tabSource.includes("PolicyCloudExceptionRequestPanel"), "cloud exceptions tab mounts request panel");
assert(panelSource.includes("handleNext") || panelSource.includes("handleBack"), "request panel supports wizard navigation");
assert(panelSource.includes("createCloudExceptionRequest"), "request panel submits through Guard Cloud proxy");
assert(stepsSource.includes("CloudExceptionSourceStep"), "source step is isolated component");
assert(stepsSource.includes("CloudExceptionScopeStep"), "scope step is isolated component");
assert(stepsSource.includes("CloudExceptionGuardrailsStep"), "guardrails step is isolated component");
assert(stepsSource.includes("CloudExceptionReviewStep"), "review step is isolated component");
assert(stepsSource.includes("CloudExceptionSubmittedStep"), "submitted step is isolated component");
assert(layoutSource.includes("RequestSummaryRail"), "modal includes request summary rail");
assert(layoutSource.includes("max-w-5xl"), "modal shell uses focused width instead of page-like max-w-6xl");
assert(!layoutSource.includes("max-w-6xl"), "modal shell must not use max-w-6xl");
assert(draftSource.includes("CloudExceptionRequestDraft"), "request panel uses typed draft object");
assert(draftSource.includes("WIZARD_STEPS"), "wizard steps are centralized");
for (const step of REQUIRED_STEPS) {
  assert(layoutSource.includes(`"${step}"`) || draftSource.includes(`"${step}"`), `flow includes ${step} step`);
}
assert(!layoutSource.includes('"Submit"'), "wizard must not expose Submit as a step label");
assert(panelSource.includes("Submit request"), "review step uses Submit request button text");
assert(panelSource.includes("sourceReceiptId") || draftSource.includes("sourceReceiptId"), "request anchors to source receipt");
assert(draftSource.includes("sourceReviewItemId"), "request supports source review item anchoring");
assert(!panelSource.includes("savePolicyDecision"), "request panel must not save local policy decisions");
assert(guardApiSource.includes("createCloudExceptionRequest"), "guard-api exposes cloud exception request create");
assert(guardApiSource.includes("/v1/policy/cloud-exception-requests"), "guard-api calls daemon proxy endpoint");

const forbiddenFixturePatterns = [
  /\bLorem ipsum\b/i,
  /\bMock Exception\b/i,
  /\breceipt_demo\b/i,
  /\breq_3f9a7b1c\b/i,
  /\breceipt_8f7c2b1a\b/i,
];

for (const pattern of forbiddenFixturePatterns) {
  assert(!panelSource.match(pattern), `request panel must not contain fixture pattern ${pattern}`);
  assert(!stepsSource.match(pattern), `request steps must not contain fixture pattern ${pattern}`);
}

console.log("policy-cloud-exception-request-ia.test.ts: all assertions passed");
