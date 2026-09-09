import { strict as assert } from "node:assert";
import fixture from "./__fixtures__/everyday-action-explanation.json";
import { opaqueExplanationIdentity, parseActionExplanation } from "./action-explanation-validation";

const explanation = parseActionExplanation(fixture.action_explanation);
assert.ok(explanation, "the browser must accept the actual Core projection");
assert.equal(await opaqueExplanationIdentity(fixture.action_identity), explanation.action_identity);
assert.equal(await opaqueExplanationIdentity(`  ${fixture.action_identity}  `), explanation.action_identity);
assert.notEqual(await opaqueExplanationIdentity("a different retained action"), explanation.action_identity);
assert.equal(await opaqueExplanationIdentity(""), null);
assert.equal(await opaqueExplanationIdentity("x".repeat(65537)), null);
for (const key of Object.keys(fixture.action_explanation)) {
  const missing = { ...fixture.action_explanation } as Record<string, unknown>;
  delete missing[key];
  assert.equal(parseActionExplanation(missing), null, `missing ${key} must be rejected`);
}
for (const changes of [
  { schema_version: "guard.action-explanation.v2" }, { renderer_version: "2.0.0" },
  { explanation_version: "2.0.0" }, { kind: "looks_safe" }, { confidence: "certain" },
  { action_identity: "raw internal identity" }, { raw_command: "not part of this contract" },
  { uncertainty_reasons: Array(17).fill("unknown") },
  { everyday: { ...explanation.everyday, headline: "x".repeat(241) } },
  { everyday: { ...explanation.everyday, secret_value: "must not be rendered" } },
  { everyday: { ...explanation.everyday, consequences: [{ message_id: "a", message: "b", severity: "high", confirmed: "true" }] } },
  { technical: { ...explanation.technical, action_id: "act_" + "0".repeat(64) } },
  { technical: { ...explanation.technical, segments: [{ executable: null, arguments_display: [], execution_context: "shell", pipeline_index: 0.5 }] } },
  { technical: { ...explanation.technical, command_display: "x".repeat(4097) } },
  { redaction: { ...explanation.redaction, policy_version: "2" } },
]) assert.equal(parseActionExplanation({ ...explanation, ...changes }), null, JSON.stringify(changes).slice(0, 80));
assert.ok(parseActionExplanation({ ...explanation, everyday: { ...explanation.everyday, headline: "😀".repeat(240) } }), "schema lengths use Unicode code points");
console.log("action-explanation-validation.test.ts: all tests passed");
