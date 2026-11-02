mod activation;
mod bindings;
mod canonical;
mod catalog;
mod consent;
mod intake;
mod policy;

use base64::{engine::general_purpose::STANDARD, Engine};
use ring::rand::SystemRandom;
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::{json, Value};

use crate::cloud_action::{error_result, CloudActionEvaluator, MAX_SAVED_CONSENTS, RESULT_SCHEMA};
use crate::cloud_action_activation::{
    parse_public_key, verify_activation, ActivationContext, SignedActivation, ACTIVATION_SCHEMA,
};
use crate::cloud_action_binding::load_binding_set;
use crate::cloud_action_binding::ActionEffect;
use crate::cloud_action_canonical::{
    canonical_arguments, canonical_bytes, domain_digest, parse_strict, CanonicalError,
    MAX_ARGUMENT_BYTES, MAX_DEPTH,
};
use crate::cloud_action_policy::{decide_policy, CloudPolicyRule, PolicySubject, MAX_POLICY_RULES};
use crate::effect_decision::GuardAction;
use crate::native_command_program::packaged_command_program;

const BINDINGS: &str = include_str!("../tests/fixtures/cloud-action/binding-set.json");
const REQUEST: &str = include_str!("../tests/fixtures/cloud-action/request.json");

/// A mutation applied to a base request or binding document.
type Edit = fn(&mut Value);

const POST: &str = "slack.chat.post_message";
const ARCHIVE: &str = "slack.channels.archive";
const LIST: &str = "slack.channels.list";
const TRANSFER: &str = "slack.workspace.transfer_ownership";

fn evaluator() -> CloudActionEvaluator {
    CloudActionEvaluator::new(load_binding_set(BINDINGS.as_bytes()).unwrap(), None)
}

fn request_for(evaluator: &CloudActionEvaluator) -> Value {
    let mut request: Value = serde_json::from_str(REQUEST).unwrap();
    request["binding_set_digest"] = evaluator.binding_set_digest().into();
    request
}

fn run(evaluator: &CloudActionEvaluator, request: &Value) -> Value {
    evaluator.evaluate(request.to_string().as_bytes())
}

fn run_with_rules(rules: Value) -> Value {
    let evaluator = evaluator();
    let mut request = request_for(&evaluator);
    request["policy"]["rules"] = rules;
    run(&evaluator, &request)
}

fn set_action(request: &mut Value, action_id: &str, arguments: Value) {
    request["action"]["action_id"] = action_id.into();
    request["action"]["arguments"] = arguments;
}

fn rule(rule_id: &str, action: &str, action_id: &str) -> Value {
    json!({"rule_id": rule_id, "action": action, "match": {"action_id": action_id}})
}

fn consent(consent_id: &str, kind: &str, identity: &str) -> Value {
    json!({"consent_id": consent_id, "kind": kind, "action_identity_sha256": identity})
}

fn identity_of(evaluator: &CloudActionEvaluator, request: &Value) -> String {
    let result = run(evaluator, request);
    assert_success(&result);
    result["action_identity_sha256"].as_str().unwrap().into()
}

fn assert_success(result: &Value) {
    assert!(result.get("error").is_none(), "{result}");
    assert_eq!(result["schema"], RESULT_SCHEMA);
}

fn assert_error(result: &Value, code: &str) {
    assert_eq!(result["error"]["code"], code, "{result}");
    assert_eq!(result["schema"], RESULT_SCHEMA, "{result}");
    assert_eq!(result["action"], "block", "{result}");
    assert_eq!(result["dispatch_permitted"], false, "{result}");
    assert!(result.get("action_identity_sha256").is_none(), "{result}");
}

/// The request with its arguments replaced by `raw` JSON text, for inputs a
/// `Value` cannot hold (duplicate keys, floats, numbers past 2^53).
fn line_with_raw_arguments(request: &Value, raw: &str) -> String {
    let mut request = request.clone();
    request["action"]["arguments"] = "@@arguments@@".into();
    request.to_string().replace("\"@@arguments@@\"", raw)
}

fn is_hex_digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
