//! Byte-parity golden vectors for `evaluate_effect_decision` /
//! `effect_decision_to_dict`, generated from the live Python oracle
//! (effect_decision.py + command_decision_adapter.py) and committed as a
//! fixture. Each case feeds the Python-built request JSON through the native
//! `evaluate_effect_decision` and asserts the emitted `decision_plane` dict is
//! identical to the Python `effect_decision_to_dict` output.

use guard_command::effect_decision::{
    effect_decision_to_payload, evaluate_effect_decision, EffectDecisionRequest,
};
use serde_json::Value;

fn vectors() -> Value {
    let raw = include_str!("fixtures/effect_decision_vectors.json");
    serde_json::from_str(raw).expect("effect decision vector corpus must be valid JSON")
}

#[test]
fn golden_vectors_match_python_effect_decision_to_dict() {
    let corpus = vectors();
    let cases = corpus.as_array().expect("corpus is an array");
    assert_eq!(cases.len(), 15, "expected 15 golden vectors");

    for entry in cases {
        let case = entry["case"].as_u64().unwrap();
        let request: EffectDecisionRequest = serde_json::from_value(entry["request"].clone())
            .unwrap_or_else(|e| panic!("case {case}: request must deserialize: {e}"));

        let decision = evaluate_effect_decision(&request)
            .unwrap_or_else(|e| panic!("case {case}: evaluation must succeed: {e}"));

        let payload = effect_decision_to_payload(&decision);
        let expected = &entry["expected"];
        assert_eq!(
            &payload,
            expected,
            "case {case}: decision_plane payload diverges from Python oracle\n\
             native:   {}\nexpected: {}",
            serde_json::to_string_pretty(&payload).unwrap(),
            serde_json::to_string_pretty(expected).unwrap(),
        );
    }
}
