//! Replays suggestion vectors recorded from the reference Python
//! (`scripts/record_custom_extension_suggestion_vectors.py`).

use guard_contracts::{SuggestionToolV1, SuggestionVerdictV1};
use serde_json::Value;

use super::*;

const VECTORS: &str = include_str!("../tests/fixtures/custom_extension_suggestion_vectors.json");

#[test]
fn suggestions_match_python_vectors() {
    let vectors: Vec<Value> = serde_json::from_str(VECTORS).expect("vectors");
    assert!(vectors.len() >= 300);
    let tools: Vec<SuggestionToolV1> = vectors
        .iter()
        .map(|vector| serde_json::from_value(vector["tool"].clone()).expect("tool"))
        .collect();
    let verdicts = suggestion_verdicts(&tools).expect("verdicts");
    for (vector, got) in vectors.iter().zip(verdicts) {
        let expected: SuggestionVerdictV1 =
            serde_json::from_value(vector["expected"].clone()).expect("expected");
        assert_eq!(got, expected, "tool {}", vector["tool"]);
    }
}

#[test]
fn oversized_batches_are_refused() {
    let tool = SuggestionToolV1 {
        name: "deploy-tool".to_owned(),
        kind: "script".to_owned(),
        source_path: None,
        observed_count: 0,
        help_status: None,
        surface: "cli".to_owned(),
    };
    assert_eq!(
        suggestion_verdicts(&vec![tool.clone(); MAX_TOOLS]).map(|v| v.len()),
        Ok(MAX_TOOLS)
    );
    assert_eq!(
        suggestion_verdicts(&vec![tool; MAX_TOOLS + 1]),
        Err(ERR_TOO_MANY_TOOLS)
    );
}
