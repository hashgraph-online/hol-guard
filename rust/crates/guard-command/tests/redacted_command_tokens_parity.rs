//! Command-token redaction agrees with the vectors Python records for its own
//! copy of the same chain.
//!
//! `redacted_command_tokens` turns a package manager invocation into the command
//! text Guard stores on a receipt and prints in a review. Each token goes through
//! the package-source redaction, then a key-fragment check that masks
//! `API_KEY=...` and `api-key: ...` shaped tokens, then the text rules for
//! whatever is left. Python keeps the same chain in
//! `local_supply_chain._redact_command_token`, and each side redacts on the route
//! it owns, so a fragment dropped or an order swapped in either copy would
//! persist a secret the other copy masks.
//!
//! The two sub-routines are pinned on their own; these vectors cover the chain.
//! Each case assembles its tokens from fragments so no complete secret-shaped
//! literal sits in the tree, the same discipline `oracle_vectors` follows.

use guard_command::redacted_command_tokens::redacted_command_tokens;
use serde_json::Value;

const VECTORS: &str = include_str!("../../../../tests/fixtures/redacted-command-tokens.v1.json");

fn text_entries(value: &Value) -> Vec<String> {
    value
        .as_array()
        .expect("array of strings")
        .iter()
        .map(|entry| entry.as_str().expect("string entry").to_owned())
        .collect()
}

#[test]
fn recorded_commands_redact_to_their_recorded_tokens() {
    let vectors: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    assert_eq!(
        vectors["schema"].as_str(),
        Some("redacted-command-tokens-parity.v1")
    );
    let cases = vectors["cases"].as_array().expect("cases array");
    assert!(cases.len() >= 19);

    for case in cases {
        let name = case["name"].as_str().unwrap_or_default();
        let command: Vec<String> = case["command"]
            .as_array()
            .expect("command tokens")
            .iter()
            .map(|token| text_entries(token).concat())
            .collect();
        let expected = text_entries(&case["redacted"]);

        assert_eq!(redacted_command_tokens(&command), expected, "{name}");
    }
}
