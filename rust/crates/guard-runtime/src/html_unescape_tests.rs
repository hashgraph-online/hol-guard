use super::*;

/// Inputs and the text Python's `html.unescape` produced for each.
const VECTORS: &str = include_str!("../testdata/html_unescape_vectors.json");

#[test]
fn every_named_reference_is_loaded() {
    assert_eq!(entities().len(), 2231);
    assert_eq!(entities()["nbsp"], "\u{a0}");
    assert_eq!(entities()["NotNestedGreaterGreater;"], "\u{2aa2}\u{338}");
}

#[test]
fn decoding_matches_python() {
    let vectors: Vec<(String, String)> = serde_json::from_str(VECTORS).expect("vectors");
    assert!(vectors.len() > 20);
    for (input, expected) in vectors {
        assert_eq!(unescape(&input), expected, "{input:?}");
    }
}
