use serde_json::json;

use super::*;

#[test]
fn a_raw_line_break_folds_the_way_a_double_quoted_scalar_does() {
    assert_eq!(folded("a\u{85}b").as_deref(), Some("a b"));
    assert_eq!(folded("a  \u{85}  b").as_deref(), Some("a b"));
    assert_eq!(folded("a\u{85}\u{85}b").as_deref(), Some("a\nb"));
    assert_eq!(folded("a\u{85} \u{2028}b").as_deref(), Some("a\u{2028}b"));
    assert_eq!(folded("a\u{2028}b").as_deref(), Some("a\u{2028}b"));
    assert_eq!(folded("a\u{2029}\u{85}b").as_deref(), Some("a\u{2029}\nb"));
    assert_eq!(folded("trailing  ").as_deref(), Some("trailing  "));
    assert_eq!(folded("in  side").as_deref(), Some("in  side"));
    assert_eq!(folded("é\n\"\\").as_deref(), Some("é\n\"\\"));
}

#[test]
fn a_document_marker_after_a_raw_break_is_refused() {
    assert_eq!(folded("a\u{85}--- b"), None);
    assert_eq!(folded("a\u{2028}...\u{85}b"), None);
    assert_eq!(folded("a\u{85}  ... b").as_deref(), Some("a ... b"));
    assert_eq!(folded("a\u{85}---").as_deref(), Some("a ---"));
    assert_eq!(folded("a\u{85}----").as_deref(), Some("a ----"));
}

#[test]
fn keys_the_loader_refuses_are_refused() {
    assert_eq!(simple_key("name").as_deref(), Some("name"));
    assert_eq!(simple_key("<<"), None);
    assert_eq!(simple_key("a\u{85}b"), None);
    assert_eq!(simple_key("a\u{2029}"), None);
    assert!(simple_key(&"k".repeat(1_022)).is_some());
    assert_eq!(simple_key(&"k".repeat(1_023)), None);
    // An escaped quote takes two characters of the key's span.
    assert_eq!(simple_key(&format!("{}\"", "k".repeat(1_021))), None);
    assert_eq!(simple_key(&format!("{}\u{1}", "k".repeat(1_017))), None);
}

#[test]
fn scalars_and_integers_past_the_loader_limits_are_refused() {
    let mut tokens = 0;
    assert!(loaded(&json!("x".repeat(4_096)), 0, &mut tokens).is_some());
    assert!(loaded(&json!("x".repeat(4_097)), 0, &mut tokens).is_none());
    assert!(loaded(&json!(9_999_999_999_999_999_i64), 0, &mut tokens).is_some());
    assert!(loaded(&json!(-9_999_999_999_999_999_i64), 0, &mut tokens).is_some());
    assert!(loaded(&json!(10_000_000_000_000_000_i64), 0, &mut tokens).is_none());
}

#[test]
fn nesting_past_the_loader_depth_is_refused() {
    let nest = |levels: usize| (0..levels).fold(json!(1), |inner, _| json!([inner]));
    let mut tokens = 0;
    assert!(loaded(&nest(33), 0, &mut tokens).is_some());
    assert!(loaded(&nest(34), 0, &mut tokens).is_none());
}

#[test]
fn tokens_count_the_flow_scanner_output() {
    let mut tokens = 0;
    loaded(&json!({"a": [1, 2], "b": {}}), 0, &mut tokens).unwrap();
    // Mapping 2 + 1 entry separator; each key 3; list 2 + 1 + 2 items; empty map 2.
    assert_eq!(tokens, 3 + 3 + 5 + 3 + 2);
}

#[test]
fn only_the_loader_printable_set_passes() {
    assert!("a\t\n\r\u{85}\u{a0}\u{e000}\u{1f600}"
        .chars()
        .all(printable));
    for ch in ['\u{7f}', '\u{84}', '\u{fffe}', '\u{1}'] {
        assert!(!printable(ch), "{ch:?}");
    }
}

#[test]
fn the_bounds_claim_frames_text_as_utf32() {
    assert_eq!(
        claim(&json!({"k": ["é", 1, null]})),
        json!([
            "mapping",
            [[
                ["text", "awAAAA=="],
                [
                    "list",
                    [["text", "6QAAAA=="], ["scalar", null], ["scalar", null]]
                ]
            ]]
        ])
    );
}

#[test]
fn the_ordered_mapping_framing_decodes_and_refuses_duplicates() {
    let framed = json!({"object": [["a", {"array": [1, "x", null]}], ["b", true]]});
    assert_eq!(
        ordered(&framed),
        Some(json!({"a": [1, "x", null], "b": true}))
    );
    assert_eq!(ordered(&json!({"object": [["a", 1], ["a", 2]]})), None);
    assert_eq!(ordered(&json!({"other": []})), None);
    assert_eq!(ordered(&json!(1.5)), None);
}

#[test]
fn a_payload_outside_the_json_subset_has_no_hash() {
    assert_eq!(payload_hash(&json!([])), None);
    assert_eq!(payload_hash(&json!({"revision": 1.5})), None);
    let deep = (0..41).fold(json!(1), |inner, _| json!([inner]));
    assert_eq!(payload_hash(&json!({ "deep": deep })), None);
    assert_eq!(payload_hash(&json!({"name": "a\u{85}--- b"})), None);
}
