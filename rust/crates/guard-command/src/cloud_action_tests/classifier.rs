//! The unclassified-action classifier against a corpus of real tool names.

use crate::cloud_action_classifier::{classify, tokens};
use guard_contracts::ActionClassV2;
use serde_json::{json, Value};

const CORPUS: &str = include_str!("../../../../../contracts/cloud-actions/classifier-corpus.json");

const DESTRUCTIVE_VERBS: &[&str] = &[
    "delete",
    "remove",
    "drop",
    "purge",
    "truncate",
    "destroy",
    "erase",
    "wipe",
    "revoke",
    "refund",
    "payout",
    "withdraw",
    "terminate",
];

fn class_name(class: ActionClassV2) -> String {
    serde_json::to_value(class)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn the_corpus_classifies_as_a_reviewer_expects() {
    let corpus: Value = serde_json::from_str(CORPUS).unwrap();
    let cases = corpus["cases"].as_array().unwrap();
    assert!(cases.len() >= 200, "{}", cases.len());
    let mut failures = Vec::new();
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let proposal = classify(name, None);
        let got = class_name(proposal.class);
        if got != case["expect"] {
            failures.push(format!(
                "{name}: want {}, got {got} {:?}",
                case["expect"], proposal.evidence
            ));
        }
        assert!(
            !matches!(proposal.class, ActionClassV2::Read | ActionClassV2::Draft),
            "{name}"
        );
        let words = tokens(name);
        if DESTRUCTIVE_VERBS
            .iter()
            .any(|verb| words.iter().any(|w| w == verb))
        {
            assert!(proposal.destructive, "{name} -> {got}");
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {}:\n{}",
        failures.len(),
        cases.len(),
        failures.join("\n")
    );
}

#[test]
fn names_split_on_case_and_separators() {
    assert_eq!(tokens("chat_postMessage"), ["chat", "post", "message"]);
    assert_eq!(
        tokens("API-delete-a-block"),
        ["api", "delete", "a", "block"]
    );
    assert_eq!(
        tokens("HTTPRequest.v2/send"),
        ["http", "request", "v", "send"]
    );
    assert_eq!(tokens("ééé"), Vec::<String>::new());
    assert!(tokens(&"a_".repeat(400)).len() <= 128);
}

#[test]
fn a_destructive_word_late_in_the_name_still_counts() {
    let name = format!("{}delete_repository", "a_".repeat(32));
    let proposal = classify(&name, None);
    assert_eq!(proposal.class, ActionClassV2::Delete);
    assert!(proposal.destructive);
}

#[test]
fn a_name_past_the_limit_takes_the_strictest_class() {
    let proposal = classify(&format!("{}_list", "a".repeat(300)), None);
    assert_eq!(proposal.class, ActionClassV2::Admin);
    assert!(proposal.destructive);
    assert_eq!(proposal.evidence, ["name_too_long"]);
}

#[test]
fn a_read_name_is_still_a_write() {
    for name in ["list_files", "get_page", "readOnlyThing", "", "search"] {
        let proposal = classify(name, None);
        assert_eq!(proposal.class, ActionClassV2::Update, "{name}");
        assert!(!proposal.destructive);
    }
}

#[test]
fn the_strictest_verb_wins() {
    assert_eq!(
        classify("list_and_delete_rows", None).class,
        ActionClassV2::Delete
    );
    assert_eq!(classify("send_and_refund", None).class, ActionClassV2::Pay);
    assert_eq!(classify("remove_member", None).class, ActionClassV2::Admin);
}

#[test]
fn an_amount_and_a_currency_read_as_money() {
    let schema = json!({"type": "object", "properties": {"amount_minor": {}, "Currency": {}}});
    let proposal = classify("create_widget", Some(&schema));
    assert_eq!(proposal.class, ActionClassV2::Pay);
    assert!(proposal.destructive);
    let only_amount = json!({"properties": {"amount": {}}});
    assert_eq!(
        classify("create_widget", Some(&only_amount)).class,
        ActionClassV2::Update
    );
    let annotated = json!({"properties": {}, "annotations": {"readOnlyHint": true}});
    assert_eq!(
        classify("delete_widget", Some(&annotated)).class,
        ActionClassV2::Delete
    );
}
