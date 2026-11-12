//! Regression cases for pack limits found in review.

use super::{code, edit_action, slack, value, GITHUB, SLACK};
use crate::cloud_pack::pack_from_value;
use crate::cloud_pack_cli::answer;
use crate::cloud_pack_diff::diff;
use serde_json::json;

#[test]
fn the_rendered_content_type_cannot_be_declared_twice() {
    let pack = edit_action("slack.conversations.list", |action| {
        action["executor"]["request"]["headers"] =
            json!([{"name": "content-type", "value": "text/plain"}]);
    });
    assert_eq!(code(pack), "cloud_pack_request_header_invalid");
}

#[test]
fn a_string_default_obeys_its_argument_rule() {
    for default in ["!!!", " "] {
        let pack = edit_action("slack.conversations.history", |action| {
            action["executor"]["request"]["query"][2]["value"]["arg"]["default"] = json!(default);
        });
        assert_eq!(code(pack), "cloud_pack_request_query_invalid");
    }
    let fits = edit_action("slack.conversations.history", |action| {
        action["executor"]["request"]["query"][2]["value"]["arg"]["default"] = json!("abc123");
    });
    assert!(pack_from_value(fits).is_ok());
}

#[test]
fn integer_bounds_at_the_extremes_are_refused_without_overflow() {
    for (minimum, maximum) in [(i64::MIN, 1), (1, i64::MAX), (i64::MIN, i64::MAX)] {
        let pack = edit_action("slack.conversations.history", |action| {
            action["arguments"]["limit"]["minimum"] = json!(minimum);
            action["arguments"]["limit"]["maximum"] = json!(maximum);
        });
        assert!(pack_from_value(pack).is_err());
    }
}

#[test]
fn any_class_change_is_widening() {
    let old = slack();
    let draft = edit_action("slack.chat.post_message", |action| {
        action["facts"]["class"] = json!("draft");
    });
    let report = diff(&old, &pack_from_value(draft).unwrap()).unwrap();
    assert!(report.widening);
    assert!(report
        .changes
        .iter()
        .any(|change| change.code == "class_changed" && change.widening));
}

#[test]
fn parsed_packs_and_artifacts_keep_the_size_limit() {
    let mut big = value(SLACK);
    big["padding"] = json!("x".repeat(1024 * 1024));
    assert_eq!(code(big.clone()), "cloud_pack_too_large");
    let line = |request: serde_json::Value| answer(request.to_string().as_bytes());
    let refused = line(json!({"op": "validate", "pack": big}));
    assert_eq!(refused["error"]["code"], json!("cloud_pack_too_large"));
    let mut artifact = line(json!({"op": "compile", "pack": value(SLACK)}))["artifact"].clone();
    artifact["padding"] = json!("x".repeat(1024 * 1024));
    let refused = line(
        json!({"op": "render", "artifact": artifact, "actionId": "slack.chat.post_message", "arguments": {}}),
    );
    assert_eq!(refused["error"]["code"], json!("cloud_pack_too_large"));
}

#[test]
fn github_issue_lists_keep_up_to_a_hundred_labels() {
    let pack = pack_from_value(value(GITHUB)).unwrap();
    let action = pack.action("github.issues.list").unwrap();
    let labels: Vec<_> = (0..100).map(|n| json!({"name": format!("l{n}")})).collect();
    let issue = json!([{"number": 1, "title": "t", "state": "open", "user": {"login": "o"},
        "updated_at": "2026-11-01T00:00:00Z", "html_url": "https://github.com/o/r/issues/1",
        "labels": labels}]);
    assert!(crate::cloud_pack_response::project(action, issue.to_string().as_bytes()).is_ok());
}
