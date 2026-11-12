//! Regression cases for pack limits found in review.

use super::{code, edit_action, slack, value, GITHUB, SLACK};
use crate::cloud_pack::{pack_from_value, Template, TemplateField};
use crate::cloud_pack_cli::answer;
use crate::cloud_pack_diff::diff;
use crate::cloud_pack_request::{render_body, MAX_BODY_BYTES};
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

#[test]
fn a_closing_bracket_cannot_carry_the_body_past_its_limit() {
    let template = Template::Object(vec![TemplateField {
        name: "t".into(),
        value: Template::Arg("t".into()),
    }]);
    // `{"t":` is five bytes and the quoted string two more, so the last value
    // ends exactly at the limit and only the closing brace goes past it.
    let body = |length: usize| {
        let mut args = serde_json::Map::new();
        args.insert("t".into(), json!("x".repeat(length)));
        render_body(&template, &args)
    };
    assert_eq!(
        body(MAX_BODY_BYTES - 8).map(|out| out.len()),
        Ok(MAX_BODY_BYTES)
    );
    assert!(body(MAX_BODY_BYTES - 7).is_err());
}

#[test]
fn an_error_fixture_cannot_also_expect_decisions() {
    let pack = edit_action("slack.chat.post_message", |action| {
        action["fixtures"][1]["expect"]["decisions"] = json!({"balanced": "allow"});
    });
    assert_eq!(code(pack), "cloud_pack_fixtures_invalid");
}

#[test]
fn a_bodiless_success_projects_only_where_the_pack_accepts_it() {
    let pack = pack_from_value(value(GITHUB)).unwrap();
    let project = crate::cloud_pack_response::project;
    // GitHub answers a branch delete and a workflow dispatch with 204 and no body.
    for id in [
        "github.git.delete_branch",
        "github.repos.delete",
        "github.releases.delete",
        "github.actions.dispatch_workflow",
        "github.actions.set_secret",
    ] {
        let action = pack.action(id).unwrap();
        for body in [&b""[..], b"\n"] {
            let projection = project(action, body).unwrap();
            assert_eq!(projection.data, json!({"message": false}), "{id}");
        }
    }
    // A read that comes back empty is still an error, not an empty result.
    let list = pack.action("github.issues.list").unwrap();
    assert_eq!(project(list, b"").unwrap_err(), "response_json_invalid");
}

#[test]
fn turning_on_empty_success_is_widening() {
    let old = slack();
    let accepts = edit_action("slack.chat.delete", |action| {
        action["response"]["emptyOk"] = json!(true);
    });
    let report = diff(&old, &pack_from_value(accepts).unwrap()).unwrap();
    assert!(report.widening);
    assert!(report
        .changes
        .iter()
        .any(|change| change.code == "response_empty_accepted" && change.widening));
}

#[test]
fn a_created_issue_or_pull_request_echoing_its_longest_body_fits() {
    let pack = pack_from_value(value(GITHUB)).unwrap();
    // GitHub returns the whole body; every character may need a six-byte escape.
    let body = "\u{1}".repeat(65_536);
    let created = json!({"number": 7, "state": "open", "title": "t",
        "html_url": "https://github.com/o/r/issues/7", "body": body,
        "user": {"login": "o"}, "padding": "x".repeat(16_384)});
    let bytes = created.to_string();
    assert!(bytes.len() > 6 * 65_536);
    for id in [
        "github.issues.create",
        "github.issues.update",
        "github.pulls.create",
    ] {
        let action = pack.action(id).unwrap();
        assert!(
            crate::cloud_pack_response::project(action, bytes.as_bytes()).is_ok(),
            "{id}"
        );
    }
}
