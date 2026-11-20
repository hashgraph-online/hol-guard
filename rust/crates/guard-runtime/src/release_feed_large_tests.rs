//! Large releases. A stable release that batches a long series of merges
//! publishes far more changes, contributors and notes than a point release,
//! and the archive has to keep showing it rather than refuse the whole page.

use super::release_feed_op_tests::{detail_document, outcome, projected, request, run};
use super::*;

fn change(index: usize) -> Value {
    json!({
        "id": format!("change-{index}"),
        "kind": "fixed",
        "summary": format!("Keep the dashboard responsive while scanning connector {index} and report why a scan stopped."),
        "evidenceUrl": format!("https://github.com/hashgraph-online/hol-guard/pull/{}", 5_000 + index),
    })
}

fn contributor(index: usize) -> Value {
    json!({
        "creditId": format!("33333333-3333-4333-8333-{index:012}"),
        "githubNumericId": 10_000 + index,
        "login": format!("contributor-{index}"),
        "type": "human",
        "roles": ["author", "reviewer"],
        "verificationMethod": "pull-request-author",
        "evidenceUrl": format!("https://github.com/hashgraph-online/hol-guard/pull/{}", 5_000 + index),
    })
}

/// Shaped like the largest published stable release: 980 changes, 978
/// contributors, notes past 36,000 characters and a body near 490 KB.
fn large_release(changes: usize, roster: usize, notes_chars: usize) -> Value {
    let mut document = detail_document();
    document["changes"] = Value::Array((0..changes).map(change).collect());
    document["roster"] = Value::Array((0..roster).map(contributor).collect());
    let line = "- Name why a connector scan failed and keep the rest of the report.\n";
    let text: String = line.chars().cycle().take(notes_chars).collect();
    document["sourceNotes"] = json!({"scope": "exact_release", "text": text});
    document
}

#[test]
fn renders_the_largest_published_stable_release() {
    let document = large_release(980, 978, 36_430);
    let body_len = serde_json::to_string(&document).unwrap().len();
    assert!(
        body_len > 262_144,
        "fixture must exceed the old body cap: {body_len}"
    );

    let frame = run(request("detail", &document));
    assert_eq!(outcome(&frame), ("ok", None));
    let body = projected(&frame);
    assert_eq!(body["changes"].as_array().unwrap().len(), 980);
    assert_eq!(body["changesTotal"], json!(980));
    assert_eq!(body["roster"].as_array().unwrap().len(), 978);
    assert_eq!(body["rosterTotal"], json!(978));
    assert_eq!(
        body["sourceNotes"]["text"]
            .as_str()
            .unwrap()
            .chars()
            .count(),
        36_430
    );
}

#[test]
fn trims_a_longer_list_and_reports_the_full_count() {
    let frame = run(request("detail", &large_release(1_250, 1_100, 100)));
    assert_eq!(outcome(&frame), ("ok", None));
    let body = projected(&frame);
    assert_eq!(body["changes"].as_array().unwrap().len(), MAX_CHANGES);
    assert_eq!(body["changesTotal"], json!(1_250));
    assert_eq!(body["roster"].as_array().unwrap().len(), MAX_ROSTER);
    assert_eq!(body["rosterTotal"], json!(1_100));
}

#[test]
fn leaves_out_notes_too_long_to_render_and_keeps_the_release() {
    let frame = run(request(
        "detail",
        &large_release(3, 2, MAX_SOURCE_NOTES_CHARS + 1),
    ));
    assert_eq!(outcome(&frame), ("ok", None));
    let body = projected(&frame);
    assert_eq!(body["sourceNotes"], Value::Null);
    assert_eq!(body["changesTotal"], json!(3));
}

#[test]
fn a_small_release_reports_its_own_totals() {
    let body = projected(&run(request("detail", &detail_document())));
    assert_eq!(body["changesTotal"], json!(1));
    assert_eq!(body["rosterTotal"], json!(1));
}

#[test]
fn still_refuses_a_body_past_the_upstream_cap() {
    let mut oversized = request("detail", &detail_document());
    oversized.body = format!("{{\"pad\":\"{}\"}}", "a".repeat(MAX_BODY_BYTES));
    assert_eq!(
        outcome(&run(oversized)),
        ("error", Some("release_feed_request_invalid"))
    );
}

#[test]
fn a_trimmed_entry_past_the_cap_is_never_validated() {
    // An entry the page will not show cannot fail the release it belongs to.
    let mut document = large_release(MAX_CHANGES, 1, 10);
    document["changes"]
        .as_array_mut()
        .unwrap()
        .push(json!({"id": "", "kind": "unknown", "summary": ""}));
    assert_eq!(outcome(&run(request("detail", &document))), ("ok", None));
}
