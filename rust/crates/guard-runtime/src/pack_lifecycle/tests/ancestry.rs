//! A remote publication from another source is accepted only as a strict
//! descendant of the source the floor already holds.
use super::super::*;
use super::{floor, installed};

const REQUIRED: &str = "pack_lifecycle_source_ancestry_required";

fn candidate() -> Identity {
    let mut next = installed();
    next.profile = "remote".into();
    next.version = "100.7".into();
    next.source = "b".repeat(40);
    next
}

fn evidence() -> Value {
    json!({
        "status": "ahead",
        "base_commit": {"sha": "a".repeat(40)},
        "merge_base_commit": {"sha": "a".repeat(40)},
        "url": compare_url(&"a".repeat(40), &"b".repeat(40)),
        "ahead_by": 2,
        "behind_by": 0,
    })
}

fn changed(field: &str, value: Value) -> Value {
    let mut evidence = evidence();
    evidence[field] = value;
    evidence
}

#[test]
fn a_strict_descendant_source_moves_the_floor_forward() {
    let next = transition(&floor(), &candidate(), &evidence()).unwrap();
    assert_eq!(next.source, "b".repeat(40));
    assert_eq!(next.remote, Some(candidate()));
    assert_eq!(next.installed, floor().installed);
}

#[test]
fn regression_the_compare_response_github_actually_returns_is_accepted() {
    // The shape of `GET /repos/{repo}/compare/{base}...{head}?per_page=1&page=2`:
    // no `head_commit` member, the range echoed in `url`, one commit per page
    // and no `files` past the first page.
    let response = json!({
        "url": compare_url(&"a".repeat(40), &"b".repeat(40)),
        "html_url": format!(
            "https://github.com/hashgraph-online/hol-guard/compare/{}...{}",
            "a".repeat(40),
            "b".repeat(40)
        ),
        "permalink_url": "https://github.com/hashgraph-online/hol-guard/compare/hashgraph-online:aaaaaaa...hashgraph-online:bbbbbbb",
        "diff_url": "https://github.com/hashgraph-online/hol-guard/compare/a...b.diff",
        "patch_url": "https://github.com/hashgraph-online/hol-guard/compare/a...b.patch",
        "base_commit": {"sha": "a".repeat(40), "commit": {"message": "base"}},
        "merge_base_commit": {"sha": "a".repeat(40), "commit": {"message": "base"}},
        "status": "ahead",
        "ahead_by": 49,
        "behind_by": 0,
        "total_commits": 49,
        "commits": [{"sha": "6".repeat(40)}],
    });
    let next = transition(&floor(), &candidate(), &response).unwrap();
    assert_eq!(next.source, "b".repeat(40));
}

#[test]
fn the_same_source_needs_no_ancestry() {
    let mut same = candidate();
    same.source = floor().source;
    for ancestry in [Value::Null, json!({}), json!([])] {
        let next = transition(&floor(), &same, &ancestry).unwrap();
        assert_eq!(next.source, floor().source);
    }
}

#[test]
fn an_installed_release_never_asks_for_ancestry() {
    let mut other = installed();
    other.version = "3.16.4".into();
    other.source = "b".repeat(40);
    other.engine = "4".repeat(64);
    let next = transition(&floor(), &other, &Value::Null).unwrap();
    assert_eq!(next.source, floor().source);
}

#[test]
fn regression_divergence_or_malformed_evidence_is_refused() {
    let wrong = "3".repeat(40);
    let cases = [
        ("status", json!("behind")),
        ("status", json!("diverged")),
        ("status", json!("identical")),
        ("status", Value::Null),
        ("base_commit", Value::Null),
        ("base_commit", json!({"sha": wrong})),
        ("base_commit", json!("a".repeat(40))),
        ("merge_base_commit", json!([])),
        ("merge_base_commit", json!({"sha": wrong})),
        ("merge_base_commit", Value::Null),
        ("url", json!(compare_url(&"a".repeat(40), &wrong))),
        ("url", json!(compare_url(&wrong, &"b".repeat(40)))),
        (
            "url",
            json!(format!(
                "{}?per_page=1",
                compare_url(&"a".repeat(40), &"b".repeat(40))
            )),
        ),
        ("url", Value::Null),
        ("behind_by", json!(true)),
        ("behind_by", json!(1)),
        ("behind_by", json!("0")),
        ("behind_by", json!(0.5)),
        ("behind_by", Value::Null),
        ("ahead_by", json!(0)),
        ("ahead_by", json!(-1)),
        ("ahead_by", json!(true)),
        ("ahead_by", json!("2")),
        ("ahead_by", Value::Null),
    ];
    for (field, value) in cases {
        let ancestry = changed(field, value.clone());
        let outcome = transition(&floor(), &candidate(), &ancestry);
        assert_eq!(outcome.unwrap_err(), REQUIRED, "{field} {value}");
    }
    for ancestry in [Value::Null, json!({}), json!([]), json!("ahead")] {
        let outcome = transition(&floor(), &candidate(), &ancestry);
        assert_eq!(outcome.unwrap_err(), REQUIRED, "{ancestry}");
    }
}

#[test]
fn evidence_for_another_pair_of_sources_is_refused() {
    let mut other = floor();
    other.source = "c".repeat(40);
    let outcome = transition(&other, &candidate(), &evidence());
    assert_eq!(outcome.unwrap_err(), REQUIRED);
}
