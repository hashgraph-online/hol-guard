//! Parity tests for `artifact_hash_url`.
//!
//! The fixture is generated from the `urllib.parse` that ships with this
//! repository's pinned Python 3.12, because that is the implementation the
//! artifact hash has to keep agreeing with. The module had no tests at all
//! before, which is how a clippy lint about duplicated arms came to look like
//! a bug report instead of a note about CPython's own control flow.

use crate::artifact_hash_url::{parse_qsl, urlencode, urlsplit, urlunsplit, SplitUrl};
use serde_json::Value;

const PARITY: &str = include_str!("../testdata/artifact_hash_url_parity.json");

fn cases(section: &str) -> Vec<Value> {
    let parsed: Value = serde_json::from_str(PARITY).expect("fixture parses");
    parsed[section]
        .as_array()
        .unwrap_or_else(|| panic!("fixture has a {section} section"))
        .clone()
}

fn text(case: &Value, key: &str) -> String {
    case[key]
        .as_str()
        .unwrap_or_else(|| panic!("case {case} has a string {key}"))
        .to_string()
}

fn split_from(case: &Value) -> SplitUrl {
    SplitUrl {
        scheme: text(case, "scheme"),
        netloc: text(case, "netloc"),
        path: text(case, "path"),
        query: text(case, "query"),
        fragment: text(case, "fragment"),
    }
}

#[test]
fn urlunsplit_matches_python() {
    let cases = cases("urlunsplit");
    assert!(!cases.is_empty(), "fixture covers urlunsplit");
    for case in &cases {
        let split = split_from(case);
        let query = split.query.clone();
        assert_eq!(
            urlunsplit(&split, &query),
            text(case, "expected"),
            "urlunsplit disagrees for {case}"
        );
    }
}

#[test]
fn urlunsplit_keeps_the_separate_network_relative_arm() {
    // CPython reaches a second `//` prepend for a path that already starts with
    // `//` and carries no netloc, so the result really does gain four slashes.
    // Folding that arm into the netloc-using-scheme arm would drop them, which
    // is why the two identical bodies have to stay apart.
    let split = SplitUrl {
        scheme: String::new(),
        netloc: String::new(),
        path: "//path".to_string(),
        query: String::new(),
        fragment: String::new(),
    };
    assert_eq!(urlunsplit(&split, ""), "////path");
}

#[test]
fn urlunsplit_adds_a_netloc_only_for_a_rooted_path() {
    // The third arm is guarded on an empty or rooted path, so a relative path
    // under a netloc-using scheme stays relative.
    let rooted = SplitUrl {
        scheme: "https".to_string(),
        netloc: String::new(),
        path: "/a".to_string(),
        query: String::new(),
        fragment: String::new(),
    };
    assert_eq!(urlunsplit(&rooted, ""), "https:///a");

    let relative = SplitUrl {
        path: "a".to_string(),
        ..rooted
    };
    assert_eq!(urlunsplit(&relative, ""), "https:a");
}

#[test]
fn urlsplit_round_trips_like_python() {
    let cases = cases("roundtrip");
    assert!(!cases.is_empty(), "fixture covers round trips");
    for case in &cases {
        let url = text(case, "url");
        let split = urlsplit(&url).unwrap_or_else(|| panic!("{url} splits"));
        assert_eq!(split.scheme, text(case, "scheme"), "scheme for {url}");
        assert_eq!(split.netloc, text(case, "netloc"), "netloc for {url}");
        assert_eq!(split.path, text(case, "path"), "path for {url}");
        assert_eq!(split.query, text(case, "query"), "query for {url}");
        assert_eq!(split.fragment, text(case, "fragment"), "fragment for {url}");
        let query = split.query.clone();
        assert_eq!(
            urlunsplit(&split, &query),
            text(case, "expected"),
            "round trip for {url}"
        );
    }
}

#[test]
fn parse_qsl_and_urlencode_match_python() {
    let cases = cases("query");
    assert!(!cases.is_empty(), "fixture covers queries");
    for case in &cases {
        let query = text(case, "query");
        let expected: Vec<(String, String)> = case["pairs"]
            .as_array()
            .unwrap_or_else(|| panic!("case {case} has pairs"))
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().expect("pair key is a string").to_string(),
                    pair[1]
                        .as_str()
                        .expect("pair value is a string")
                        .to_string(),
                )
            })
            .collect();
        let parsed = parse_qsl(&query);
        assert_eq!(parsed, expected, "parse_qsl disagrees for {query:?}");
        assert_eq!(
            urlencode(&parsed),
            text(case, "encoded"),
            "urlencode disagrees for {query:?}"
        );
    }
}
