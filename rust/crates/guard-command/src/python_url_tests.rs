//! Parity tests for the CPython `urllib.parse` port.
//!
//! Every expectation comes from running the real `urlsplit` in
//! `scripts/ci/generate_inventory_url_parity.py`; regenerate the fixture after
//! changing either side.

use serde_json::Value;

use super::urlsplit;

const PARITY: &str = include_str!("../testdata/inventory_url_parity.json");

fn cases() -> Vec<Value> {
    let document: Value = serde_json::from_str(PARITY).expect("parity fixture parses");
    document
        .get("urlsplit")
        .and_then(Value::as_array)
        .expect("fixture section urlsplit")
        .clone()
}

fn text(case: &Value, key: &str) -> String {
    case.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("case field {key}"))
        .to_string()
}

fn flag(case: &Value, key: &str) -> bool {
    case.get(key).and_then(Value::as_bool).unwrap_or(false)
}

/// The corpus is only evidence for the release it was recorded on: `urlsplit`
/// has changed its stripping and its netloc checks between releases, so a
/// fixture regenerated elsewhere would quietly rewrite what this port is held
/// to. The generator refuses any other interpreter; this names the release on
/// the reading side as well.
#[test]
fn the_fixture_records_the_modeled_cpython_release() {
    let document: Value = serde_json::from_str(PARITY).expect("parity fixture parses");
    let version = document
        .get("python_version")
        .and_then(Value::as_str)
        .expect("fixture field python_version");
    assert!(
        version.starts_with("3.12."),
        "fixture recorded on CPython {version}, not the modeled 3.12 release",
    );
}

#[test]
fn urlsplit_matches_python() {
    for case in cases() {
        let url = text(&case, "url");
        let Ok(parsed) = urlsplit(&url) else {
            assert!(flag(&case, "error"), "urlsplit rejected {url:?}");
            continue;
        };
        assert!(!flag(&case, "error"), "urlsplit accepted {url:?}");
        assert_eq!(parsed.scheme, text(&case, "scheme"), "scheme of {url:?}");
        assert_eq!(parsed.netloc, text(&case, "netloc"), "netloc of {url:?}");
        assert_eq!(parsed.path, text(&case, "path"), "path of {url:?}");
        assert_eq!(parsed.query, text(&case, "query"), "query of {url:?}");
        assert_eq!(
            parsed.fragment,
            text(&case, "fragment"),
            "fragment of {url:?}"
        );
    }
}

#[test]
fn hostname_matches_python() {
    for case in cases() {
        let url = text(&case, "url");
        let Ok(parsed) = urlsplit(&url) else {
            continue;
        };
        let expected = case.get("hostname").and_then(Value::as_str);
        assert_eq!(
            parsed.hostname().as_deref(),
            expected,
            "hostname of {url:?}"
        );
    }
}

#[test]
fn port_matches_python() {
    for case in cases() {
        let url = text(&case, "url");
        let Ok(parsed) = urlsplit(&url) else {
            continue;
        };
        let Ok(port) = parsed.port() else {
            assert!(flag(&case, "port_error"), "port rejected for {url:?}");
            continue;
        };
        assert!(!flag(&case, "port_error"), "port accepted for {url:?}");
        let expected = case.get("port").and_then(Value::as_u64);
        assert_eq!(port.map(u64::from), expected, "port of {url:?}");
    }
}
