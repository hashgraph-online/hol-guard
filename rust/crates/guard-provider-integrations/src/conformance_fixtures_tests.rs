use guard_contracts::{ProviderCapabilityV1 as Cap, ProviderVerdictV1 as V};
use serde_json::json;

use super::*;
use crate::parse::{parse_strict, MAX_BODY_BYTES};

fn file(recordings: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"schema": RECORDINGS_SCHEMA, "recordings": recordings})).unwrap()
}

fn entry(name: &str) -> serde_json::Value {
    json!({
        "name": name,
        "capability": "browser.origin-reputation",
        "status": 200,
        "body": "{}",
        "expect": {"verdict": "unknown"}
    })
}

#[test]
fn signals_and_failures_are_read() {
    let bytes = file(json!([
        {"name": "flagged", "capability": "browser.script-integrity", "status": 200,
         "body": "{\"v\":\"bad\"}", "expect": {"verdict": "danger", "reasonCodes": ["skimmer"]}},
        {"name": "limited", "capability": "browser.origin-reputation", "status": 429,
         "body": "", "expect": {"failure": "rate_limited"}}
    ]));
    let recordings = parse_recordings(&bytes).unwrap();
    assert_eq!(recordings[0].capability, Cap::ScriptIntegrity);
    assert_eq!(
        recordings[0].expect,
        RecordedExpectation::Signal {
            verdict: V::Danger,
            reason_codes: vec!["skimmer".to_owned()]
        }
    );
    assert_eq!(
        recordings[1].borrow().expect,
        RecordedExpectation::Failure(RecordedFailure::RateLimited)
    );
}

#[test]
fn a_recordings_file_may_exceed_one_body_limit_up_to_its_own_cap() {
    let wide = |name: &str, bytes: usize| {
        let mut wide = entry(name);
        wide["body"] = json!(format!("{{\"pad\":\"{}\"}}", "a".repeat(bytes)));
        wide
    };
    let fits = file(json!([wide("one", 600_000), wide("two", 600_000)]));
    assert!(fits.len() > MAX_BODY_BYTES && fits.len() <= MAX_RECORDINGS_FILE_BYTES);
    assert_eq!(parse_recordings(&fits).unwrap().len(), 2);

    let over: Vec<serde_json::Value> = (0..5)
        .map(|index| wide(&format!("r{index}"), 900_000))
        .collect();
    let over = file(json!(over));
    assert!(over.len() > MAX_RECORDINGS_FILE_BYTES);
    assert_eq!(parse_recordings(&over).err(), Some(FixtureError::Invalid));

    let duplicate = format!(
        "{{\"schema\":\"{RECORDINGS_SCHEMA}\",\"schema\":\"{RECORDINGS_SCHEMA}\",\"recordings\":[]}}"
    );
    assert_eq!(
        parse_recordings(duplicate.as_bytes()).err(),
        Some(FixtureError::Invalid)
    );
}

#[test]
fn padding_appends_spaces_and_keeps_the_body_json() {
    let mut padded = entry("big");
    padded["padToBytes"] = json!(4096);
    let recordings = parse_recordings(&file(json!([padded]))).unwrap();
    assert_eq!(recordings[0].body.len(), 4096);
    assert!(parse_strict(&recordings[0].body).is_some());

    let mut over = entry("huge");
    over["padToBytes"] = json!(MAX_PAD_BYTES + 1);
    assert_eq!(
        parse_recordings(&file(json!([over]))).err(),
        Some(FixtureError::Pad(0))
    );
}

#[test]
fn malformed_files_are_refused() {
    let mut extra = entry("extra");
    extra["comment"] = json!("not a field");
    let mut both = entry("both");
    both["expect"] = json!({"verdict": "ok", "failure": "status"});
    let mut unknown_failure = entry("timeout");
    unknown_failure["expect"] = json!({"failure": "timeout"});
    let mut allow = entry("allow");
    allow["expect"] = json!({"verdict": "allow"});
    for (bytes, expected) in [
        (b"{".to_vec(), FixtureError::Invalid),
        (
            br#"{"schema":"guard.provider-recordings.v1","schema":"x","recordings":[]}"#.to_vec(),
            FixtureError::Invalid,
        ),
        (
            serde_json::to_vec(&json!({"schema": "other", "recordings": []})).unwrap(),
            FixtureError::Schema,
        ),
        (file(json!([extra])), FixtureError::Invalid),
        (file(json!([both])), FixtureError::Invalid),
        (file(json!([unknown_failure])), FixtureError::Invalid),
        (file(json!([allow])), FixtureError::Invalid),
        (file(json!([entry("a"), entry("a")])), FixtureError::Name(1)),
        (file(json!([entry("Upper")])), FixtureError::Name(0)),
        (file(json!([entry("")])), FixtureError::Name(0)),
        (
            file(json!((0..=MAX_RECORDINGS)
                .map(|index| entry(&format!("r{index}")))
                .collect::<Vec<_>>())),
            FixtureError::TooMany,
        ),
    ] {
        assert_eq!(
            parse_recordings(&bytes).err(),
            Some(expected.clone()),
            "{expected:?}"
        );
    }
}

#[test]
fn the_corpus_is_the_browser_rows_of_the_gate() {
    let gate = serde_json::to_vec(&json!({
        "cases": [{"id": "browser-shell", "expect": "allow"}],
        "mcp_cases": [
            {"id": "browser-a", "expect": "allow"},
            {"id": "browser-b", "expect": "block"},
            {"id": "browser-c", "expect": "review"},
            {"id": "browser-setup", "expect": "setup"},
            {"id": "github-read", "expect": "allow"}
        ]
    }))
    .unwrap();
    assert_eq!(
        browser_corpus(&gate),
        Some(vec![
            BaselineDecision::Allow,
            BaselineDecision::Block,
            BaselineDecision::Review
        ])
    );
    let unknown =
        serde_json::to_vec(&json!({"mcp_cases": [{"id": "browser-a", "expect": "quiet"}]}))
            .unwrap();
    assert_eq!(browser_corpus(&unknown), None);
    assert_eq!(browser_corpus(b"[]"), None);
}
