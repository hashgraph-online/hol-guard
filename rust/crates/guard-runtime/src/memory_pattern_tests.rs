//! Parity vectors recorded from the retired Python memory-pattern builders.

use std::io::Read;

use flate2::read::GzDecoder;
use guard_contracts::{ContextDigestKindV1, MemoryPatternVerdictV1};
use serde_json::{json, Value};

use super::{verdict, MemoryRequest};

const VECTORS: &[u8] = include_bytes!("../tests/fixtures/memory_pattern_vectors.json.gz");

fn vectors() -> Vec<Value> {
    let mut text = String::new();
    GzDecoder::new(VECTORS).read_to_string(&mut text).unwrap();
    let document: Value = serde_json::from_str(&text).unwrap();
    document["cases"].as_array().unwrap().clone()
}

#[test]
fn verdicts_match_the_retired_python() {
    let cases = vectors();
    assert_eq!(cases.len(), 146);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let mut wire = case["request"].clone();
        wire["kind"] = json!("memory_pattern");
        let ContextDigestKindV1::MemoryPattern {
            command,
            artifact_type,
            artifact_id,
            artifact_name,
            harness,
        } = serde_json::from_value(wire).unwrap_or_else(|error| panic!("{name}: {error}"))
        else {
            panic!("{name}: wrong kind");
        };
        let actual = verdict(&MemoryRequest {
            command: command.as_deref(),
            artifact_type: artifact_type.as_deref(),
            artifact_id: artifact_id.as_deref(),
            artifact_name: artifact_name.as_deref(),
            harness: harness.as_deref(),
        });
        let expected: MemoryPatternVerdictV1 =
            serde_json::from_value(case["expected"].clone()).unwrap();
        assert_eq!(actual, expected, "{name}");
    }
}

#[test]
fn mcp_server_backs_off_to_the_last_separator() {
    assert_eq!(
        super::mcp_command_match("run mcp__my_server__extra__tool_name now"),
        Some(("my_server__extra".to_owned(), "tool_name".to_owned()))
    );
    assert_eq!(super::mcp_command_match("mcp__server__"), None);
    assert_eq!(
        super::mcp_command_match("mcp__a__b"),
        Some(("a".to_owned(), "b".to_owned()))
    );
}

#[test]
fn path_family_collapses_volatile_identifiers() {
    assert_eq!(
        super::path_family("/tmp//0123456789abcdef0/ID-${HOME}/x").as_deref(),
        Some("tmp/<hash>/id-<env>")
    );
    assert_eq!(
        super::path_family("logs/run-42/x").as_deref(),
        Some("logs/run-<n>/x")
    );
    assert_eq!(
        super::path_family("logs/v42/x").as_deref(),
        Some("logs/v42/x")
    );
    assert_eq!(super::path_family("-n"), None);
}
