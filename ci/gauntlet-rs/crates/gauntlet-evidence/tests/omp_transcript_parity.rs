use gauntlet_evidence::{parse_omp_transcript, read_omp_transcript, TRANSCRIPT_LIMIT};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;

mod host_event_source_compatibility;

fn decode_hex(hex: &str) -> Vec<u8> {
    hex.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn bounded_ndjson_acceptance_matches_pinned_python() {
    let fixture: Value =
        serde_json::from_str(include_str!("python_omp_transcript_v1.json")).unwrap();
    let delta: Value =
        serde_json::from_str(include_str!("../../../integration-source-delta.v1.json")).unwrap();
    let source = delta["changed"]
        .as_array()
        .unwrap()
        .iter()
        .find(|row| row["path"] == "ci/gauntlet/evidence.py")
        .unwrap();
    let current =
        host_event_source_compatibility::verify("omp-transcript", &fixture["source_sha256"], 15);
    assert_eq!(current, source["sha256"]);
    assert_eq!(fixture["schema"], "gauntlet-omp-transcript-fixtures.v1");
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 15);
    for case in cases {
        let raw = decode_hex(case["raw_hex"].as_str().unwrap());
        match parse_omp_transcript(&raw) {
            Ok(events) => {
                assert_eq!(case["accepted"], true, "{}", case["name"]);
                assert_eq!(Value::Array(events), case["events"], "{}", case["name"]);
            }
            Err(_) => assert_eq!(case["accepted"], false, "{}", case["name"]),
        }
    }
}

#[test]
fn transcript_parser_additionally_refuses_unsafe_values_and_excess() {
    assert!(parse_omp_transcript(br#"{"type":"x","type":"y"}"#).is_err());
    assert!(parse_omp_transcript(br#"{"type":"x","value":NaN}"#).is_err());
    assert!(parse_omp_transcript(&vec![b'x'; TRANSCRIPT_LIMIT + 1]).is_err());
    assert!(parse_omp_transcript(
        &br#"{"type":"x"}
"#
        .repeat(50_001)
    )
    .is_err());
}

#[test]
fn exact_byte_file_reader_refuses_replacement_and_unsafe_paths() {
    let root = tempfile::tempdir().unwrap();
    let canonical_root = root.path().canonicalize().unwrap();
    let path = canonical_root.join("events.jsonl");
    let raw = br#"{"type":"model_turn","calls":[]}
"#;
    fs::write(&path, raw).unwrap();
    let digest = format!("{:x}", Sha256::digest(raw));
    assert_eq!(read_omp_transcript(&path, &digest).unwrap().len(), 1);
    assert!(read_omp_transcript(&path, &"0".repeat(64)).is_err());
    assert!(read_omp_transcript(&path, "invalid-pin").is_err());
    let wrong_extension = canonical_root.join("events.json");
    fs::write(&wrong_extension, raw).unwrap();
    assert!(read_omp_transcript(&wrong_extension, &digest).is_err());
    let linked = canonical_root.join("linked.jsonl");
    fs::hard_link(&path, &linked).unwrap();
    assert!(read_omp_transcript(&path, &digest).is_err());
    fs::remove_file(&linked).unwrap();
    let symlink = canonical_root.join("symlink.jsonl");
    std::os::unix::fs::symlink(&path, &symlink).unwrap();
    assert!(read_omp_transcript(&symlink, &digest).is_err());
    let alias = canonical_root.join("alias");
    std::os::unix::fs::symlink(&canonical_root, &alias).unwrap();
    assert!(read_omp_transcript(&alias.join("events.jsonl"), &digest).is_err());
    fs::write(&path, b"changed").unwrap();
    assert!(read_omp_transcript(&path, &digest).is_err());
}
