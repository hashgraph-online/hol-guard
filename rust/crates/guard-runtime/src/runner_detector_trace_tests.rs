use chrono::TimeZone;
use serde_json::json;

use super::*;
use crate::runner_authority_op::dispatch;

fn stamp() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 22, 6, 30, 5)
        .single()
        .expect("valid time")
}

fn action() -> Value {
    json!({
        "tool": "Bash",
        "prompt_excerpt": "keep this out",
        "raw_payload_redacted": {"Prompt": "also out", "items": [{"systemPrompt": "out"}, {"cwd": "w"}]},
    })
}

fn args(guard_home: &Path) -> Value {
    json!({
        "guard_home": guard_home.to_str().expect("utf-8 path"),
        "action": action(),
        "signals": [{"signal_id": "s1"}],
        "telemetry": [{"detector_id": "d1", "status": "ok"}],
    })
}

fn trace_files(guard_home: &Path) -> Vec<PathBuf> {
    let directory = guard_home.join("debug").join("detectors");
    let mut files: Vec<PathBuf> = fs::read_dir(directory)
        .expect("trace directory")
        .map(|entry| entry.expect("entry").path())
        .collect();
    files.sort();
    files
}

#[test]
fn every_prompt_field_is_redacted_at_any_depth() {
    let redacted = redacted(&action());
    assert_eq!(redacted["prompt_excerpt"], "[redacted]");
    assert_eq!(redacted["raw_payload_redacted"]["Prompt"], "[redacted]");
    assert_eq!(
        redacted["raw_payload_redacted"]["items"][0]["systemPrompt"],
        "[redacted]"
    );
    assert_eq!(redacted["raw_payload_redacted"]["items"][1]["cwd"], "w");
    assert_eq!(redacted["tool"], "Bash");
}

#[test]
fn the_payload_carries_the_schema_time_signals_and_telemetry() {
    let payload = trace_payload(stamp(), &action(), &json!([1]), &json!([2]));
    assert_eq!(payload["schema_version"], 1);
    assert_eq!(payload["created_at"], "2026-11-22T06:30:05.000000+00:00");
    assert_eq!(payload["signals"], json!([1]));
    assert_eq!(payload["telemetry"], json!([2]));
    let keys: Vec<&String> = payload.as_object().expect("object").keys().collect();
    let mut sorted_keys = keys.clone();
    sorted_keys.sort();
    assert_eq!(keys, sorted_keys);
}

#[test]
fn the_file_name_is_the_stamp_and_a_stable_action_digest() {
    let name = trace_file_name(stamp(), &action()).expect("name");
    assert!(name.starts_with("20261122T063005000000Z-"), "{name}");
    assert!(name.ends_with(".json"));
    let digest = &name["20261122T063005000000Z-".len()..name.len() - ".json".len()];
    assert_eq!(digest.len(), 12);
    assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));
    let reordered = json!({
        "raw_payload_redacted": {"items": [{"systemPrompt": "out"}, {"cwd": "w"}], "Prompt": "also out"},
        "prompt_excerpt": "keep this out",
        "tool": "Bash",
    });
    assert_eq!(trace_file_name(stamp(), &reordered).expect("name"), name);
}

#[test]
fn the_kind_writes_one_redacted_trace() {
    let home = tempfile::tempdir().expect("tempdir");
    let guard_home = home.path().join("guard-home");
    let answer = dispatch("detector_debug_trace", &args(&guard_home)).expect("answer");
    assert_eq!(answer, json!({"trace_error": null}));
    let files = trace_files(&guard_home);
    assert_eq!(files.len(), 1);
    let text = fs::read_to_string(&files[0]).expect("trace text");
    assert!(!text.contains("keep this out"));
    assert!(!text.contains("also out"));
    assert!(text.ends_with('\n'));
    let trace: Value = serde_json::from_str(&text).expect("trace json");
    assert_eq!(trace["action"]["prompt_excerpt"], "[redacted]");
    assert_eq!(trace["signals"], json!([{"signal_id": "s1"}]));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(&files[0])
            .expect("metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[test]
fn a_debug_entry_that_is_a_file_is_reported_not_raised() {
    let home = tempfile::tempdir().expect("tempdir");
    fs::write(home.path().join("debug"), "not a directory").expect("write");
    let answer = dispatch("detector_debug_trace", &args(home.path())).expect("answer");
    assert_eq!(answer["trace_error"]["error_type"], "FileExistsError");
    assert!(answer["trace_error"]["message"].is_string());
}

#[test]
fn a_detectors_entry_that_is_a_file_is_reported_not_raised() {
    let home = tempfile::tempdir().expect("tempdir");
    fs::create_dir(home.path().join("debug")).expect("debug dir");
    fs::write(home.path().join("debug").join("detectors"), "x").expect("write");
    let answer = dispatch("detector_debug_trace", &args(home.path())).expect("answer");
    assert_eq!(answer["trace_error"]["error_type"], "FileExistsError");
}

#[test]
fn malformed_arguments_are_refused() {
    let home = tempfile::tempdir().expect("tempdir");
    let good = args(home.path());
    let mut cases = vec![json!(null), json!([]), json!({})];
    for (key, value) in [
        ("guard_home", json!("relative/home")),
        ("guard_home", json!(7)),
        ("action", json!([])),
        ("action", json!("text")),
        ("signals", json!({})),
        ("telemetry", json!(null)),
    ] {
        let mut case = good.clone();
        case[key] = value;
        cases.push(case);
    }
    for key in ["guard_home", "action", "signals", "telemetry"] {
        let mut case = good.clone();
        case.as_object_mut().expect("object").remove(key);
        cases.push(case);
    }
    for case in cases {
        assert_eq!(
            dispatch("detector_debug_trace", &case),
            Err(ERR_INVALID),
            "{case}"
        );
    }
    assert!(!home.path().join("debug").exists());
}

#[test]
fn io_failures_carry_python_error_names() {
    let not_found = io::Error::from(io::ErrorKind::NotFound);
    assert_eq!(io_failure(&not_found)["error_type"], "FileNotFoundError");
    let denied = io::Error::from(io::ErrorKind::PermissionDenied);
    assert_eq!(io_failure(&denied)["error_type"], "PermissionError");
    let other = io::Error::other("boom");
    assert_eq!(io_failure(&other)["error_type"], "OSError");
    assert_eq!(io_failure(&other)["message"], "boom");
}
