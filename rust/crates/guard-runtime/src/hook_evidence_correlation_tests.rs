use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Map, Value};

use super::*;

/// The identifier and digest in these tests come from the Python
/// implementation, so a change to the framing fails here instead of silently
/// orphaning every handle written before it.
const MATERIAL: [u8; 32] = [
    1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
    27, 28, 29, 30, 31, 32,
];
const KEY_ID: &str = "correlation.v1.ae216c2ef5247a37";
const ENCODED_MATERIAL: &str = "AQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyA=";
const TOOL_USE_ID: &str = "toolu_01A9bN2c3Dq4Ef5Gh6Jk7Lm8";
const EXPECTED_DIGEST: &str = "309834093e5d5d29c68d0654ccc6eac60e5e899dcf13de5e0b492bdb2ee8906a";

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn guard_home() -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "hol-guard-correlation-{}-{suffix}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ))
}

fn payload(pairs: &[(&str, Value)]) -> Map<String, Value> {
    let mut map = Map::new();
    for (key, value) in pairs {
        let _ = map.insert((*key).to_owned(), value.clone());
    }
    map
}

fn fixed_key() -> InstallationCorrelationKey {
    InstallationCorrelationKey::new(KEY_ID, &MATERIAL).expect("key")
}

#[test]
fn a_handle_matches_the_python_framing() {
    let handle = derive_proven_request_correlation(
        "claude-code",
        "PreToolUse",
        &payload(&[("tool_use_id", json!(TOOL_USE_ID))]),
        &fixed_key(),
    )
    .expect("derived")
    .expect("handle");
    assert_eq!(handle.kind, "request");
    assert_eq!(handle.harness, "claude-code");
    assert_eq!(handle.key_id, KEY_ID);
    assert_eq!(handle.digest, EXPECTED_DIGEST);
}

#[test]
fn the_same_identifier_under_another_harness_is_another_handle() {
    let claude = derive_proven_request_correlation(
        "claude-code",
        "PreToolUse",
        &payload(&[("tool_use_id", json!(TOOL_USE_ID))]),
        &fixed_key(),
    )
    .expect("derived")
    .expect("handle");
    let zcode = derive_proven_request_correlation(
        "zcode",
        "PreToolUse",
        &payload(&[("tool_use_id", json!(TOOL_USE_ID))]),
        &fixed_key(),
    )
    .expect("derived")
    .expect("handle");
    assert_ne!(claude.digest, zcode.digest);
}

#[test]
fn an_undocumented_pair_or_a_missing_field_carries_no_handle() {
    let key = fixed_key();
    let present = payload(&[("tool_use_id", json!(TOOL_USE_ID))]);
    for (harness, event) in [
        ("claude-code", "SessionStart"),
        ("gemini", "PreToolUse"),
        ("cline", "PostToolUse"),
    ] {
        assert!(
            derive_proven_request_correlation(harness, event, &present, &key)
                .expect("derived")
                .is_none()
        );
    }
    for absent in [payload(&[]), payload(&[("tool_use_id", Value::Null)])] {
        assert!(
            derive_proven_request_correlation("claude-code", "PreToolUse", &absent, &key)
                .expect("derived")
                .is_none()
        );
    }
}

#[test]
fn a_cursor_pre_tool_payload_proves_nothing_without_its_source_hook() {
    let key = fixed_key();
    let without = payload(&[("generation_id", json!(TOOL_USE_ID))]);
    assert!(
        derive_proven_request_correlation("cursor", "PreToolUse", &without, &key)
            .expect("derived")
            .is_none()
    );
    let foreign = payload(&[
        ("generation_id", json!(TOOL_USE_ID)),
        ("cursor_source_hook_event", json!("beforeSubmitPrompt")),
    ]);
    assert!(
        derive_proven_request_correlation("cursor", "PreToolUse", &foreign, &key)
            .expect("derived")
            .is_none()
    );
    for source in ["beforeShellExecution", "beforeMCPExecution"] {
        let allowed = payload(&[
            ("generation_id", json!(TOOL_USE_ID)),
            ("cursor_source_hook_event", json!(source)),
        ]);
        assert!(
            derive_proven_request_correlation("cursor", "PreToolUse", &allowed, &key)
                .expect("derived")
                .is_some()
        );
    }
    // The post-execution events carry the id on their own.
    let after = payload(&[("generation_id", json!(TOOL_USE_ID))]);
    assert!(
        derive_proven_request_correlation("cursor", "afterShellExecution", &after, &key)
            .expect("derived")
            .is_some()
    );
}

#[test]
fn a_guessable_identifier_is_not_derived_from() {
    let key = fixed_key();
    for value in [
        json!(17),
        json!(true),
        json!({"id": "x"}),
        json!("short"),
        json!("0123456789012345678"),
        json!("request-0123456789012345"),
        json!("2026-10-17T09:30:00.123456+00:00"),
        json!("2026-10-17T09:30:00Z"),
        json!("aaaaaaaaaaaaaaaaaaaaaa"),
        json!("tool use id with spaces!!"),
    ] {
        let error = derive_proven_request_correlation(
            "claude-code",
            "PreToolUse",
            &payload(&[("tool_use_id", value.clone())]),
            &key,
        )
        .expect_err("refused");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{value}");
    }
}

#[test]
fn an_unsupported_harness_is_refused() {
    // The table is keyed by harness, so this can only be reached by an event
    // name that a supported harness shares; the identifier check still runs.
    assert!(frame_identifier("claude", "request", TOOL_USE_ID, KEY_ID).is_err());
    assert!(frame_identifier("claude-code", "request", TOOL_USE_ID, KEY_ID).is_ok());
}

#[test]
fn one_key_is_created_once_and_read_back() {
    let home = guard_home();
    let created = load_or_create_correlation_key(&home).expect("created");
    let path = home.join(CORRELATION_KEY_FILE);
    assert!(path.is_file());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).expect("stat").permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(&home).expect("stat").permissions().mode() & 0o777,
            0o700
        );
    }
    let reloaded = load_or_create_correlation_key(&home).expect("reloaded");
    assert_eq!(created.key_id, reloaded.key_id);
    assert_eq!(created.material(), reloaded.material());
    assert!(created.key_id.starts_with("correlation.v1."));
    assert_eq!(created.material().len(), 32);
    // No temporary file is left beside the key.
    let leftovers: Vec<_> = fs::read_dir(&home)
        .expect("listing")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name() != CORRELATION_KEY_FILE)
        .collect();
    assert!(leftovers.is_empty());
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn a_key_written_by_the_python_writer_is_read_as_written() {
    let home = guard_home();
    fs::create_dir_all(&home).expect("home");
    let path = home.join(CORRELATION_KEY_FILE);
    fs::write(
        &path,
        format!(
            "{{\"key_id\":\"{KEY_ID}\",\"material\":\"{ENCODED_MATERIAL}\",\
             \"schema_version\":\"guard.command-activity-correlation-key.v1\"}}\n"
        ),
    )
    .expect("write");
    let key = load_or_create_correlation_key(&home).expect("read");
    assert_eq!(key.key_id, KEY_ID);
    assert_eq!(key.material(), MATERIAL);
    // And what this module writes is what that reader accepts.
    let serialized = serialize_key(KEY_ID, &MATERIAL);
    assert_eq!(
        String::from_utf8(serialized).expect("ascii"),
        format!(
            "{{\"key_id\":\"{KEY_ID}\",\"material\":\"{ENCODED_MATERIAL}\",\
             \"schema_version\":\"guard.command-activity-correlation-key.v1\"}}\n"
        )
    );
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn a_key_file_that_was_edited_is_refused_rather_than_replaced() {
    for body in [
        format!("{{\"key_id\":\"{KEY_ID}\",\"material\":\"{ENCODED_MATERIAL}\",\"schema_version\":\"guard.command-activity-correlation-key.v2\"}}"),
        format!("{{\"key_id\":\"correlation.v1.0000000000000000\",\"material\":\"{ENCODED_MATERIAL}\",\"schema_version\":\"guard.command-activity-correlation-key.v1\"}}"),
        format!("{{\"key_id\":\"{KEY_ID}\",\"material\":\"{ENCODED_MATERIAL}\",\"schema_version\":\"guard.command-activity-correlation-key.v1\",\"extra\":1}}"),
        format!("{{\"key_id\":\"{KEY_ID}\",\"material\":\"not base64!\",\"schema_version\":\"guard.command-activity-correlation-key.v1\"}}"),
        format!("{{\"key_id\":\"{KEY_ID}\",\"material\":\"AQID\",\"schema_version\":\"guard.command-activity-correlation-key.v1\"}}"),
        "[]".to_owned(),
        "not json".to_owned(),
    ] {
        let home = guard_home();
        fs::create_dir_all(&home).expect("home");
        let path = home.join(CORRELATION_KEY_FILE);
        fs::write(&path, &body).expect("write");
        // Destructured rather than `expect_err`, which would need the key type
        // to be printable; key material must never reach a panic message.
        let Err(error) = load_or_create_correlation_key(&home) else {
            panic!("refused: {body}");
        };
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput, "{body}");
        // The unreadable key stays on disk: a writer that silently replaced it
        // would orphan every handle already recorded under it.
        assert_eq!(fs::read_to_string(&path).expect("kept"), body);
        let _ = fs::remove_dir_all(&home);
    }
}

#[cfg(unix)]
#[test]
fn a_symlinked_key_is_not_followed() {
    let home = guard_home();
    fs::create_dir_all(&home).expect("home");
    let target = home.join("elsewhere.json");
    fs::write(&target, "{}").expect("write");
    std::os::unix::fs::symlink(&target, home.join(CORRELATION_KEY_FILE)).expect("symlink");
    assert!(load_or_create_correlation_key(&home).is_err());
    let _ = fs::remove_dir_all(&home);
}

#[test]
fn a_file_where_the_guard_home_belongs_is_refused() {
    let home = guard_home();
    fs::write(&home, "not a directory").expect("write");
    assert!(load_or_create_correlation_key(&home).is_err());
    let _ = fs::remove_file(&home);
}

#[test]
fn a_sixteen_character_identifier_still_carries_a_correlation() {
    // `[A-Za-z0-9][A-Za-z0-9._:-]{15,511}` is a leading character plus fifteen
    // more, so sixteen is the shortest value Python derives from. A native
    // harness that mints ids this short would otherwise lose its pairing.
    let key = fixed_key();
    let shortest = "toolu_01A9bN2c";
    assert_eq!(shortest.len(), 14);
    for (value, derived) in [
        (format!("{shortest}xy"), true),
        (shortest.to_owned(), false),
    ] {
        let outcome = derive_proven_request_correlation(
            "claude-code",
            "PreToolUse",
            &payload(&[("tool_use_id", json!(value))]),
            &key,
        );
        assert_eq!(outcome.is_ok(), derived, "{value}");
    }
}
