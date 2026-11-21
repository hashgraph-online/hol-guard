//! The canonical form is the Python source's, so the digests pinned here were
//! taken from `codex_hook_identity.py` itself rather than from this module.

use super::*;
use serde_json::json;

fn request(entries: Vec<Value>, tokens: Value) -> CodexHookIdentityRequestV1 {
    serde_json::from_value(json!({
        "schema": CODEX_HOOK_IDENTITY_REQUEST_SCHEMA,
        "request_id": "test",
        "scalar_tokens": tokens,
        "entries": entries,
    }))
    .expect("request parses")
}

fn answers(request: &CodexHookIdentityRequestV1) -> Vec<Value> {
    evaluate_request(request)["identities"]
        .as_array()
        .expect("identities is a list")
        .clone()
}

fn plain_group() -> Value {
    json!({
        "matcher": {"tool": "Bash", "weight": 2.0},
        "note": "ünïcode",
        "hooks": [
            {"type": "command", "command": "echo hello  world", "timeout": 1.5},
            {"type": "command", "command": "sh -c 'echo $HOME'"},
        ],
    })
}

#[test]
fn handler_identity_matches_the_python_source() {
    let group = plain_group();
    let entry = json!({
        "kind": "handler",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "PreToolUse",
        "group": group,
        "handler": group["hooks"][0].clone(),
    });
    let request = request(vec![entry], json!({}));
    assert_eq!(
        answers(&request)[0]["digest"],
        json!("76d0c3c9803856ba308b3a5c24fe2f223f13e03853c6268fe9c0d9906911c0e9")
    );
}

#[test]
fn group_identity_matches_the_python_source() {
    let entry = json!({
        "kind": "group",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "PreToolUse",
        "group": plain_group(),
    });
    let request = request(vec![entry], json!({}));
    assert_eq!(
        answers(&request)[0]["digest"],
        json!("ad7cef543c4bb147e05d780b381b7bfe793105f3fd6f61f776c7b1ef2ae3f41b")
    );
}

#[test]
fn conflict_keys_match_the_python_source() {
    let entry = json!({
        "kind": "conflict",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "PreToolUse",
        "group": plain_group(),
    });
    let request = request(vec![entry], json!({}));
    assert_eq!(
        answers(&request)[0]["digests"],
        json!([
            "4e823548f3c7be2cd4771f0b6a75768c79e068be935b1b75d201a9f2729cc08e",
            "83d9ddc0d8a66dc793c507fa9c88c8a0d6552890b89e88e53a01bfd4aca0bee9",
        ])
    );
}

/// A date, a time, a datetime and a non-finite float cannot cross a JSON
/// request, so the caller sends a token for each. The digest must come out the
/// same as the one Python took over the scalars themselves.
#[test]
fn tokenized_scalars_reproduce_the_python_digests() {
    let group = json!({
        "matcher": "*",
        "since": "tok-date",
        "ratio": "tok-inf",
        "big": 1e30,
        "hooks": [],
    });
    let handler = json!({
        "type": "command",
        "command": "run",
        "at": "tok-time",
        "stamp": "tok-datetime",
    });
    let tokens = json!({
        "tok-date": {"type": "date", "value": "2026-10-23"},
        "tok-inf": {"type": "float", "value": "inf"},
        "tok-time": {"type": "time", "value": "09:30:00"},
        "tok-datetime": {"type": "datetime", "value": "2026-01-02T03:04:05"},
    });
    let request = request(
        vec![
            json!({
                "kind": "handler",
                "source_scope": "project",
                "source_hooks_enabled": false,
                "event_name": "PostToolUse",
                "group": group,
                "handler": handler,
            }),
            json!({
                "kind": "group",
                "source_scope": "project",
                "source_hooks_enabled": false,
                "event_name": "PostToolUse",
                "group": group,
            }),
        ],
        tokens,
    );
    let answers = answers(&request);
    assert_eq!(
        answers[0]["digest"],
        json!("a94767e7eb75cac21cd274b00e44b622741ebdccf77a984170e61b2889837c25")
    );
    assert_eq!(
        answers[1]["digest"],
        json!("3f6d29ed1025a44e7a9b180126596d462b9d34821016e3d7fb23279051e33e71")
    );
}

#[test]
fn a_whole_float_writes_the_digits_python_int_would() {
    assert_eq!(whole_float_digits(2.0), "2");
    assert_eq!(whole_float_digits(-0.0), "0");
    assert_eq!(whole_float_digits(0.0), "0");
    assert_eq!(whole_float_digits(-7.0), "-7");
    assert_eq!(whole_float_digits(1e30), "1000000000000000019884624838656");
}

#[test]
fn argv_is_derived_only_for_an_uncomplicated_command() {
    let request = request(
        vec![
            json!({"kind": "argv", "command": "echo hello  world"}),
            json!({"kind": "argv", "command": "sh -c 'echo $HOME'"}),
            json!({"kind": "argv", "command": "   "}),
            json!({"kind": "argv"}),
        ],
        json!({}),
    );
    let answers = answers(&request);
    assert_eq!(answers[0]["argv"], json!(["echo", "hello", "world"]));
    assert_eq!(answers[1]["argv"], json!(null));
    assert_eq!(answers[2]["argv"], json!(null));
    assert_eq!(answers[3]["argv"], json!(null));
}

/// `shlex` splits on spaces and tabs only. A vertical tab is not whitespace to
/// it, and the sensitive-character class never sees one, so it stays inside
/// its token.
#[test]
fn only_spaces_and_tabs_separate_argv_tokens() {
    assert_eq!(
        canonical_command_argv(Some("a\tb c")),
        Some(vec!["a".to_owned(), "b".to_owned(), "c".to_owned()])
    );
    assert_eq!(
        canonical_command_argv(Some("a\u{0b}b")),
        Some(vec!["a\u{0b}b".to_owned()])
    );
}

#[test]
fn a_request_naming_another_contract_is_refused() {
    let mut request = request(vec![json!({"kind": "argv"})], json!({}));
    request.schema = "guard-other-request.v1".to_owned();
    assert_eq!(
        refusal(&request),
        Some("native_codex_hook_identity_schema_mismatch")
    );
}

#[test]
fn an_entry_without_what_its_kind_needs_is_refused() {
    let missing_handler = request(vec![json!({"kind": "handler", "group": {}})], json!({}));
    assert_eq!(
        refusal(&missing_handler),
        Some("native_codex_hook_identity_entry_invalid")
    );
    let unknown_kind = request(vec![json!({"kind": "elsewhere"})], json!({}));
    assert_eq!(
        refusal(&unknown_kind),
        Some("native_codex_hook_identity_entry_invalid")
    );
}

#[test]
fn a_batch_past_the_bound_is_refused() {
    let entries = vec![json!({"kind": "argv"}); CODEX_HOOK_IDENTITY_MAX_ENTRIES + 1];
    let request = request(entries, json!({}));
    assert_eq!(
        refusal(&request),
        Some("native_codex_hook_identity_too_many_entries")
    );
}

#[test]
fn the_result_binds_itself_to_its_request() {
    let request = request(vec![json!({"kind": "argv", "command": "ls"})], json!({}));
    let encoded = evaluate_codex_hook_identity_request(&request).expect("the op answers");
    let result: CodexHookIdentityResultV1 =
        serde_json::from_slice(&encoded).expect("the result parses");
    assert_eq!(result.schema, CODEX_HOOK_IDENTITY_RESULT_SCHEMA);
    assert_eq!(result.status, "ok");
    assert_eq!(result.code, "ok");
    let digest = result
        .request_sha256
        .strip_prefix("sha256:")
        .expect("the digest names the algorithm that took it");
    assert_eq!(digest.len(), 64);
}

/// An integer wider than a JSON number travels as its digits, so the digest
/// must be the one Python took over the integer itself.
#[test]
fn a_wide_integer_token_keeps_every_digit() {
    let entry = json!({
        "kind": "handler",
        "source_scope": "user",
        "source_hooks_enabled": true,
        "event_name": "PreToolUse",
        "group": {"matcher": "x", "n": "tok-int", "hooks": []},
        "handler": {"type": "command", "command": "ls"},
    });
    let tokens = json!({"tok-int": {"__int__": "10000000000000000000000000000000000000000"}});
    let request = request(vec![entry], tokens);
    assert_eq!(
        answers(&request)[0]["digest"],
        json!("b89c69fd96f98b74254210b555c9bd541d77751c9f74bc7482229f8c5f565d73")
    );
}
