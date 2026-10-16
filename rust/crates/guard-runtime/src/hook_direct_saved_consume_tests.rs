#[cfg(unix)]
use super::super::tests::{binding, bound_query, local_store, vectors, workspace};
use super::*;
#[cfg(unix)]
use rusqlite::Connection;

/// `_native_review_launch_target` (`hook_native_review_approval.py`) on each
/// payload, recorded from the daemon.
#[test]
fn launch_targets_match_the_daemon() {
    let cases = json!([
        [{"tool_name": "Bash", "tool_input": {"command": "  ls -la "}}, "  ls -la "],
        [{"tool_name": "Bash", "arguments": {"cmd": "echo hi"}}, "echo hi"],
        [{"tool_name": "Read", "tool_input": {"file_path": "  src/a.py  ", "path": "   "}}, "src/a.py"],
        [{"tool_name": "Read", "toolInput": {"path": "/etc/hosts", "url": "https://example.test/x"}}, "https://example.test/x"],
        [{"tool_name": "WebFetch", "tool_input": {"url": "\thttps://example.test\n", "target": "t"}}, "https://example.test"],
        [{"tool_name": "Edit", "tool_input": {"file_path": 7, "target": " t "}}, "t"],
        [{"tool_name": " Glob ", "tool_input": {"pattern": "*.py"}}, "tool:Glob"],
        [{"toolName": "Grep", "tool_input": {"path": ""}}, "tool:Grep"],
        [{"tool": "   ", "tool_input": "not-a-map"}, "tool:tool"],
        [{"tool_name": "Bash", "command": "top level", "tool_input": {"path": "p"}}, "top level"],
    ]);
    for case in cases.as_array().unwrap() {
        let payload = case[0].as_object().unwrap();
        let expected = case[1].as_str().unwrap();
        assert!(
            matches!(launch_target(payload), Ok(target) if target == expected),
            "{expected}"
        );
    }
}

#[test]
fn a_separator_python_strips_defers() {
    let payload = json!({"tool_name": "Read", "tool_input": {"path": "\u{1c}a"}});
    assert!(matches!(
        launch_target(payload.as_object().unwrap()),
        Err(HookDirectDefer::SavedDecision)
    ));
}

#[test]
fn a_missing_storage_gate_defers() {
    let home = std::env::temp_dir().join(format!("hg-consume-gate-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let _ = std::fs::remove_file(home.join(STORAGE_GATE_FILE_NAME));
    assert!(matches!(
        storage_gate(&home),
        Err(HookDirectDefer::SavedDecision)
    ));
    std::fs::write(home.join(STORAGE_GATE_FILE_NAME), b"").unwrap();
    assert!(storage_gate(&home).is_ok());
}

/// The daemon's Windows hold, `msvcrt.locking` on the gate's first byte,
/// keeps the resident out until it is released.
#[cfg(windows)]
#[test]
fn a_daemon_storage_hold_defers_on_windows() {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Command, Stdio};
    let home = std::env::temp_dir().join(format!("hg-consume-hold-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let gate = home.join(STORAGE_GATE_FILE_NAME);
    std::fs::write(&gate, b"0").unwrap();
    let script = "import msvcrt, sys\n\
        handle = open(sys.argv[1], 'a+b')\n\
        handle.seek(0)\n\
        msvcrt.locking(handle.fileno(), msvcrt.LK_NBRLCK, 1)\n\
        print('held', flush=True)\n\
        sys.stdin.read()\n";
    let mut daemon = Command::new("python")
        .args(["-c", script])
        .arg(&gate)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(daemon.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "held");
    assert!(matches!(
        storage_gate(&home),
        Err(HookDirectDefer::SavedDecision)
    ));
    daemon.stdin.take().unwrap().write_all(b"").unwrap();
    assert!(daemon.wait().unwrap().success());
    assert!(storage_gate(&home).is_ok());
}

#[cfg(unix)]
#[test]
fn store_files_stay_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let home = std::env::temp_dir().join(format!("hg-consume-mode-{}", std::process::id()));
    std::fs::create_dir_all(&home).unwrap();
    let wal = home.join(format!("{STORE_FILE_NAME}-wal"));
    std::fs::write(&wal, b"").unwrap();
    std::fs::set_permissions(&wal, std::fs::Permissions::from_mode(0o644)).unwrap();
    repair_store_permissions(&home);
    let mode = std::fs::metadata(&wal).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

/// The bound `Read` vector needs a POSIX workspace, as the lane does.
#[cfg(unix)]
const CONSUME_VECTORS: &str =
    include_str!("../testdata/guard_store/native_review_consume_vectors.json");

/// The inbox tables the daemon spends an approve-once from, the storage gate
/// it creates, and a request resolved as "allow once" for the bound `Read`
/// vector just now.
#[cfg(unix)]
fn seed_approval(path: &std::path::Path, connection: &Connection, identity: &str, workspace: &str) {
    let vectors: Value = serde_json::from_str(CONSUME_VECTORS).unwrap();
    connection
        .execute_batch(
            "create table guard_review_outbox_events (stream_sequence integer primary key, \
             payload_hash text not null default '')",
        )
        .unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    let mut row = vectors["scenarios"][0]["rows"][0].clone();
    let now = super::super::super::lifecycle::utc_now_isoformat().unwrap();
    for (key, value) in [
        ("artifact_hash", identity),
        ("artifact_id", "claude-code:native-pretool:Read"),
        ("artifact_name", "Read"),
        ("launch_target", "src/a.py"),
        ("workspace", workspace),
        ("created_at", now.as_str()),
        ("resolved_at", now.as_str()),
    ] {
        row[key] = json!(value);
    }
    crate::guard_store_cmd_vectors_tests::insert_rows(
        connection,
        "approval_requests",
        &json!([row]),
    );
    std::fs::write(path.parent().unwrap().join("storage-access.lock"), b"").unwrap();
}

#[cfg(unix)]
fn consume_with(
    tag: &str,
    seed: bool,
    block: bool,
) -> (
    Result<Value, HookDirectDefer>,
    Result<Value, HookDirectDefer>,
) {
    let vectors = vectors();
    let workspace = workspace(tag);
    let full = binding();
    let (edge, payload, artifact_id, exact) = bound_query(&full, &workspace);
    assert_eq!(artifact_id, "claude-code:native-pretool:Read");
    let receipt: Value = serde_json::from_slice::<Value>(&edge).unwrap()["receipt"].clone();
    let identity =
        crate::native_exact_action_op::review_binding_for(&exact, Some(&receipt)).unwrap();
    let (path, connection) = local_store(tag);
    if seed {
        seed_approval(&path, &connection, &identity, &workspace);
        if block {
            connection
                .execute(
                    "update approval_requests set resolution_action = 'block'",
                    [],
                )
                .unwrap();
        }
    }
    let guard_home = path.parent().unwrap().to_str().unwrap().to_owned();
    let context = Context {
        harness: "claude-code",
        payload: &payload,
        recorded_payload: &payload,
        workspace: &workspace,
        home_dir: vectors["home_dir"].as_str().unwrap(),
        guard_home: &guard_home,
        binding: &full,
    };
    (
        super::super::answer(&edge, &context),
        super::super::answer(&edge, &context),
    )
}

#[cfg(unix)]
#[test]
fn an_approve_once_answers_one_retry() {
    let (first, second) = consume_with("consume-once", true, false);
    let answered = first.unwrap_or_else(|_| panic!("the approve-once retry deferred"));
    let response = &answered["harness_response"];
    assert_eq!(response["approval_reuse_status"], json!("accepted"));
    assert_eq!(
        response["hookSpecificOutput"]["permissionDecision"],
        json!("allow")
    );
    // Spent, so the retry reaches the inbox, which a home that published no
    // review facts leaves to the daemon.
    assert!(matches!(second, Err(HookDirectDefer::ReviewQueue)));
}

#[cfg(unix)]
#[test]
fn a_review_without_an_approval_defers() {
    let (first, second) = consume_with("consume-none", false, false);
    assert!(matches!(first, Err(HookDirectDefer::SavedDecision)));
    assert!(matches!(second, Err(HookDirectDefer::SavedDecision)));
}

#[cfg(unix)]
#[test]
fn a_keep_blocked_answers_repeated_retries_without_queueing() {
    let (first, second) = consume_with("consume-block", true, true);
    for answer in [first, second] {
        let response = answer.expect("a matching refusal must not defer");
        let response = &response["harness_response"];
        assert_eq!(response["approval_reuse_status"], "blocked");
        assert_eq!(response["reason_code"], "native_review_user_block");
        assert_eq!(response["prompted"], false);
        assert_eq!(response["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(response.get("approval_request_id").is_none());
    }
}
