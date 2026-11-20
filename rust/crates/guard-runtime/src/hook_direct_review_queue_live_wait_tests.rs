//! A silent Codex review links the wait its bridge holds open.

use super::*;

/// The default blocked-request mode answers a Codex review with the silent
/// block, and the Codex bridge holds its wait whenever that block links the
/// approval. The resident links the wait in the same write, so approving the
/// row releases the waiting call; a block that links nothing holds no wait.
#[cfg(unix)]
#[test]
fn a_silent_codex_review_links_the_wait_its_bridge_holds_open() {
    let (pid, token) = crate::codex_hook_identity::current_process_identity().unwrap();
    for (tag, retry_reuses_approval, linked) in [
        ("silent-codex-wait", true, true),
        ("silent-codex-cannot-unblock", false, false),
    ] {
        let home = store_home(tag, SILENT_VECTORS);
        std::fs::write(home.join("daemon-auth-token"), b"token").unwrap();
        let guard_home = home.to_string_lossy().into_owned();
        let payload = json!({
            "guard_codex_browser_wait_process": {"pid": pid, "startToken": token},
            "guard_codex_browser_wait_timeout_seconds": 90,
        });
        let payload = payload.as_object().unwrap();
        let mut binding = ask_binding();
        binding.review.blocked_request_mode = Some("safe-alternative".to_owned());
        let context = Context {
            harness: "codex",
            payload,
            recorded_payload: payload,
            workspace: "/work/space",
            home_dir: "/home/user",
            guard_home: &guard_home,
            binding: &binding,
            hint: None,
        };
        let vectors: Value = serde_json::from_str(SILENT_VECTORS).unwrap();
        let request = vectors["scenarios"][1]["request"].clone();
        let result = json!({
            "decision": "review",
            "minimum_action": "require-reapproval",
            "reason": "Deletes files.",
            "reason_code": "native_review",
        });
        let response = silent(
            &context,
            result.as_object().unwrap(),
            "default",
            request,
            Flags {
                ask: false,
                retry_reuses_approval,
                exact_action_allowable: false,
            },
            None,
        )
        .unwrap()
        .0;
        assert_eq!(
            response.to_string().contains("/requests/r-new"),
            linked,
            "{tag}"
        );
        let connection = rusqlite::Connection::open(home.join(STORE_FILE_NAME)).unwrap();
        let count = |sql: &str| -> i64 { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
        let snapshot: Option<String> = connection
            .query_row(
                "select continuation_snapshot_json from approval_requests where request_id = 'r-new'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        let suspended = snapshot
            .as_deref()
            .and_then(|text| serde_json::from_str::<Value>(text).ok())
            .is_some_and(|snapshot| snapshot["capability"] == "suspended-response");
        assert_eq!(
            (
                count(
                    "select count(*) from guard_operations where operation_id = 'codex-hook-r-new'"
                ),
                count("select count(*) from guard_request_resumes where request_id = 'r-new'"),
                suspended,
            ),
            if linked { (1, 1, true) } else { (0, 0, false) },
            "{tag}"
        );
        assert_eq!(
            count("select count(*) from guard_events where event_name = 'approval.created'"),
            1,
            "{tag}"
        );
        std::fs::remove_dir_all(home).ok();
    }
}
