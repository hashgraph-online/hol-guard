use super::*;
use crate::policy_store::policy_store_direct_lane::{DirectLaneBinding, DirectLaneReviewFacts};

fn ask_binding() -> DirectLaneBinding {
    let mut binding = super::super::tests::binding();
    binding.review = DirectLaneReviewFacts {
        blocked_request_mode: Some("ask".to_owned()),
        approval_center_origin: Some("http://127.0.0.1:4781".to_owned()),
        review_oauth_source: Some("default".to_owned()),
        review_host_cwd: Some("/work".to_owned()),
    };
    binding
}

/// `Some(asks_for_approval)` when the resident queues the review.
fn queued(harness: &str, binding: &DirectLaneBinding, result: &Value) -> Option<bool> {
    queued_payload(harness, binding, result, &Map::new())
}

fn queued_payload(
    harness: &str,
    binding: &DirectLaneBinding,
    result: &Value,
    payload: &Map<String, Value>,
) -> Option<bool> {
    let context = Context {
        harness,
        payload,
        recorded_payload: payload,
        workspace: "/work",
        home_dir: "/home/user",
        guard_home: "/home/user/.hol-guard",
        binding,
    };
    facts(&context, result.as_object().unwrap()).map(|facts| facts.ask)
}

#[test]
fn only_a_fully_published_home_queues() {
    let review = json!({"reason_code": "native_review", "reason": "Review this."});
    let binding = ask_binding();
    assert_eq!(queued("codex", &binding, &review), Some(true));
    // Claude Code's paused review is queued with its permission notice; a
    // spelling `_native_review_artifact_id` would keep stays with the daemon.
    assert_eq!(queued(CLAUDE_CODE, &binding, &review), Some(true));
    assert_eq!(queued("Claude_Code", &binding, &review), None);
    // A package review without a command is left to the queue; an npm
    // install the daemon may settle stays with it, except on Windows.
    let package =
        json!({"reason_code": package::PACKAGE_REVIEW_REASON, "minimum_action": "review"});
    assert_eq!(queued("codex", &binding, &package), Some(true));
    let install = json!({
        "tool_input": {"command": "npm install left-pad"},
        "guard_execution_environment": {"path": "/usr/bin", "environment_names": []},
    });
    let install = install.as_object().unwrap();
    assert_eq!(
        queued_payload("codex", &binding, &package, install),
        cfg!(windows).then_some(true)
    );
    let mut safe_alternative = ask_binding();
    safe_alternative.review.blocked_request_mode = Some("safe-alternative".to_owned());
    assert_eq!(queued("codex", &safe_alternative, &review), Some(false));
    for strip in [
        (|facts: &mut DirectLaneReviewFacts| facts.blocked_request_mode = None)
            as fn(&mut DirectLaneReviewFacts),
        |facts: &mut DirectLaneReviewFacts| facts.approval_center_origin = None,
        |facts: &mut DirectLaneReviewFacts| facts.review_oauth_source = None,
        |facts: &mut DirectLaneReviewFacts| facts.review_host_cwd = None,
    ] {
        let mut partial = ask_binding();
        strip(&mut partial.review);
        assert_eq!(queued("codex", &partial, &review), None);
    }
    let mut no_environment = ask_binding();
    no_environment.exact_action_environment = None;
    assert_eq!(queued("codex", &no_environment, &review), None);
}

#[test]
fn only_a_claude_code_session_queues_with_its_notice() {
    let mut binding = ask_binding();
    binding.integrity_key = Some(
        crate::policy_store::policy_store_direct_lane::DirectLaneIntegrityKey {
            key: zeroize::Zeroizing::new(vec![7; 32]),
            key_id: "bound".to_owned(),
        },
    );
    let result = json!({"decision": "review", "reason": "Deletes files."});
    let result = result.as_object().unwrap();
    let method = |harness: &str, payload: Value| {
        let payload = payload.as_object().unwrap().clone();
        let context = Context {
            harness,
            payload: &payload,
            recorded_payload: &payload,
            workspace: "/work",
            home_dir: "/home/user",
            guard_home: "/home/user/.hol-guard",
            binding: &binding,
        };
        store_method(&context, result, Some("rb-1"))
            .map(|(method, extra)| (method, extra.get("claude_notice").cloned()))
    };
    let vectors: Value = serde_json::from_str(include_str!(
        "../testdata/guard_store/claude_review_notice_vectors.json"
    ))
    .unwrap();
    let session = vectors["scenarios"][0]["payload"].clone();
    let (claude, notice) = method(CLAUDE_CODE, session.clone()).unwrap();
    assert_eq!(claude, CLAUDE_WRITE_METHOD);
    let notice = notice.expect("a notice");
    assert_eq!(notice["session_id"], "sess-1");
    assert_eq!(notice["integrity_key_id"], "bound");
    assert_eq!(
        method("codex", session.clone()).unwrap(),
        (WRITE_METHOD, None)
    );
    let mut sessionless = session;
    sessionless.as_object_mut().unwrap().remove("session_id");
    assert_eq!(
        method(CLAUDE_CODE, sessionless).unwrap(),
        (WRITE_METHOD, None)
    );
}

#[test]
fn request_ids_are_uuid4_hex() {
    let first = request_id().unwrap();
    let second = request_id().unwrap();
    assert_ne!(first, second);
    for id in [first, second] {
        assert_eq!(id.len(), 32);
        assert!(id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(&id[12..13], "4");
        assert!(matches!(&id[16..17], "8" | "9" | "a" | "b"));
    }
}

#[test]
fn harness_names_canonicalize_as_the_daemon_does() {
    assert_eq!(canonical_harness(" Gemini_CLI \n"), "gemini-cli");
    assert_eq!(canonical_harness("codex"), "codex");
}

#[test]
fn the_pause_carries_the_queued_request() {
    let result = json!({"decision": "review", "reason": "Review this."});
    let response = respond(
        "codex",
        result.as_object().unwrap(),
        "abc123",
        "http://127.0.0.1:4781/requests/abc123",
        "Review this. Approve at http://127.0.0.1:4781/requests/abc123",
        "http://127.0.0.1:4781",
    )
    .unwrap();
    assert_eq!(response["prompted"], json!(true));
    assert_eq!(
        response["approval_center_url"],
        json!("http://127.0.0.1:4781")
    );
    let mut approval = Object::new();
    approval.insert("request_id".to_owned(), json!("abc123"));
    approval.insert(
        "approval_url".to_owned(),
        json!("http://127.0.0.1:4781/requests/abc123"),
    );
    let mut expected = pre_tool_review(
        "codex",
        result.as_object().unwrap(),
        Some(&approval),
        Some("Review this. Approve at http://127.0.0.1:4781/requests/abc123"),
    );
    expected.insert("prompted".to_owned(), json!(true));
    expected.insert(
        "approval_center_url".to_owned(),
        json!("http://127.0.0.1:4781"),
    );
    assert_eq!(response, Value::Object(expected));
}

#[test]
fn an_oversized_pause_defers() {
    let result = json!({"reason": "x".repeat(HOOK_RENDER_MAX_BYTES)});
    assert!(respond(
        "codex",
        result.as_object().unwrap(),
        "abc123",
        "http://127.0.0.1:4781/requests/abc123",
        "linked",
        "http://127.0.0.1:4781",
    )
    .is_none());
}

// The storage gate opens without following links only on Unix.
#[cfg(unix)]
const WRITE_VECTORS: &str =
    include_str!("../testdata/guard_store/approval_request_write_vectors.json");
#[cfg(unix)]
const SILENT_VECTORS: &str = include_str!("../testdata/guard_store/silent_review_vectors.json");

/// A Guard home with the daemon's store schema and its storage gate.
#[cfg(unix)]
fn store_home(tag: &str, vectors: &str) -> std::path::PathBuf {
    let home = crate::guard_store_cmd_vectors_tests::temp_home(tag);
    let vectors: Value = serde_json::from_str(vectors).unwrap();
    let connection = rusqlite::Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    for statement in vectors["schema_sql"].as_array().unwrap() {
        connection
            .execute_batch(statement.as_str().unwrap())
            .unwrap();
    }
    std::fs::write(home.join("storage-access.lock"), b"").unwrap();
    home
}

#[cfg(unix)]
#[test]
fn the_queue_write_keeps_a_pending_request_for_the_same_action() {
    let home = store_home("review-queue-write", WRITE_VECTORS);
    let guard_home = home.to_string_lossy().into_owned();
    let payload = Map::new();
    let binding = ask_binding();
    let context = Context {
        harness: "codex",
        payload: &payload,
        recorded_payload: &payload,
        workspace: "/work/space",
        home_dir: "/home/user",
        guard_home: &guard_home,
        binding: &binding,
    };
    let vectors: Value = serde_json::from_str(WRITE_VECTORS).unwrap();
    let request = vectors["scenarios"][0]["request"].clone();
    assert_eq!(
        write(
            &context,
            WRITE_METHOD,
            "default",
            request.clone(),
            Map::new()
        ),
        Ok("r-new".to_owned())
    );
    let mut retry = request;
    retry["request_id"] = json!("r-retry");
    retry["approval_url"] = json!("http://127.0.0.1:4781/approvals/r-retry");
    retry["review_command"] = json!("hol-guard approvals approve r-retry");
    assert_eq!(
        write(&context, WRITE_METHOD, "default", retry, Map::new()),
        Ok("r-new".to_owned())
    );
    let connection = rusqlite::Connection::open(home.join(STORE_FILE_NAME)).unwrap();
    let (rows, dedupe_count): (i64, i64) = connection
        .query_row(
            "select count(*), max(dedupe_count) from approval_requests",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((rows, dedupe_count), (1, 2));
    std::fs::remove_dir_all(home).ok();
}

#[test]
fn only_a_string_or_falsy_reason_is_reproduced() {
    assert_eq!(falsy_or_text(None, "fallback"), Ok("fallback"));
    for falsy in [json!(null), json!(false), json!("")] {
        assert_eq!(falsy_or_text(Some(&falsy), "fallback"), Ok("fallback"));
    }
    let text = json!("Review this.");
    assert_eq!(falsy_or_text(Some(&text), "fallback"), Ok("Review this."));
    for other in [json!(0), json!(true), json!([]), json!({})] {
        assert_eq!(
            falsy_or_text(Some(&other), "fallback"),
            Err(HookDirectDefer::ReviewQueue)
        );
    }
}

#[cfg(unix)]
#[test]
fn a_silent_review_blocks_after_queueing_its_request_and_event() {
    let safe = safe_alternative_reason_with_retry(
        "Deletes files.",
        Some("native_review"),
        Some(true),
        true,
        false,
    );
    // Without a daemon token Codex cannot sign the loopback link, so it says
    // so instead of handing out an unsigned one.
    for (harness, reason) in [
        (
            "claude-code",
            format!(
                "{safe} Open HOL Guard to approve or keep this blocked: \
                 http://127.0.0.1:4781/requests/r-new."
            ),
        ),
        (
            "codex",
            format!(
                "{safe} HOL Guard could not create a signed approval link; open Inbox \
                 from Guard on this device, then retry."
            ),
        ),
    ] {
        let home = store_home(&format!("review-queue-silent-{harness}"), SILENT_VECTORS);
        let guard_home = home.to_string_lossy().into_owned();
        let payload = Map::new();
        let mut binding = ask_binding();
        binding.review.blocked_request_mode = Some("safe-alternative".to_owned());
        let context = Context {
            harness,
            payload: &payload,
            recorded_payload: &payload,
            workspace: "/work/space",
            home_dir: "/home/user",
            guard_home: &guard_home,
            binding: &binding,
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
            true,
            false,
        )
        .unwrap();
        let mut blocked = result.as_object().unwrap().clone();
        blocked.insert("decision".to_owned(), json!("deny"));
        blocked.insert("minimum_action".to_owned(), json!("block"));
        blocked.insert("policy_action".to_owned(), json!("block"));
        blocked.insert("reason".to_owned(), json!(reason));
        let mut expected = pre_tool(harness, &blocked);
        expected.insert("prompted".to_owned(), json!(false));
        expected.insert("blocked_request_mode".to_owned(), json!("safe-alternative"));
        assert_eq!(response, Value::Object(expected), "{harness}");
        let connection = rusqlite::Connection::open(home.join(STORE_FILE_NAME)).unwrap();
        let count = |sql: &str| -> i64 { connection.query_row(sql, [], |row| row.get(0)).unwrap() };
        assert_eq!(count("select count(*) from approval_requests"), 1);
        assert_eq!(
            count("select count(*) from guard_events where event_name = 'approval.created'"),
            1
        );
        std::fs::remove_dir_all(home).ok();
    }
}

#[cfg(unix)]
#[test]
fn a_silent_review_links_its_row_only_when_approval_can_unblock_it() {
    // Unbound: an exact-action Always can still let the retry run, so the
    // user gets the row's link; without one no approval can, so nothing sends
    // the user to approve it.
    for (tag, exact_action_allowable, linked) in [
        ("always-only", true, true),
        ("cannot-unblock", false, false),
    ] {
        let home = store_home(&format!("review-queue-silent-{tag}"), SILENT_VECTORS);
        let guard_home = home.to_string_lossy().into_owned();
        let payload = Map::new();
        let mut binding = ask_binding();
        binding.review.blocked_request_mode = Some("safe-alternative".to_owned());
        let context = Context {
            harness: "claude-code",
            payload: &payload,
            recorded_payload: &payload,
            workspace: "/work/space",
            home_dir: "/home/user",
            guard_home: &guard_home,
            binding: &binding,
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
            false,
            exact_action_allowable,
        )
        .unwrap();
        let safe = safe_alternative_reason_with_retry(
            "Deletes files.",
            Some("native_review"),
            Some(true),
            false,
            exact_action_allowable,
        );
        let reason = if linked {
            format!(
                "{safe} Open HOL Guard to approve or keep this blocked: \
                 http://127.0.0.1:4781/requests/r-new."
            )
        } else {
            safe
        };
        let mut blocked = result.as_object().unwrap().clone();
        blocked.insert("decision".to_owned(), json!("deny"));
        blocked.insert("minimum_action".to_owned(), json!("block"));
        blocked.insert("policy_action".to_owned(), json!("block"));
        blocked.insert("reason".to_owned(), json!(reason));
        let mut expected = pre_tool("claude-code", &blocked);
        expected.insert("prompted".to_owned(), json!(false));
        expected.insert("blocked_request_mode".to_owned(), json!("safe-alternative"));
        assert_eq!(response, Value::Object(expected), "{tag}");
        let connection = rusqlite::Connection::open(home.join(STORE_FILE_NAME)).unwrap();
        let rows: i64 = connection
            .query_row("select count(*) from approval_requests", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(rows, 1, "{tag}");
        std::fs::remove_dir_all(home).ok();
    }
}

#[cfg(unix)]
#[test]
fn an_omp_silent_review_hands_the_extension_a_resume_only_when_its_retry_is_bound() {
    // The OMP extension waits for the queued row and then asks the agent to
    // run the identical call again; an unbound row, or another harness, gets
    // no handle because approving it cannot let that retry run.
    for (tag, harness, retry_reuses_approval, exact_action_allowable, resumes) in [
        ("omp-bound", "omp", true, false, true),
        ("omp-always-only", "omp", false, true, false),
        ("omp-cannot-unblock", "omp", false, false, false),
        ("claude-bound", "claude-code", true, false, false),
    ] {
        let home = store_home(&format!("review-queue-resume-{tag}"), SILENT_VECTORS);
        let guard_home = home.to_string_lossy().into_owned();
        let payload = Map::new();
        let mut binding = ask_binding();
        binding.review.blocked_request_mode = Some("safe-alternative".to_owned());
        let context = Context {
            harness,
            payload: &payload,
            recorded_payload: &payload,
            workspace: "/work/space",
            home_dir: "/home/user",
            guard_home: &guard_home,
            binding: &binding,
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
            retry_reuses_approval,
            exact_action_allowable,
        )
        .unwrap();
        let expected =
            resumes.then(|| json!({"request_id": "r-new", "poll_path": "/v1/requests/r-new"}));
        assert_eq!(response.get("approval_resume").cloned(), expected, "{tag}");
        assert_eq!(
            response["blocked_request_mode"], "safe-alternative",
            "{tag}"
        );
        std::fs::remove_dir_all(home).ok();
    }
}

#[cfg(unix)]
#[test]
fn ask_without_any_reusable_identity_records_without_starting_a_wait() {
    for (tag, command) in [
        ("ask-python", "python3 script.py"),
        ("ask-push", "git push origin dev"),
    ] {
        let home = store_home(tag, SILENT_VECTORS);
        let guard_home = home.to_string_lossy().into_owned();
        let binding = ask_binding();
        let workspace = super::super::tests::workspace(tag);
        let (_, _, _, mut exact) = super::super::tests::bound_query(&binding, &workspace);
        let NativeExactActionQueryV1::ExactAction {
            command: query_command,
            ..
        } = &mut exact
        else {
            panic!("an exact-action query");
        };
        *query_command = Some(command.to_owned());
        assert!(crate::native_exact_action_op::review_binding_for(&exact, None, None).is_none());
        let payload = json!({"tool_name": "Bash", "tool_input": {"command": command}});
        let payload = payload.as_object().unwrap();
        let fixture = super::super::tests::vectors();
        let context = Context {
            harness: "omp",
            payload,
            recorded_payload: payload,
            workspace: &workspace,
            home_dir: fixture["home_dir"].as_str().unwrap(),
            guard_home: &guard_home,
            binding: &binding,
        };
        let result = json!({"decision": "deny", "policy_action": "review", "minimum_action": "review",
                           "reason": "Review this command.", "reason_code": "native_command_review_required"});
        let response = answer(
            &context,
            result.as_object().unwrap(),
            None,
            &exact,
            &Err("mutable_command"),
        )
        .expect("an unbound review is recorded without a pause");
        assert_eq!(response["prompted"], false);
        assert_eq!(response["policy_action"], "block");
        assert!(response["reason"]
            .as_str()
            .unwrap()
            .contains("approving it there will not let you run it"));
        assert!(response.get("approval_request_id").is_none());
        assert!(response.get("approval_url").is_none());
        let connection = rusqlite::Connection::open(home.join(STORE_FILE_NAME)).unwrap();
        let pending: i64 = connection
            .query_row(
                "select count(*) from approval_requests where status = 'pending'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(pending, 1);
        std::fs::remove_dir_all(home).unwrap();
    }
}
