use super::native_check_budget_ms;

#[test]
fn the_native_check_leaves_time_to_queue_a_timed_out_review() {
    // A short hook budget keeps three quarters for the check.
    assert_eq!(native_check_budget_ms(Some(1_240)), 930);
    assert_eq!(native_check_budget_ms(Some(750)), 563);
    // A long one keeps all but half a second.
    assert_eq!(native_check_budget_ms(Some(2_191)), 1_691);
    assert_eq!(native_check_budget_ms(Some(60_000)), 8_500);
    assert_eq!(native_check_budget_ms(None), 8_500);
}

#[test]
fn a_tiny_budget_still_gives_the_check_some_time() {
    assert_eq!(native_check_budget_ms(Some(1)), 1);
    assert_eq!(native_check_budget_ms(Some(4)), 3);
    assert_eq!(native_check_budget_ms(Some(0)), 0);
}

mod rule_reviews_then_runtime {
    use super::super::rule_reviews_then_runtime;
    use crate::local_store_read::STORE_FILE_NAME;
    use crate::policy_enforcement::AdmittedPolicySnapshot;
    use crate::runtime_known_vulnerable::{grant_answers, raise, Finding};
    use guard_contracts::{
        GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolActionV1, PreToolOperationV1,
        PreToolResultV1, PRE_TOOL_ACTION_V1_SCHEMA,
    };

    const COMMAND: &str = "node ./tools/build.mjs";

    fn allowed() -> PreToolResultV1 {
        PreToolResultV1 {
            schema: "guard-pre-tool-result.v1".into(),
            version: 1,
            authority: "rust".into(),
            action: PreToolActionV1 {
                schema: PRE_TOOL_ACTION_V1_SCHEMA.into(),
                version: 1,
                harness: "claude-code".into(),
                event: "PreToolUse".into(),
                action_type: PreToolActionTypeV1::Command,
                operation: PreToolOperationV1::Execute,
                bounded: true,
                sensitive_target: false,
            },
            decision: "allow".into(),
            policy_action: "allow".into(),
            minimum_action: "allow".into(),
            reason_code: "native_test".into(),
            reason: "native test".into(),
            explicitly_benign: true,
            command_extensions: None,
            prompt_risk_classes: Vec::new(),
        }
    }

    /// A call held only because Guard did not recognize the command.
    fn unrecognized() -> PreToolResultV1 {
        PreToolResultV1 {
            decision: "deny".into(),
            policy_action: "review".into(),
            minimum_action: "review".into(),
            reason_code: "native_command_review_required".into(),
            reason: "Guard does not recognize this command.".into(),
            explicitly_benign: false,
            ..allowed()
        }
    }

    fn envelope(guard_home: &std::path::Path) -> GuardHookEnvelopeV2 {
        serde_json::from_value(serde_json::json!({
            "schema": "guard-hook-envelope.v2",
            "harness": "claude-code",
            "event": "PreToolUse",
            "raw_payload": {"tool_input": {"command": COMMAND}},
            "policy_generation": 0,
            "policy_snapshot": {},
            "source": {"home_dir": "/home/user", "guard_home": guard_home.to_str().unwrap()},
        }))
        .unwrap()
    }

    /// Stands in for the runtime overlay finding an affected Node.js build.
    fn vulnerable_runtime(
        _: &GuardHookEnvelopeV2,
        _: Option<&AdmittedPolicySnapshot>,
        result: PreToolResultV1,
    ) -> PreToolResultV1 {
        raise(
            result,
            &Finding::for_tests("CVE-0000-0001"),
            "review",
            false,
        )
    }

    fn saved_review_home() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        let connection = rusqlite::Connection::open(home.path().join(STORE_FILE_NAME)).unwrap();
        connection
            .execute_batch(
                "create table policy_decisions (harness text, scope text, artifact_id text, \
                 action text, source text, expires_at text, workspace text)",
            )
            .unwrap();
        let id = crate::memory_pattern::verdict(&crate::memory_pattern::MemoryRequest {
            command: Some(COMMAND),
            artifact_type: Some("shell_command"),
            artifact_id: None,
            artifact_name: None,
            harness: None,
        })
        .exact_artifact_ids[0]
            .clone();
        connection
            .execute(
                "insert into policy_decisions values ('*', 'artifact', ?1, 'review', 'local', null, null)",
                [id],
            )
            .unwrap();
        home
    }

    fn unreadable_home() -> tempfile::TempDir {
        let home = tempfile::tempdir().unwrap();
        std::fs::write(home.path().join(STORE_FILE_NAME), b"not a database at all").unwrap();
        home
    }

    #[test]
    fn a_rule_review_stays_apart_from_a_vulnerable_runtime_finding() {
        for (home, rule, before) in [
            (saved_review_home(), "saved review rule", allowed()),
            (unreadable_home(), "unreadable rule store", allowed()),
            // A non-recognition review is one a grant answers, so the rule
            // still records over it.
            (saved_review_home(), "saved review rule", unrecognized()),
            (unreadable_home(), "unreadable rule store", unrecognized()),
        ] {
            let rule = format!("{rule} over {}", before.reason_code);
            let raised =
                rule_reviews_then_runtime(&envelope(home.path()), None, before, vulnerable_runtime);
            assert_eq!(raised.minimum_action, "review", "{rule}");
            assert_eq!(
                raised.reason_code, "native_runtime_known_vulnerable_with_review",
                "{rule}"
            );
            // A saved grant for the script answers only a lone finding.
            assert!(!grant_answers(&raised.reason_code), "{rule}");
        }
    }

    #[test]
    fn a_lone_finding_is_still_one_a_script_grant_answers() {
        for before in [allowed(), unrecognized()] {
            let home = tempfile::tempdir().unwrap();
            let raised =
                rule_reviews_then_runtime(&envelope(home.path()), None, before, vulnerable_runtime);
            assert_eq!(raised.reason_code, "native_runtime_known_vulnerable");
            assert!(grant_answers(&raised.reason_code));
        }
    }
}
