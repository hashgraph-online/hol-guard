use super::*;
use guard_command::exact_command::exact_command_sha256;
use guard_command::pretool::evaluate_pre_tool_envelope;
use guard_policy_snapshot::scoped_authority::NativePolicyAuthority;
use serde_json::json;

const COMMAND: &str = "\tprintf 'Synthetic  exact bytes'\r\n";

fn envelope(command: &str) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "harness":"codex", "event":"PreToolUse",
        "raw_payload":{"tool_name":"Shell","tool_input":{"command":command}},
        "policy_generation":1, "policy_snapshot":{},
        "source":{"cwd":std::env::temp_dir(),"home_dir":std::env::temp_dir(),"guard_home":std::env::temp_dir()}
    })).unwrap()
}

fn row(id: u64, scope: &str, action: &str, source: &str) -> Value {
    json!({
        "decision_id":id,"harness":"codex","scope":scope,"action":action,
        "source_kind":source,"updated_at_us":id,
        "artifact_id":if scope == "artifact" {Some("codex:project:Shell")} else {None},
        "artifact_hash":null,"workspace":null,"publisher":null,"expires_at_ms":null,
        "exact_command_sha256":if scope == "artifact" {exact_command_sha256(COMMAND)} else {None},
        "requires_exact_context":false
    })
}

fn snapshot(default: &str, rows: Vec<Value>) -> PolicySnapshotV4 {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
    ))
    .unwrap();
    let mut value = vector["snapshot"].clone();
    value["scoped_authority"] = json!({
        "schema":"guard-native-policy-authority.v1","generic_precedence":"specificity-recency.v1",
        "rows":rows,"managed":null
    });
    let mut snapshot: PolicySnapshotV4 = serde_json::from_value(value).unwrap();
    snapshot.mode = "enforce".to_owned();
    snapshot.effective_policy.default_action = default.to_owned();
    snapshot.effective_policy.subprocess_action = "allow".to_owned();
    snapshot.effective_policy.harness_actions.clear();
    snapshot.effective_policy.harness_risk_actions.clear();
    snapshot.effective_policy.artifact_actions.clear();
    snapshot.effective_policy.publisher_actions.clear();
    snapshot.effective_policy.risk_actions.clear();
    snapshot
}

fn evaluate(snapshot: &PolicySnapshotV4, source: &GuardHookEnvelopeV2) -> ScopedPolicyEvaluation {
    let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
    assert_eq!(intrinsic.minimum_action, "allow");
    apply_scoped_pre_tool_policy(snapshot, source, "codex", intrinsic, 100).unwrap()
}

#[test]
fn exact_signed_allow_satisfies_review_and_binds_selected_snapshot_row() {
    for kind in ["signed-bundle", "signed-memory"] {
        let policy = snapshot("review", vec![row(7, "artifact", "allow", kind)]);
        let result = evaluate(&policy, &envelope(COMMAND));
        assert_eq!(result.result.decision, "allow");
        assert_eq!(result.result.policy_action, "allow");
        assert_eq!(result.selected_decision_id, Some(7));
        for command in [COMMAND.trim(), "\tprintf 'Synthetic exact bytes'\r\n"] {
            let changed = evaluate(&policy, &envelope(command));
            assert_eq!(changed.result.minimum_action, "review");
            assert_eq!(changed.selected_decision_id, None);
        }
        let mut changed_artifact = envelope(COMMAND);
        changed_artifact.raw_payload["artifact_id"] = json!("codex:project:other");
        assert_eq!(
            evaluate(&policy, &changed_artifact).result.minimum_action,
            "review"
        );
    }
}

#[test]
fn installed_review_probe_requires_a_rule_that_changes_the_current_action() {
    for (command, baseline, selected_id) in [
        ("printf 'scoped review'", "review", None),
        ("pwd", "warn", Some(7)),
    ] {
        let mut source = envelope(command);
        source.raw_payload["tool_name"] = json!("Bash");
        source.raw_payload["source_scope"] = json!("project");
        let mut policy = snapshot("review", vec![]);
        policy
            .effective_policy
            .harness_actions
            .insert("codex".to_owned(), "review".to_owned());
        let before = evaluate(&policy, &source);
        assert_eq!(before.result.policy_action, baseline);
        assert_eq!(before.selected_decision_id, None);

        let mut selected = row(7, "artifact", "review", "signed-bundle");
        selected["artifact_id"] = json!("codex:project:Bash");
        selected["exact_command_sha256"] = json!(exact_command_sha256(command));
        let mut signed = snapshot("review", vec![selected]);
        signed.effective_policy.harness_actions = policy.effective_policy.harness_actions;
        let after = evaluate(&signed, &source);
        assert_eq!(after.result.policy_action, "review");
        assert_eq!(after.result.decision, "deny");
        assert_eq!(after.selected_decision_id, selected_id);

        if command == "pwd" {
            source.raw_payload["tool_input"]["command"] = json!("pwd ");
            let different_bytes = evaluate(&signed, &source);
            assert_eq!(different_bytes.result.policy_action, "warn");
            assert_eq!(different_bytes.selected_decision_id, None);
        }
    }
}

#[test]
fn modeled_destination_only_ssh_uses_exact_signed_review_without_lowering_stronger_floors() {
    let command = "ssh synthetic@example.invalid";
    for kind in ["signed-bundle", "signed-memory"] {
        let mut selected = row(7, "artifact", "allow", kind);
        selected["exact_command_sha256"] = json!(exact_command_sha256(command));
        let source = envelope(command);
        let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
        assert_eq!(intrinsic.reason_code, "native_command_review_required");
        assert_eq!(intrinsic.minimum_action, "review");
        let result = apply_scoped_pre_tool_policy(
            &snapshot("review", vec![selected.clone()]),
            &source,
            "codex",
            intrinsic.clone(),
            100,
        )
        .unwrap();
        assert_eq!(result.result.minimum_action, "allow");
        assert_eq!(result.selected_decision_id, Some(7));
        for floor in ["require-reapproval", "sandbox-required", "block"] {
            let result = apply_scoped_pre_tool_policy(
                &snapshot(floor, vec![selected.clone()]),
                &source,
                "codex",
                intrinsic.clone(),
                100,
            )
            .unwrap();
            assert_eq!(result.result.minimum_action, floor);
            assert_eq!(result.selected_decision_id, None);
        }
        let changed = envelope(&format!("{command} "));
        let result = apply_scoped_pre_tool_policy(
            &snapshot("review", vec![selected]),
            &changed,
            "codex",
            intrinsic,
            100,
        )
        .unwrap();
        assert_eq!(result.result.minimum_action, "review");
        assert_eq!(result.selected_decision_id, None);
    }
}

#[test]
fn specificity_then_recency_selects_one_winner_without_source_severity_floor() {
    let broad_block = row(9, "global", "block", "signed-bundle");
    let exact_allow = row(7, "artifact", "allow", "signed-memory");
    let policy = snapshot("review", vec![broad_block.clone(), exact_allow.clone()]);
    assert_eq!(
        evaluate(&policy, &envelope(COMMAND)).result.minimum_action,
        "allow"
    );
    let exact_block = row(6, "artifact", "block", "local");
    let policy = snapshot("review", vec![exact_block.clone(), exact_allow.clone()]);
    assert_eq!(
        evaluate(&policy, &envelope(COMMAND)).selected_decision_id,
        Some(7)
    );
    let mut newer_block = exact_block;
    newer_block["updated_at_us"] = json!(8);
    let policy = snapshot("review", vec![newer_block, exact_allow]);
    let result = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(result.result.minimum_action, "block");
    assert_eq!(result.selected_decision_id, Some(6));
}

#[test]
fn local_or_artifact_only_allow_does_not_become_a_reusable_approval() {
    for (kind, exact) in [
        ("local", true),
        ("signed-bundle", false),
        ("signed-memory", false),
    ] {
        let mut selected = row(7, "artifact", "allow", kind);
        if !exact {
            selected["exact_command_sha256"] = Value::Null;
        }
        let result = evaluate(&snapshot("review", vec![selected]), &envelope(COMMAND));
        assert_eq!(result.result.minimum_action, "review");
        assert_eq!(result.selected_decision_id, None);
    }
}

#[test]
fn actual_mcp_identity_selects_policy_without_lowering_its_intrinsic_review() {
    let mut source = envelope(COMMAND);
    source.raw_payload = json!({"tool_name":"mcp__synthetic__inspect","tool_input":{}});
    let mut selected = row(7, "artifact", "block", "signed-bundle");
    selected["artifact_id"] = json!("codex:project:mcp__synthetic__inspect");
    selected["exact_command_sha256"] = Value::Null;
    for (saved, expected, winner) in [
        ("allow", "review", None),
        ("review", "review", None),
        ("block", "block", Some(7)),
    ] {
        selected["action"] = json!(saved);
        let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
        assert_eq!(intrinsic.minimum_action, "review");
        let result = apply_scoped_pre_tool_policy(
            &snapshot("allow", vec![selected.clone()]),
            &source,
            "codex",
            intrinsic,
            100,
        )
        .unwrap();
        assert_eq!(result.result.minimum_action, expected);
        assert_eq!(result.result.decision, "deny");
        assert_eq!(result.selected_decision_id, winner);
    }
    source.raw_payload["tool_name"] = json!("mcp__synthetic__other");
    let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
    let result = apply_scoped_pre_tool_policy(
        &snapshot("allow", vec![selected]),
        &source,
        "codex",
        intrinsic,
        100,
    )
    .unwrap();
    assert_eq!(result.result.minimum_action, "review");
    assert_eq!(result.selected_decision_id, None);
}

#[test]
fn observe_retains_the_winning_scoped_rule_identity_before_projection() {
    let mut policy = snapshot("allow", vec![row(7, "artifact", "block", "signed-bundle")]);
    policy.mode = "observe".to_owned();
    let result = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(result.result.minimum_action, "allow");
    assert_eq!(result.result.decision, "allow");
    assert_eq!(result.observed_policy_action, Some("block"));
    assert_eq!(result.selected_decision_id, Some(7));
    policy.effective_policy.default_action = "block".to_owned();
    let default_wins = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(default_wins.selected_decision_id, None);
}

#[test]
fn expired_selected_row_and_workspace_mismatch_cannot_authorize() {
    let mut expired = row(7, "artifact", "allow", "signed-memory");
    expired["expires_at_ms"] = json!(100);
    assert_eq!(
        evaluate(&snapshot("review", vec![expired]), &envelope(COMMAND))
            .result
            .minimum_action,
        "review"
    );
    let mut workspace = row(7, "artifact", "allow", "signed-memory");
    workspace["scope"] = json!("workspace");
    workspace["workspace"] = json!("/synthetic/unrelated-workspace");
    assert_eq!(
        evaluate(&snapshot("review", vec![workspace]), &envelope(COMMAND))
            .result
            .minimum_action,
        "review"
    );
}

#[test]
fn current_terminal_and_every_intrinsic_floor_survive_signed_allow() {
    for floor in ["require-reapproval", "sandbox-required", "block"] {
        let result = evaluate(
            &snapshot(floor, vec![row(7, "artifact", "allow", "signed-memory")]),
            &envelope(COMMAND),
        );
        assert_eq!(result.result.minimum_action, floor);
        assert_eq!(result.selected_decision_id, None);
    }
    let source = envelope(COMMAND);
    for mode in ["enforce", "observe"] {
        for floor in [
            "warn",
            "review",
            "require-reapproval",
            "sandbox-required",
            "block",
        ] {
            let mut policy = snapshot("allow", vec![row(7, "artifact", "allow", "signed-memory")]);
            policy.mode = mode.to_owned();
            let mut intrinsic =
                evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
            intrinsic.minimum_action = floor.to_owned();
            intrinsic.policy_action = floor.to_owned();
            intrinsic.decision = if floor == "warn" { "allow" } else { "deny" }.to_owned();
            intrinsic.explicitly_benign = false;
            let result =
                apply_scoped_pre_tool_policy(&policy, &source, "codex", intrinsic, 100).unwrap();
            assert_eq!(result.result.minimum_action, floor);
            assert_eq!(result.observed_policy_action, None);
            assert_eq!(result.selected_decision_id, None);
        }
    }
}

#[test]
fn observe_policy_projection_retains_its_rule_but_not_an_equal_default() {
    let mut policy = snapshot("allow", vec![row(7, "artifact", "block", "signed-memory")]);
    policy.mode = "observe".to_owned();
    let result = evaluate(&policy, &envelope(COMMAND));
    assert_eq!(result.result.minimum_action, "allow");
    assert_eq!(result.result.decision, "allow");
    assert_eq!(result.observed_policy_action, Some("block"));
    assert_eq!(result.selected_decision_id, Some(7));
    let result = evaluate(
        &snapshot("block", vec![row(7, "artifact", "block", "signed-memory")]),
        &envelope(COMMAND),
    );
    assert_eq!(result.selected_decision_id, None);
}

#[test]
fn unsupported_authority_and_request_posture_are_never_partially_applied() {
    let source = envelope(COMMAND);
    let baseline = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
    let mut hashed = row(7, "artifact", "block", "signed-memory");
    hashed["artifact_hash"] = json!("synthetic-content-binding");
    let mut policy = snapshot("allow", vec![hashed]);
    assert_eq!(
        apply_scoped_pre_tool_policy(&policy, &source, "codex", baseline.clone(), 100)
            .err()
            .as_deref(),
        Some("native_scoped_content_context_unsupported")
    );
    let managed = json!({"revision":1,"managed_revision":1,"catalog_digest":"a".repeat(64),"global_lockdown":true,"controls":[]});
    let mut authority = serde_json::to_value(&policy.scoped_authority).unwrap();
    authority["rows"] = json!([]);
    authority["managed"] = managed;
    policy.scoped_authority =
        NativePolicyAuthority::from_slice(&serde_json::to_vec(&authority).unwrap()).unwrap();
    assert_eq!(
        apply_scoped_pre_tool_policy(&policy, &source, "codex", baseline.clone(), 100)
            .err()
            .as_deref(),
        Some("native_scoped_managed_catalog_mismatch")
    );
    let policy = snapshot("allow", vec![]);
    for key in [
        "policy_action",
        "daemon_status",
        "fail_mode",
        "permission_mode",
        "permissionMode",
    ] {
        let mut supplied = source.clone();
        supplied.raw_payload[key] = json!("allow");
        assert_eq!(
            apply_scoped_pre_tool_policy(&policy, &supplied, "codex", baseline.clone(), 100)
                .err()
                .as_deref(),
            Some("native_scoped_request_posture_unsupported")
        );
    }
}

fn with_managed(
    mut policy: PolicySnapshotV4,
    lockdown: bool,
    controls: Vec<Value>,
) -> PolicySnapshotV4 {
    let mut value = serde_json::to_value(&policy.scoped_authority).unwrap();
    value["managed"] = json!({"revision":2,"managed_revision":7,
        "catalog_digest":crate::policy_scoped_managed::catalog_digest(),
        "global_lockdown":lockdown,"controls":controls});
    policy.scoped_authority = serde_json::from_value(value).unwrap();
    policy
}

#[test]
fn managed_lockdown_cannot_be_lowered_by_exact_allow_or_observe() {
    for mode in ["enforce", "observe"] {
        for kind in ["signed-bundle", "signed-memory"] {
            let mut policy = with_managed(
                snapshot("review", vec![row(7, "artifact", "allow", kind)]),
                true,
                vec![],
            );
            policy.mode = mode.to_owned();
            let result = evaluate(&policy, &envelope(COMMAND));
            assert_eq!(result.result.minimum_action, "block");
            assert_eq!(result.result.decision, "deny");
            assert_eq!(result.selected_decision_id, None);
            assert_eq!(result.observed_policy_action, None);
        }
    }
}

#[test]
fn unrelated_managed_controls_neither_grant_permission_nor_lose_generic_precedence() {
    for state in ["enabled", "disabled"] {
        let controls =
            vec![json!({"target_kind":"extension","target_id":"command.filesystem","state":state})];
        let policy = with_managed(snapshot("review", vec![]), false, controls.clone());
        assert_eq!(
            evaluate(&policy, &envelope(COMMAND)).result.minimum_action,
            "review"
        );
        let policy = with_managed(
            snapshot("review", vec![row(7, "artifact", "allow", "signed-bundle")]),
            false,
            controls.clone(),
        );
        assert_eq!(
            evaluate(&policy, &envelope(COMMAND)).result.minimum_action,
            "allow"
        );
        for floor in ["require-reapproval", "sandbox-required", "block"] {
            let policy = with_managed(
                snapshot(floor, vec![row(7, "artifact", "allow", "signed-bundle")]),
                false,
                controls.clone(),
            );
            assert_eq!(
                evaluate(&policy, &envelope(COMMAND)).result.minimum_action,
                floor
            );
        }
    }
}

#[test]
fn current_catalog_targets_do_not_authorize_unmodeled_mcp_requests() {
    for (kind, target) in [
        ("extension", "command.mcp-instapods"),
        (
            "permission",
            "command.mcp-instapods.permission.mcp-instapods-tool",
        ),
    ] {
        for state in ["enabled", "disabled"] {
            let policy = with_managed(
                snapshot("review", vec![]),
                false,
                vec![json!({"target_kind":kind,"target_id":target,"state":state})],
            );
            assert_eq!(
                evaluate(&policy, &envelope(COMMAND)).result.minimum_action,
                "review"
            );
            let mut source = envelope(COMMAND);
            source.raw_payload = json!({"tool_name":"mcp__instapods__synthetic","tool_input":{}});
            let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
            assert_eq!(
                apply_scoped_pre_tool_policy(&policy, &source, "codex", intrinsic, 100)
                    .err()
                    .as_deref(),
                Some("native_scoped_managed_policy_unsupported")
            );
        }
    }
}

#[test]
fn managed_unknown_delegated_and_unmodeled_requests_refuse_as_a_whole() {
    for target in [
        "command.synthetic",
        "command.package.node",
        "command.package.node.permission.install",
    ] {
        let kind = if target.contains(".permission.") {
            "permission"
        } else {
            "extension"
        };
        let policy = with_managed(
            snapshot("allow", vec![]),
            false,
            vec![json!({"target_kind":kind,"target_id":target,"state":"enabled"})],
        );
        let source = envelope(COMMAND);
        let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
        assert_eq!(
            apply_scoped_pre_tool_policy(&policy, &source, "codex", intrinsic, 100)
                .err()
                .as_deref(),
            Some("native_scoped_managed_policy_unsupported")
        );
    }
    let policy = with_managed(snapshot("allow", vec![]), false, vec![]);
    let mut source = envelope(COMMAND);
    source.raw_payload = json!({"tool_name":"mcp__synthetic__inspect","tool_input":{}});
    let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
    assert_eq!(
        apply_scoped_pre_tool_policy(&policy, &source, "codex", intrinsic, 100)
            .err()
            .as_deref(),
        Some("native_scoped_managed_policy_unsupported")
    );
}

#[path = "policy_scoped_expression_tests.rs"]
mod expression_tests;
