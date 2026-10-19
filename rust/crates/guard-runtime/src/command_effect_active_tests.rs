use super::*;
use guard_command::{parse_command, CommandModelRequestV1};
use serde_json::{json, Value};

fn request(controls: &CompiledNativeCommandControls) -> CommandEffectRequestV1 {
    command_request(controls, "vttforge init example")
}

fn command_request(
    controls: &CompiledNativeCommandControls,
    command: &str,
) -> CommandEffectRequestV1 {
    let model = parse_command(&CommandModelRequestV1 {
        command: command.into(),
        dialect: "posix".into(),
        transport: "shell_string".into(),
        extraction_provenance: "guard-shell".into(),
    })
    .unwrap();
    let result = guard_command::pretool::evaluate_pre_tool_envelope_with_execution_context(
        "claude-code",
        "PreToolUse",
        &json!({"tool_name":"Bash","tool_input":{"command":command}}),
        Some(controls),
        None,
        Default::default(),
        None,
    );
    let mut evidence = serde_json::to_value(result).unwrap();
    evidence["command_model"] = serde_json::to_value(&model).unwrap();
    serde_json::from_value(json!({
        "schema":COMMAND_EFFECT_REQUEST_SCHEMA,"request_id":"active-command",
        "command_text":command,"canonical_command":model,
        "native_extension_evidence":evidence,"control_snapshot":controls.control_binding(),
    }))
    .unwrap()
}

#[test]
fn compatibility_labels_require_request_bound_native_rule_evidence() {
    let home = std::env::temp_dir().join(format!(
        "guard-command-effect-compatibility-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    let controls =
        crate::contributed_mcp_catalog_test_support::controls_for(&home, false, &[], &[]);
    let catalog = controls.command_catalog().unwrap();
    // This source is intentionally absent from the admitted sparse catalog.
    let optional: Value = serde_json::from_str(include_str!(
        "../../../../contributions/command-sources/command.vttforge.json"
    ))
    .unwrap();
    let class = optional["extension"]["rules"][0]["action_classes"][0]
        .as_str()
        .unwrap();
    assert!(!catalog.has_action_class_owner(class));
    let mut inactive = request(&controls);
    inactive.compatibility_action_class = Some(class.into());
    let result = evaluate(&inactive, Some(&controls)).unwrap();
    assert!(result["controlling_action_class"].is_null());
    assert!(result["controlling_rule_id"].is_null());
    assert!(result["extension_observations"]
        .as_array()
        .unwrap()
        .is_empty());

    // Genuine legacy core labels retain their exact matched native owner.
    let (_, rule) = catalog.get_rule("command.git.force-push").unwrap();
    let core_class = rule.action_classes.first().unwrap();
    let mut core = command_request(&controls, "git push --force origin main");
    core.compatibility_action_class = Some(core_class.clone());
    let result = evaluate(&core, Some(&controls)).unwrap();
    assert_eq!(result["controlling_action_class"], *core_class);
    assert_eq!(result["controlling_rule_id"], rule.rule_id);
    assert_ne!(result["minimum_action"], "allow");
    // A real core label still cannot be replayed against another command.
    inactive.compatibility_action_class = Some(core_class.clone());
    let result = evaluate(&inactive, Some(&controls)).unwrap();
    assert!(result["controlling_action_class"].is_null());

    // The classifier's unowned fetch diagnostic is bound to the one rule whose
    // evidence selects it, and no other command's evidence admits it.
    let diagnostic = "unverified Git remote refresh";
    for command in [
        "git fetch https://example.invalid/project.git",
        "git -c core.sshCommand=payload fetch origin",
        "git --config-env credential.helper=HELPER fetch origin",
        "git --exec-path=/tmp fetch origin",
        "git fetch origin && git -c core.sshCommand=payload fetch origin",
    ] {
        let mut fetch = command_request(&controls, command);
        fetch.compatibility_action_class = Some(diagnostic.into());
        let result = evaluate(&fetch, Some(&controls)).unwrap();
        assert_eq!(result["controlling_action_class"], diagnostic, "{command}");
        assert_eq!(
            result["controlling_rule_id"], "command.git.unverified-fetch",
            "{command}"
        );
        assert_ne!(result["minimum_action"], "allow", "{command}");
    }
    let mut replay = command_request(&controls, "git push --force origin main");
    replay.compatibility_action_class = Some(diagnostic.into());
    let result = evaluate(&replay, Some(&controls)).unwrap();
    assert_ne!(result["controlling_action_class"], diagnostic);
    assert_eq!(result["controlling_rule_id"], rule.rule_id);
    inactive.compatibility_action_class = Some(diagnostic.into());
    let result = evaluate(&inactive, Some(&controls)).unwrap();
    assert!(result["controlling_action_class"].is_null());
    std::fs::remove_dir_all(home).unwrap();
}

#[test]
fn optional_command_effect_uses_admitted_catalog_and_rejects_tampering() {
    let home = std::env::temp_dir().join(format!(
        "guard-command-effect-active-{}",
        std::process::id()
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    let controls = crate::contributed_mcp_catalog_test_support::controls_for(
        &home,
        false,
        &["command.vttforge"],
        &["command.vttforge"],
    );
    let active = request(&controls);
    let result = evaluate(&active, Some(&controls)).unwrap();
    assert_eq!(result["controlling_rule_id"], "command.vttforge.init");
    assert_eq!(result["minimum_action"], "review");
    // Request layers cannot authorize optional metadata without a capture.
    assert!(evaluate(&active, None).is_err());
    let batch: CommandEffectBatchRequestV1 = serde_json::from_value(json!({
        "schema":COMMAND_EFFECT_BATCH_REQUEST_SCHEMA,"request_id":"active-batch","items":[active],
    }))
    .unwrap();
    let result: Value =
        serde_json::from_slice(&batch_in(&batch, Some(&controls)).unwrap()).unwrap();
    assert_eq!(result["items"][0]["status"], "ok");
    let mut tampered = batch.items[0].clone();
    tampered.control_snapshot["program_digest"] = json!("0".repeat(64));
    assert!(evaluate(&tampered, Some(&controls)).is_err());
    let inactive = crate::contributed_mcp_catalog_test_support::controls_for(
        &home,
        false,
        &["command.vttforge"],
        &[],
    );
    let result = evaluate(&request(&inactive), Some(&inactive)).unwrap();
    assert!(result["extension_observations"]
        .as_array()
        .unwrap()
        .iter()
        .all(|observation| observation["extension_id"] != "command.vttforge"));
    std::fs::remove_dir_all(home).unwrap();
}
